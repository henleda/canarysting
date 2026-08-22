// Package cilium is a Cilium-backed containment enforcer: instead of programming
// the kernel verdict map (internal/sting/containment.KernelContainer), it writes a
// namespaced CiliumNetworkPolicy that makes Cilium DROP the attributed flow — the
// "we attribute, Cilium enforces" spine.
//
// It is a SECOND implementation of the same containment.Container shape the kernel
// enforcer satisfies (Apply(contract.Verdict, containment.Action) / Release(...)),
// so it drops into the adapter's OnVerdict->enforcer seam without touching the
// decision path. Apply renders + writes the CNP; Release deletes it.
//
// Precision (mirrors containment's cookie-0 refusal, rule "containment must be
// precise"): if the flow's source is unresolvable — neither a source IP off the
// flow (contract.AttrSourceAddress) nor a resolved source label set — Apply REFUSES
// (returns an error) and writes nothing. It never emits an over-broad CNP that
// would deny bystanders.
package cilium

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/k8s/cnp"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// ErrUnresolvableSource is returned by Apply when the flow carries no resolvable
// source (no source IP and no source labels) — there is nothing precise to deny.
// It mirrors containment.ErrUnattributable (which guards the socket-cookie join);
// here the CNP enforces on source identity, so the source is what must resolve.
var ErrUnresolvableSource = errors.New("cilium: flow source unresolvable (no source IP and no source labels); refusing to write a CNP")

// SourceResolver optionally resolves a flow's SOURCE workload labels (the
// higher-confidence fromEndpoints path). It returns ok=false when it cannot resolve
// the source to a label set, and the enforcer falls back to the source IP (the
// minimal fromCIDR path). It exists so mesh/label identity (internal/identity) can
// be plugged in later without changing the enforcer; the minimal actuator runs with
// a nil resolver (IP path only).
type SourceResolver interface {
	SourceLabels(v contract.Verdict) (map[string]string, bool)
}

// Config configures an Enforcer.
type Config struct {
	// Writer is the CNP write seam (a *cnp.DynamicWriter in production, a fake in
	// tests). Required.
	Writer cnp.PolicyWriter

	// Scope is the CanarySting scope key stamped on every CNP this enforcer writes.
	Scope contract.ScopeKey

	// TargetNamespace and TargetLabels select the decoy (target) workload the CNP
	// protects (its endpointSelector). Both are required — an empty target would
	// render a match-all policy, which cnp.Render refuses.
	TargetNamespace string
	TargetLabels    map[string]string

	// Resolver optionally upgrades a flow to the fromEndpoints (label) path. Nil
	// means IP-only (the minimal actuator).
	Resolver SourceResolver
}

// Enforcer writes/deletes CiliumNetworkPolicies to contain/release attributed
// flows. It satisfies the same Apply/Release shape as containment.Container.
type Enforcer struct {
	w        cnp.PolicyWriter
	scope    contract.ScopeKey
	targetNS string
	targetLb map[string]string
	resolver SourceResolver
}

// Compile-time proof the CNP enforcer is drop-in for the kernel containment shape.
var _ containment.Container = (*Enforcer)(nil)

// New builds an Enforcer, refusing a config that would produce imprecise policies
// (nil writer, empty target).
func New(cfg Config) (*Enforcer, error) {
	if cfg.Writer == nil {
		return nil, errors.New("cilium: nil PolicyWriter")
	}
	if cfg.TargetNamespace == "" || len(cfg.TargetLabels) == 0 {
		return nil, errors.New("cilium: TargetNamespace and TargetLabels are required (a CNP must not select every pod)")
	}
	// Copy the target labels so a later mutation of the caller's map cannot change
	// what this enforcer writes.
	tl := make(map[string]string, len(cfg.TargetLabels))
	for k, v := range cfg.TargetLabels {
		tl[k] = v
	}
	return &Enforcer{
		w:        cfg.Writer,
		scope:    cfg.Scope,
		targetNS: cfg.TargetNamespace,
		targetLb: tl,
		resolver: cfg.Resolver,
	}, nil
}

// Apply renders the CNP for the flow and writes it (create-or-update). It refuses
// (ErrUnresolvableSource) and writes nothing when the source cannot be resolved.
func (e *Enforcer) Apply(v contract.Verdict, a containment.Action) error {
	p, err := e.params(v, a)
	if err != nil {
		return err
	}
	obj, err := cnp.Render(p)
	if err != nil {
		return fmt.Errorf("cilium: render CNP: %w", err)
	}
	if err := e.w.Ensure(context.Background(), obj); err != nil {
		return fmt.Errorf("cilium: apply CNP %s/%s: %w", e.targetNS, cnp.Name(p), err)
	}
	return nil
}

// Release deletes the CNP that Apply wrote for this flow. It is idempotent: a
// NotFound is a no-op (handled by the writer), and an unresolvable source is a
// no-op nil (nothing could ever have been written under a deterministic name),
// mirroring the kernel container's cookie-0 Release.
func (e *Enforcer) Release(v contract.Verdict) error {
	p, err := e.params(v, containment.Jail)
	if err != nil {
		// Unresolvable source: we never wrote anything to delete. Do not surface an
		// error on a de-escalation path — releasing an unattributable flow is a no-op.
		return nil
	}
	name := cnp.Name(p)
	if err := e.w.Delete(context.Background(), e.targetNS, name); err != nil {
		return fmt.Errorf("cilium: release CNP %s/%s: %w", e.targetNS, name, err)
	}
	return nil
}

// params builds the render params from a verdict + action. It resolves the source
// (labels via the optional resolver, else the source IP off the flow) and REFUSES
// (ErrUnresolvableSource) when neither resolves.
func (e *Enforcer) params(v contract.Verdict, a containment.Action) (cnp.Params, error) {
	scope := v.Scope
	if scope == "" {
		scope = e.scope
	}
	p := cnp.Params{
		Scope:           string(scope),
		TargetNamespace: e.targetNS,
		TargetLabels:    e.targetLb,
		SocketCookie:    v.Flow.SocketCookie,
		Tier:            strconv.Itoa(int(v.Tier)),
		Reason:          a.String(),
	}

	// Higher-confidence path: resolved source workload labels.
	if e.resolver != nil {
		if lbls, ok := e.resolver.SourceLabels(v); ok && len(lbls) > 0 {
			p.SourceLabels = lbls
			p.Confidence = "label"
			return p, nil
		}
	}

	// Minimal path: the caller's IP straight off the flow (scoring-irrelevant context
	// the adapter stamps under AttrSourceAddress — rule 4 keeps the cookie the join).
	if ip := sourceIP(v); ip != "" {
		p.SourceIP = ip
		p.Confidence = "source-ip"
		return p, nil
	}

	return cnp.Params{}, ErrUnresolvableSource
}

// sourceIP extracts a bare IP from the flow's stamped source address. The address
// may arrive as "ip", "ip:port", or "[v6]:port"; we return the host portion only,
// or "" when there is no parseable IP.
func sourceIP(v contract.Verdict) string {
	raw := strings.TrimSpace(v.Flow.L7Attributes[contract.AttrSourceAddress])
	if raw == "" {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	// Try host:port.
	if host, _, err := net.SplitHostPort(raw); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
	}
	return ""
}
