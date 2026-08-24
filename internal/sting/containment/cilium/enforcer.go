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
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

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

	// written tracks the EXACT object Apply Ensured for each flow, keyed by a stable
	// verdict key (socket cookie, or the source IP when the cookie is 0), so Release
	// deletes precisely THAT object rather than a name it recomputes. A SourceResolver
	// can drift between Apply and Release (labels resolve, then stop resolving, or
	// resolve to a different set); a recomputed name would then address a DIFFERENT
	// CNP and leak the original. Guarded by mu (the adapter delivers verdicts from
	// multiple request goroutines). See Finding #2.
	mu      sync.Mutex
	written map[string]writtenCNP
}

// writtenCNP is the namespace/name identity of a CNP this enforcer created, recorded
// so Release can delete exactly it.
type writtenCNP struct {
	namespace string
	name      string
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
		written:  make(map[string]writtenCNP),
	}, nil
}

// Apply renders the CNP for the flow and writes it (create-or-update). It refuses
// (ErrUnresolvableSource) and writes nothing when the source cannot be resolved.
//
// Compose with the CNI, don't overreach it (Finding #1): a Cilium L3/L4 policy has
// no rate-limit primitive — it can only PERMIT or DROP. So only a DROP-intent action
// (containment.Jail / containment.HardDeny) writes a deny CNP. A Tier-2
// containment.RateLimit is an L7 velocity-attrition concern handled by the adapter's
// attritor (the tarpit), NOT by the CNI: turning it into a hard-deny CNP would over-
// enforce, dropping a flow the tier only meant to throttle. This is the honest split:
// the CNI does drops, L7 does throttling.
//
// A non-drop action is not merely a no-op, though: on a Tier-3 -> Tier-2 DE-ESCALATION
// the engine downgraded a jailed flow to throttle, so any drop CNP this enforcer wrote
// for the flow must be LIFTED — otherwise Cilium keeps dropping the flow before it can
// reach L7 and the throttle can never engage. The kernel enforcer gets this for free
// (its Apply reprograms the verdict map from jail to rate-limit); we mirror it by
// Releasing the drop. Release is idempotent, so a never-jailed flow is a cheap no-op.
func (e *Enforcer) Apply(v contract.Verdict, a containment.Action) error {
	if !isDropAction(a) {
		if err := e.Release(v); err != nil {
			return err
		}
		log.Printf("cilium enforcer: non-drop action is an L7 concern; no CNI drop, lifted any prior jail (action=%s cookie=%#x)", a, v.Flow.SocketCookie)
		return nil
	}
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
	// Record the EXACT object we wrote so Release deletes precisely it, even if the
	// resolver's answer drifts before the release (Finding #2).
	e.recordWritten(v, e.targetNS, cnp.Name(p))
	return nil
}

// isDropAction reports whether a containment action carries DROP intent — the only
// intent a Cilium L3/L4 CNP can express. Tier-3 Jail and HardDeny drop; a Tier-2
// RateLimit does not (it is throttled at L7, not the CNI).
func isDropAction(a containment.Action) bool {
	return a == containment.Jail || a == containment.HardDeny
}

// Release deletes the CNP that Apply wrote for this flow. It is idempotent: a
// NotFound is a no-op (handled by the writer), and an unresolvable source is a
// no-op nil (nothing could ever have been written under a deterministic name),
// mirroring the kernel container's cookie-0 Release.
//
// Correct under resolver drift (Finding #2): it first looks the flow up by its
// STABLE verdict key and deletes the EXACT {namespace,name} Apply recorded — so a
// SourceResolver whose answer changes between Apply and Release cannot make Release
// address a recomputed (and therefore wrong) name and leak the original CNP. Only
// when there is no record (this enforcer instance never Applied this flow, e.g.
// after a restart) does it fall back to the best-effort recompute-and-delete.
func (e *Enforcer) Release(v contract.Verdict) error {
	if key := verdictKey(v); key != "" {
		e.mu.Lock()
		rec, ok := e.written[key]
		if ok {
			delete(e.written, key)
		}
		e.mu.Unlock()
		if ok {
			if err := e.w.Delete(context.Background(), rec.namespace, rec.name); err != nil {
				return fmt.Errorf("cilium: release CNP %s/%s: %w", rec.namespace, rec.name, err)
			}
			return nil
		}
	}

	// Fallback (no recorded object): recompute the deterministic name and best-effort
	// delete. This is the pre-Finding-#2 behavior, correct only when the resolver has
	// not drifted since Apply.
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

// Close satisfies the adapter's enforcer interface (Apply/Release/Close). The CNP
// enforcer owns no kernel/loader handle of its own — the dynamic client's lifecycle
// belongs to the caller that built it — so Close is a no-op.
func (e *Enforcer) Close() error { return nil }

// maxWritten bounds the in-memory tracking map. A contained flow that never receives
// a sub-TierContain verdict (an attacker flow that simply ends while still jailed —
// the common case) is only removed on Release, so without a cap the map would grow
// unbounded in a long-lived adapter. Contained flows are rare, so this ceiling is far
// above any real working set; on the pathological path an evicted entry only costs its
// flow the keyed-delete fast path (Release falls back to the deterministic-name
// recompute, still correct for the stable cookie/IP source). Mirrors the self-bounding
// discipline of the adapter's verdictSequencer.
const maxWritten = 4096

// recordWritten remembers the object Apply Ensured for a flow, keyed by the flow's
// stable verdict key, so Release can delete precisely it (Finding #2). A flow with
// no stable key (no cookie and no source IP) is never written in the first place, so
// it is simply not recorded.
func (e *Enforcer) recordWritten(v contract.Verdict, ns, name string) {
	key := verdictKey(v)
	if key == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Bound the map: if at capacity and this is a new key, evict one arbitrary entry
	// (Go map iteration order is unspecified) before inserting. Evicting a tracking
	// record only degrades that flow's Release to the recompute fallback, never leaks
	// the live CNP itself.
	if _, exists := e.written[key]; !exists && len(e.written) >= maxWritten {
		for k := range e.written {
			delete(e.written, k)
			break
		}
		log.Printf("cilium enforcer: written-map at cap %d; evicted one tracking entry (Release for that flow falls back to name recompute)", maxWritten)
	}
	e.written[key] = writtenCNP{namespace: ns, name: name}
}

// verdictKey is a STABLE identity for a flow across an Apply/Release pair, chosen so
// it does NOT depend on a SourceResolver whose answer may drift. The socket cookie
// (rule 4, the cross-boundary join) is the key; when it is 0 — the minimal actuator/
// harness path, which has no kernel cookie — the resolved source IP stands in. Empty
// only when neither is present (an unwritable flow).
func verdictKey(v contract.Verdict) string {
	if v.Flow.SocketCookie != 0 {
		return fmt.Sprintf("cookie:%d", v.Flow.SocketCookie)
	}
	if ip := sourceIP(v); ip != "" {
		return "ip:" + ip
	}
	return ""
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
