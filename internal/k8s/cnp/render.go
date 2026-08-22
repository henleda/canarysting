// Package cnp renders and writes the minimal CiliumNetworkPolicy (CNP) that
// surgically contains an attributed flow: "we attribute, Cilium enforces".
//
// The rendered shape is the one we validated on a live Cilium 1.19.5 / k3s
// cluster: a namespaced ingressDeny CNP whose endpointSelector picks the decoy
// (target) workload and whose ingressDeny rule names the attributed SOURCE — by
// CIDR (the minimal, source-IP path) or by fromEndpoints matchLabels (the
// higher-confidence path when the source's workload labels resolve). Such a CNP
// DROPS the same-node attributed flow, leaves siblings untouched, and recovers on
// delete.
//
// This file is PURE Go: Render() builds an *unstructured.Unstructured and touches
// no cluster. It is proxy-agnostic and enforcement-mechanism-agnostic in the same
// spirit as the kernel containment layer (internal/sting/containment): the
// attribution decision lives elsewhere; this only renders the actuation object.
//
// Precision (mirrors containment's ErrUnattributable / cookie-0 refusal): Render
// REFUSES to produce a CNP when the source is unresolvable (neither a source label
// set nor a source IP) or when the target is unconstrained (no namespace or no
// target labels). An over-broad CNP would deny bystanders — a critical failure.
package cnp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVR is the GroupVersionResource of a CiliumNetworkPolicy. The dynamic client
// addresses CNPs through it. We do NOT import github.com/cilium/cilium — the CNP
// is written as an unstructured object over this GVR.
var GVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}

const (
	apiVersion = "cilium.io/v2"
	kind       = "CiliumNetworkPolicy"

	// namePrefix is the stable prefix of every CNP this actuator writes, so an
	// operator can find and reap them (kubectl get cnp -l canarysting.io/managed-by=canarysting).
	namePrefix = "canarysting-contain-"

	// Metadata stamp keys (canarysting.io/*): auditability + lifecycle. socket-cookie,
	// tier and confidence are LABELS (short, charset-safe, selectable). scope, reason
	// and the resolved source are ANNOTATIONS (free-form; a scope key or reason may
	// carry characters a label value forbids).
	LabelManagedBy    = "canarysting.io/managed-by"
	LabelSocketCookie = "canarysting.io/socket-cookie"
	LabelTier         = "canarysting.io/tier"
	LabelConfidence   = "canarysting.io/confidence"
	AnnScope          = "canarysting.io/scope"
	AnnReason         = "canarysting.io/reason"
	AnnSource         = "canarysting.io/source"

	managedByValue = "canarysting"
)

// Errors returned by Render when the inputs would produce an imprecise or malformed
// CNP. They mirror containment.ErrUnattributable: refuse rather than over-deny.
var (
	// ErrUnresolvableSource is returned when neither a source label set nor a source
	// IP is present — there is nothing precise to deny, so nothing is rendered.
	ErrUnresolvableSource = errors.New("cnp: source unresolvable (no labels and no IP); refusing to render an over-broad policy")
	// ErrEmptyTarget is returned when the target namespace or target labels are
	// empty — an unconstrained endpointSelector would select every pod in scope.
	ErrEmptyTarget = errors.New("cnp: target namespace and target labels are required; refusing to render a match-all endpointSelector")
	// ErrInvalidSourceIP is returned when a source IP is set but does not parse.
	ErrInvalidSourceIP = errors.New("cnp: source IP does not parse")
)

// Params are the inputs to Render. The SOURCE is one of two mutually-exclusive
// forms: SourceLabels (higher confidence — fromEndpoints) OR SourceIP (the minimal
// path — fromCIDR /32). When both are set, SourceLabels wins (higher confidence).
type Params struct {
	// Scope is the CanarySting scope key this containment belongs to (stamped for
	// audit; per-scope isolation is enforced by the caller, not here).
	Scope string

	// SourceLabels, when non-empty, renders a fromEndpoints matchLabels rule (the
	// source's workload identity resolved — higher confidence).
	SourceLabels map[string]string
	// SourceIP, when SourceLabels is empty, renders a fromCIDR <ip>/32 rule (the
	// minimal path: the caller's IP straight off the flow). A bare IP, no mask.
	SourceIP string

	// TargetNamespace and TargetLabels select the decoy (target) workload the CNP
	// protects — the endpointSelector. Both are required (precision).
	TargetNamespace string
	TargetLabels    map[string]string

	// SocketCookie is the flow's attribution key (rule 4). Stamped as a label for
	// correlation; a CNP enforces on source, so this is audit context, not the match.
	SocketCookie uint64
	// Tier is the engine tier that produced this containment (stamped, e.g. "3").
	Tier string
	// Confidence marks the attribution confidence of the source (e.g. "source-ip",
	// "label", "mesh"). Stamped so an operator can see how the source was resolved.
	Confidence string
	// Reason is a free-text audit note (stamped as an annotation).
	Reason string
}

// Name is the deterministic CNP name for these params, derived from
// scope + source + target so that Apply and Release address the SAME object. It is
// a valid DNS-1123 name (prefix + 16 lowercase hex chars). The socket cookie is NOT
// part of the name (it is per-connection; a re-attributed same source→target flow
// must reuse the one policy rather than pile up per-cookie duplicates).
func Name(p Params) string {
	h := sha256.New()
	// A newline-delimited canonical form; each field is order-independent.
	fmt.Fprintf(h, "scope=%s\n", p.Scope)
	fmt.Fprintf(h, "ns=%s\n", p.TargetNamespace)
	fmt.Fprintf(h, "target=%s\n", canonLabels(p.TargetLabels))
	fmt.Fprintf(h, "source=%s\n", sourceDescriptor(p))
	sum := h.Sum(nil)
	return namePrefix + hex.EncodeToString(sum[:8])
}

// Render builds the golden CNP for these params, or an error when the source is
// unresolvable or the target is unconstrained (precision refusal).
func Render(p Params) (*unstructured.Unstructured, error) {
	if p.TargetNamespace == "" || len(p.TargetLabels) == 0 {
		return nil, ErrEmptyTarget
	}
	useEndpoints := len(p.SourceLabels) > 0
	if !useEndpoints && strings.TrimSpace(p.SourceIP) == "" {
		return nil, ErrUnresolvableSource
	}

	var ingressRule map[string]interface{}
	if useEndpoints {
		ingressRule = map[string]interface{}{
			"fromEndpoints": []interface{}{
				map[string]interface{}{"matchLabels": toIfaceMap(p.SourceLabels)},
			},
		}
	} else {
		ip := net.ParseIP(strings.TrimSpace(p.SourceIP))
		if ip == nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidSourceIP, p.SourceIP)
		}
		ingressRule = map[string]interface{}{
			"fromCIDR": []interface{}{hostCIDR(ip)},
		}
	}

	labels := map[string]interface{}{
		LabelManagedBy:    managedByValue,
		LabelSocketCookie: fmt.Sprintf("%d", p.SocketCookie),
	}
	if p.Tier != "" {
		labels[LabelTier] = p.Tier
	}
	if p.Confidence != "" {
		labels[LabelConfidence] = p.Confidence
	}

	annotations := map[string]interface{}{
		AnnSource: sourceDescriptor(p),
	}
	if p.Scope != "" {
		annotations[AnnScope] = p.Scope
	}
	if p.Reason != "" {
		annotations[AnnReason] = p.Reason
	}

	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":        Name(p),
			"namespace":   p.TargetNamespace,
			"labels":      labels,
			"annotations": annotations,
		},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": toIfaceMap(p.TargetLabels),
			},
			"ingressDeny": []interface{}{ingressRule},
		},
	}}
	return obj, nil
}

// sourceDescriptor is the canonical, human-legible string identifying the source of
// a containment: "ep:<sorted k=v>" for the endpoints path, "cidr:<ip>/32" for the
// IP path. It feeds both the deterministic name hash and the audit annotation.
func sourceDescriptor(p Params) string {
	if len(p.SourceLabels) > 0 {
		return "ep:" + canonLabels(p.SourceLabels)
	}
	if ip := net.ParseIP(strings.TrimSpace(p.SourceIP)); ip != nil {
		return "cidr:" + hostCIDR(ip)
	}
	return "cidr:" + strings.TrimSpace(p.SourceIP) + "/32"
}

// hostCIDR renders a single-host CIDR for an IP: /32 for IPv4, /128 for IPv6.
func hostCIDR(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

// canonLabels renders a label map as a sorted, comma-joined "k=v" string, so two
// equal maps always produce the same descriptor (hence the same name).
func canonLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

// toIfaceMap converts a string map to the map[string]interface{} unstructured
// requires (scalar leaves must be interface{}-typed).
func toIfaceMap(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
