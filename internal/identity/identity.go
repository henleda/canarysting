// Package identity is the single home for workload-identity resolution — "the
// spine" (docs/ARCHITECTURE_SPEC_K8S §2: "Identity is the spine"). It defines the
// stable, logical identity of a workload (never an ephemeral pod or IP) and the
// confidence with which it was resolved.
//
// Mesh/SPIFFE identity is cryptographically verified per connection (high
// confidence); label-derived identity is control-plane-asserted, spoofable by a
// compromised node, and racy under pod-IP churn (explicitly LOWER confidence). Any
// code that resolves workload identity MUST prefer mesh identity and MUST mark
// label-derived identity with lower confidence on the edges it produces — the two
// are never equal (CLAUDE.md safety rule; docs/IDENTITY.md).
//
// This root package holds only types and imports nothing but stdlib, so it stays
// production-importable and free of any engine/adapter/proxy coupling. The
// resolvers live in the mesh/ and labels/ leaves; the workload/ facade prefers
// mesh over labels; the scopemap/ leaf maps a resolved identity onto the engine's
// scope key.
//
// Status: prototype (M1 slice 1). The label-derived Source (a read-only Kubernetes
// informer) and the mesh source binding are wired in later slices.
package identity

// Confidence expresses how much to trust a resolved WorkloadID. It is ordered: a
// higher value is strictly more trustworthy. Any reachability edge or attribution
// derived from an identity MUST carry its Confidence so a label-derived (spoofable)
// edge is never treated as equal to a mesh-verified one.
type Confidence uint8

const (
	// ConfidenceNone means no identity could be resolved.
	ConfidenceNone Confidence = iota
	// ConfidenceAsserted is label-/control-plane-derived identity: spoofable by a
	// compromised node and racy under pod-IP churn. An explicitly LOWER-confidence
	// fallback, never the primary assumption.
	ConfidenceAsserted
	// ConfidenceVerified is mesh/SPIFFE identity, cryptographically verified per
	// connection: the primary, high-confidence path.
	ConfidenceVerified
)

// String renders the confidence for logs and edge annotations.
func (c Confidence) String() string {
	switch c {
	case ConfidenceVerified:
		return "verified"
	case ConfidenceAsserted:
		return "asserted"
	default:
		return "none"
	}
}

// WorkloadID is a stable, logical workload identity. It is intentionally free of
// pods and IPs: pods and IPs churn, identities do not (docs/ARCHITECTURE_SPEC_K8S
// §3 — nodes are stable logical workloads abstracted from ephemeral pods, mapped
// to identity via label/SA set, never by raw IP).
//
// NOTE — a WorkloadID is a per-flow RESOLUTION RESULT (the identity plus how, and
// therefore from which source, it was resolved), NOT a canonical graph node key.
// The same logical workload resolved via mesh (ns+sa, Verified) versus labels
// (ns+name, Asserted) yields different field values, so raw struct equality /
// map-keying would split one workload into several nodes. The M4 blast-radius
// graph must project a stable node key that reconciles mesh and label identity,
// and must carry Confidence on EDGES (per docs), never fold it into node identity.
type WorkloadID struct {
	// TrustDomain is the SPIFFE trust domain (mesh). It also serves as the
	// cluster-level identity for scope derivation. Empty for a label-only identity
	// with no known cluster UID.
	TrustDomain string
	// Namespace is the Kubernetes namespace the workload runs in.
	Namespace string
	// ServiceAccount is the Kubernetes ServiceAccount (the mesh SVID's `sa`).
	ServiceAccount string
	// Name is a human-legible service name (e.g. "payments" or "orders/payments").
	Name string
	// Confidence is how this identity was resolved (verified mesh vs asserted label).
	Confidence Confidence
}

// Empty reports whether no identity was resolved (Confidence is None). Resolvers
// return the zero WorkloadID to signal a miss; callers continue down the
// precedence chain (mesh → labels → hard fail) rather than inventing a scope.
func (w WorkloadID) Empty() bool { return w.Confidence == ConfidenceNone }
