// Package mesh resolves the PRIMARY, high-confidence workload identity: the
// mesh/SPIFFE identity a service mesh (Istio/Linkerd/Cilium mTLS, SPIFFE/SPIRE)
// cryptographically verifies per connection and surfaces as the peer SVID. It
// parses the SPIFFE ID the adapter stamps onto contract.FlowIdentity.SPIFFEID.
//
// The SPIFFE ID is L7 CONTEXT for attribution and scope, NEVER the cross-boundary
// join key — that is always the socket cookie (rule 4). Resolving identity from it
// does not make it a second join mechanism.
//
// Status: prototype (M1 slice 1). A concrete mesh SOURCE binding (e.g. Istio SDS)
// is a later slice; today the verified SVID already arrives on the flow via the
// Envoy adapter, so this package consumes that directly.
package mesh

import (
	"strings"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/identity"
	"github.com/canarysting/canarysting/internal/identity/naming"
)

// ParseSPIFFE parses a SPIFFE ID of the Workload-API shape into a Verified
// WorkloadID. It recognizes the SVID path conventions:
//
//	spiffe://<trust-domain>/ns/<ns>/sa/<sa>
//	spiffe://<trust-domain>/sa/<sa>
//	spiffe://<trust-domain>/ns/<ns>
//
// It returns ok=false only when id is not a parseable spiffe:// URI with a trust
// domain and at least one path segment — the caller then falls through the
// precedence chain. On success Confidence is Verified and Name is derived via the
// shared naming parser. Never panics.
func ParseSPIFFE(id string) (identity.WorkloadID, bool) {
	const scheme = "spiffe://"
	if !strings.HasPrefix(id, scheme) {
		return identity.WorkloadID{}, false
	}
	rest := id[len(scheme):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return identity.WorkloadID{}, false // trust domain only, no path
	}
	trustDomain := rest[:slash]
	path := strings.Trim(rest[slash:], "/")
	if trustDomain == "" || path == "" {
		return identity.WorkloadID{}, false
	}

	var ns, sa string
	segs := strings.Split(path, "/")
	for i := 0; i+1 < len(segs); i += 2 {
		switch segs[i] {
		case "ns":
			ns = segs[i+1]
		case "sa":
			sa = segs[i+1]
		}
	}

	return identity.WorkloadID{
		TrustDomain:    trustDomain,
		Namespace:      ns,
		ServiceAccount: sa,
		Name:           deriveName(ns, sa, id),
		Confidence:     identity.ConfidenceVerified,
	}, true
}

// deriveName builds the service name from the SAME structured ns/sa parse that
// populates Namespace and ServiceAccount, so Name can never disagree with them
// about what was parsed. Only a non-conforming path that carries no ns/sa markers
// falls back to the tolerant last-segment parser — such an SVID legitimately
// yields a name-only identity (empty Namespace/ServiceAccount).
func deriveName(ns, sa, id string) string {
	switch {
	case ns != "" && sa != "":
		return ns + "/" + sa
	case sa != "":
		return sa
	case ns != "":
		return ns
	default:
		name, _ := naming.ServiceNameFromSPIFFE(id)
		return name
	}
}

// Resolve returns the verified mesh identity carried on a flow's SPIFFE SVID, or
// the zero WorkloadID (Confidence None) if the flow carries no parseable SPIFFE
// identity (no mesh, or a plaintext peer). It never blends in any lower-confidence
// signal — that is the workload facade's job.
func Resolve(f contract.FlowIdentity) identity.WorkloadID {
	w, ok := ParseSPIFFE(f.SPIFFEID)
	if !ok {
		return identity.WorkloadID{}
	}
	return w
}
