// Package scopemap maps a resolved workload identity onto the engine's scope key —
// the identity→scope glue that makes scope resolution identity-driven rather than a
// single static operator boundary (docs/SCOPE.md; docs/ARCHITECTURE_SPEC_K8S §2).
//
// It produces values the engine's scope.StaticResolver already understands: a
// scope.ClusterIdentity (the cluster-level scope + unzoned catch-all) and ordered
// scope.Zones (per-namespace trust zones). It is the ONLY identity leaf that
// imports the engine's scope package; the core resolvers stay engine-free.
//
// Fail-closed is preserved (rule 5): the ClusterIdentity returns ok=false when it
// can derive nothing, so the resolver falls through to its Boundary/hard-fail
// rather than inventing a global scope; empty zone keys are dropped rather than
// emitted (an empty zone key forces ErrUnresolved).
//
// Status: prototype (M1 slice 1). The composition root wires these from an
// operator-supplied cluster UID + namespace→scope map in a later slice.
package scopemap

import (
	"sort"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/identity/workload"
)

// ClusterIdentity returns a scope.ClusterIdentity that derives the cluster-level
// scope key from a flow's resolved workload identity: the SPIFFE trust domain in a
// mesh (prefixed "td:"), else the operator-supplied clusterUID (prefixed
// "cluster:"). Only a VERIFIED mesh identity carries a TrustDomain (a label-derived
// identity leaves it empty), so a non-mesh flow always routes to "cluster:<uid>"
// and only a real mesh trust domain ever lands under "td:" — the two never collide
// on the same key, and one cluster's non-mesh flows all share a single scope key
// (no fragmentation). It returns ok=false only when neither is available, so the
// caller's resolver falls through to its Boundary/hard-fail — never a global scope
// (rule 5).
func ClusterIdentity(r workload.Resolver, clusterUID string) scope.ClusterIdentity {
	return func(f contract.FlowIdentity) (contract.ScopeKey, bool) {
		if w := r.Resolve(f); w.TrustDomain != "" {
			return contract.ScopeKey("td:" + w.TrustDomain), true
		}
		if clusterUID != "" {
			return contract.ScopeKey("cluster:" + clusterUID), true
		}
		return "", false
	}
}

// Zones builds ordered scope.Zones mapping each Kubernetes namespace to a scope
// key, so per-namespace trust zones become the partition unit: a flow lands in the
// zone for its resolved namespace. Ordering is deterministic (sorted by namespace)
// so precedence is stable and reproducible. Entries with an empty namespace or an
// empty scope key are dropped — an empty zone key would force ErrUnresolved on any
// matching flow (rule 5), which must be a config decision, not an accident.
//
// PERF NOTE — each zone's Match closure resolves the flow's identity independently,
// and the scope.StaticResolver tries zones in order then Cluster, so resolving one
// flow costs up to N+1 identity resolutions. This is cheap today (SPIFFE parse only)
// and stays cheap in slice 2 because the label Source is a client-go informer whose
// Lookup is an in-memory cache read. A resolve-once-per-flow optimization (memoizing
// on the socket cookie) can land with that wiring if the resolver ever moves onto a
// hot path; it is deliberately not built now (no hot-path consumer yet).
func Zones(r workload.Resolver, nsToScope map[string]contract.ScopeKey) []scope.Zone {
	names := make([]string, 0, len(nsToScope))
	for ns, key := range nsToScope {
		if ns == "" || key == "" {
			continue
		}
		names = append(names, ns)
	}
	sort.Strings(names)

	zones := make([]scope.Zone, 0, len(names))
	for _, ns := range names {
		ns, key := ns, nsToScope[ns] // capture per iteration for the closure
		zones = append(zones, scope.Zone{
			Key: key,
			Match: func(f contract.FlowIdentity) bool {
				return r.Resolve(f).Namespace == ns
			},
		})
	}
	return zones
}
