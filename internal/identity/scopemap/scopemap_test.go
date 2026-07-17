package scopemap

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/identity/labels"
	"github.com/canarysting/canarysting/internal/identity/workload"
)

func meshFlow(spiffe string) contract.FlowIdentity { return contract.FlowIdentity{SPIFFEID: spiffe} }

type fakeLabelSource struct {
	meta labels.PodMeta
	ok   bool
}

func (f fakeLabelSource) Lookup(contract.FlowIdentity) (labels.PodMeta, bool) { return f.meta, f.ok }

// A label-derived (non-mesh) flow must route to "cluster:<operatorUID>", never
// "td:<...>" — so one cluster's non-mesh flows all share ONE scope key and its
// learned state does not fragment. Guards the fix for the TrustDomain-overload bug.
func TestClusterIdentity_LabelDerivedFlowRoutesToClusterNotTrustDomain(t *testing.T) {
	r := workload.Resolver{Labels: fakeLabelSource{
		meta: labels.PodMeta{Namespace: "prod", Labels: map[string]string{"app": "web"}},
		ok:   true,
	}}
	ci := ClusterIdentity(r, "cluster-uid-1")
	if got, ok := ci(contract.FlowIdentity{SocketCookie: 5}); !ok || got != "cluster:cluster-uid-1" {
		t.Fatalf("label-derived flow: got (%q,%v), want (cluster:cluster-uid-1,true) — never a td:<uid> key", got, ok)
	}
}

func TestClusterIdentity_PrefersTrustDomainThenUID(t *testing.T) {
	ci := ClusterIdentity(workload.Resolver{}, "uid-123")

	if k, ok := ci(meshFlow("spiffe://cluster.local/ns/orders/sa/payments")); !ok || k != "td:cluster.local" {
		t.Fatalf("mesh flow: got (%q,%v), want (td:cluster.local,true)", k, ok)
	}
	if k, ok := ci(contract.FlowIdentity{SocketCookie: 1}); !ok || k != "cluster:uid-123" {
		t.Fatalf("no-mesh flow: got (%q,%v), want (cluster:uid-123,true)", k, ok)
	}
}

func TestClusterIdentity_FailsClosedWithoutMeshOrUID(t *testing.T) {
	ci := ClusterIdentity(workload.Resolver{}, "") // no usable mesh source, no UID
	if k, ok := ci(contract.FlowIdentity{}); ok || k != "" {
		t.Fatalf("got (%q,%v), want (\"\",false) so the resolver falls through to hard-fail", k, ok)
	}
	// Wired into the real resolver with no Boundary => ErrUnresolved, never a global scope (rule 5).
	r, err := scope.NewStaticResolver(scope.Config{Cluster: ci})
	if err != nil {
		t.Fatalf("resolver build: %v", err)
	}
	if _, err := r.Resolve(contract.FlowIdentity{}); !errors.Is(err, scope.ErrUnresolved) {
		t.Fatalf("want ErrUnresolved, got %v", err)
	}
}

func TestScopeResolution_IsIdentityDrivenNotWireDriven(t *testing.T) {
	r, err := scope.NewStaticResolver(scope.Config{
		Cluster:  ClusterIdentity(workload.Resolver{}, "uid-123"),
		Boundary: "operator-boundary",
	})
	if err != nil {
		t.Fatalf("resolver build: %v", err)
	}
	// Two different mesh-verified identities resolve to two distinct scopes — the
	// scope is a pure function of the verified identity, never an attacker-chosen value.
	a, _ := r.Resolve(meshFlow("spiffe://td-a/ns/x/sa/y"))
	b, _ := r.Resolve(meshFlow("spiffe://td-b/ns/x/sa/y"))
	if a != "td:td-a" || b != "td:td-b" || a == b {
		t.Fatalf("identity-driven scope: got a=%q b=%q, want td:td-a / td:td-b (distinct)", a, b)
	}
	// No mesh identity -> the configured cluster catch-all, never silently boundary-collapsed.
	if got, _ := r.Resolve(contract.FlowIdentity{SocketCookie: 9}); got != "cluster:uid-123" {
		t.Fatalf("no-mesh catch-all: got %q, want cluster:uid-123", got)
	}
}

func TestZones_PerNamespacePartition(t *testing.T) {
	zones := Zones(workload.Resolver{}, map[string]contract.ScopeKey{
		"orders":   "scope-orders",
		"payments": "scope-payments",
		"":         "dropped-empty-ns", // empty namespace -> dropped
		"blank":    "",                 // empty scope key -> dropped (would force ErrUnresolved)
	})
	if len(zones) != 2 {
		t.Fatalf("got %d zones, want 2 (empty ns and empty key dropped)", len(zones))
	}
	if zones[0].Key != "scope-orders" || zones[1].Key != "scope-payments" {
		t.Fatalf("zones not in deterministic namespace order: %q, %q", zones[0].Key, zones[1].Key)
	}

	r, err := scope.NewStaticResolver(scope.Config{
		Zones:    zones,
		Cluster:  ClusterIdentity(workload.Resolver{}, "uid-123"),
		Boundary: "operator-boundary",
	})
	if err != nil {
		t.Fatalf("resolver build: %v", err)
	}
	// A flow whose identity is in the orders namespace lands in the orders zone —
	// the per-namespace zone wins over the cluster catch-all.
	if got, err := r.Resolve(meshFlow("spiffe://cluster.local/ns/orders/sa/payments")); err != nil || got != "scope-orders" {
		t.Fatalf("orders flow: got (%q,%v), want (scope-orders,nil)", got, err)
	}
	// A flow in an unmapped namespace falls through zones to the cluster catch-all.
	if got, _ := r.Resolve(meshFlow("spiffe://cluster.local/ns/other/sa/x")); got != "td:cluster.local" {
		t.Fatalf("unmapped namespace: got %q, want cluster catch-all td:cluster.local", got)
	}
}
