package workload

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/identity"
	"github.com/canarysting/canarysting/internal/identity/labels"
)

// fakeSource is a labels.Source stub for tests.
type fakeSource struct {
	meta labels.PodMeta
	ok   bool
}

func (f fakeSource) Lookup(contract.FlowIdentity) (labels.PodMeta, bool) { return f.meta, f.ok }

func TestResolve_MeshWinsOverLabels(t *testing.T) {
	r := Resolver{Labels: fakeSource{meta: labels.PodMeta{Namespace: "wrong", Labels: map[string]string{"app": "impostor"}}, ok: true}}
	got := r.Resolve(contract.FlowIdentity{SPIFFEID: "spiffe://cluster.local/ns/orders/sa/payments"})
	if got.Confidence != identity.ConfidenceVerified {
		t.Fatalf("mesh identity must win: got confidence %v", got.Confidence)
	}
	if got.Namespace != "orders" || got.Name != "orders/payments" {
		t.Fatalf("expected mesh identity, got %+v (label fallback must not be consulted)", got)
	}
}

func TestResolve_FallsBackToLabelsWhenNoMesh(t *testing.T) {
	r := Resolver{Labels: fakeSource{meta: labels.PodMeta{Namespace: "orders", Labels: map[string]string{"app.kubernetes.io/name": "payments"}}, ok: true}}
	got := r.Resolve(contract.FlowIdentity{SocketCookie: 7}) // no SPIFFE
	if got.Confidence != identity.ConfidenceAsserted || got.Name != "orders/payments" {
		t.Fatalf("expected asserted label identity, got %+v", got)
	}
}

func TestResolve_NoneWhenNeitherResolves(t *testing.T) {
	// mesh-only resolver (nil Labels), flow without SPIFFE.
	if got := (Resolver{}).Resolve(contract.FlowIdentity{}); !got.Empty() {
		t.Fatalf("mesh-only resolver with no SPIFFE must be Empty, got %+v", got)
	}
	// labels source present but returns ok=false.
	r := Resolver{Labels: fakeSource{ok: false}}
	if got := r.Resolve(contract.FlowIdentity{}); !got.Empty() {
		t.Fatalf("no mesh + label miss must be Empty, got %+v", got)
	}
	// labels source resolves but to unusable meta => Empty.
	r2 := Resolver{Labels: fakeSource{meta: labels.PodMeta{}, ok: true}}
	if got := r2.Resolve(contract.FlowIdentity{}); !got.Empty() {
		t.Fatalf("no mesh + unusable label meta must be Empty, got %+v", got)
	}
}
