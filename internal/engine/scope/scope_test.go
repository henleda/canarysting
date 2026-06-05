package scope

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
)

func spiffeMatch(id string) func(contract.FlowIdentity) bool {
	return func(f contract.FlowIdentity) bool { return f.SPIFFEID == id }
}

func TestResolve_ZoneWinsOverClusterAndBoundary(t *testing.T) {
	r, err := NewStaticResolver(Config{
		Zones:    []Zone{{Key: "zone-a", Match: spiffeMatch("spiffe://a")}},
		Cluster:  func(contract.FlowIdentity) (contract.ScopeKey, bool) { return "cluster", true },
		Boundary: "boundary",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(contract.FlowIdentity{SPIFFEID: "spiffe://a"})
	if err != nil || got != "zone-a" {
		t.Fatalf("got (%q,%v), want (zone-a,nil)", got, err)
	}
}

func TestResolve_FirstMatchingZoneIsDeterministicPrecedence(t *testing.T) {
	// A flow matching two zones must land in exactly one — the earlier.
	r, _ := NewStaticResolver(Config{Zones: []Zone{
		{Key: "first", Match: func(contract.FlowIdentity) bool { return true }},
		{Key: "second", Match: func(contract.FlowIdentity) bool { return true }},
	}})
	got, _ := r.Resolve(contract.FlowIdentity{})
	if got != "first" {
		t.Fatalf("got %q, want first (order is precedence)", got)
	}
}

func TestResolve_ClusterIsCatchAllForUnzonedTraffic(t *testing.T) {
	r, _ := NewStaticResolver(Config{
		Zones:   []Zone{{Key: "zone-a", Match: spiffeMatch("spiffe://a")}},
		Cluster: func(contract.FlowIdentity) (contract.ScopeKey, bool) { return "cluster-uid", true },
	})
	got, err := r.Resolve(contract.FlowIdentity{SPIFFEID: "spiffe://other"})
	if err != nil || got != "cluster-uid" {
		t.Fatalf("got (%q,%v), want (cluster-uid,nil)", got, err)
	}
}

func TestResolve_BoundaryOnlyWhenNoClusterIdentity(t *testing.T) {
	r, _ := NewStaticResolver(Config{
		Cluster:  func(contract.FlowIdentity) (contract.ScopeKey, bool) { return "", false },
		Boundary: "operator-boundary",
	})
	got, err := r.Resolve(contract.FlowIdentity{})
	if err != nil || got != "operator-boundary" {
		t.Fatalf("got (%q,%v), want (operator-boundary,nil)", got, err)
	}
}

func TestResolve_HardFailNeverGlobalScope(t *testing.T) {
	r, _ := NewStaticResolver(Config{Boundary: "b"})
	// Replace with a resolver that can match nothing: zones that never match and
	// no cluster/boundary.
	r2 := &StaticResolver{cfg: Config{Zones: []Zone{{Key: "z", Match: func(contract.FlowIdentity) bool { return false }}}}}
	if _, err := r2.Resolve(contract.FlowIdentity{}); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("want ErrUnresolved, got %v", err)
	}
	// Sanity: the valid resolver still resolves.
	if _, err := r.Resolve(contract.FlowIdentity{}); err != nil {
		t.Fatalf("valid resolver errored: %v", err)
	}
}

func TestResolve_ZoneWithEmptyKeyIsUnresolved(t *testing.T) {
	r := &StaticResolver{cfg: Config{Zones: []Zone{{Key: "", Match: func(contract.FlowIdentity) bool { return true }}}}}
	if _, err := r.Resolve(contract.FlowIdentity{}); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("want ErrUnresolved for empty zone key, got %v", err)
	}
}

func TestNewStaticResolver_RefusesEmptyConfig(t *testing.T) {
	if _, err := NewStaticResolver(Config{}); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("empty config must refuse to start; got %v", err)
	}
}
