package signal

import (
	"math/rand"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
)

func seededRegistry(t *testing.T, scope contract.ScopeKey) (*seeder.Store, seeder.Location) {
	t.Helper()
	cat, err := catalog.New(catalog.Config{Rand: rand.New(rand.NewSource(1)), HarmlessSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	s, err := seeder.New(seeder.Config{Catalog: cat, Rand: rand.New(rand.NewSource(2))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Seed(scope, seeder.Minefield); err != nil {
		t.Fatal(err)
	}
	placed := s.Registry().List(scope)
	if len(placed) == 0 {
		t.Fatal("no placement to touch")
	}
	return s, placed[0].Location
}

func TestBuildRefusesEmptyScope(t *testing.T) {
	b := NewBuilder(seeder.NewMemRegistry())
	if _, err := b.Build("", Touch{Flow: contract.FlowIdentity{SocketCookie: 1}, Location: "x"}); err != ErrNoScope {
		t.Fatalf("want ErrNoScope, got %v", err)
	}
}

func TestBuildRefusesZeroSocketCookie(t *testing.T) {
	b := NewBuilder(seeder.NewMemRegistry())
	if _, err := b.Build("scope", Touch{Location: "x"}); err != ErrNoSocketCookie {
		t.Fatalf("want ErrNoSocketCookie, got %v", err)
	}
}

func TestBuildRefusesUnplacedLocation(t *testing.T) {
	b := NewBuilder(seeder.NewMemRegistry()) // empty registry
	_, err := b.Build("scope", Touch{Flow: contract.FlowIdentity{SocketCookie: 1}, Location: "nowhere"})
	if err != ErrNoPlacement {
		t.Fatalf("a non-canary touch must not become a signal: got %v", err)
	}
}

func TestBuildProducesValidEvent(t *testing.T) {
	const scope = contract.ScopeKey("scope-a")
	s, loc := seededRegistry(t, scope)
	want, _ := s.Registry().Lookup(scope, loc)

	b := NewBuilder(s.Registry())
	at := time.Unix(1_700_000_000, 0)
	ev, err := b.Build(scope, Touch{
		Flow:     contract.FlowIdentity{SocketCookie: 0xABCD},
		Location: loc,
		At:       at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Canary != want.Type {
		t.Errorf("event canary = %q, want %q (resolved from registry, not the wire)", ev.Canary, want.Type)
	}
	if ev.Scope != scope {
		t.Errorf("event scope = %q, want %q", ev.Scope, scope)
	}
	if ev.Flow.SocketCookie != 0xABCD {
		t.Errorf("event dropped the socket cookie")
	}
	if !ev.Timestamp.Equal(at) {
		t.Errorf("event timestamp = %v, want %v", ev.Timestamp, at)
	}
}

func TestBuildScopeIsolation(t *testing.T) {
	// A location placed in scope-a must not resolve under scope-b.
	const scopeA = contract.ScopeKey("scope-a")
	s, loc := seededRegistry(t, scopeA)
	b := NewBuilder(s.Registry())
	if _, err := b.Build("scope-b", Touch{Flow: contract.FlowIdentity{SocketCookie: 1}, Location: loc}); err != ErrNoPlacement {
		t.Fatalf("scope-b must not resolve a scope-a placement: got %v", err)
	}
}
