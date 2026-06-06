package seeder

import (
	"context"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
)

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.New(catalog.Config{Rand: rand.New(rand.NewSource(1)), HarmlessSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newStore(t *testing.T, clk func() time.Time, planner Planner) *Store {
	t.Helper()
	s, err := New(Config{
		Catalog: testCatalog(t),
		Planner: planner,
		Clock:   clk,
		Rand:    rand.New(rand.NewSource(2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSeedRefusesEmptyScope(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.Seed("", Minefield); err != ErrNoScope {
		t.Fatalf("empty scope must be refused, got %v", err)
	}
}

func TestSeedAndRegistryScopeIsolation(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.Seed("scope-a", Minefield); err != nil {
		t.Fatal(err)
	}
	if err := s.Seed("scope-b", Minefield); err != nil {
		t.Fatal(err)
	}
	a := s.Registry().List("scope-a")
	if len(a) == 0 {
		t.Fatal("scope-a got no placements")
	}
	// A scope-a location must be invisible in scope-b.
	if _, ok := s.Registry().Lookup("scope-b", a[0].Location); ok {
		t.Fatal("scope-b leaked a scope-a placement")
	}
	for _, p := range a {
		if p.Scope != "scope-a" {
			t.Fatalf("placement carries wrong scope %q", p.Scope)
		}
	}
}

func TestActiveModeIsRicherSurface(t *testing.T) {
	s := newStore(t, nil, nil)
	s.Seed("a", Minefield)
	s.Seed("b", Active)
	mine := len(s.Registry().List("a"))
	active := len(s.Registry().List("b"))
	if active <= mine {
		t.Fatalf("active mode must be a richer surface: active=%d minefield=%d", active, mine)
	}
}

func TestRefreshExpiresAndRotates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clk := func() time.Time { return now }
	s := newStore(t, clk, nil)
	s.Seed("scope", Minefield)

	before := s.Registry().List("scope")
	if len(before) == 0 {
		t.Fatal("no placements to rotate")
	}
	payloads := map[PlacementID]string{}
	for _, p := range before {
		payloads[p.ID] = string(p.Instance.Payload)
	}

	// Advance past expiry and refresh.
	now = now.Add(48 * time.Hour)
	if err := s.Refresh("scope"); err != nil {
		t.Fatal(err)
	}
	after := s.Registry().List("scope")
	// Every placement should be new (different id) with freshly generated content.
	for _, p := range after {
		if _, wasOld := payloads[p.ID]; wasOld {
			t.Fatalf("stale placement %s survived refresh", p.ID)
		}
		if p.ExpiresAt.Before(now) {
			t.Fatalf("refreshed placement is already expired")
		}
	}
}

func TestAutoRefreshSweepNeedsNoOperator(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newStore(t, func() time.Time { return now }, nil)
	s.Seed("scope", Minefield)
	oldIDs := map[PlacementID]bool{}
	for _, p := range s.Registry().List("scope") {
		oldIDs[p.ID] = true
	}
	now = now.Add(72 * time.Hour)
	if err := s.sweepExpired(now); err != nil { // the core RunAutoRefresh drives, no operator call
		t.Fatal(err)
	}
	for _, p := range s.Registry().List("scope") {
		if oldIDs[p.ID] {
			t.Fatal("auto-refresh sweep left a stale placement")
		}
	}
}

func TestRunAutoRefreshStopsOnContextCancel(t *testing.T) {
	s := newStore(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RunAutoRefresh(ctx, time.Millisecond); err != context.Canceled {
		t.Fatalf("RunAutoRefresh should return context.Canceled, got %v", err)
	}
}

func TestPutRejectsEmptyScope(t *testing.T) {
	r := NewMemRegistry()
	if err := r.Put(Placement{Location: "x"}); err != ErrNoScope {
		t.Fatalf("registry must refuse a scopeless placement, got %v", err)
	}
}

func TestRegistryConcurrency(t *testing.T) {
	r := NewMemRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			loc := Location(string(rune('a' + i%26)))
			_ = r.Put(Placement{ID: PlacementID("p"), Scope: "s", Type: "t", Location: loc, ExpiresAt: time.Now()})
			r.Lookup("s", loc)
			r.List("s")
			r.Expired(time.Now())
		}(i)
	}
	wg.Wait()
}

func TestPlacementHasNoUnlockGraph(t *testing.T) {
	// Independence (ARCH §11) enforced by the data model: apart from its OWN
	// identity (ID, Location), no field may reference another placement — in any
	// form: a scalar edge (Next PlacementID), a collection ([]PlacementID), a
	// pointer (*Placement), or a map. This catches scalar edges the kind-switch
	// alone would miss.
	self := map[string]bool{"ID": true, "Location": true}
	link := map[reflect.Type]bool{
		reflect.TypeOf(PlacementID("")): true,
		reflect.TypeOf(Location("")):    true,
		reflect.TypeOf(Placement{}):     true,
	}
	rt := reflect.TypeOf(Placement{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if self[f.Name] {
			continue
		}
		ft := f.Type
		if link[ft] { // scalar edge, e.g. Next PlacementID / UnlockKey Location
			t.Fatalf("field %q is a link to another placement (%s) — a chained-credential edge", f.Name, ft)
		}
		switch ft.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map, reflect.Ptr:
			if link[ft.Elem()] {
				t.Fatalf("field %q links to other placements (%s) — a chained-credential edge", f.Name, ft)
			}
		}
	}
}

func TestRefreshPreservesPerTypeCardinality(t *testing.T) {
	// Active seeds multiple placements of a type at distinct locations; rotating
	// an expired one must NOT collapse siblings onto a single location.
	now := time.Unix(1_700_000_000, 0)
	s := newStore(t, func() time.Time { return now }, nil)
	s.Seed("scope", Active)
	before := countByType(s.Registry().List("scope"))
	if before[catalog.TypePlantedCredential] < 2 {
		t.Fatalf("expected Active to seed multiple planted_credential, got %d", before[catalog.TypePlantedCredential])
	}
	now = now.Add(72 * time.Hour) // expire everything
	if err := s.Refresh("scope"); err != nil {
		t.Fatal(err)
	}
	after := countByType(s.Registry().List("scope"))
	for typ, n := range before {
		if after[typ] != n {
			t.Fatalf("rotation changed %s cardinality: before=%d after=%d (surface collapsed)", typ, n, after[typ])
		}
	}
}

func countByType(ps []Placement) map[contract.CanaryType]int {
	m := map[contract.CanaryType]int{}
	for _, p := range ps {
		m[p.Type]++
	}
	return m
}

func TestSeedAndRefreshConcurrencySafe(t *testing.T) {
	// Concurrent Seed across scopes and a refresh sweep both drive cat.Generate;
	// fails under -race if the catalog RNG is unguarded.
	now := time.Unix(1_700_000_000, 0)
	s := newStore(t, func() time.Time { return now }, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.Seed(contract.ScopeKey(string(rune('a'+i))), Minefield)
			_ = s.sweepExpired(now.Add(72 * time.Hour))
		}(i)
	}
	wg.Wait()
}

// stubPlanner places everything at one fixed location to prove the planner steers
// WHERE bait goes (and nothing more — it emits no events).
type stubPlanner struct{ loc Location }

func (p stubPlanner) Plan(_ contract.ScopeKey, _ Mode, want map[contract.CanaryType]int) []Proposal {
	var out []Proposal
	for typ, n := range want {
		for i := 0; i < n; i++ {
			out = append(out, Proposal{Location: p.loc, Type: typ, Origin: OriginNegativeSpace})
		}
	}
	return out
}

func TestPlannerInfluencesPlacementOnly(t *testing.T) {
	s := newStore(t, nil, stubPlanner{loc: "negative-space/path"})
	s.Seed("scope", Minefield)
	got := s.Registry().List("scope")
	if len(got) == 0 {
		t.Fatal("no placements")
	}
	for _, p := range got {
		if p.Location != "negative-space/path" || p.Origin != OriginNegativeSpace {
			t.Fatalf("planner did not steer placement: loc=%q origin=%v", p.Location, p.Origin)
		}
	}
}

func TestBroadPlannerIsDefault(t *testing.T) {
	s := newStore(t, nil, nil) // nil planner -> BroadPlanner
	s.Seed("scope", Minefield)
	for _, p := range s.Registry().List("scope") {
		if p.Origin != OriginOperatorBroad {
			t.Fatalf("default planner should be broad, got origin %v", p.Origin)
		}
	}
}
