package observebaseline

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

// newTopoAgg builds an aggregator with a fixed clock for topology tests.
func newTopoAgg(t *testing.T, r *fakeReader, now time.Time, store *persist.Store) *Aggregator {
	t.Helper()
	return New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Store: store, Bucketer: baseline.WindowBucketer, Floor: testFloor(),
		Now: func() time.Time { return now },
	})
}

func (a *Aggregator) topoFor(sc contract.ScopeKey) *topology {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.topology[sc]
}

// One completed flow -> exactly one edge with the right endpoints, plus the
// initiator and service node-catalog entries (fold-once).
func TestTopologyOneFlowOneEdge(t *testing.T) {
	r := newFakeReader()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := newTopoAgg(t, r, now, nil)

	completeFlow(agg, r, 100, flowFromIPs(5, 1, 1400, 12, 2_000_000), now)

	topo := agg.topoFor(testScope)
	if topo == nil {
		t.Fatal("no topology accrued for scope")
	}
	if len(topo.edges) != 1 {
		t.Fatalf("edges = %d, want exactly 1", len(topo.edges))
	}
	// Two node entries: one initiator (SrcIP) + one service (DstIP,DstPort).
	if len(topo.nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 (initiator + service)", len(topo.nodes))
	}
	var e *topoEdge
	for _, v := range topo.edges {
		e = v
	}
	// 10.0.1.5 -> 10.0.2.1:8080 (see flowFromIPs).
	if e.SrcIP[3] != 5 || e.DstIP[2] != 2 || e.DstIP[3] != 1 || e.DstPort != 8080 {
		t.Fatalf("edge endpoints wrong: src=%v dst=%v port=%d", e.SrcIP[:4], e.DstIP[:4], e.DstPort)
	}
	if e.Family != observe.AFInet {
		t.Fatalf("edge family = %d, want AFInet", e.Family)
	}
	if e.FlowCount != 1 {
		t.Fatalf("edge FlowCount = %d, want 1", e.FlowCount)
	}
	// TotalBytes = ingress+egress = 1400+1400.
	if e.TotalBytes != 2800 {
		t.Fatalf("edge TotalBytes = %d, want 2800", e.TotalBytes)
	}

	// The roles are present and correct.
	roles := map[nodeRole]int{}
	for _, n := range topo.nodes {
		roles[n.Role]++
	}
	if roles[roleInitiator] != 1 || roles[roleService] != 1 {
		t.Fatalf("node roles = %v, want one initiator + one service", roles)
	}
}

// Repeated completed flows on the SAME edge bump FlowCount/TotalBytes/LastSeen —
// they do NOT create new edges (the fold-once + canonical-key discipline).
func TestTopologyRepeatBumpsNotDuplicates(t *testing.T) {
	r := newFakeReader()
	t0 := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := newTopoAgg(t, r, t0, nil)

	// Five flows on the identical edge (same src/dst/port), at advancing wall times
	// (we re-create the aggregator clock per fold via foldOnce(now)).
	for i := 0; i < 5; i++ {
		completeFlow(agg, r, uint64(200+i), flowFromIPs(7, 1, 1000, 10, 1_000_000), t0)
	}

	topo := agg.topoFor(testScope)
	if len(topo.edges) != 1 {
		t.Fatalf("edges = %d, want 1 (all five folded onto one edge)", len(topo.edges))
	}
	var e *topoEdge
	for _, v := range topo.edges {
		e = v
	}
	if e.FlowCount != 5 {
		t.Fatalf("edge FlowCount = %d, want 5", e.FlowCount)
	}
	if e.TotalBytes != 5*2000 {
		t.Fatalf("edge TotalBytes = %d, want %d", e.TotalBytes, 5*2000)
	}
	// The node-catalog FlowCount for the initiator should also be 5.
	for _, n := range topo.nodes {
		if n.Role == roleInitiator && n.FlowCount != 5 {
			t.Fatalf("initiator node FlowCount = %d, want 5", n.FlowCount)
		}
	}
}

// FirstSeen/LastSeen come from the INJECTED clock (wall) — never the kernel ns.
// The kernel FirstSeenNs/LastSeenNs in flowFromIPs are tiny monotonic values; the
// stored timestamps must equal the injected wall clock instead.
func TestTopologyWallClockStamping(t *testing.T) {
	r := newFakeReader()

	first := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	agg := newTopoAgg(t, r, first, nil)

	// First fold at `first`.
	completeFlow(agg, r, 300, flowFromIPs(8, 1, 1000, 10, 1_000_000), first)

	topo := agg.topoFor(testScope)
	var e *topoEdge
	for _, v := range topo.edges {
		e = v
	}
	if !e.FirstSeen.Equal(first) || !e.LastSeen.Equal(first) {
		t.Fatalf("first fold wall times = %v/%v, want %v", e.FirstSeen, e.LastSeen, first)
	}
	// The kernel ns must NOT have leaked in (FirstSeenNs=1000 in flowFromIPs would
	// be a 1970-epoch-ish time, definitely not 2026).
	if e.FirstSeen.Year() != 2026 {
		t.Fatalf("FirstSeen looks kernel-derived: %v", e.FirstSeen)
	}

	// A later fold of the same edge advances LastSeen to the new wall time but
	// leaves FirstSeen pinned.
	later := first.Add(3 * time.Hour)
	completeFlow(agg, r, 301, flowFromIPs(8, 1, 1000, 10, 1_000_000), later)
	for _, v := range topo.edges {
		e = v
	}
	if !e.FirstSeen.Equal(first) {
		t.Fatalf("FirstSeen moved: %v, want pinned at %v", e.FirstSeen, first)
	}
	if !e.LastSeen.Equal(later) {
		t.Fatalf("LastSeen = %v, want advanced to %v", e.LastSeen, later)
	}
}

// Cap eviction keeps the high-FlowCount edge and drops the lowest, and bumps the
// observable lost-count.
func TestTopologyCapEvictsLowest(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	topo := newTopology()

	// A hot edge with a high count.
	hotKey := "hot"
	topo.edges[hotKey] = &topoEdge{FlowCount: 1000, LastSeen: now, FirstSeen: now}
	// Fill to one below cap with single-count cold edges so the next insert evicts.
	for i := 0; i < topoEdgeCapDefault-1; i++ {
		topo.edges[keyN(i)] = &topoEdge{FlowCount: 1, LastSeen: now, FirstSeen: now}
	}
	if len(topo.edges) != topoEdgeCapDefault {
		t.Fatalf("setup: edges = %d, want %d", len(topo.edges), topoEdgeCapDefault)
	}

	victim, ok := topo.evictEdgeIfFull(now)
	if !ok {
		t.Fatal("evictEdgeIfFull did not evict at cap")
	}
	if victim == hotKey {
		t.Fatal("cap eviction dropped the HOT (highest-count) edge")
	}
	if _, stillThere := topo.edges[hotKey]; !stillThere {
		t.Fatal("hot edge was evicted; cap must keep high-FlowCount edges")
	}
	if len(topo.edges) != topoEdgeCapDefault-1 {
		t.Fatalf("after eviction edges = %d, want %d", len(topo.edges), topoEdgeCapDefault-1)
	}
}

func keyN(i int) string {
	return "cold-" + strconv.Itoa(i)
}

// The TTL reaper drops stale edges/nodes (older than the TTL by wall clock) and
// the lost count increments through the fold tick.
func TestTopologyReaperTTLAndLostCount(t *testing.T) {
	r := newFakeReader()
	t0 := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	// Short TTL so the test is fast.
	ttl := time.Hour

	// Build the aggregator with an advancing clock via a pointer.
	clk := t0
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(),
		TopologyTTL: ttl, Now: func() time.Time { return clk },
	})

	// Fold an edge at t0.
	completeFlow(agg, r, 400, flowFromIPs(9, 1, 1000, 10, 1_000_000), t0)
	if topo := agg.topoFor(testScope); len(topo.edges) != 1 {
		t.Fatalf("precondition: edges = %d, want 1", len(topo.edges))
	}
	before := agg.Stats().TopologyEvicted

	// Advance the clock past the TTL and run a fold tick with no new flows: the
	// stale edge must be reaped.
	clk = t0.Add(2 * time.Hour)
	agg.foldOnce(clk)

	topo := agg.topoFor(testScope)
	if len(topo.edges) != 0 {
		t.Fatalf("stale edge not reaped: edges = %d", len(topo.edges))
	}
	if len(topo.nodes) != 0 {
		t.Fatalf("stale nodes not reaped: nodes = %d", len(topo.nodes))
	}
	got := agg.Stats().TopologyEvicted
	if got <= before {
		t.Fatalf("TopologyEvicted did not increment: before=%d after=%d", before, got)
	}
	// 1 edge + 2 nodes reaped.
	if got-before != 3 {
		t.Fatalf("reaped count = %d, want 3 (1 edge + 2 nodes)", got-before)
	}
}

// Scope isolation: edges accrued under scope A are never readable under scope B
// in the persisted store (scopeSub layout). Drives two aggregators on two scopes
// through one store and asserts each scope's topology bucket holds only its own.
func TestTopologyScopeIsolation(t *testing.T) {
	const scopeA = contract.ScopeKey("scope-A")
	const scopeB = contract.ScopeKey("scope-B")
	path := filepath.Join(t.TempDir(), "baseline.db")
	store, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	rA := newFakeReader()
	aggA := New(Config{
		Reader: rA, Gates: newRecordGates(), Resolver: fakeResolver{scope: scopeA}, Store: store,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	completeFlow(aggA, rA, 500, flowFromIPs(5, 1, 1000, 10, 1_000_000), now)

	rB := newFakeReader()
	aggB := New(Config{
		Reader: rB, Gates: newRecordGates(), Resolver: fakeResolver{scope: scopeB}, Store: store,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	completeFlow(aggB, rB, 600, flowFromIPs(6, 1, 1000, 10, 1_000_000), now)

	countScope := func(sc contract.ScopeKey) int {
		n := 0
		if err := store.RangeTopology(sc, func(_, _ []byte) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Each scope has its own 1 edge + 2 nodes = 3 records; never the other's.
	if got := countScope(scopeA); got != 3 {
		t.Fatalf("scope A topology records = %d, want 3", got)
	}
	if got := countScope(scopeB); got != 3 {
		t.Fatalf("scope B topology records = %d, want 3", got)
	}
	// A read of a third, unwritten scope yields nothing.
	if got := countScope(contract.ScopeKey("scope-C")); got != 0 {
		t.Fatalf("unwritten scope C topology records = %d, want 0", got)
	}
}

// The edge/node records survive a persist + reopen + rehydrate round-trip with
// their wall-clock timestamps and counts intact (local-rich map survives reboot).
func TestTopologyPersistAndRehydrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	store1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r1 := newFakeReader()
	a1 := newTopoAgg(t, r1, now, store1)
	for i := 0; i < 3; i++ {
		completeFlow(a1, r1, uint64(700+i), flowFromIPs(5, 1, 1000, 10, 1_000_000), now)
	}
	_ = store1.Close()

	store2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	r2 := newFakeReader()
	a2 := newTopoAgg(t, r2, now, store2)
	a2.Rehydrate()

	topo := a2.topoFor(testScope)
	if topo == nil || len(topo.edges) != 1 {
		t.Fatalf("rehydrated topology edges = %v", topo)
	}
	var e *topoEdge
	for _, v := range topo.edges {
		e = v
	}
	if e.FlowCount != 3 {
		t.Fatalf("rehydrated edge FlowCount = %d, want 3", e.FlowCount)
	}
	if !e.FirstSeen.Equal(now) {
		t.Fatalf("rehydrated FirstSeen = %v, want %v (wall clock preserved)", e.FirstSeen, now)
	}
	if len(topo.nodes) != 2 {
		t.Fatalf("rehydrated nodes = %d, want 2", len(topo.nodes))
	}
}
