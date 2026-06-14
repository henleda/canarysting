package observebaseline

import (
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/engine/scope"
)

// fakeReader is an in-memory stand-in for the kernel observe map.
type fakeReader struct {
	mu    sync.Mutex
	flows map[uint64]observe.FlowStats
}

func newFakeReader() *fakeReader { return &fakeReader{flows: map[uint64]observe.FlowStats{}} }

func (r *fakeReader) set(cookie uint64, fs observe.FlowStats) {
	r.mu.Lock()
	r.flows[cookie] = fs
	r.mu.Unlock()
}
func (r *fakeReader) del(cookie uint64) {
	r.mu.Lock()
	delete(r.flows, cookie)
	r.mu.Unlock()
}
func (r *fakeReader) ReadStats(cookie uint64) (observe.FlowStats, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fs, ok := r.flows[cookie]
	return fs, ok, nil
}
func (r *fakeReader) IterStats(fn func(uint64, observe.FlowStats) error) error {
	r.mu.Lock()
	snap := make(map[uint64]observe.FlowStats, len(r.flows))
	for k, v := range r.flows {
		snap[k] = v
	}
	r.mu.Unlock()
	for k, v := range snap {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

// recordGates records the gate calls so tests can assert what the aggregator drove.
type recordGates struct {
	mu   sync.Mutex
	live map[contract.ScopeKey]bool
	suff map[string]bool
}

func newRecordGates() *recordGates {
	return &recordGates{live: map[contract.ScopeKey]bool{}, suff: map[string]bool{}}
}
func (g *recordGates) SetLive(s contract.ScopeKey, l bool) {
	g.mu.Lock()
	g.live[s] = l
	g.mu.Unlock()
}
func (g *recordGates) SetBucketSufficient(s contract.ScopeKey, b string, ok bool) {
	g.mu.Lock()
	g.suff[string(s)+"|"+b] = ok
	g.mu.Unlock()
}
func (g *recordGates) isLive(s contract.ScopeKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.live[s]
}

type fakeResolver struct {
	scope contract.ScopeKey
	err   error
}

func (r fakeResolver) Resolve(contract.FlowIdentity) (contract.ScopeKey, error) {
	return r.scope, r.err
}

func testFloor() DataFloor {
	return DataFloor{
		MinFlowsPerBucket:      8,
		MinIdentitiesPerBucket: 2,
		MinDaysPerBucket:       1,
		MinP2Samples:           5,
		MinSufficientBuckets:   1,
		MinCalendarDays:        1,
		FreshnessTTL:           time.Hour,
		MaxCoverageGap:         24 * time.Hour,
	}
}

// completeFlow drives a flow from open to closed (one fold) at time now, the
// mark-closed lifecycle: observed open (tracked), then marked Closed (the kernel
// keeps the entry), then folded exactly once.
func completeFlow(a *Aggregator, r *fakeReader, cookie uint64, fs observe.FlowStats, now time.Time) {
	fs.Closed = 0
	r.set(cookie, fs)
	a.foldOnce(now) // observed open: tracked, not yet folded
	fs.Closed = 1
	r.set(cookie, fs) // marked closed (entry persists, as the kernel does)
	a.foldOnce(now)   // closed: folded once with final totals
}

const testScope = contract.ScopeKey("scopeA")

// Accrue a benign baseline, then assert: a known-legit flow derives near-neutral
// features, a brand-new attacker identity derives maximal novelty, the bucket
// goes sufficient and the scope live.
func TestBenignNeutralAttackerNovel(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC) // a Monday afternoon
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})

	// 30 benign flows from three legit identities (10.0.1.{5,6,7}).
	for i := 0; i < 30; i++ {
		src := byte(5 + i%3)
		completeFlow(agg, r, uint64(1000+i), flowFromIPs(src, 1, 1400, 12, 2_000_000), now)
	}
	bucket := baseline.WindowBucketer(now)
	if !gates.suff[string(testScope)+"|"+bucket] {
		t.Fatalf("bucket %q not marked sufficient after benign accrual", bucket)
	}
	if !gates.isLive(testScope) {
		t.Fatal("scope not live after benign accrual")
	}

	// A known-legit flow now present in the map -> near-neutral features.
	r.set(2000, flowFromIPs(5, 1, 1400, 12, 2_000_000))
	lf, ok := agg.Features(testScope, contract.FlowIdentity{SocketCookie: 2000}, now)
	if !ok {
		t.Fatal("Features(legit) returned ok=false")
	}
	if lf.IdentityNovelty > 0.2 || lf.AdjacencyNovelty > 0.2 {
		t.Fatalf("legit novelty too high: %+v", lf)
	}

	// The attacker: a never-seen source identity -> maximal novelty.
	r.set(3000, flowFromIPs(199, 1, 1400, 12, 2_000_000))
	af, ok := agg.Features(testScope, contract.FlowIdentity{SocketCookie: 3000}, now)
	if !ok {
		t.Fatal("Features(attacker) returned ok=false")
	}
	if af.IdentityNovelty != 1.0 || af.AdjacencyNovelty != 1.0 {
		t.Fatalf("attacker novelty not maximal: %+v", af)
	}
}

// LiveFlows surfaces currently-open flows with derived novelty, coarse-only: a
// brand-new identity reads as highly anomalous (the recon signal), a known-legit
// flow reads near-neutral, and a CLOSED flow drops out.
func TestLiveFlows(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	// Establish a benign baseline so novelty is meaningful.
	for i := 0; i < 30; i++ {
		completeFlow(agg, r, uint64(1000+i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), now)
	}

	// Two OPEN flows: a known-legit identity and a never-seen (anomalous) one.
	// foldOnce tracks open flows in a.live without folding them, so their derived
	// novelty is meaningful and they appear in LiveFlows.
	r.set(2000, flowFromIPs(5, 1, 1400, 12, 2_000_000))
	r.set(3000, flowFromIPs(199, 1, 1400, 12, 2_000_000))
	agg.foldOnce(now)

	byCookie := map[uint64]LiveFlow{}
	for _, f := range agg.LiveFlows(now) {
		byCookie[f.Cookie] = f
	}
	legit, ok := byCookie[2000]
	if !ok {
		t.Fatal("LiveFlows missing the open legit flow 2000")
	}
	recon, ok := byCookie[3000]
	if !ok {
		t.Fatal("LiveFlows missing the open anomalous flow 3000")
	}
	if recon.IdentityNovelty != 1.0 || recon.AdjacencyNovelty != 1.0 {
		t.Fatalf("anomalous flow novelty not maximal: %+v", recon)
	}
	if legit.IdentityNovelty > 0.2 || legit.AdjacencyNovelty > 0.2 {
		t.Fatalf("legit flow novelty too high: %+v", legit)
	}
	if recon.IngressBytes == 0 && recon.EgressBytes == 0 {
		t.Fatal("expected coarse byte totals on the live flow")
	}

	// A CLOSED flow is not "live" and must drop out of LiveFlows.
	closed := flowFromIPs(199, 1, 1400, 12, 2_000_000)
	closed.Closed = 1
	r.set(3000, closed)
	for _, f := range agg.LiveFlows(now) {
		if f.Cookie == 3000 {
			t.Fatal("a closed flow must not appear in LiveFlows")
		}
	}
}

// A confirmed-malicious source is excluded from the baseline-of-normal: its
// flows are never folded, so its identity stays at count 0 (novelty 1.0) no
// matter how many times it connects — it cannot normalize itself.
func TestExcludedNeverFolds(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	mal := NewMaliciousSet(nil)
	if err := mal.MarkAddr(testScope, netip.MustParseAddr("10.0.1.66")); err != nil {
		t.Fatal(err)
	}
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Excluder: mal, Bucketer: baseline.WindowBucketer, Floor: testFloor(),
		Now: func() time.Time { return now },
	})

	// Fold the attacker's flows many times.
	for i := 0; i < 20; i++ {
		completeFlow(agg, r, uint64(5000+i), flowFromIPs(66, 1, 9_000_000, 5000, 1_000_000), now)
	}
	st := agg.Stats()
	if st.ExcludedFolds == 0 || st.CompletedFolds != 0 {
		t.Fatalf("exclusion failed: excluded=%d completed=%d", st.ExcludedFolds, st.CompletedFolds)
	}
	// The attacker's identity never accrued -> still maximally novel.
	r.set(6000, flowFromIPs(66, 1, 9_000_000, 5000, 1_000_000))
	f, ok := agg.Features(testScope, contract.FlowIdentity{SocketCookie: 6000}, now)
	if ok && f.IdentityNovelty != 1.0 {
		t.Fatalf("excluded attacker normalized itself: IdentityNovelty=%v", f.IdentityNovelty)
	}
}

// A flow whose scope cannot be resolved is dropped (counted), never folded into
// a global or guessed scope.
func TestUnresolvedScopeDropped(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{err: scope.ErrUnresolved},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	completeFlow(agg, r, 7000, flowFromIPs(5, 1, 1400, 12, 2_000_000), now)
	st := agg.Stats()
	if st.UnresolvedFolds == 0 {
		t.Fatal("unresolved flow not counted")
	}
	if st.CompletedFolds != 0 {
		t.Fatalf("unresolved flow was folded (completed=%d)", st.CompletedFolds)
	}
}

// cookie 0 (unattributable) is never tracked or folded.
func TestCookieZeroRefused(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	completeFlow(agg, r, 0, flowFromIPs(5, 1, 1400, 12, 2_000_000), now)
	if st := agg.Stats(); st.CompletedFolds != 0 || st.UnresolvedFolds != 0 {
		t.Fatalf("cookie 0 was processed: %+v", st)
	}
	// Features for cookie 0 is always neutral/false.
	if _, ok := agg.Features(testScope, contract.FlowIdentity{SocketCookie: 0}, now); ok {
		t.Fatal("Features(cookie 0) returned ok=true")
	}
}

// Rehydrate loads persisted aggregates but forces the scope STALE: it must not
// trust a persisted live state across a restart.
func TestRehydrateForcesStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	// First process: accrue to live, persist.
	store1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r1 := newFakeReader()
	g1 := newRecordGates()
	a1 := New(Config{
		Reader: r1, Gates: g1, Resolver: fakeResolver{scope: testScope}, Store: store1,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	for i := 0; i < 30; i++ {
		completeFlow(a1, r1, uint64(1000+i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), now)
	}
	if !g1.isLive(testScope) {
		t.Fatal("precondition: scope should be live before restart")
	}
	_ = store1.Close()

	// Second process: rehydrate. The scope must come back STALE.
	store2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	r2 := newFakeReader()
	g2 := newRecordGates()
	a2 := New(Config{
		Reader: r2, Gates: g2, Resolver: fakeResolver{scope: testScope}, Store: store2,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	a2.Rehydrate()
	if g2.isLive(testScope) {
		t.Fatal("scope came back LIVE after rehydrate; must force STALE until a fresh fold")
	}
	// The accrued aggregate is still there, so Features works again immediately.
	r2.set(9000, flowFromIPs(5, 1, 1400, 12, 2_000_000))
	if _, ok := a2.Features(testScope, contract.FlowIdentity{SocketCookie: 9000}, now); !ok {
		t.Fatal("rehydrated aggregate not usable for feature derivation")
	}
}

// A large coverage gap (downtime) forces the scope to re-accrue fresh flows
// before it can go live again — a downtime hole is not silently backfilled.
func TestCoverageGapRequiresRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	t0 := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	store1, _, _ := persist.Open(path)
	r1 := newFakeReader()
	g1 := newRecordGates()
	a1 := New(Config{
		Reader: r1, Gates: g1, Resolver: fakeResolver{scope: testScope}, Store: store1,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return t0 },
	})
	for i := 0; i < 30; i++ {
		completeFlow(a1, r1, uint64(1000+i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), t0)
	}
	_ = store1.Close() // heartbeat is at t0

	// Reopen two days later: coverage gap >> MaxCoverageGap(24h).
	later := t0.Add(48 * time.Hour)
	store2, _, _ := persist.Open(path)
	defer store2.Close()
	r2 := newFakeReader()
	g2 := newRecordGates()
	a2 := New(Config{
		Reader: r2, Gates: g2, Resolver: fakeResolver{scope: testScope}, Store: store2,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return later },
	})
	a2.Rehydrate()
	// One fresh fold: not enough to clear the recovery quorum -> still not live.
	completeFlow(a2, r2, 9001, flowFromIPs(5, 1, 1400, 12, 2_000_000), later)
	if g2.isLive(testScope) {
		t.Fatal("scope went live after a single fresh fold post-gap; recovery quorum not enforced")
	}
}
