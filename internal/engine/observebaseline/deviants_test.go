package observebaseline

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

// fakeArmed is a test armedSet: the named cookies are treated as canary-touchers
// (Tier>=1) within the scope, so the deviant capture must EXCLUDE them.
type fakeArmed struct {
	cookies map[uint64]bool
}

func (f fakeArmed) armed(_ contract.ScopeKey, cookie uint64) bool { return f.cookies[cookie] }

func (a *Aggregator) deviantsFor(sc contract.ScopeKey) *deviants {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.deviants[sc]
}

// accrueBenign folds a benign baseline so the scope/bucket aggregate exists and
// novelty is meaningful (otherwise the deviant gate skips for lack of a bucket).
func accrueBenign(t *testing.T, agg *Aggregator, r *fakeReader, now time.Time) {
	t.Helper()
	for i := 0; i < 30; i++ {
		completeFlow(agg, r, uint64(1000+i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), now)
	}
}

// A DEVIANT, NON-ARMED flow (a brand-new source identity reads maximally novel)
// produces exactly one deviant record with the raw identity + peak dim captured.
func TestDeviantCaptureGatesToDeviantNonArmed(t *testing.T) {
	r := newFakeReader()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	accrueBenign(t, agg, r, now)

	// A never-seen source identity (.199) -> maximal identity/adjacency novelty,
	// well above deviantFloor, and not armed -> captured.
	completeFlow(agg, r, 3000, flowFromIPs(199, 1, 1400, 12, 2_000_000), now)

	dv := agg.deviantsFor(testScope)
	if dv == nil || len(dv.records) != 1 {
		t.Fatalf("want exactly 1 deviant record, got %v", dv)
	}
	var rec *DeviantFlowRecord
	for _, v := range dv.records {
		rec = v
	}
	// Raw identity captured (local-rich): 10.0.1.199 -> 10.0.2.1:8080.
	if rec.SrcIP[3] != 199 || rec.DstIP[2] != 2 || rec.DstIP[3] != 1 || rec.DstPort != 8080 {
		t.Fatalf("raw identity wrong: src=%v dst=%v port=%d", rec.SrcIP[:4], rec.DstIP[:4], rec.DstPort)
	}
	if rec.PeakNovelty < deviantFloor {
		t.Fatalf("peak novelty %v below floor %v on a captured deviant", rec.PeakNovelty, deviantFloor)
	}
	if rec.HitCount != 1 {
		t.Fatalf("HitCount = %d, want 1", rec.HitCount)
	}
	if rec.SocketCookie != 3000 {
		t.Fatalf("SocketCookie = %d, want 3000 (the producing cookie)", rec.SocketCookie)
	}
	if rec.PeakLabel == "" || rec.PeakLabel == "unknown" {
		t.Fatalf("PeakLabel not set: %q", rec.PeakLabel)
	}
}

// A NORMAL (low-novelty) flow produces NO deviant record: we keep no dossier on
// normal traffic.
func TestDeviantNormalFlowNotCaptured(t *testing.T) {
	r := newFakeReader()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	accrueBenign(t, agg, r, now)

	// A well-learned benign identity (.5, folded 10x in the baseline) on the same
	// adjacency/volume -> near-neutral novelty, below the floor -> NOT captured.
	completeFlow(agg, r, 4000, flowFromIPs(5, 1, 1400, 12, 2_000_000), now)

	dv := agg.deviantsFor(testScope)
	if dv != nil && len(dv.records) != 0 {
		var rec *DeviantFlowRecord
		for _, v := range dv.records {
			rec = v
		}
		t.Fatalf("normal low-novelty flow was captured as a deviant: peak=%v %+v", rec.PeakNovelty, rec)
	}
}

// An ARMED (canary-touching) flow produces NO deviant record even though it is
// highly novel: a canary-toucher belongs to escalation/containment, not the hunt
// log (Rule 8).
func TestDeviantArmedFlowNotCaptured(t *testing.T) {
	r := newFakeReader()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
		Armed: fakeArmed{cookies: map[uint64]bool{5000: true}},
	})
	accrueBenign(t, agg, r, now)

	// Cookie 5000 is "armed" (touched a canary); its flow is maximally novel but
	// must NOT be logged as a deviant.
	completeFlow(agg, r, 5000, flowFromIPs(200, 1, 1400, 12, 2_000_000), now)

	dv := agg.deviantsFor(testScope)
	if dv != nil && len(dv.records) != 0 {
		t.Fatalf("armed canary-toucher was captured as a deviant: %d records", len(dv.records))
	}

	// Control: a NON-armed but equally novel flow IS captured, proving the gate is
	// the armed predicate (not some other reason nothing was recorded).
	completeFlow(agg, r, 5001, flowFromIPs(201, 1, 1400, 12, 2_000_000), now)
	dv = agg.deviantsFor(testScope)
	if dv == nil || len(dv.records) != 1 {
		t.Fatalf("non-armed deviant control not captured: %v", dv)
	}
}

// A repeat deviant from the SAME canonical behavioral key bumps HitCount +
// LastSeen instead of writing a new record (a scanner collapses into few records).
// Tested at the deviants.fold mechanism level with a FIXED feature vector so the
// dedup key is exercised in isolation from the baseline self-normalization that
// would otherwise decay a recurring deviant's novelty across folds.
func TestDeviantRecurrenceDedup(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	dv := newDeviants()
	fs := flowFromIPs(199, 1, 1400, 12, 2_000_000)
	feat := baseline.Features{IdentityNovelty: 1.0, AdjacencyNovelty: 0.9} // peak = identity, stable

	// Five recurrences of the same pattern at advancing wall times, distinct
	// per-connection cookies -> ONE record, HitCount 5, LastSeen advanced.
	var lastKey string
	for i := 0; i < 5; i++ {
		now := t0.Add(time.Duration(i) * time.Hour)
		k, _ := dv.fold(fs, uint64(6000+i), feat, 0, now)
		lastKey = k
	}
	if len(dv.records) != 1 {
		t.Fatalf("recurrence did not dedup: want 1 record, got %d", len(dv.records))
	}
	rec := dv.records[lastKey]
	if rec.HitCount != 5 {
		t.Fatalf("HitCount = %d, want 5 (five recurrences on one pattern)", rec.HitCount)
	}
	if !rec.LastSeen.Equal(t0.Add(4 * time.Hour)) {
		t.Fatalf("LastSeen = %v, want advanced to the 5th fold", rec.LastSeen)
	}
	// The recurrence key is NOT the cookie: the latest cookie wins the snapshot.
	if rec.SocketCookie != 6004 {
		t.Fatalf("SocketCookie = %d, want 6004 (latest observation); recurrence must not key on the cookie", rec.SocketCookie)
	}

	// A DIFFERENT identity (distinct edge tuple) is a NEW record, not a bump — a
	// sweep over many identities yields several records, not one.
	dv.fold(flowFromIPs(200, 1, 1400, 12, 2_000_000), 7000, feat, 0, t0)
	if len(dv.records) != 2 {
		t.Fatalf("distinct identity did not create a new record: %d records", len(dv.records))
	}
}

// FirstSeen/LastSeen come from the INJECTED wall clock — never the kernel ns. A
// later recurrence advances LastSeen but pins FirstSeen.
func TestDeviantWallClockStamping(t *testing.T) {
	r := newFakeReader()
	first := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	clk := first
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return clk },
	})
	accrueBenign(t, agg, r, first)

	completeFlow(agg, r, 7000, flowFromIPs(199, 1, 1400, 12, 2_000_000), first)
	dv := agg.deviantsFor(testScope)
	var rec *DeviantFlowRecord
	for _, v := range dv.records {
		rec = v
	}
	if !rec.FirstSeen.Equal(first) || !rec.LastSeen.Equal(first) {
		t.Fatalf("first capture wall times = %v/%v, want %v", rec.FirstSeen, rec.LastSeen, first)
	}
	if rec.FirstSeen.Year() != 2026 {
		t.Fatalf("FirstSeen looks kernel-derived: %v", rec.FirstSeen)
	}

	// A later recurrence of the same pattern advances LastSeen, pins FirstSeen.
	// Stay within the SAME window bucket (09:00 -> 11:00 are both "morning") so the
	// recurrence folds into the same accrued, sufficient baseline — a cross-bucket
	// time would land in a fresh, insufficient bucket and skip capture.
	later := first.Add(2 * time.Hour)
	clk = later
	completeFlow(agg, r, 7001, flowFromIPs(199, 1, 1400, 12, 2_000_000), later)
	for _, v := range dv.records {
		rec = v
	}
	if !rec.FirstSeen.Equal(first) {
		t.Fatalf("FirstSeen moved: %v, want pinned at %v", rec.FirstSeen, first)
	}
	if !rec.LastSeen.Equal(later) {
		t.Fatalf("LastSeen = %v, want advanced to %v", rec.LastSeen, later)
	}
}

// Cap eviction keeps the high-HitCount record and drops the lowest.
func TestDeviantCapEvictsLowest(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	dv := newDeviants()

	hotKey := "hot"
	dv.records[hotKey] = &DeviantFlowRecord{HitCount: 1000, LastSeen: now, FirstSeen: now}
	for i := 0; i < deviantCapDefault-1; i++ {
		dv.records[devKeyN(i)] = &DeviantFlowRecord{HitCount: 1, LastSeen: now, FirstSeen: now}
	}
	if len(dv.records) != deviantCapDefault {
		t.Fatalf("setup: records = %d, want %d", len(dv.records), deviantCapDefault)
	}

	victim, ok := dv.evictIfFull(now)
	if !ok {
		t.Fatal("evictIfFull did not evict at cap")
	}
	if victim == hotKey {
		t.Fatal("cap eviction dropped the HOT (highest-HitCount) record")
	}
	if _, stillThere := dv.records[hotKey]; !stillThere {
		t.Fatal("hot record was evicted; cap must keep high-HitCount records")
	}
	if len(dv.records) != deviantCapDefault-1 {
		t.Fatalf("after eviction records = %d, want %d", len(dv.records), deviantCapDefault-1)
	}
}

func devKeyN(i int) string { return "cold-" + strconv.Itoa(i) }

// The TTL reaper drops stale deviant records and increments the observable
// lost-count through the fold tick.
func TestDeviantReaperTTLAndLostCount(t *testing.T) {
	r := newFakeReader()
	t0 := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	ttl := time.Hour
	clk := t0
	agg := New(Config{
		Reader: r, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(),
		DeviantTTL: ttl, Now: func() time.Time { return clk },
	})
	accrueBenign(t, agg, r, t0)

	completeFlow(agg, r, 8000, flowFromIPs(199, 1, 1400, 12, 2_000_000), t0)
	if dv := agg.deviantsFor(testScope); dv == nil || len(dv.records) != 1 {
		t.Fatalf("precondition: deviant records = %v", dv)
	}
	before := agg.Stats().DeviantsEvicted

	// Advance past the TTL and run a fold tick with no new flows: the stale record
	// is reaped.
	clk = t0.Add(2 * time.Hour)
	agg.foldOnce(clk)

	dv := agg.deviantsFor(testScope)
	if len(dv.records) != 0 {
		t.Fatalf("stale deviant not reaped: records = %d", len(dv.records))
	}
	got := agg.Stats().DeviantsEvicted
	if got <= before {
		t.Fatalf("DeviantsEvicted did not increment: before=%d after=%d", before, got)
	}
	if got-before != 1 {
		t.Fatalf("reaped count = %d, want 1", got-before)
	}
}

// Scope isolation: deviants accrued under scope A are never readable under scope B
// in the persisted store (scopeSub layout).
func TestDeviantScopeIsolation(t *testing.T) {
	const scopeA = contract.ScopeKey("scope-A")
	const scopeB = contract.ScopeKey("scope-B")
	path := filepath.Join(t.TempDir(), "baseline.db")
	store, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	mk := func(sc contract.ScopeKey, srcLast byte, cookieBase uint64) {
		rr := newFakeReader()
		ag := New(Config{
			Reader: rr, Gates: newRecordGates(), Resolver: fakeResolver{scope: sc}, Store: store,
			Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
		})
		// Accrue a benign baseline in THIS scope so the bucket exists, then a deviant.
		for i := 0; i < 30; i++ {
			completeFlow(ag, rr, cookieBase+uint64(i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), now)
		}
		completeFlow(ag, rr, cookieBase+999, flowFromIPs(srcLast, 1, 1400, 12, 2_000_000), now)
	}
	mk(scopeA, 199, 10000)
	mk(scopeB, 198, 20000)

	count := func(sc contract.ScopeKey) int {
		n := 0
		if err := store.RangeDeviants(sc, func(_, _ []byte) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(scopeA); got != 1 {
		t.Fatalf("scope A deviant records = %d, want 1", got)
	}
	if got := count(scopeB); got != 1 {
		t.Fatalf("scope B deviant records = %d, want 1", got)
	}
	if got := count(contract.ScopeKey("scope-C")); got != 0 {
		t.Fatalf("unwritten scope C deviant records = %d, want 0", got)
	}
}

// The deviant records survive a persist + reopen + rehydrate round-trip with their
// wall-clock timestamps + HitCount intact (local-rich log survives reboot).
func TestDeviantPersistAndRehydrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	store1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r1 := newFakeReader()
	a1 := New(Config{
		Reader: r1, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope}, Store: store1,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	accrueBenign(t, a1, r1, now)
	// Two recurrences of one novel identity -> HitCount 2 (a 3rd would decay the
	// novelty below the floor as the flow folds into the baseline-of-normal, the
	// correct self-normalizing behavior; 2 stays above the floor and is enough to
	// prove HitCount survives the round-trip).
	for i := 0; i < 2; i++ {
		completeFlow(a1, r1, uint64(700+i), flowFromIPs(199, 1, 1400, 12, 2_000_000), now)
	}
	_ = store1.Close()

	store2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	r2 := newFakeReader()
	a2 := New(Config{
		Reader: r2, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope}, Store: store2,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	a2.Rehydrate()

	dv := a2.deviantsFor(testScope)
	if dv == nil || len(dv.records) != 1 {
		t.Fatalf("rehydrated deviant records = %v", dv)
	}
	var rec *DeviantFlowRecord
	for _, v := range dv.records {
		rec = v
	}
	if rec.HitCount != 2 {
		t.Fatalf("rehydrated HitCount = %d, want 2", rec.HitCount)
	}
	if !rec.FirstSeen.Equal(now) {
		t.Fatalf("rehydrated FirstSeen = %v, want %v (wall clock preserved)", rec.FirstSeen, now)
	}
	if rec.SrcIP[3] != 199 {
		t.Fatalf("rehydrated raw identity lost: src=%v", rec.SrcIP[:4])
	}
}

// Back-compat: a pre-deviants baseline.db (no deviants bucket, schema_version
// unchanged) reopens cleanly and rehydrates with no deviant records.
func TestDeviantBackCompatPreDeviantsDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)

	// First process: accrue a baseline only (no deviants written here is fine).
	store1, ver1, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ver1 != persist.SchemaVersion {
		t.Fatalf("fresh store schema = %d, want %d", ver1, persist.SchemaVersion)
	}
	r1 := newFakeReader()
	a1 := New(Config{
		Reader: r1, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope}, Store: store1,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	accrueBenign(t, a1, r1, now)
	_ = store1.Close()

	// Reopen: SchemaVersion must be UNCHANGED, the baseline intact, and a rehydrate
	// finds zero deviants (the bucket was created tolerantly, empty).
	store2, ver2, err := persist.Open(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer store2.Close()
	if ver2 != persist.SchemaVersion {
		t.Fatalf("reopen schema = %d, want %d (must NOT bump for deviants)", ver2, persist.SchemaVersion)
	}
	r2 := newFakeReader()
	a2 := New(Config{
		Reader: r2, Gates: newRecordGates(), Resolver: fakeResolver{scope: testScope}, Store: store2,
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	a2.Rehydrate()
	if dv := a2.deviantsFor(testScope); dv != nil && len(dv.records) != 0 {
		t.Fatalf("pre-deviants DB rehydrated phantom deviants: %d", len(dv.records))
	}
	// And the store is immediately usable for new deviant writes after reopen.
	for i := 0; i < 30; i++ {
		completeFlow(a2, r2, uint64(1000+i), flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000), now)
	}
	completeFlow(a2, r2, 9999, flowFromIPs(199, 1, 1400, 12, 2_000_000), now)
	if dv := a2.deviantsFor(testScope); dv == nil || len(dv.records) != 1 {
		t.Fatalf("deviant capture after reopen failed: %v", dv)
	}
}
