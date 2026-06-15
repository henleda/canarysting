package siem

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/l7events"
)

// fakeSource is an in-process Source: no real store, no real net.
type fakeSource struct {
	mu       sync.Mutex
	byScope  map[contract.ScopeKey][]l7events.EnrichedTouchRecord
	reapHits int
}

func newFakeSource() *fakeSource {
	return &fakeSource{byScope: map[contract.ScopeKey][]l7events.EnrichedTouchRecord{}}
}

func (f *fakeSource) set(scope contract.ScopeKey, recs ...l7events.EnrichedTouchRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byScope[scope] = recs
}

func (f *fakeSource) Scopes() []contract.ScopeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]contract.ScopeKey, 0, len(f.byScope))
	for sc := range f.byScope {
		out = append(out, sc)
	}
	return out
}

func (f *fakeSource) Snapshot(scope contract.ScopeKey) []l7events.EnrichedTouchRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := f.byScope[scope]
	out := make([]l7events.EnrichedTouchRecord, len(src))
	copy(out, src)
	return out
}

func (f *fakeSource) Reap(time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reapHits++
	return 0
}

// fakeSink is an in-process Emitter recording what it received. It is WRITE-ONLY: Emit
// takes an event and returns only an error — there is no method by which the sink hands
// data BACK to the drain (that is the structural one-way property).
type fakeSink struct {
	mu     sync.Mutex
	events []SiemEvent
	failN  int // fail the first failN Emit calls, then succeed
}

func (s *fakeSink) Emit(_ context.Context, ev SiemEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failN > 0 {
		s.failN--
		return errors.New("simulated transport failure")
	}
	s.events = append(s.events, ev)
	return nil
}
func (s *fakeSink) Name() string { return "fake" }
func (s *fakeSink) count() int   { s.mu.Lock(); defer s.mu.Unlock(); return len(s.events) }
func (s *fakeSink) snapshot() []SiemEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SiemEvent, len(s.events))
	copy(out, s.events)
	return out
}

func rec(id, scope string, hit uint64, last time.Time) l7events.EnrichedTouchRecord {
	return l7events.EnrichedTouchRecord{
		EventID: id, Scope: scope, CanaryType: "decoy_file",
		Tier: int(contract.TierTag), Verdict: "tag",
		HitCount: hit, FirstSeen: last, LastSeen: last,
	}
}

// drive runs N drain ticks synchronously (no real ticker), so the test is
// deterministic and never sleeps.
func drive(d *Drainer, n int) {
	for i := 0; i < n; i++ {
		d.drainOnce(context.Background())
	}
}

func TestDrain_EmitsEachTouchOnce(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("s1", rec("e1", "s1", 1, t0), rec("e2", "s1", 1, t0))
	sink := &fakeSink{}
	d := New(Config{Source: src, Sink: sink, Now: func() time.Time { return t0 }})

	drive(d, 1)
	if sink.count() != 2 {
		t.Fatalf("first drain emitted %d, want 2", sink.count())
	}
	// Re-draining the SAME, unchanged snapshot must NOT re-emit (cursor dedup).
	drive(d, 3)
	if sink.count() != 2 {
		t.Fatalf("re-draining unchanged records emitted %d, want still 2 (dedup by EventID)", sink.count())
	}
}

func TestDrain_ReEmitsOnRecurrenceBump(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("s1", rec("e1", "s1", 1, t0))
	sink := &fakeSink{}
	d := New(Config{Source: src, Sink: sink, Now: func() time.Time { return t0 }})
	drive(d, 1)
	if sink.count() != 1 {
		t.Fatalf("initial emit = %d, want 1", sink.count())
	}
	// A repeat touch bumps HitCount + LastSeen in place (mirrors l7events.Capture).
	src.set("s1", rec("e1", "s1", 2, t0.Add(time.Second)))
	drive(d, 1)
	if sink.count() != 2 {
		t.Fatalf("after recurrence bump emit = %d, want 2 (re-emit as an update)", sink.count())
	}
}

func TestDrain_PerScope(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("scopeA", rec("a1", "scopeA", 1, t0))
	src.set("scopeB", rec("b1", "scopeB", 1, t0))
	sink := &fakeSink{}
	d := New(Config{Source: src, Sink: sink, Now: func() time.Time { return t0 }})
	drive(d, 1)
	got := map[string]bool{}
	for _, ev := range sink.snapshot() {
		got[ev.Scope] = true
		// every event must carry its own scope label (never merged unlabeled).
		if ev.Scope == "" {
			t.Fatal("emitted event has empty scope — scopes must never be merged unlabeled (rule 5)")
		}
	}
	if !got["scopeA"] || !got["scopeB"] {
		t.Fatalf("expected one event per scope, got scopes %v", got)
	}
}

func TestDrain_TransportFailureBoundedDropNoFlood(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("s1", rec("e1", "s1", 1, t0))
	// Fail more times than maxRetries on this tick: the event is attempted a bounded
	// number of times, then DROPPED. The drain must NOT panic or block.
	sink := &fakeSink{failN: maxRetries + 1}
	d := New(Config{Source: src, Sink: sink, Now: func() time.Time { return t0 }})

	done := make(chan struct{})
	go func() { drive(d, 1); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain blocked on a failing transport — a SIEM outage must never block")
	}
	if sink.count() != 0 {
		t.Fatalf("failing sink recorded %d events, want 0 (all dropped)", sink.count())
	}
	// Bounded-drop: the cursor ADVANCED on the permanent drop, so on recovery the same
	// unchanged record is NOT re-hammered — no every-tick retry, no flood-on-recovery.
	// A FRESH touch after recovery DOES emit (the drain is healthy), so emitting only
	// the new e2 (not the dropped e1) proves both: drain recovered AND e1 not replayed.
	sink.failN = 0
	src.set("s1", rec("e1", "s1", 1, t0), rec("e2", "s1", 1, t0))
	drive(d, 1)
	if sink.count() != 1 {
		t.Fatalf("after recovery emit = %d, want 1 (the dropped e1 must NOT replay; only the fresh e2 emits)", sink.count())
	}
	if got := sink.snapshot()[0].EventID; got != "e2" {
		t.Fatalf("recovery emitted %q, want e2 (e1 was dropped, cursor advanced, not replayed)", got)
	}
}

func TestDrain_ReapCoarseCadence(t *testing.T) {
	src := newFakeSource()
	now := time.Unix(1700000000, 0)
	d := New(Config{Source: src, Sink: &fakeSink{}, Now: func() time.Time { return now }, ReapEnabled: true})
	// Several quick ticks within reapInterval reap only ONCE (the first), not per-tick:
	// the 30d TTL boundary is crossed at most once per record per ~30d, so the
	// full-store scan under the Capture lock runs on a coarse cadence.
	drive(d, 3)
	if src.reapHits != 1 {
		t.Fatalf("Reap called %d times across 3 quick ticks, want 1 (coarse cadence, not per-tick)", src.reapHits)
	}
	// Advancing past reapInterval reaps again.
	now = now.Add(reapInterval + time.Second)
	drive(d, 1)
	if src.reapHits != 2 {
		t.Fatalf("Reap called %d times after advancing past reapInterval, want 2", src.reapHits)
	}
	// And NOT driven when disabled.
	src2 := newFakeSource()
	d2 := New(Config{Source: src2, Sink: &fakeSink{}, Now: func() time.Time { return now }, ReapEnabled: false})
	drive(d2, 3)
	if src2.reapHits != 0 {
		t.Fatalf("Reap called %d times with ReapEnabled=false, want 0", src2.reapHits)
	}
}

func TestDrain_ExtraScopesAlwaysDrained(t *testing.T) {
	src := newFakeSource() // no scopes have records yet
	t0 := time.Unix(1700000000, 0)
	sink := &fakeSink{}
	d := New(Config{Source: src, Sink: sink, Now: func() time.Time { return t0 }, ExtraScopes: []contract.ScopeKey{"m7-window"}})
	// The boundary scope is in the drain set even though Scopes() is empty; Snapshot of
	// an empty scope is a harmless no-op (no events), but the scope IS visited.
	scopes := d.scopes()
	found := false
	for _, sc := range scopes {
		if sc == "m7-window" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExtraScopes boundary not in drain set: %v", scopes)
	}
}

func TestRun_StopsOnContextCancelWithFinalDrain(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("s1", rec("e1", "s1", 1, t0))
	sink := &fakeSink{}
	d := New(Config{Source: src, Sink: sink, Interval: time.Hour, Now: func() time.Time { return t0 }})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	cancel() // before any tick fires, so only the final drain runs
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
	if sink.count() != 1 {
		t.Fatalf("final drain on shutdown emitted %d, want 1 (a touch just before shutdown is not lost)", sink.count())
	}
}

func TestNew_NilSinkIsInert(t *testing.T) {
	src := newFakeSource()
	t0 := time.Unix(1700000000, 0)
	src.set("s1", rec("e1", "s1", 1, t0))
	// nil Sink => NopEmitter; the drain runs but discards (off-by-default fail-safe).
	d := New(Config{Source: src, Sink: nil, Now: func() time.Time { return t0 }})
	if _, ok := d.sink.(NopEmitter); !ok {
		t.Fatalf("nil sink should default to NopEmitter, got %T", d.sink)
	}
	drive(d, 1) // must not panic
}

func TestNew_NilSourceRunIsNoOp(t *testing.T) {
	d := New(Config{Source: nil, Sink: &fakeSink{}})
	done := make(chan struct{})
	go func() { d.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run with nil Source should return immediately")
	}
}
