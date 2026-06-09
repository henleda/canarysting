package observebaseline

import (
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
)

// TestConcurrentFoldAndFeatures exercises the exact production overlap the serial
// completeFlow suite never touches: the aggregator's fold loop (writer, takes
// Aggregator.mu then the gate's mutex, A→B) racing the scoring hot path
// (baseline.Store.Multiplier → Aggregator.Features, which takes Aggregator.mu
// after releasing Store.mu). Run under `go test -race` it locks in the
// no-map-race / no-deadlock invariant and guards the lock-drop-relock in
// baseline.Store.Multiplier against a refactor that would invert the lock order.
func TestConcurrentFoldAndFeatures(t *testing.T) {
	r := newFakeReader()
	base := baseline.New(baseline.Config{
		Bucketer:   baseline.WindowBucketer,
		Calibrated: func(contract.ScopeKey) bool { return true },
	})
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: base, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})
	base.UseFeatureSource(agg)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: continuously open and close flows (mark-closed), driving foldOnce.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var i uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			cookie := 1000 + (i % 64)
			fs := flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000)
			r.set(cookie, fs)
			agg.foldOnce(now)
			fs.Closed = 1
			r.set(cookie, fs)
			agg.foldOnce(now)
			r.del(cookie) // LRU eviction
			i++
		}
	}()

	// Readers: hammer the scoring multiplier path (Store.Multiplier → Features).
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			for j := uint64(0); ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				cookie := 2000 + ((seed*97 + j) % 64)
				r.set(cookie, flowFromIPs(7, 1, 1400, 12, 2_000_000))
				_ = base.Multiplier(testScope, contract.FlowIdentity{SocketCookie: cookie}, now)
				_ = agg.Stats()
			}
		}(uint64(g))
	}

	time.Sleep(80 * time.Millisecond)
	close(stop)
	wg.Wait()
	// Reaching here without the race detector firing or a deadlock is the assertion.
}

// A closed flow that LINGERS in the map across several ticks (the kernel keeps it
// until the LRU evicts it) is folded EXACTLY ONCE — the folded-set prevents
// double-counting, and a sub-tick flow (one that is already closed the first time
// the aggregator sees it) is still caught.
func TestClosedFlowFoldedExactlyOnce(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})

	// A flow already CLOSED the first time the aggregator sees it (opened+closed
	// between ticks) — and it lingers, present on three consecutive ticks.
	fs := flowFromIPs(5, 1, 1400, 12, 2_000_000)
	fs.Closed = 1
	r.set(42, fs)
	agg.foldOnce(now)
	agg.foldOnce(now)
	agg.foldOnce(now)
	if st := agg.Stats(); st.CompletedFolds != 1 {
		t.Fatalf("CompletedFolds = %d, want 1 (a lingering closed flow must fold exactly once)", st.CompletedFolds)
	}

	// Once the LRU evicts it (gone from the map), a fresh tick prunes it and a NEW
	// cookie folds independently.
	r.del(42)
	agg.foldOnce(now)
	completeFlow(agg, r, 43, flowFromIPs(6, 1, 1400, 12, 2_000_000), now)
	if st := agg.Stats(); st.CompletedFolds != 2 {
		t.Fatalf("CompletedFolds = %d, want 2 (a new flow folds after the first was evicted)", st.CompletedFolds)
	}
}
