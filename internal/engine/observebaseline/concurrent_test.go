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

	// Writer: continuously bring flows up and complete them (drives foldOnce).
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
			r.set(cookie, flowFromIPs(byte(5+i%3), 1, 1400, 12, 2_000_000))
			agg.foldOnce(now)
			r.del(cookie)
			agg.foldOnce(now)
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

// A cookie that is reused within a single tick for a NEW socket (cumulative
// counters step backwards / start time changes) is detected: the old flow is
// folded once with its original totals, and the new socket is tracked fresh.
func TestCookieReuseFoldsOldAndResetsNew(t *testing.T) {
	r := newFakeReader()
	gates := newRecordGates()
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := New(Config{
		Reader: r, Gates: gates, Resolver: fakeResolver{scope: testScope},
		Bucketer: baseline.WindowBucketer, Floor: testFloor(), Now: func() time.Time { return now },
	})

	// Tick 1: a large, long-lived flow on cookie C.
	big := flowFromIPs(5, 1, 9_000_000, 5000, 2_000_000) // FirstSeenNs=1000
	r.set(42, big)
	agg.foldOnce(now)

	// Tick 2: cookie C now names a DIFFERENT socket — smaller totals, new start.
	small := flowFromIPs(6, 1, 100, 2, 1000)
	small.FirstSeenNs = 9_999 // distinct start => detected as a new socket
	small.LastSeenNs = 10_999
	r.set(42, small)
	agg.foldOnce(now)

	// The OLD flow was folded exactly once on the reset; the new one is still live.
	if st := agg.Stats(); st.CompletedFolds != 1 {
		t.Fatalf("CompletedFolds = %d, want 1 (old flow folded on cookie reuse)", st.CompletedFolds)
	}

	// Complete the new socket and confirm it folds as its own (second) flow.
	r.del(42)
	agg.foldOnce(now)
	if st := agg.Stats(); st.CompletedFolds != 2 {
		t.Fatalf("CompletedFolds = %d, want 2 (new socket folded separately)", st.CompletedFolds)
	}
}
