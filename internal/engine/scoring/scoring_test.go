package scoring

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// uniformWeights returns 1.0 for every type — the cold-start weight source.
type uniformWeights struct{}

func (uniformWeights) Weight(contract.ScopeKey, contract.CanaryType) float64 { return 1.0 }

// customWeights returns a per-type weight, for the "learned weights feed the
// score" path.
type customWeights map[contract.CanaryType]float64

func (c customWeights) Weight(_ contract.ScopeKey, ct contract.CanaryType) float64 {
	if w, ok := c[ct]; ok {
		return w
	}
	return 1.0
}

// excludeCookie excludes one socket cookie (a stand-in for a benign service
// account flow).
type excludeCookie uint64

func (e excludeCookie) Excluded(f contract.FlowIdentity) bool { return f.SocketCookie == uint64(e) }

func ev(scope contract.ScopeKey, cookie uint64, ct string, at time.Time) contract.SignalEvent {
	return contract.SignalEvent{
		Flow:      contract.FlowIdentity{SocketCookie: cookie},
		Canary:    contract.CanaryType(ct),
		Scope:     scope,
		Timestamp: at,
	}
}

func TestScore_ColdStartIsRawCountOfDistinctTouches(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	got, _ := s.Score("scope", ev("scope", 1, "a", t0))
	if got != 1.0 {
		t.Fatalf("first touch: got %.2f want 1.0", got)
	}
	got, _ = s.Score("scope", ev("scope", 1, "b", t0.Add(time.Second)))
	if got != 2.0 {
		t.Fatalf("second distinct touch: got %.2f want 2.0", got)
	}
	got, _ = s.Score("scope", ev("scope", 1, "c", t0.Add(2*time.Second)))
	if got != 3.0 {
		t.Fatalf("third distinct touch: got %.2f want 3.0", got)
	}
}

func TestScore_RepeatedTypeCountsOnce(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	s.Score("scope", ev("scope", 1, "a", t0))
	got, _ := s.Score("scope", ev("scope", 1, "a", t0.Add(time.Second)))
	if got != 1.0 {
		t.Fatalf("same type twice: got %.2f want 1.0 (distinct)", got)
	}
}

func TestScore_WindowExpiresOldTouches(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	s.Score("scope", ev("scope", 1, "a", t0))
	// 10 minutes later, "a" is outside the 5m window; only "b" counts.
	got, _ := s.Score("scope", ev("scope", 1, "b", t0.Add(10*time.Minute)))
	if got != 1.0 {
		t.Fatalf("after window: got %.2f want 1.0 (old touch expired)", got)
	}
}

func TestScore_BenignExclusionNeverAccrues(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, excludeCookie(7))
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < 5; i++ {
		got, _ := s.Score("scope", ev("scope", 7, string(rune('a'+i)), t0))
		if got != 0.0 {
			t.Fatalf("excluded flow accrued score %.2f", got)
		}
	}
}

func TestScore_StateIsScopeIsolated(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	// Same socket cookie, two scopes. Touches in scope-a must not raise scope-b.
	s.Score("scope-a", ev("scope-a", 1, "a", t0))
	s.Score("scope-a", ev("scope-a", 1, "b", t0))
	got, _ := s.Score("scope-b", ev("scope-b", 1, "a", t0))
	if got != 1.0 {
		t.Fatalf("scope-b leaked scope-a state: got %.2f want 1.0", got)
	}
}

func TestScore_LearnedWeightsFeedTheScore(t *testing.T) {
	w := customWeights{"hot": 2.0, "cold": 0.5}
	s := New(5*time.Minute, w, nil)
	t0 := time.Unix(1_000_000, 0)
	s.Score("scope", ev("scope", 1, "hot", t0))
	got, _ := s.Score("scope", ev("scope", 1, "cold", t0.Add(time.Second)))
	if got != 2.5 {
		t.Fatalf("weighted sum: got %.2f want 2.5", got)
	}
}

func TestScore_EmptyScopeIsError(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	if _, err := s.Score("", ev("", 1, "a", time.Now())); err == nil {
		t.Fatal("empty scope must error, never score")
	}
}

// fixedMultiplier returns a constant M for the Score = B × M tests.
type fixedMultiplier float64

func (m fixedMultiplier) Multiplier(contract.ScopeKey, contract.FlowIdentity, time.Time) float64 {
	return float64(m)
}

func TestScore_AppliesBaselineMultiplier(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil).UseMultiplier(fixedMultiplier(2.0))
	t0 := time.Unix(1_000_000, 0)
	s.Score("scope", ev("scope", 1, "a", t0))
	s.Score("scope", ev("scope", 1, "b", t0.Add(time.Second)))
	got, _ := s.Score("scope", ev("scope", 1, "c", t0.Add(2*time.Second)))
	if got != 6.0 { // base 3.0 × M 2.0
		t.Fatalf("Score = B×M: got %.2f, want 6.0", got)
	}
}

func TestScore_MultiplierClampedToFloorOfOne(t *testing.T) {
	// A misbehaving source returning < 1 must never suppress the base.
	s := New(5*time.Minute, uniformWeights{}, nil).UseMultiplier(fixedMultiplier(0.5))
	got, _ := s.Score("scope", ev("scope", 1, "a", time.Unix(1_000_000, 0)))
	if got != 1.0 {
		t.Fatalf("M<1 must clamp to floor 1: got %.2f, want 1.0", got)
	}
}

func TestScore_ZeroBaseStaysZeroUnderAnyMultiplier(t *testing.T) {
	// B = 0 (here via benign exclusion) × M = 0, even at maximal M. The guardrail.
	s := New(5*time.Minute, uniformWeights{}, excludeCookie(9)).UseMultiplier(fixedMultiplier(3.0))
	got, _ := s.Score("scope", ev("scope", 9, "a", time.Unix(1_000_000, 0)))
	if got != 0.0 {
		t.Fatalf("zero base must yield zero score under any M: got %.2f", got)
	}
}

// liveCookies reports how many per-flow entries are currently held for a scope.
// White-box helper: the reaper's whole job is to bound this number.
func (s *WindowedScorer) liveCookies(scope contract.ScopeKey) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.state[scope])
}

func TestReap_IdleCookieIsReaped(t *testing.T) {
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	// Cookie 1 touches once, then goes silent.
	s.Score("scope", ev("scope", 1, "a", t0))
	if got := s.liveCookies("scope"); got != 1 {
		t.Fatalf("after first flow: live cookies = %d, want 1", got)
	}
	// Cookie 2 touches 10 minutes later — past cookie 1's 5m window. The reap
	// triggered by cookie 2's event must drop the now-idle cookie 1.
	s.Score("scope", ev("scope", 2, "a", t0.Add(10*time.Minute)))
	if got := s.liveCookies("scope"); got != 1 {
		t.Fatalf("idle cookie not reaped: live cookies = %d, want 1 (only the active flow)", got)
	}
}

func TestReap_ExpiredEmptyStateIsReaped(t *testing.T) {
	// A flow whose only touches all aged out of the window leaves empty per-type
	// state. The next reap (from any later event) must reclaim the whole flow,
	// not leave a zombie empty map behind.
	s := New(5*time.Minute, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)
	s.Score("scope", ev("scope", 1, "a", t0))
	s.Score("scope", ev("scope", 1, "b", t0.Add(time.Second)))
	// Much later, a different flow drives a reap; cookie 1 is fully idle.
	s.Score("scope", ev("scope", 2, "a", t0.Add(time.Hour)))
	if got := s.liveCookies("scope"); got != 1 {
		t.Fatalf("expired flow state not reclaimed: live cookies = %d, want 1", got)
	}
}

func TestReap_MapBoundedUnderFloodOfDistinctCookies(t *testing.T) {
	const cap = 50
	s := New(5*time.Minute, uniformWeights{}, nil).WithMaxCookiesPerScope(cap)
	t0 := time.Unix(1_000_000, 0)
	// 10_000 distinct cookies all touching inside the SAME window (1ms apart) —
	// the worst case where TTL eviction reclaims nothing and only the size cap
	// keeps memory bounded.
	for i := 0; i < 10_000; i++ {
		at := t0.Add(time.Duration(i) * time.Millisecond)
		if _, err := s.Score("scope", ev("scope", uint64(i+1), "a", at)); err != nil {
			t.Fatalf("score %d: %v", i, err)
		}
		if got := s.liveCookies("scope"); got > cap {
			t.Fatalf("map grew past cap: live cookies = %d, want <= %d", got, cap)
		}
	}
	if got := s.liveCookies("scope"); got != cap {
		t.Fatalf("after flood: live cookies = %d, want exactly cap %d", got, cap)
	}
}

func TestReap_ActiveFlowScoreUnchangedAcrossReap(t *testing.T) {
	// An active flow that keeps touching inside its window must score identically
	// whether or not idle flows are reaped around it. The reap must never evict
	// the flow being scored, nor drop its in-window touches. Here a flood of
	// distinct noise cookies arrives, but each goes idle (touches once, then is
	// silent for longer than the window) while the active flow keeps touching —
	// so TTL eviction reclaims the noise and the active flow is preserved.
	t0 := time.Unix(1_000_000, 0)

	// Baseline: the active flow alone, three distinct in-window touches => 3.0.
	solo := New(5*time.Minute, uniformWeights{}, nil)
	solo.Score("scope", ev("scope", 7, "a", t0))
	solo.Score("scope", ev("scope", 7, "b", t0.Add(time.Minute)))
	want, _ := solo.Score("scope", ev("scope", 7, "c", t0.Add(2*time.Minute)))
	if want != 3.0 {
		t.Fatalf("baseline active score = %.2f, want 3.0", want)
	}

	// Same active flow, interleaved with bursts of one-shot noise cookies. The
	// active flow re-touches every minute (well inside its 5m window, so all its
	// touches stay live), while each noise burst sits a window+ in the past by
	// the time the next active touch fires — so the reap evicts noise but never
	// the active flow's live state.
	s := New(5*time.Minute, uniformWeights{}, nil)
	s.Score("scope", ev("scope", 7, "a", t0))
	for i := 0; i < 100; i++ { // noise burst near t0
		s.Score("scope", ev("scope", uint64(1000+i), "x", t0.Add(time.Duration(i)*time.Millisecond)))
	}
	s.Score("scope", ev("scope", 7, "b", t0.Add(time.Minute)))
	for i := 0; i < 100; i++ { // noise burst near t0+1m
		s.Score("scope", ev("scope", uint64(2000+i), "x", t0.Add(time.Minute+time.Duration(i)*time.Millisecond)))
	}
	got, _ := s.Score("scope", ev("scope", 7, "c", t0.Add(2*time.Minute)))
	if got != want {
		t.Fatalf("active flow score changed across reap: got %.2f, want %.2f", got, want)
	}
}

func TestReap_SizeCapEvictsLeastRecentlyTouchedFirst(t *testing.T) {
	// When a genuine flood of concurrently-active (in-window) flows exceeds the
	// cap, the size cap is the only thing keeping memory bounded: it evicts the
	// least-recently-touched flows first, preserving the most recent ones. This
	// is the documented memory-safety tradeoff — under that load the oldest
	// in-window flows are sacrificed, never the newest.
	const cap = 5
	s := New(time.Hour, uniformWeights{}, nil).WithMaxCookiesPerScope(cap)
	t0 := time.Unix(1_000_000, 0)
	// 20 distinct flows, each 1s apart, all inside the 1h window.
	for i := 0; i < 20; i++ {
		s.Score("scope", ev("scope", uint64(i+1), "a", t0.Add(time.Duration(i)*time.Second)))
	}
	if got := s.liveCookies("scope"); got != cap {
		t.Fatalf("flood not bounded to cap: live cookies = %d, want %d", got, cap)
	}
	// The 5 most-recently-touched cookies (16..20) survive; the oldest are gone.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range []uint64{16, 17, 18, 19, 20} {
		if _, ok := s.state["scope"][c]; !ok {
			t.Fatalf("recently-touched cookie %d was evicted; LRU order wrong", c)
		}
	}
	for _, c := range []uint64{1, 5, 10, 15} {
		if _, ok := s.state["scope"][c]; ok {
			t.Fatalf("stale cookie %d survived; LRU order wrong", c)
		}
	}
}

func TestReap_BoundaryFlowAtExactCutoffIsRetained(t *testing.T) {
	// Boundary consistency: the reaper's TTL test must match the score loop's
	// retention boundary exactly. The score loop drops a touch only when it is
	// strictly Before(cutoff), so a touch at last == cutoff is RETAINED. The
	// reaper must therefore NOT evict a flow whose newest touch is exactly at the
	// cutoff — otherwise a flow the score loop still treats as active would be
	// dropped at the exact-boundary instant.
	const window = 5 * time.Minute
	s := New(window, uniformWeights{}, nil)
	t0 := time.Unix(1_000_000, 0)

	// Boundary flow: cookie 1 touches once at t0.
	s.Score("scope", ev("scope", 1, "a", t0))

	// Driver flow: cookie 2 touches at exactly t0+window, so the reap it triggers
	// uses cutoff == (t0+window)-window == t0. Cookie 1's lastTouch == t0 == cutoff.
	// last == cutoff is NOT Before(cutoff), so cookie 1 must survive this reap.
	s.Score("scope", ev("scope", 2, "a", t0.Add(window)))
	if got := s.liveCookies("scope"); got != 2 {
		t.Fatalf("flow at exact cutoff was reaped: live cookies = %d, want 2 (boundary is strict, matching the score loop)", got)
	}

	// And it is genuinely still active per the score loop: re-touching cookie 1
	// at exactly t0+window keeps its t0 "a" touch (last == cutoff is retained),
	// so a second distinct type makes the base 2.0, not 1.0.
	got, _ := s.Score("scope", ev("scope", 1, "b", t0.Add(window)))
	if got != 2.0 {
		t.Fatalf("score loop dropped a touch at exact cutoff: got %.2f, want 2.0 (boundary retained)", got)
	}

	// One nanosecond past the boundary, the flow is strictly idle and reapable.
	// Cookie 3 drives a reap with cutoff just past cookie 1/2's last touches.
	s.Score("scope", ev("scope", 3, "a", t0.Add(2*window).Add(time.Nanosecond)))
	if got := s.liveCookies("scope"); got != 1 {
		t.Fatalf("strictly-idle flows past the boundary not reaped: live cookies = %d, want 1 (only the active driver)", got)
	}
}

func TestReap_DoesNotLeakAcrossScopes(t *testing.T) {
	// Reaping a flood in one scope must not disturb another scope's flows
	// (scope isolation — rule 5). A flow idle in scope-a is reaped; scope-b's
	// same-cookie flow is independent.
	s := New(5*time.Minute, uniformWeights{}, nil).WithMaxCookiesPerScope(5)
	t0 := time.Unix(1_000_000, 0)
	// Active flow in scope-b.
	s.Score("scope-b", ev("scope-b", 7, "a", t0))
	// Flood scope-a well past the cap, far in the future.
	for i := 0; i < 50; i++ {
		s.Score("scope-a", ev("scope-a", uint64(i+1), "a", t0.Add(time.Hour)))
	}
	// scope-b is untouched by scope-a's reaping; its flow still scores.
	got, _ := s.Score("scope-b", ev("scope-b", 7, "b", t0.Add(time.Second)))
	if got != 2.0 {
		t.Fatalf("scope-b flow disturbed by scope-a reap: got %.2f, want 2.0", got)
	}
	if live := s.liveCookies("scope-a"); live > 5 {
		t.Fatalf("scope-a not bounded: live cookies = %d, want <= 5", live)
	}
}
