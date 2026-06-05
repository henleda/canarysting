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
