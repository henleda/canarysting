package cost

import (
	"testing"

	"github.com/canarysting/canarysting/internal/intelligence"
)

func ev(tier int, time, tokens float64, reqs, bytes int64, depth int) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		Tier: tier,
		Sting: intelligence.StingOutcome{
			TimeHeldSec: time, TokenCostProxy: tokens, RequestsAbsrb: reqs, BytesServed: bytes, DepthReached: depth,
		},
	}
}

func TestRollup(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0, 0, 0, 0, 0, 0),          // observe
		ev(1, 0, 0, 0, 0, 0),          // tag
		ev(2, 30, 12000, 400, 5e6, 4), // contain/attrition
		ev(3, 60, 26000, 800, 6e6, 7), // jail
	}
	s := Rollup(events)
	if s.Interactions != 4 {
		t.Fatalf("interactions = %d, want 4", s.Interactions)
	}
	if s.TimeImposedSec != 90 || s.TokensBurned != 38000 || s.RequestsAbsorbed != 1200 || s.BytesServed != 11e6 {
		t.Fatalf("cost rollup wrong: %+v", s)
	}
	if s.MaxDepth != 7 {
		t.Fatalf("max depth = %d, want 7", s.MaxDepth)
	}
	if s.TierCounts != [4]int{1, 1, 1, 1} {
		t.Fatalf("tier counts = %v, want [1 1 1 1]", s.TierCounts)
	}
	if s.ActiveResponse() != 2 {
		t.Fatalf("active response = %d, want 2 (T2+T3)", s.ActiveResponse())
	}
	if s.Jailed() != 1 {
		t.Fatalf("jailed = %d, want 1", s.Jailed())
	}
	if f := s.TierFraction(0); f != 0.25 {
		t.Fatalf("tier-0 fraction = %v, want 0.25", f)
	}
}

func TestRollupEmpty(t *testing.T) {
	s := Rollup(nil)
	if s.Interactions != 0 || s.ActiveResponse() != 0 || s.TierFraction(2) != 0 {
		t.Fatalf("empty rollup not zero: %+v", s)
	}
}
