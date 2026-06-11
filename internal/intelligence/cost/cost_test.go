package cost

import (
	"bytes"
	"os"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
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
	if s.EngagementMedianSec != 0 || s.DisengagedEarly != 0 || s.AxisTimeSec != [NumAxes]float64{} {
		t.Fatalf("empty rollup has non-zero axis/engagement fields: %+v", s)
	}
}

func TestRollupPerAxisOverlapping(t *testing.T) {
	// fake_tree imposes BOTH poison and opportunity cost: one such event counts
	// toward BOTH axes (overlapping), so the per-axis sums EXCEED the flat total —
	// the dashboard must never render them as a partition.
	mk := func(axes contract.AttritionAxis, held float64) intelligence.AdversaryInteractionEvent {
		return intelligence.AdversaryInteractionEvent{Tier: 2, Sting: intelligence.StingOutcome{TimeHeldSec: held, TokenCostProxy: held * 10, Axes: uint32(axes)}}
	}
	s := Rollup([]intelligence.AdversaryInteractionEvent{
		mk(contract.AxisVelocity, 2),                    // tarpit
		mk(contract.AxisPoison|contract.AxisOppCost, 5), // fake_tree: poison + opportunity cost
		mk(contract.AxisPoison, 3),                      // poison_field
	})
	// ordinals: velocity=0, poison=1, opportunity=2
	if s.AxisCount[0] != 1 || s.AxisCount[1] != 2 || s.AxisCount[2] != 1 {
		t.Fatalf("axis counts = %v, want velocity=1 poison=2 opportunity=1", s.AxisCount)
	}
	if s.AxisTimeSec[1] != 8 { // poison = fake_tree(5) + poison_field(3)
		t.Fatalf("poison axis time = %v, want 8", s.AxisTimeSec[1])
	}
	if s.AxisTimeSec[2] != 5 { // opportunity = fake_tree(5) only
		t.Fatalf("opportunity axis time = %v, want 5", s.AxisTimeSec[2])
	}
	overlapSum := s.AxisTimeSec[0] + s.AxisTimeSec[1] + s.AxisTimeSec[2]
	if s.TimeImposedSec != 10 || overlapSum <= s.TimeImposedSec {
		t.Fatalf("per-axis (%v) must OVERLAP and exceed the flat total (%v), not partition it", overlapSum, s.TimeImposedSec)
	}
}

func TestRollupEngagement(t *testing.T) {
	mk := func(held float64, reason int) intelligence.AdversaryInteractionEvent {
		return intelligence.AdversaryInteractionEvent{Tier: 2, Sting: intelligence.StingOutcome{TimeHeldSec: held, DisengageReason: reason}}
	}
	s := Rollup([]intelligence.AdversaryInteractionEvent{
		mk(2, contract.DisengageAttacker),
		mk(4, contract.DisengageDefenderCapped),
		mk(6, contract.DisengageGeneratorDone),
		mk(8, contract.DisengageDefenderCapped),
		mk(0, contract.DisengageUnknown), // no hold: excluded from the percentile sample
	})
	if s.DisengagedEarly != 1 || s.GeneratorExhausted != 1 || s.DefenderCapped != 2 {
		t.Fatalf("disengage buckets: early=%d gen=%d capped=%d, want 1/1/2", s.DisengagedEarly, s.GeneratorExhausted, s.DefenderCapped)
	}
	// held samples sorted = [2,4,6,8]: nearest-rank median=6, p90=8, longest=8.
	if s.EngagementMedianSec != 6 || s.EngagementP90Sec != 8 || s.EngagementLongestSec != 8 {
		t.Fatalf("engagement median/p90/longest = %v/%v/%v, want 6/8/8", s.EngagementMedianSec, s.EngagementP90Sec, s.EngagementLongestSec)
	}
}

func TestNoEconomicCostFraming(t *testing.T) {
	// AX3 anti-regression guard: the cost layer must not reintroduce the
	// dollar/"economic cost" framing the five-axis model replaced with opportunity
	// cost. A future edit that regresses the framing fails here.
	src, err := os.ReadFile("cost.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte("economic cost")) {
		t.Fatal(`cost.go reintroduced "economic cost" framing; AX3 reframes to opportunity/attrition cost`)
	}
}
