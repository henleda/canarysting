package cost

import (
	"sort"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
)

// NumAxes is the number of attrition axes (contract.Axis* bit order: velocity,
// poison, opportunity-cost, exploit-burn, operational-exposure). The per-axis
// subtotals below are indexed by this ordinal.
const NumAxes = 5

// AxisNames labels the per-axis subtotals in bit order, for the dashboard.
var AxisNames = [NumAxes]string{"velocity", "poison", "opportunity", "exploit", "exposure"}

// axisBits maps the ordinal -> the contract bit, so the subtotals track the
// AttritionAxis constants rather than a hand-rolled shift (robust to a reorder).
var axisBits = [NumAxes]contract.AttritionAxis{
	contract.AxisVelocity, contract.AxisPoison, contract.AxisOppCost,
	contract.AxisExploitBurn, contract.AxisOpExposure,
}

// AxesOf decodes a StingOutcome.Axes bitset into the ordered axis NAMES it fired
// (OVERLAPPING — an interaction lands on every axis its mechanism imposed). It lets a
// read-view (e.g. the dashboard's attacker-journey ribbon) label "which axes fired at
// this event" without importing contract, reusing the same bit order as the rollup.
func AxesOf(axes uint32) []string {
	a := contract.AttritionAxis(axes)
	var out []string
	for i := 0; i < NumAxes; i++ {
		if a&axisBits[i] != 0 {
			out = append(out, AxisNames[i])
		}
	}
	return out
}

// Summary is the board-level attacker-cost rollup (docs/INTELLIGENCE.md §5.3)
// plus the response-tier distribution, computed over ONE scope's interaction
// events. The framing is OPPORTUNITY COST on a velocity-dependent adversary, not a
// dollar bill: the headline is imposed time + engagement; tokens/bytes are a
// qualified proxy, never the lead. The defender cost is bounded by construction.
type Summary struct {
	Interactions     int     // total canary interactions in the window
	TimeImposedSec   float64 // attacker wall-time imposed (sum of TimeHeldSec) — the headline
	TokensBurned     float64 // estimated attacker tokens imposed (sum of TokenCostProxy) — a PROXY, demoted below time
	RequestsAbsorbed int64   // requests absorbed by attrition
	BytesServed      int64   // fake bytes served
	MaxDepth         int     // deepest maze/nesting level any attacker descended
	TierCounts       [4]int  // interactions at each tier: [Observe, Tag, Contain, Jail]

	// Per-axis subtotals (AX3), indexed by the axis ordinal. These OVERLAP: one
	// interaction lands on every axis its mechanism imposes (fake_tree is poison +
	// opportunity-cost), so the per-axis sums can EXCEED the flat totals and must
	// NEVER be rendered as a partition that sums to 100%.
	AxisTimeSec [NumAxes]float64
	AxisTokens  [NumAxes]float64
	AxisCount   [NumAxes]int

	// Engagement (AX3 / the engagement contest). The imposed-hold distribution over
	// held attrition EVENTS (each inline Tier-2/3 hold produces one event), plus the
	// disengage-reason buckets (from the adapter's D7 classifier). Time-to-disengage
	// is sourced from the REAL held time, not an event-timestamp span.
	EngagementMedianSec  float64 // median imposed hold across held attrition events
	EngagementP90Sec     float64 // p90 imposed hold
	EngagementLongestSec float64 // longest single imposed hold
	DisengagedEarly      int     // sessions the ATTACKER ended before any defender bound (DisengageAttacker) — the engagement signal
	GeneratorExhausted   int     // sessions that reached the generator's natural end
	DefenderCapped       int     // sessions the defender stopped (budget / ceiling / max-hold / kill)

	// Reaction signals (AX2/AX4/AX5), aggregated across the window. These count what
	// the attacker DID in response to the deception — distinct from the imposed-cost
	// totals above: how far into the fabricated environment they walked (poison), how
	// many real exploits they fired at decoys, how many times they exposed their
	// tooling. Deployment-local-only (rule 9; the egress filter gates any
	// cross-boundary use). Zero on a passive-floor window (these axes don't fire below
	// their floors); they light up once the operator raises the floor.
	ExploitsObserved   int64  // AX4: total exploits fired at decoys, captured in-perimeter
	ExposureSignals    int64  // AX5: total tooling/C2 fingerprints exposed, captured in-perimeter
	PoisonReachedMax   int    // AX2: deepest fabricated-environment stage any flow walked
	PoisonClassDeepest string // AX2: class label of that deepest stage ("" if none)
}

// Rollup aggregates a scope's interaction events into the attacker-cost summary.
// It is pure and operates only on the events handed to it (already scope-
// isolated — rule 5); it never reaches across a scope boundary.
func Rollup(events []intelligence.AdversaryInteractionEvent) Summary {
	var s Summary
	held := make([]float64, 0, len(events)) // imposed-hold samples for the percentiles
	for _, e := range events {
		s.Interactions++
		s.TimeImposedSec += e.Sting.TimeHeldSec
		s.TokensBurned += e.Sting.TokenCostProxy
		s.RequestsAbsorbed += e.Sting.RequestsAbsrb
		s.BytesServed += e.Sting.BytesServed
		if e.Sting.DepthReached > s.MaxDepth {
			s.MaxDepth = e.Sting.DepthReached
		}
		if e.Tier >= 0 && e.Tier < len(s.TierCounts) {
			s.TierCounts[e.Tier]++
		}
		// Reaction signals (AX2/AX4/AX5): sum the exploit/exposure counts; track the
		// deepest poison stage any flow walked + its class.
		s.ExploitsObserved += e.Sting.ExploitsObserved
		s.ExposureSignals += e.Sting.ExposureSignals
		if e.Sting.PoisonReached > s.PoisonReachedMax {
			s.PoisonReachedMax = e.Sting.PoisonReached
			s.PoisonClassDeepest = e.Sting.PoisonClass
		}
		// Per-axis OVERLAPPING subtotals: an interaction contributes to EVERY axis
		// its mechanism imposed (never a partition).
		axes := contract.AttritionAxis(e.Sting.Axes)
		for i := 0; i < NumAxes; i++ {
			if axes&axisBits[i] != 0 {
				s.AxisCount[i]++
				s.AxisTimeSec[i] += e.Sting.TimeHeldSec
				s.AxisTokens[i] += e.Sting.TokenCostProxy
			}
		}
		// Engagement: a real attrition hold contributes to the imposed-hold
		// distribution; the disengage reason (set by the adapter's D7 classifier)
		// buckets how the session ended.
		if e.Sting.TimeHeldSec > 0 {
			held = append(held, e.Sting.TimeHeldSec)
		}
		switch e.Sting.DisengageReason {
		case contract.DisengageAttacker:
			s.DisengagedEarly++
		case contract.DisengageGeneratorDone:
			s.GeneratorExhausted++
		case contract.DisengageDefenderCapped:
			s.DefenderCapped++
		}
	}
	// Percentiles over the held-time samples (the only O(N log N) step; the rest is
	// a single linear pass).
	if len(held) > 0 {
		sort.Float64s(held)
		s.EngagementMedianSec = percentile(held, 0.5)
		s.EngagementP90Sec = percentile(held, 0.9)
		s.EngagementLongestSec = held[len(held)-1]
	}
	return s
}

// percentile returns the nearest-rank value at p (0..1) of an ascending-sorted
// slice. Empty -> 0.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted)-1) + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ActiveResponse is the count of interactions under active response — Tier 2
// (contain/attrition) plus Tier 3 (jail) — the traffic that drives the attacker
// cost. Tiers 0–1 observe/tag and impose no opportunity/attrition cost.
func (s Summary) ActiveResponse() int { return s.TierCounts[2] + s.TierCounts[3] }

// Jailed is the Tier-3 (kernel-jailed) interaction count.
func (s Summary) Jailed() int { return s.TierCounts[3] }

// TierFraction returns the fraction (0..1) of interactions at the given tier.
func (s Summary) TierFraction(tier int) float64 {
	if s.Interactions == 0 || tier < 0 || tier >= len(s.TierCounts) {
		return 0
	}
	return float64(s.TierCounts[tier]) / float64(s.Interactions)
}
