package cost

import "github.com/canarysting/canarysting/internal/intelligence"

// Summary is the board-level attacker-cost rollup (docs/INTELLIGENCE.md §5.3)
// plus the response-tier distribution, computed over ONE scope's interaction
// events. It is the number a CISO reports: time, tokens, compute imposed on the
// attacker — against a defender cost that is bounded by construction.
type Summary struct {
	Interactions     int     // total canary interactions in the window
	TimeImposedSec   float64 // attacker wall-time imposed (sum of TimeHeldSec)
	TokensBurned     float64 // estimated LLM tokens burned (sum of TokenCostProxy)
	RequestsAbsorbed int64   // requests absorbed by attrition
	BytesServed      int64   // fake bytes served
	MaxDepth         int     // deepest maze/nesting level any attacker descended
	TierCounts       [4]int  // interactions at each tier: [Observe, Tag, Contain, Jail]
}

// Rollup aggregates a scope's interaction events into the attacker-cost summary.
// It is pure and operates only on the events handed to it (already scope-
// isolated — rule 5); it never reaches across a scope boundary.
func Rollup(events []intelligence.AdversaryInteractionEvent) Summary {
	var s Summary
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
	}
	return s
}

// ActiveResponse is the count of interactions under active response — Tier 2
// (contain/attrition) plus Tier 3 (jail) — the traffic that drives the attacker
// cost. Tiers 0–1 observe/tag and impose no economic cost.
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
