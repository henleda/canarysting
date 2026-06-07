// Package intelligence turns CanarySting's observation vantage point into a
// proprietary, compounding data asset. See docs/INTELLIGENCE.md for the full
// spec and the build order.
//
// HARD RULE (docs/INTELLIGENCE.md §2): only derived, anonymized adversary
// patterns may cross a deployment boundary. Customer traffic, baselines, scope
// state, decoy contents, and any environment-identifying detail NEVER leave the
// deployment. The egress filter in internal/intelligence/network is the single
// chokepoint for anything that crosses a boundary, and it is default-deny.
package intelligence

import "time"

// AdversaryInteractionEvent is the canonical record of one canary interaction
// and the flow that produced it. It is the join of the canary signal, the
// flow's baseline-feature vector at interaction time, the engine verdict/tier,
// and the sting outcome with cost-proxy measures. Scope-keyed. Carries no raw
// payloads, addresses, identities, or decoy contents — only structured features
// and identifiers internal to the deployment. See docs/INTELLIGENCE.md §3.2.
type AdversaryInteractionEvent struct {
	ScopeKey   string // per-scope isolation key (see docs/SCOPE.md)
	FlowID     uint64 // socket cookie (see docs/IDENTITY.md)
	CanaryType string // which decoy type was touched
	Timestamp  time.Time

	// Baseline-feature vector at interaction time (see docs/BASELINE_MULTIPLIER.md §3).
	// Structured deviations only; not raw traffic.
	Features map[string]float64

	Tier    int    // engine tier reached (0..3)
	Verdict string // engine verdict
	Sting   StingOutcome
}

// StingOutcome records what the sting layer did and the cost-proxy measures
// used to compute the attacker-cost metric (docs/INTELLIGENCE.md §5.3).
type StingOutcome struct {
	Mechanism     string  // containment or attrition mechanism applied
	TimeHeldSec   float64 // attacker time imposed
	BytesServed   int64   // fake bytes served (attrition)
	RequestsAbsrb int64   // requests absorbed (attrition)
	// TokenCostProxy estimates LLM tokens an agent would burn processing the
	// bait. Research-direction; see docs/INTELLIGENCE.md §6 (Model 2).
	TokenCostProxy float64
	// DepthReached is the deepest maze/nesting level the attacker descended — a
	// behavioral reaction signal for the D2 adversary profiler (docs/STING.md).
	DepthReached int
}

// EventStore is the per-scope, deployment-local store of interaction events.
// Implementations MUST isolate by ScopeKey and MUST NOT emit across a
// deployment boundary. See docs/INTELLIGENCE.md §3.3.
type EventStore interface {
	Append(ev AdversaryInteractionEvent) error
	// Query returns events for a single scope within a window. Never cross-scope.
	Query(scopeKey string, since, until time.Time) ([]AdversaryInteractionEvent, error)
}
