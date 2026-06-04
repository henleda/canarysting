// Package attrition imposes economic cost on automated/LLM-driven attackers:
// tarpit, plausible-endless fake resources, deep recursive fake structures,
// token-maximizing bait. Aggressive-capable but operator-elective; the default
// floor is conservative. Every generator MUST bound its own resource use. See
// docs/STING.md.
package attrition

import "github.com/canarysting/canarysting/internal/contract"

// Budget bounds the sting's own cost so attrition burns the attacker, not the
// defender. Every generator respects it.
type Budget struct {
	MaxBytesPerFlow int64
	MaxDepth        int
	MaxDuration     int64 // seconds
	GlobalCeiling   int64 // host-wide cap across all flows
}

// Attritor serves adversarial responses up to the operator's floor.
type Attritor interface {
	// Respond produces the next adversarial response for a flow, within floor
	// and budget. Returns a signal to stop when budget is exhausted.
	Respond(contract.Verdict, contract.StingFloor, Budget) ([]byte, bool, error)
}

// TODO: implement tarpit + bounded fake-structure generators; never make
// FloorAggressive a silent default; honor the global ceiling and a kill switch.
