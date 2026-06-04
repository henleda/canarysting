// Package tiers maps a suspicion score plus operator config to a response tier
// and an enforcement mode. Tier 0-1 are async-only; Tier 2-3 are operator-
// chosen inline/async. Async must enforce in the kernel. Strictness is per-tier.
// See docs/ENGINE.md.
package tiers

import "github.com/canarysting/canarysting/internal/contract"

// Config carries per-tier strictness and the inline/async choice for 2-3.
type Config struct {
	// ConfidenceRequired is the per-tier strictness, 0.01 (permissive) to 1.00
	// (strict). It expresses a target false-positive rate. Higher = stricter.
	ConfidenceRequired map[contract.Tier]float64
	// Mode for tiers 2 and 3. Tiers 0-1 are always async regardless.
	Mode map[contract.Tier]contract.EnforcementMode
	// FailClosed per tier for inline mode. Tier 1 fail-open, Tier 3 fail-closed.
	FailClosed map[contract.Tier]bool
}

// Decide returns the tier and mode for a score in a scope.
type Decider interface {
	Decide(scope contract.ScopeKey, score float64, cfg Config) (contract.Tier, contract.EnforcementMode, error)
}

// TODO: pull thresholds from calibration (calibrated mode) or the documented
// static map (uncalibrated mode); enforce the async-only rule for 0-1; reject
// async + proxy-only enforcement for 2-3.
