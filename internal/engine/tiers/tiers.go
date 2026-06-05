// Package tiers maps a suspicion score plus operator config to a response tier
// and an enforcement mode. Tier 0-1 are async-only; Tier 2-3 are operator-
// chosen inline/async. Async must enforce in the kernel. Strictness is per-tier.
// See docs/ENGINE.md.
package tiers

import (
	"errors"
	"fmt"

	"github.com/canarysting/canarysting/internal/contract"
)

// Strictness bounds for the operator-facing confidence_required knob
// (docs/ENGINE.md "Strictness control"): 0.01 permissive .. 1.00 strict.
const (
	MinConfidence = 0.01
	MaxConfidence = 1.00
)

// Static uncalibrated threshold model (docs/ENGINE.md "Cold-start defaults",
// docs/ARCHITECTURE.md §8). In cold start the score is a raw count of distinct
// canary touches, so thresholds are expressed in that unit: depth of
// interaction. A tier's entry threshold is minTouches[t] + confidence*span[t],
// so the strictness knob slides each tier across the published lateral-movement
// FP band (permissive ~10% FP -> escalate on fewer touches; strict sub-1% ->
// require more). Higher tiers sit higher and are strict by construction.
var (
	minTouches = map[contract.Tier]float64{
		contract.TierTag:     1, // a second-ish distinct touch begins to tag
		contract.TierContain: 2,
		contract.TierJail:    3,
	}
	span = map[contract.Tier]float64{
		contract.TierTag:     1, // permissive 1 .. strict 2 distinct touches
		contract.TierContain: 2, // permissive 2 .. strict 4
		contract.TierJail:    3, // permissive 3 .. strict 6
	}
)

// actionTiers are the tiers whose enforcement mode the operator may choose.
// Tiers 0-1 are async-only and not operator-configurable.
var actionTiers = []contract.Tier{contract.TierContain, contract.TierJail}

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

// DefaultConfig is the documented conservative default: strictness rising with
// tier, both action tiers async (kernel-enforced) by default, and the mandated
// fail behavior (Tier 1 fail-open, Tiers 2-3 fail-closed).
func DefaultConfig() Config {
	return Config{
		ConfidenceRequired: map[contract.Tier]float64{
			contract.TierTag:     0.30,
			contract.TierContain: 0.50,
			contract.TierJail:    0.70,
		},
		Mode: map[contract.Tier]contract.EnforcementMode{
			contract.TierContain: contract.ModeAsync,
			contract.TierJail:    contract.ModeAsync,
		},
		FailClosed: map[contract.Tier]bool{
			contract.TierTag:     false, // fail-open
			contract.TierContain: true,  // fail-closed
			contract.TierJail:    true,  // fail-closed
		},
	}
}

// Validate enforces the invariants an operator config must satisfy. It encodes
// the async-only and fail-open/closed rules so they cannot be violated by
// configuration (docs/ENGINE.md).
func (c Config) Validate() error {
	for t, v := range c.ConfidenceRequired {
		if t < contract.TierTag || t > contract.TierJail {
			return fmt.Errorf("tiers: confidence_required set for non-thresholded tier %d", t)
		}
		if v < MinConfidence || v > MaxConfidence {
			return fmt.Errorf("tiers: confidence_required %.3f for tier %d out of [%.2f,%.2f]", v, t, MinConfidence, MaxConfidence)
		}
	}
	// Mode is operator-choosable only for the action tiers (2-3). A mode set for
	// tier 0 or 1 is the "async-only" rule being violated by config.
	for t := range c.Mode {
		if t != contract.TierContain && t != contract.TierJail {
			return fmt.Errorf("tiers: tier %d is async-only; its mode is not operator-configurable", t)
		}
	}
	// Mandated fail behavior: Tier 1 must fail-open, Tier 3 must fail-closed.
	if fc, ok := c.FailClosed[contract.TierTag]; ok && fc {
		return errors.New("tiers: Tier 1 must fail-open (a low-confidence tier must not block on engine outage)")
	}
	if fc, ok := c.FailClosed[contract.TierJail]; ok && !fc {
		return errors.New("tiers: Tier 3 must fail-closed (a confirmed tier must not release an actor on engine outage)")
	}
	return nil
}

// OnEngineUnavailable reports whether to ALLOW the flow when the engine is
// unavailable while deciding inline. Fail-open allows; fail-closed denies. Tiers
// 0-1 carry no inline enforcement, so they allow. This makes the fail behavior a
// tested property rather than an accident of timeout handling (docs/ENGINE.md).
func (c Config) OnEngineUnavailable(tier contract.Tier) (allow bool) {
	if tier <= contract.TierTag {
		return true
	}
	return !c.FailClosed[tier]
}

// Decide returns the tier and mode for a score in a scope.
type Decider interface {
	Decide(scope contract.ScopeKey, score float64, cfg Config) (contract.Tier, contract.EnforcementMode, error)
}

// StaticDecider maps a score to a tier using the documented static threshold
// model. (Calibrated mode reaches the engine through learned weights feeding the
// score, not through a different threshold curve; FP-target threshold solving is
// a later calibration increment — see docs/ENGINE.md "Implementation status".)
type StaticDecider struct{}

// Decide returns the highest tier whose threshold the score meets, and the
// enforcement mode for that tier. Thresholds are forced monotonic across tiers
// so a misordered strictness config can never make a higher tier easier to enter
// than a lower one.
func (StaticDecider) Decide(scope contract.ScopeKey, score float64, cfg Config) (contract.Tier, contract.EnforcementMode, error) {
	if err := cfg.Validate(); err != nil {
		return contract.TierObserve, contract.ModeAsync, err
	}
	const eps = 1e-9
	t1 := threshold(contract.TierTag, cfg)
	t2 := threshold(contract.TierContain, cfg)
	t3 := threshold(contract.TierJail, cfg)
	if t2 < t1+eps {
		t2 = t1 + eps
	}
	if t3 < t2+eps {
		t3 = t2 + eps
	}

	tier := contract.TierObserve
	switch {
	case score >= t3:
		tier = contract.TierJail
	case score >= t2:
		tier = contract.TierContain
	case score >= t1:
		tier = contract.TierTag
	}
	return tier, modeFor(tier, cfg), nil
}

// modeFor applies the async-only rule for tiers 0-1 and the operator choice for
// 2-3 (default async). Async enforcement is in the kernel; the downstream sting
// layer honors that — the engine never enforces at the proxy for an async tier.
func modeFor(tier contract.Tier, cfg Config) contract.EnforcementMode {
	if tier <= contract.TierTag {
		return contract.ModeAsync
	}
	if m, ok := cfg.Mode[tier]; ok {
		return m
	}
	return contract.ModeAsync
}

// threshold returns the static entry threshold for a tier given the config's
// per-tier confidence. Confidence is clamped to [MinConfidence, MaxConfidence].
func threshold(t contract.Tier, cfg Config) float64 {
	c := cfg.ConfidenceRequired[t]
	if c < MinConfidence {
		c = MinConfidence
	}
	if c > MaxConfidence {
		c = MaxConfidence
	}
	return minTouches[t] + c*span[t]
}
