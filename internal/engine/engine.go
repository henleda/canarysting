// Package engine composes the decision engine: it resolves a flow's scope,
// scores the flow, decides a tier and enforcement mode, and reports calibration
// status — emitting one verdict per signal event. It implements contract.Engine
// and is proxy-agnostic: it talks only to internal/contract and its own
// subpackages, never to an adapter or a proxy SDK. See docs/ENGINE.md.
package engine

import (
	"errors"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
)

// Config wires the engine's collaborators. Resolver, Scorer, and Decider are
// required. Calibration is optional but, when present, supplies the Calibrated
// flag on each verdict (and is normally the Weights source behind Scorer).
type Config struct {
	Resolver    scope.Resolver
	Scorer      scoring.Scorer
	Decider     tiers.Decider
	Tiers       tiers.Config
	Calibration calibration.Calibrator
	// TierDepthMultiplier, when non-nil, un-inflates the score by the baseline
	// multiplier M for the TIER decision ONLY, so the tier reflects depth of
	// interaction (the touch-count base B) rather than B×M. Verdict.Score still
	// carries the full B×M, so the live M stays visible to the dashboard. This is
	// wired ONLY for the DEMO-ONLY escalation band (-demo-escalation): that band's
	// graduated Tag→Contain→Jail thresholds are expressed in touch units and would
	// otherwise collapse once M goes live (a live M ≈2.5 makes a single touch's
	// score vault past the higher thresholds, forcing straight-to-jail). nil in
	// production — tiering uses the full score, unchanged.
	TierDepthMultiplier scoring.MultiplierSource
}

// Service is the concrete contract.Engine.
type Service struct {
	cfg Config
}

// New validates the configuration and returns a Service. It refuses to start —
// returning the resolver's error (e.g. scope.ErrUnresolved) — if the scope
// resolver cannot resolve any scope, rather than ever defaulting to a global
// scope. It also validates the tier config up front so a bad strictness/mode
// config fails at startup, not on the first request.
func New(cfg Config) (*Service, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("engine: nil scope resolver")
	}
	if cfg.Scorer == nil {
		return nil, errors.New("engine: nil scorer")
	}
	if cfg.Decider == nil {
		return nil, errors.New("engine: nil decider")
	}
	// Refuse to start if the resolver could never resolve a scope.
	if v, ok := cfg.Resolver.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return nil, err
		}
	}
	if err := cfg.Tiers.Validate(); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg}, nil
}

// Submit ingests a signal event and returns the current verdict for the flow.
//
// SCOPE IS RESOLVED, NEVER TRUSTED FROM THE WIRE. The engine derives the scope
// from the flow via its own resolver — the single authority on scope mapping
// (docs/SCOPE.md: "Other packages ask it for the scope key; they do not re-derive
// it"). A wire-supplied ev.Scope is only ever an echo/optimization and is NOT
// honored verbatim: if it disagrees with the resolved scope the RESOLVED scope
// wins. This closes the B1 forge: a caller that reaches the gRPC surface cannot
// pick an arbitrary scope (e.g. a victim deployment's) to drive learned-state
// writes or a kernel jail on the wrong scope. Trusting the wire scope would also
// violate rule 5 (scope isolation), since a forged scope is a cross-boundary
// write. For async tiers the verdict is advisory to the adapter and the
// authoritative enforcement is programmed into the kernel out of band.
func (s *Service) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	scopeKey, err := s.cfg.Resolver.Resolve(ev.Flow)
	if err != nil {
		return contract.Verdict{}, err
	}
	// A non-empty wire scope that disagrees with what the resolver derived is a
	// forged or stale claim; ignore it and use the resolved scope. (We do not error
	// out: the resolver is authoritative, so honoring it is always the safe action.)

	score, err := s.cfg.Scorer.Score(scopeKey, ev)
	if err != nil {
		return contract.Verdict{}, err
	}

	// The tier is decided on depth-of-interaction. Normally that is the score
	// itself; under the demo-escalation band (TierDepthMultiplier wired) we divide
	// out the baseline multiplier M so a live M cannot compress the graduated
	// Tag→Contain→Jail climb (its thresholds are in touch units). Verdict.Score
	// below is unchanged (full B×M), so the live M stays visible. M is floored at 1
	// (docs/BASELINE_MULTIPLIER.md), so this never inflates the tier input.
	tierInput := score
	if s.cfg.TierDepthMultiplier != nil {
		if m := s.cfg.TierDepthMultiplier.Multiplier(scopeKey, ev.Flow, ev.Timestamp); m >= 1 {
			tierInput = score / m
		}
	}

	tier, mode, err := s.cfg.Decider.Decide(scopeKey, tierInput, s.cfg.Tiers)
	if err != nil {
		return contract.Verdict{}, err
	}

	calibrated := false
	if s.cfg.Calibration != nil {
		calibrated = s.cfg.Calibration.State(scopeKey).Calibrated
	}

	return contract.Verdict{
		Flow:       ev.Flow,
		Scope:      scopeKey,
		Tier:       tier,
		Mode:       mode,
		Score:      score,
		Calibrated: calibrated,
	}, nil
}

// Ensure Service satisfies the contract.
var _ contract.Engine = (*Service)(nil)
