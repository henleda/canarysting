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
// The scope is taken from the event if the adapter already resolved it; else the
// engine resolves it. For async tiers the verdict is advisory to the adapter and
// the authoritative enforcement is programmed into the kernel out of band.
func (s *Service) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	scopeKey := ev.Scope
	if scopeKey == "" {
		k, err := s.cfg.Resolver.Resolve(ev.Flow)
		if err != nil {
			return contract.Verdict{}, err
		}
		scopeKey = k
	}

	score, err := s.cfg.Scorer.Score(scopeKey, ev)
	if err != nil {
		return contract.Verdict{}, err
	}

	tier, mode, err := s.cfg.Decider.Decide(scopeKey, score, s.cfg.Tiers)
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
