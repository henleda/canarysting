// Package calibration turns feedback labels into calibrated per-scope canary
// weights. A single evidence floor gates the switch from uncalibrated (uniform
// weights, score = raw count) to calibrated (learned weights) for ALL learned
// parameters of a scope at once. The seed intent-strength prior (docs/CANARY.md)
// regularizes the learned weight and is overridden as evidence accrues. Learned
// state is per scope and NEVER aggregates across scopes. See docs/ENGINE.md and
// docs/SCOPE.md.
package calibration

import (
	"errors"
	"sync"

	"github.com/canarysting/canarysting/internal/contract"
)

// DefaultEvidenceFloor is the documented uncalibrated default: the number of
// confirmed analyst labels a scope must accrue before it leaves cold start.
// Below it, the scope uses uniform weights (raw-count scoring) and static
// thresholds, and reports Calibrated=false. Operators may tune it; the finer a
// scope is sliced the longer it sits below the floor (docs/SCOPE.md).
const DefaultEvidenceFloor = 50

// weight clamp for learned weights. A neutral canary type calibrates to ~1.0;
// the clamp keeps a single noisy type from dominating or vanishing the score.
const (
	defaultMinWeight = 0.1
	defaultMaxWeight = 2.0
)

// State reports a scope's calibration status, surfaced to operators.
type State struct {
	Calibrated    bool
	EvidenceSeen  int
	EvidenceFloor int
}

// Calibrator consumes labels and reports calibration status per scope.
type Calibrator interface {
	// Ingest records a label and updates learned state for its scope only.
	Ingest(contract.FeedbackLabel) error
	// State returns the calibration status for a scope.
	State(contract.ScopeKey) State
}

// Config tunes a Store. Zero values fall back to documented defaults.
type Config struct {
	// EvidenceFloor gates uncalibrated->calibrated. Defaults to DefaultEvidenceFloor.
	EvidenceFloor int
	// SeedWeights is the cold-start intent-strength prior per canary type
	// (docs/CANARY.md). It is static config, NOT learned state, and is never
	// written back per scope. Missing types default to a neutral prior (1.0).
	SeedWeights map[contract.CanaryType]float64
	// MinWeight, MaxWeight clamp learned weights. Default 0.1 / 2.0.
	MinWeight, MaxWeight float64
}

type canaryCounts struct{ mal, ben int }

type scopeState struct {
	total  int
	counts map[contract.CanaryType]canaryCounts
}

// Store is the in-memory, per-scope implementation of Calibrator. It also
// satisfies scoring.Weights via Weight. All access is mutex-guarded so the
// engine can call it concurrently with feedback intake.
type Store struct {
	mu     sync.Mutex
	cfg    Config
	scopes map[contract.ScopeKey]*scopeState
}

// New returns a Store with documented defaults filled in.
func New(cfg Config) *Store {
	if cfg.EvidenceFloor <= 0 {
		cfg.EvidenceFloor = DefaultEvidenceFloor
	}
	if cfg.MinWeight <= 0 {
		cfg.MinWeight = defaultMinWeight
	}
	if cfg.MaxWeight <= 0 {
		cfg.MaxWeight = defaultMaxWeight
	}
	return &Store{cfg: cfg, scopes: map[contract.ScopeKey]*scopeState{}}
}

// Ingest records one analyst label against its scope only. A label with no
// scope is rejected — calibration must never guess a scope. See docs/SCOPE.md.
func (s *Store) Ingest(l contract.FeedbackLabel) error {
	if l.Scope == "" {
		return errors.New("calibration: label has no scope; refusing to aggregate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.scopes[l.Scope]
	if st == nil {
		st = &scopeState{counts: map[contract.CanaryType]canaryCounts{}}
		s.scopes[l.Scope] = st
	}
	st.total++
	for _, ct := range l.CanariesTouched {
		c := st.counts[ct]
		if l.WasMalicious {
			c.mal++
		} else {
			c.ben++
		}
		st.counts[ct] = c
	}
	return nil
}

// State returns the calibration status for a scope.
func (s *Store) State(scope contract.ScopeKey) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := 0
	if st := s.scopes[scope]; st != nil {
		seen = st.total
	}
	return State{
		Calibrated:    seen >= s.cfg.EvidenceFloor,
		EvidenceSeen:  seen,
		EvidenceFloor: s.cfg.EvidenceFloor,
	}
}

// Weight returns the live weight for a canary type in a scope. Below the
// evidence floor it returns the uniform weight 1.0 — so the score is a raw count
// of distinct touches (the cold-start behavior, by construction). At or above
// the floor it returns a learned weight: a smoothed estimate of how strongly the
// type predicts a confirmed-malicious flow in THIS scope, regularized by the
// seed prior and clamped. Implements scoring.Weights.
func (s *Store) Weight(scope contract.ScopeKey, ct contract.CanaryType) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.scopes[scope]
	if st == nil || st.total < s.cfg.EvidenceFloor {
		return 1.0 // uniform: score == raw count of distinct touches
	}
	c := st.counts[ct]
	// Beta-style smoothing with the seed prior as pseudo-counts: a high-seed
	// (high intent-strength) type starts above neutral and is pulled by evidence;
	// a type confirmed malicious earns weight > 1, one seen in false positives
	// earns weight < 1. p in (0,1); weight = 2p maps neutral 0.5 -> 1.0.
	a0 := s.seed(ct) // prior "malicious" pseudo-count
	const b0 = 1.0   // prior "benign" pseudo-count
	p := (float64(c.mal) + a0) / (float64(c.mal+c.ben) + a0 + b0)
	w := 2 * p
	if w < s.cfg.MinWeight {
		w = s.cfg.MinWeight
	}
	if w > s.cfg.MaxWeight {
		w = s.cfg.MaxWeight
	}
	return w
}

// seed returns the cold-start prior pseudo-count for a canary type. A neutral
// type (no seed configured) priors at 1.0, giving p=0.5 -> weight 1.0 before any
// evidence — i.e. calibrated mode starts where cold start left off and diverges
// on this scope's own feedback.
func (s *Store) seed(ct contract.CanaryType) float64 {
	if w, ok := s.cfg.SeedWeights[ct]; ok && w > 0 {
		return w
	}
	return 1.0
}
