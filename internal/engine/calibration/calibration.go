// Package calibration turns feedback labels into calibrated per-scope canary
// weights. A single evidence floor gates the switch from uncalibrated (uniform
// weights, score = raw count) to calibrated (learned weights) for ALL learned
// parameters of a scope at once. Once calibrated, the live weight is the product
// of two separated factors (Option Y, docs/DECOY_WEIGHTS.md): a PERSISTENT,
// mean-centered intent strength from the seed ordering (docs/CANARY.md) and a
// LEARNED per-scope maliciousness factor calibrated by this scope's feedback.
// Centering intent on 1.0 preserves the average weight, so the tier thresholds
// tuned against it still hold. Learned state is per scope and NEVER aggregates
// across scopes. See docs/ENGINE.md and docs/SCOPE.md.
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
// MaxWeight is raised 2.0 -> 3.0 for the intent x maliciousness model so a
// high-intent decoy can sit above a low-intent one at full maliciousness
// (max intentNorm 1.36 x malFactor 2.0 = 2.73). See docs/DECOY_WEIGHTS.md.
const (
	defaultMinWeight = 0.1
	defaultMaxWeight = 3.0
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
	// MinWeight, MaxWeight clamp learned weights. Default 0.1 / 3.0.
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
	mu  sync.Mutex
	cfg Config
	// meanSeed is the arithmetic mean of the CONFIGURED cfg.SeedWeights values
	// (NOT the 1.0 default for unconfigured types). It centers intentNorm on 1.0
	// so the AVERAGE decoy weight is preserved. Computed once at construction; if
	// no seed weights are configured it is 1.0, making intentNorm a no-op.
	meanSeed float64
	scopes   map[contract.ScopeKey]*scopeState
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
	// Mean of the CONFIGURED seed weights only (not the 1.0 default), so
	// intentNorm = seed/meanSeed is centered on 1.0 across the catalog. Empty or
	// non-positive -> 1.0 so intentNorm is a no-op (back-compat). See
	// docs/DECOY_WEIGHTS.md.
	meanSeed := 1.0
	if n := len(cfg.SeedWeights); n > 0 {
		sum := 0.0
		for _, w := range cfg.SeedWeights {
			sum += w
		}
		if m := sum / float64(n); m > 0 {
			meanSeed = m
		}
	}
	return &Store{cfg: cfg, meanSeed: meanSeed, scopes: map[contract.ScopeKey]*scopeState{}}
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

// Weight returns the live weight for a canary type in a scope under the
// intent x maliciousness model (Option Y, docs/DECOY_WEIGHTS.md).
//
// Below the evidence floor it returns the uniform weight 1.0 — so the score is a
// raw count of distinct touches (the cold-start behavior, by construction).
// Severity applies only once a scope is calibrated.
//
// At or above the floor the weight separates the two things the old "2p" weight
// conflated and multiplies them:
//
//	weight = clamp( intentNorm(ct) x malFactor(ct, scope), MinWeight, MaxWeight )
//
//	intentNorm(ct)  = seed(ct) / meanSeed     PERSISTENT relative intent strength,
//	                  centered on 1.0 so the AVERAGE decoy is unchanged (preserving
//	                  the scoring scale and the tier thresholds tuned against it).
//	malFactor       = 2 * q, q = (mal+0.5)/(mal+ben+1)   LEARNED maliciousness in
//	                  THIS scope with a neutral Jeffreys prior: no evidence -> 1.0,
//	                  confirmed-malicious -> 2.0, confirmed-FP -> 0.
//
// The result is clamped to [MinWeight, MaxWeight]. Implements scoring.Weights.
func (s *Store) Weight(scope contract.ScopeKey, ct contract.CanaryType) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.scopes[scope]
	if st == nil || st.total < s.cfg.EvidenceFloor {
		return 1.0 // uniform: score == raw count of distinct touches
	}
	c := st.counts[ct]
	// Learned maliciousness with a neutral Jeffreys prior (0.5): q in (0,1),
	// malFactor = 2q maps neutral 0.5 -> 1.0, all-malicious -> 2.0, all-FP -> 0.
	q := (float64(c.mal) + 0.5) / (float64(c.mal+c.ben) + 1.0)
	malFactor := 2 * q
	// Multiply in the persistent, mean-centered intent strength.
	w := s.intentNorm(ct) * malFactor
	if w < s.cfg.MinWeight {
		w = s.cfg.MinWeight
	}
	if w > s.cfg.MaxWeight {
		w = s.cfg.MaxWeight
	}
	return w
}

// intentNorm returns the type's relative intent strength, seed(ct) normalized by
// the mean of the configured seed weights, so it is centered on 1.0 across the
// catalog. With no seed weights configured meanSeed is 1.0 and this reduces to
// seed(ct) (a no-op when seeds are absent). See docs/DECOY_WEIGHTS.md.
func (s *Store) intentNorm(ct contract.CanaryType) float64 {
	return s.seed(ct) / s.meanSeed
}

// seed returns the cold-start intent-strength prior for a canary type
// (docs/CANARY.md). A type with no seed configured priors at the neutral 1.0. In
// the intent x maliciousness model this is the raw, un-normalized intent that
// intentNorm centers on 1.0; it no longer acts as a Beta pseudo-count.
func (s *Store) seed(ct contract.CanaryType) float64 {
	if w, ok := s.cfg.SeedWeights[ct]; ok && w > 0 {
		return w
	}
	return 1.0
}
