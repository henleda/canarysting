// Package scoring computes a flow's suspicion score: one windowed, weighted
// function over distinct canary interactions within a scope. Weights start
// uniform (raw count) and are learned per scope by calibration. There is no
// separate "count mode" — uniform weights ARE the count. See docs/ENGINE.md.
package scoring

import (
	"errors"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// DefaultWindow is the correlation window default (a few minutes), per
// docs/ENGINE.md: repeated touches inside it count more than the same touches
// spread over hours.
const DefaultWindow = 5 * time.Minute

// Window is the correlation window; repeated touches inside it count more than
// the same touches spread over hours. Default to a few minutes via config.
type Window struct {
	Duration time.Duration
}

// Scorer holds per-scope weights and computes scores. All state is scope-keyed;
// nothing is shared across scopes. See docs/SCOPE.md.
type Scorer interface {
	// Score returns the current suspicion score for a flow in a scope, given a
	// new event. Implementations apply benign-exclusion before scoring.
	Score(scope contract.ScopeKey, ev contract.SignalEvent) (float64, error)
}

// Weights supplies the live per-scope weight for a canary type. It is satisfied
// by calibration.Store: uniform 1.0 in cold start, learned once calibrated. The
// scorer does not know or care whether a weight is uniform or learned — that
// keeps the "one weighted model whose weights evolve" rule (docs/ENGINE.md).
type Weights interface {
	Weight(contract.ScopeKey, contract.CanaryType) float64
}

// BenignExcluder is the first-class benign-exclusion input. Excluded flows
// (service accounts, monitoring, scheduled tasks) never accrue score, so a
// benign brush of a canary never escalates them. Exclusion is explicit and
// configurable, never buried in scoring internals. See docs/ENGINE.md.
type BenignExcluder interface {
	Excluded(contract.FlowIdentity) bool
}

// NoExclusions excludes nothing. It is the explicit default.
type NoExclusions struct{}

// Excluded always returns false.
func (NoExclusions) Excluded(contract.FlowIdentity) bool { return false }

// WindowedScorer is the windowed weighted-sum Scorer. For each (scope, flow) it
// remembers the last touch time of each distinct canary type and, at score time,
// sums the weights of the types touched within the trailing window. A type
// touched repeatedly counts once (distinct), but keeps the flow's score alive
// while touches stay inside the window.
//
// A flow is keyed by its socket cookie (docs/IDENTITY.md) — the cross-boundary
// join key. A real flow always carries a non-zero cookie once the kernel join
// (M5) is in place; pure-Go tests set explicit cookies.
type WindowedScorer struct {
	mu       sync.Mutex
	window   time.Duration
	weights  Weights
	excluder BenignExcluder
	// state[scope][socketCookie][canaryType] = last touch time.
	state map[contract.ScopeKey]map[uint64]map[contract.CanaryType]time.Time
}

// New returns a WindowedScorer. A zero window falls back to DefaultWindow; a nil
// excluder falls back to NoExclusions. weights is required.
func New(window time.Duration, weights Weights, excluder BenignExcluder) *WindowedScorer {
	if window <= 0 {
		window = DefaultWindow
	}
	if excluder == nil {
		excluder = NoExclusions{}
	}
	return &WindowedScorer{
		window:   window,
		weights:  weights,
		excluder: excluder,
		state:    map[contract.ScopeKey]map[uint64]map[contract.CanaryType]time.Time{},
	}
}

// Score records the event's touch and returns the flow's current windowed,
// weighted score within the scope. Benign-excluded flows score 0 and accrue
// nothing. The score is always computed within a single scope, never across.
func (s *WindowedScorer) Score(scope contract.ScopeKey, ev contract.SignalEvent) (float64, error) {
	if scope == "" {
		return 0, errors.New("scoring: empty scope; resolve scope before scoring")
	}
	if s.weights == nil {
		return 0, errors.New("scoring: nil weights source")
	}
	// Benign exclusion is applied before scoring: an excluded flow never accrues.
	if s.excluder.Excluded(ev.Flow) {
		return 0, nil
	}

	key := ev.Flow.SocketCookie
	cutoff := ev.Timestamp.Add(-s.window)

	s.mu.Lock()
	defer s.mu.Unlock()

	byFlow := s.state[scope]
	if byFlow == nil {
		byFlow = map[uint64]map[contract.CanaryType]time.Time{}
		s.state[scope] = byFlow
	}
	touches := byFlow[key]
	if touches == nil {
		touches = map[contract.CanaryType]time.Time{}
		byFlow[key] = touches
	}
	touches[ev.Canary] = ev.Timestamp

	var sum float64
	for ct, last := range touches {
		if last.Before(cutoff) {
			delete(touches, ct) // expired out of the window; drop it
			continue
		}
		sum += s.weights.Weight(scope, ct)
	}
	return sum, nil
}
