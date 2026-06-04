// Package scoring computes a flow's suspicion score: one windowed, weighted
// function over distinct canary interactions within a scope. Weights start
// uniform (raw count) and are learned per scope by calibration. There is no
// separate "count mode" — uniform weights ARE the count. See docs/ENGINE.md.
package scoring

import (
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

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

// TODO: implement the windowed weighted sum; load weights from calibration;
// apply the benign-exclusion input as a first-class, configurable filter.
