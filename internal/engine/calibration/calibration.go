// Package calibration turns feedback labels into calibrated thresholds and
// per-scope canary weights. A single evidence floor gates the switch from
// uncalibrated (uniform weights, static thresholds) to calibrated for ALL
// learned parameters. The seed prior is overridden once calibrated. See
// docs/ENGINE.md.
package calibration

import "github.com/canarysting/canarysting/internal/contract"

// State reports a scope's calibration status, surfaced to operators.
type State struct {
	Calibrated   bool
	EvidenceSeen int
	EvidenceFloor int
}

// Calibrator consumes labels and produces thresholds and weights per scope.
type Calibrator interface {
	// Ingest records a label and updates learned state for its scope only.
	Ingest(contract.FeedbackLabel) error
	// State returns the calibration status for a scope.
	State(contract.ScopeKey) State
}

// TODO: hold uniform weights + static thresholds below the floor; learn
// per-scope weights above it; never aggregate labels across scopes.
