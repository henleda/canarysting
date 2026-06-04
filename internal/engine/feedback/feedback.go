// Package feedback is the single intake for analyst labels confirming whether a
// Tier 2/3 action was correct. It is the only calibration signal feeding both
// strictness thresholds and canary weights. See docs/ENGINE.md.
package feedback

import "github.com/canarysting/canarysting/internal/contract"

// Intake implements contract.FeedbackSink and routes labels to calibration,
// per scope.
type Intake struct {
	// TODO: wire to calibration.Calibrator
}

// Label records an analyst confirmation. Implements contract.FeedbackSink.
func (i *Intake) Label(l contract.FeedbackLabel) error {
	_ = l
	// TODO: validate, persist, forward to the scope's calibrator
	return nil
}
