// Package feedback is the single intake for analyst labels confirming whether a
// Tier 2/3 action was correct. It is the only calibration signal feeding both
// strictness thresholds and canary weights. See docs/ENGINE.md.
package feedback

import (
	"errors"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/calibration"
)

// Intake implements contract.FeedbackSink and routes labels to calibration, per
// scope. It is the single seam through which analyst confirmations enter the
// engine — there is no other calibration signal.
type Intake struct {
	calib calibration.Calibrator
}

// NewIntake wires the intake to a calibrator. The calibrator must be non-nil.
func NewIntake(calib calibration.Calibrator) *Intake {
	return &Intake{calib: calib}
}

// Label records an analyst confirmation and forwards it to the scope's
// calibrator. A label with no scope is rejected — feedback must never be
// attributed to a guessed scope (docs/SCOPE.md). Implements contract.FeedbackSink.
func (i *Intake) Label(l contract.FeedbackLabel) error {
	if i.calib == nil {
		return errors.New("feedback: no calibrator wired")
	}
	if l.Scope == "" {
		return errors.New("feedback: label missing scope; refusing to attribute")
	}
	return i.calib.Ingest(l)
}

// Ensure Intake satisfies the contract.
var _ contract.FeedbackSink = (*Intake)(nil)
