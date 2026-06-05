package feedback

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/calibration"
)

func TestLabel_RoutesToCalibrator(t *testing.T) {
	calib := calibration.New(calibration.Config{EvidenceFloor: 1})
	in := NewIntake(calib)
	err := in.Label(contract.FeedbackLabel{
		Scope:           "scope",
		WasMalicious:    true,
		CanariesTouched: []contract.CanaryType{"hot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := calib.State("scope"); st.EvidenceSeen != 1 {
		t.Fatalf("label did not reach the calibrator: %+v", st)
	}
}

func TestLabel_RejectsMissingScope(t *testing.T) {
	in := NewIntake(calibration.New(calibration.Config{}))
	if err := in.Label(contract.FeedbackLabel{WasMalicious: true}); err == nil {
		t.Fatal("label with no scope must be rejected")
	}
}

func TestLabel_RejectsNilCalibrator(t *testing.T) {
	in := NewIntake(nil)
	if err := in.Label(contract.FeedbackLabel{Scope: "scope"}); err == nil {
		t.Fatal("intake with no calibrator must error")
	}
}
