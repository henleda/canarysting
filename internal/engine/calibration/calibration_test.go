package calibration

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
)

func label(scope contract.ScopeKey, malicious bool, canaries ...contract.CanaryType) contract.FeedbackLabel {
	return contract.FeedbackLabel{Scope: scope, WasMalicious: malicious, CanariesTouched: canaries}
}

func TestWeight_UniformBelowFloor(t *testing.T) {
	c := New(Config{EvidenceFloor: 3})
	// Two labels (below the floor of 3): still cold start, uniform weight.
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", true, "hot"))
	if w := c.Weight("s", "hot"); w != 1.0 {
		t.Fatalf("below floor must be uniform 1.0, got %.3f", w)
	}
	if st := c.State("s"); st.Calibrated {
		t.Fatal("must report uncalibrated below floor")
	}
}

func TestWeight_LearnedAboveFloor(t *testing.T) {
	c := New(Config{EvidenceFloor: 3})
	// 3 malicious labels touching "hot"; 0 benign -> weight should rise above 1.
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", true, "hot"))
	if st := c.State("s"); !st.Calibrated {
		t.Fatalf("must be calibrated at the floor: %+v", st)
	}
	if w := c.Weight("s", "hot"); w <= 1.0 {
		t.Fatalf("malicious-correlated type must earn weight > 1, got %.3f", w)
	}
	// A type seen only in false positives must earn weight < 1.
	c2 := New(Config{EvidenceFloor: 3})
	c2.Ingest(label("s", false, "cold"))
	c2.Ingest(label("s", false, "cold"))
	c2.Ingest(label("s", false, "cold"))
	if w := c2.Weight("s", "cold"); w >= 1.0 {
		t.Fatalf("false-positive type must earn weight < 1, got %.3f", w)
	}
}

func TestWeight_RespectsClamp(t *testing.T) {
	c := New(Config{EvidenceFloor: 1, MinWeight: 0.2, MaxWeight: 1.5})
	for i := 0; i < 50; i++ {
		c.Ingest(label("s", true, "hot"))
	}
	if w := c.Weight("s", "hot"); w > 1.5 {
		t.Fatalf("weight exceeded MaxWeight clamp: %.3f", w)
	}
}

func TestSeedPriorBiasesUnlabeledTypeWhenCalibrated(t *testing.T) {
	// A high-seed type, with the scope calibrated but no evidence for that type,
	// should prior above neutral (the seed ordering as prior).
	c := New(Config{EvidenceFloor: 1, SeedWeights: map[contract.CanaryType]float64{"strong": 4.0}})
	c.Ingest(label("s", true, "other")) // crosses the floor
	if w := c.Weight("s", "strong"); w <= 1.0 {
		t.Fatalf("seed prior should bias unlabeled strong type above 1.0, got %.3f", w)
	}
}

func TestCrossScopeIsolation(t *testing.T) {
	c := New(Config{EvidenceFloor: 2})
	c.Ingest(label("scope-a", true, "hot"))
	c.Ingest(label("scope-a", true, "hot"))
	// scope-b saw nothing: must be uncalibrated and uniform.
	if st := c.State("scope-b"); st.Calibrated || st.EvidenceSeen != 0 {
		t.Fatalf("scope-b leaked scope-a evidence: %+v", st)
	}
	if w := c.Weight("scope-b", "hot"); w != 1.0 {
		t.Fatalf("scope-b weight leaked from scope-a: %.3f", w)
	}
}

func TestIngest_RejectsMissingScope(t *testing.T) {
	c := New(Config{})
	if err := c.Ingest(label("", true, "hot")); err == nil {
		t.Fatal("label with no scope must be rejected, never aggregated")
	}
}

func TestState_ReportsEvidenceAndFloor(t *testing.T) {
	c := New(Config{EvidenceFloor: 5})
	c.Ingest(label("s", true, "hot"))
	st := c.State("s")
	if st.EvidenceSeen != 1 || st.EvidenceFloor != 5 || st.Calibrated {
		t.Fatalf("unexpected state: %+v", st)
	}
}
