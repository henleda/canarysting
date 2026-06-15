package calibration

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
)

func label(scope contract.ScopeKey, malicious bool, canaries ...contract.CanaryType) contract.FeedbackLabel {
	return contract.FeedbackLabel{Scope: scope, WasMalicious: malicious, CanariesTouched: canaries}
}

// catalogSeeds mirrors the five shipped catalog SeedWeights (intent ordering,
// docs/CANARY.md). The calibration package cannot import the catalog (the
// import-graph test forbids it), so the values are duplicated here. mean = 1.32.
var catalogSeeds = map[contract.CanaryType]float64{
	"planted_credential": 1.8,
	"fake_secret":        1.5,
	"decoy_file":         1.2,
	"fake_bucket":        1.1,
	"fake_endpoint":      1.0,
}

func TestWeight_UniformBelowFloor(t *testing.T) {
	// Cold start applies even with seed weights configured: severity only kicks
	// in once calibrated. Every type reads the uniform raw-count weight 1.0.
	c := New(Config{EvidenceFloor: 3, SeedWeights: catalogSeeds})
	// Two labels (below the floor of 3): still cold start, uniform weight.
	c.Ingest(label("s", true, "planted_credential"))
	c.Ingest(label("s", true, "fake_endpoint"))
	for ct := range catalogSeeds {
		if w := c.Weight("s", ct); w != 1.0 {
			t.Fatalf("below floor must be uniform 1.0 for %q, got %.3f", ct, w)
		}
	}
	if st := c.State("s"); st.Calibrated {
		t.Fatal("must report uncalibrated below floor")
	}
}

func TestWeight_LearnedAboveFloor(t *testing.T) {
	// With no seed weights configured, intentNorm is a no-op (meanSeed=1.0), so
	// the weight is just the learned malFactor = 2*(mal+0.5)/(mal+ben+1).
	c := New(Config{EvidenceFloor: 3})
	// 3 malicious labels touching "hot"; 0 benign -> malFactor > 1.
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

// TestWeight_CalibratedAllMalicious_DifferentiatedByIntent is the key property:
// a calibrated all-malicious scope (the demo) yields per-type weights spread by
// intent (intentNorm x ~2.0) instead of all pinned at the ceiling, AND the mean
// of the five shipped types' weights is preserved at ~2.0 (so tier thresholds
// hold on average). See docs/DECOY_WEIGHTS.md.
func TestWeight_CalibratedAllMalicious_DifferentiatedByIntent(t *testing.T) {
	c := New(Config{EvidenceFloor: 50, SeedWeights: catalogSeeds})
	// All-malicious (ben=0), plentiful evidence: malFactor -> ~2.0 for every type.
	types := []contract.CanaryType{
		"planted_credential", "fake_secret", "decoy_file", "fake_bucket", "fake_endpoint",
	}
	for i := 0; i < 200; i++ {
		c.Ingest(label("s", true, types...))
	}
	if st := c.State("s"); !st.Calibrated {
		t.Fatalf("must be calibrated: %+v", st)
	}

	cred := c.Weight("s", "planted_credential")
	endpoint := c.Weight("s", "fake_endpoint")
	// Differentiated by intent: the crown-jewel decoy outweighs the static one.
	if !(cred > endpoint) {
		t.Fatalf("credential weight (%.3f) must exceed endpoint weight (%.3f)", cred, endpoint)
	}
	// Not pinned uniformly at the ceiling: there is real spread.
	if cred-endpoint < 0.5 {
		t.Fatalf("weights should be spread by intent, got cred=%.3f endpoint=%.3f", cred, endpoint)
	}

	// Mean-preservation: the mean of the five shipped types' weights ~= 2.0.
	sum := 0.0
	for _, ct := range types {
		sum += c.Weight("s", ct)
	}
	mean := sum / float64(len(types))
	if mean < 1.95 || mean > 2.05 {
		t.Fatalf("mean of shipped weights must be preserved at ~2.0, got %.4f", mean)
	}
}

// TestWeight_FPHeavySuppressedBelowIntent: with more benign than malicious
// labels for a type, malFactor < 1, so the weight is pushed BELOW its bare
// intentNorm. See docs/DECOY_WEIGHTS.md.
func TestWeight_FPHeavySuppressedBelowIntent(t *testing.T) {
	c := New(Config{EvidenceFloor: 5, SeedWeights: catalogSeeds})
	// 3 malicious, 7 benign for fake_secret -> q=(3+0.5)/(10+1)=0.318, malFactor=0.636.
	for i := 0; i < 3; i++ {
		c.Ingest(label("s", true, "fake_secret"))
	}
	for i := 0; i < 7; i++ {
		c.Ingest(label("s", false, "fake_secret"))
	}
	w := c.Weight("s", "fake_secret")
	intentNorm := c.intentNorm("fake_secret")
	if !(w < intentNorm) {
		t.Fatalf("FP-heavy weight (%.3f) must be below bare intentNorm (%.3f)", w, intentNorm)
	}
}

func TestWeight_RespectsClamp(t *testing.T) {
	// Upper clamp: all-malicious, high-intent type, low MaxWeight.
	c := New(Config{EvidenceFloor: 1, MinWeight: 0.2, MaxWeight: 1.5, SeedWeights: catalogSeeds})
	for i := 0; i < 50; i++ {
		c.Ingest(label("s", true, "planted_credential"))
	}
	if w := c.Weight("s", "planted_credential"); w > 1.5 {
		t.Fatalf("weight exceeded MaxWeight clamp: %.3f", w)
	}
	// Lower clamp: all false-positive, low-intent type drives malFactor toward 0.
	c2 := New(Config{EvidenceFloor: 1, MinWeight: 0.2, MaxWeight: 1.5, SeedWeights: catalogSeeds})
	for i := 0; i < 50; i++ {
		c2.Ingest(label("s", false, "fake_endpoint"))
	}
	if w := c2.Weight("s", "fake_endpoint"); w < 0.2 {
		t.Fatalf("weight fell below MinWeight clamp: %.3f", w)
	}
}

// TestWeight_DefaultMaxWeightIsThree confirms the raised default clamp lets a
// high-intent decoy at full maliciousness sit above 2.0 (1.36 x 2.0 = 2.73).
func TestWeight_DefaultMaxWeightIsThree(t *testing.T) {
	c := New(Config{EvidenceFloor: 50, SeedWeights: catalogSeeds})
	for i := 0; i < 200; i++ {
		c.Ingest(label("s", true, "planted_credential"))
	}
	w := c.Weight("s", "planted_credential")
	if w <= 2.0 {
		t.Fatalf("default MaxWeight 3.0 should allow high-intent weight > 2.0, got %.3f", w)
	}
	if w > 3.0 {
		t.Fatalf("weight must not exceed default MaxWeight 3.0, got %.3f", w)
	}
}

// TestWeight_EmptySeedsBackCompat: with no SeedWeights, intentNorm is a no-op
// (meanSeed=1.0) and the weight equals the bare malFactor.
func TestWeight_EmptySeedsBackCompat(t *testing.T) {
	c := New(Config{EvidenceFloor: 3})
	// 3 malicious, 1 benign -> q=(3+0.5)/(4+1)=0.7, malFactor=1.4.
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", true, "hot"))
	c.Ingest(label("s", false, "hot"))
	want := 1.4
	if w := c.Weight("s", "hot"); w < want-1e-9 || w > want+1e-9 {
		t.Fatalf("empty seeds: weight should equal malFactor %.3f, got %.3f", want, w)
	}
	if got := c.intentNorm("hot"); got != 1.0 {
		t.Fatalf("empty seeds: intentNorm must be 1.0 no-op, got %.3f", got)
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
