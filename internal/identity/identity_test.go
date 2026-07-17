package identity

import "testing"

func TestConfidenceOrdering(t *testing.T) {
	// Higher confidence must be strictly greater so callers can compare and so a
	// verified identity always wins over an asserted one.
	if !(ConfidenceVerified > ConfidenceAsserted && ConfidenceAsserted > ConfidenceNone) {
		t.Fatalf("confidence not strictly ordered: none=%d asserted=%d verified=%d",
			ConfidenceNone, ConfidenceAsserted, ConfidenceVerified)
	}
}

func TestConfidenceString(t *testing.T) {
	for c, want := range map[Confidence]string{
		ConfidenceNone:     "none",
		ConfidenceAsserted: "asserted",
		ConfidenceVerified: "verified",
		Confidence(99):     "none",
	} {
		if got := c.String(); got != want {
			t.Errorf("Confidence(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestWorkloadIDEmpty(t *testing.T) {
	if !(WorkloadID{}).Empty() {
		t.Error("zero WorkloadID must be Empty")
	}
	// A resolved identity (any non-None confidence) is not empty, even if the
	// descriptive fields are sparse.
	if (WorkloadID{Confidence: ConfidenceAsserted}).Empty() {
		t.Error("asserted identity must not be Empty")
	}
	if (WorkloadID{TrustDomain: "cluster.local", Confidence: ConfidenceVerified}).Empty() {
		t.Error("verified identity must not be Empty")
	}
}
