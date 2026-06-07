package envoy

import (
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/canarysting/canarysting/internal/contract"
)

func TestResponseForVerdict(t *testing.T) {
	cases := []struct {
		name      string
		tier      contract.Tier
		mode      contract.EnforcementMode
		immediate int // -1 means CONTINUE expected
	}{
		{"observe", contract.TierObserve, contract.ModeAsync, -1},
		{"tag", contract.TierTag, contract.ModeAsync, -1},
		{"contain-async", contract.TierContain, contract.ModeAsync, -1},
		{"contain-inline", contract.TierContain, contract.ModeInline, int(typev3.StatusCode_TooManyRequests)},
		{"jail-async", contract.TierJail, contract.ModeAsync, -1},
		{"jail-inline", contract.TierJail, contract.ModeInline, int(typev3.StatusCode_Forbidden)},
	}
	for _, tc := range cases {
		r := responseForVerdict(contract.Verdict{Tier: tc.tier, Mode: tc.mode})
		ir := r.GetImmediateResponse()
		if tc.immediate < 0 {
			if ir != nil {
				t.Fatalf("%s: expected CONTINUE, got immediate %d", tc.name, ir.GetStatus().GetCode())
			}
			if r.GetRequestHeaders() == nil {
				t.Fatalf("%s: expected a request-headers CONTINUE response", tc.name)
			}
			continue
		}
		if ir == nil || int(ir.GetStatus().GetCode()) != tc.immediate {
			t.Fatalf("%s: expected immediate %d, got %+v", tc.name, tc.immediate, r)
		}
		if len(ir.GetBody()) == 0 {
			t.Fatalf("%s: deny response should carry a body", tc.name)
		}
	}
}

func TestSuspiciousTagOnlyAtTier1(t *testing.T) {
	// Tier 1 attaches the suspicious tag; Tier 0 does not.
	r1 := responseForVerdict(contract.Verdict{Tier: contract.TierTag, Score: 1.3})
	if r1.GetDynamicMetadata() == nil {
		t.Fatal("Tier 1 should attach a suspicious dynamic-metadata tag")
	}
	ns, ok := r1.GetDynamicMetadata().GetFields()[dynMetaNamespace]
	if !ok {
		t.Fatalf("tag missing the %q namespace", dynMetaNamespace)
	}
	// Assert the tag CONTENTS, not just the namespace key.
	fields := ns.GetStructValue().GetFields()
	if !fields["suspicious"].GetBoolValue() {
		t.Fatal("tag must carry suspicious=true")
	}
	if fields["tier"].GetNumberValue() != float64(contract.TierTag) {
		t.Fatalf("tag tier = %v, want %d", fields["tier"].GetNumberValue(), contract.TierTag)
	}
	if fields["score"].GetNumberValue() != 1.3 {
		t.Fatalf("tag score = %v, want 1.3", fields["score"].GetNumberValue())
	}
	r0 := responseForVerdict(contract.Verdict{Tier: contract.TierObserve})
	if r0.GetDynamicMetadata() != nil {
		t.Fatal("Tier 0 should not attach a tag")
	}
}
