package convert

import (
	"reflect"
	"testing"
	"time"

	pb "github.com/canarysting/canarysting/api/gen"
	"github.com/canarysting/canarysting/internal/contract"
)

// TestEnumValuesAligned pins the assumption the package doc relies on: the
// contract integer values EQUAL the proto enum values, so the casts in
// VerdictToProto/VerdictFromProto are value-preserving. A divergence here (e.g. a
// renumbered proto enum) is exactly the silent corruption the round-trip test over
// the gRPC boundary cannot catch.
func TestEnumValuesAligned(t *testing.T) {
	if int(contract.TierObserve) != int(pb.Tier_TIER_OBSERVE) ||
		int(contract.TierTag) != int(pb.Tier_TIER_TAG) ||
		int(contract.TierContain) != int(pb.Tier_TIER_CONTAIN) ||
		int(contract.TierJail) != int(pb.Tier_TIER_JAIL) {
		t.Fatal("contract.Tier values diverge from the proto Tier enum — the casts are not value-preserving")
	}
	if int(contract.ModeAsync) != int(pb.EnforcementMode_MODE_ASYNC) ||
		int(contract.ModeInline) != int(pb.EnforcementMode_MODE_INLINE) {
		t.Fatal("contract.EnforcementMode values diverge from the proto enum")
	}
}

func TestSignalRoundTrip(t *testing.T) {
	ev := contract.SignalEvent{
		Flow:      contract.FlowIdentity{SocketCookie: 0xC0FFEE, CgroupID: 7, PID: 9, SPIFFEID: "spiffe://x", L7Attributes: map[string]string{"k": "v"}},
		Canary:    "decoy_file",
		Scope:     "scope-a",
		Timestamp: time.UnixMilli(1_700_000_000_123),
	}
	if got := SignalFromProto(SignalToProto(ev)); !reflect.DeepEqual(got, ev) {
		t.Fatalf("signal round-trip lost data:\n got %+v\nwant %+v", got, ev)
	}
}

func TestVerdictRoundTrip(t *testing.T) {
	v := contract.Verdict{
		Flow:       contract.FlowIdentity{SocketCookie: 0xABCD, PID: 2, SPIFFEID: "s"},
		Scope:      "scope-a",
		Tier:       contract.TierContain,
		Mode:       contract.ModeInline,
		Score:      3.5,
		Calibrated: true,
	}
	if got := VerdictFromProto(VerdictToProto(v)); !reflect.DeepEqual(got, v) {
		t.Fatalf("verdict round-trip lost data:\n got %+v\nwant %+v", got, v)
	}
}

func TestNilProtoIsZeroValue(t *testing.T) {
	if !reflect.DeepEqual(FlowFromProto(nil), contract.FlowIdentity{}) {
		t.Fatal("nil proto flow should yield the zero FlowIdentity")
	}
	// Must not panic on nil messages.
	_ = SignalFromProto(nil)
	_ = VerdictFromProto(nil)
}
