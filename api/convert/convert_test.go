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
	_ = StingOutcomeFromProto(nil)
	_ = OutcomeFromProto(nil)
}

func TestStingOutcomeRoundTrip(t *testing.T) {
	s := contract.StingOutcome{
		Mechanism:      "fake_tree",
		TimeHeldSec:    12.5,
		BytesServed:    4096,
		RequestsAbsrb:  17,
		TokenCostProxy: 1024.0,
		DepthReached:   9,
		DoneReason:     5, // DoneComplete
		// Five-axis fields set to DISTINCT non-zero values: convert.go has no
		// reflection guard, so a field dropped in either direction must surface as a
		// DeepEqual mismatch here (both-zero would pass silently).
		Axes:               contract.AxisVelocity | contract.AxisOppCost | contract.AxisOpExposure,
		TimeToDisengageSec: 3.5,
		PoisonClass:        "credential",
		PoisonReached:      4,
		ExploitsObserved:   2,
		ExposureSignals:    1,
		DisengageReason:    1,
	}
	if got := StingOutcomeFromProto(StingOutcomeToProto(s)); !reflect.DeepEqual(got, s) {
		t.Fatalf("sting-outcome round-trip lost data:\n got %+v\nwant %+v", got, s)
	}
}

func TestOutcomeRecordRoundTrip(t *testing.T) {
	o := contract.OutcomeRecord{
		SocketCookie:    0xC0FFEE,
		Scope:           "scope-a",
		TimestampUnixMs: 1_700_000_000_123,
		Outcome: contract.StingOutcome{
			Mechanism:      "tarpit",
			TimeHeldSec:    2.0,
			BytesServed:    64,
			RequestsAbsrb:  1,
			TokenCostProxy: 16.0,
			DepthReached:   0,
			DoneReason:     2, // DoneFlowBudget
		},
	}
	if got := OutcomeFromProto(OutcomeToProto(o)); !reflect.DeepEqual(got, o) {
		t.Fatalf("outcome-record round-trip lost data:\n got %+v\nwant %+v", got, o)
	}
}
