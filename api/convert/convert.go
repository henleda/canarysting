// Package convert translates between the in-process contract types
// (internal/contract — the source of truth) and the generated protobuf types
// (api/gen) used on the out-of-process gRPC boundary. It is the single place that
// knows both shapes, so the engine gRPC server and the Envoy adapter client share
// one translation and cannot drift. internal/contract never imports outward, so
// this boundary glue lives here, not there.
//
// The contract.Tier / contract.EnforcementMode integer values are defined equal
// to the proto enum values (see api/proto/contract.proto), so the casts here are
// value-preserving by construction; tests assert the equivalence.
package convert

import (
	"time"

	pb "github.com/canarysting/canarysting/api/gen"
	"github.com/canarysting/canarysting/internal/contract"
)

// FlowToProto converts a contract.FlowIdentity to its proto form.
func FlowToProto(f contract.FlowIdentity) *pb.FlowIdentity {
	return &pb.FlowIdentity{
		SocketCookie: f.SocketCookie,
		CgroupId:     f.CgroupID,
		Pid:          f.PID,
		SpiffeId:     f.SPIFFEID,
		L7Attributes: f.L7Attributes,
	}
}

// FlowFromProto converts a proto FlowIdentity (possibly nil) to the contract type.
func FlowFromProto(f *pb.FlowIdentity) contract.FlowIdentity {
	if f == nil {
		return contract.FlowIdentity{}
	}
	return contract.FlowIdentity{
		SocketCookie: f.GetSocketCookie(),
		CgroupID:     f.GetCgroupId(),
		PID:          f.GetPid(),
		SPIFFEID:     f.GetSpiffeId(),
		L7Attributes: f.GetL7Attributes(),
	}
}

// SignalToProto converts a contract.SignalEvent to its proto form.
func SignalToProto(e contract.SignalEvent) *pb.SignalEvent {
	return &pb.SignalEvent{
		Flow:            FlowToProto(e.Flow),
		CanaryType:      string(e.Canary),
		Scope:           string(e.Scope),
		TimestampUnixMs: e.Timestamp.UnixMilli(),
	}
}

// SignalFromProto converts a proto SignalEvent (possibly nil) to the contract type.
func SignalFromProto(e *pb.SignalEvent) contract.SignalEvent {
	if e == nil {
		return contract.SignalEvent{}
	}
	return contract.SignalEvent{
		Flow:      FlowFromProto(e.GetFlow()),
		Canary:    contract.CanaryType(e.GetCanaryType()),
		Scope:     contract.ScopeKey(e.GetScope()),
		Timestamp: time.UnixMilli(e.GetTimestampUnixMs()),
	}
}

// VerdictToProto converts a contract.Verdict to its proto form.
func VerdictToProto(v contract.Verdict) *pb.Verdict {
	return &pb.Verdict{
		Flow:       FlowToProto(v.Flow),
		Scope:      string(v.Scope),
		Tier:       pb.Tier(v.Tier),
		Mode:       pb.EnforcementMode(v.Mode),
		Score:      v.Score,
		Calibrated: v.Calibrated,
	}
}

// VerdictFromProto converts a proto Verdict (possibly nil) to the contract type.
func VerdictFromProto(v *pb.Verdict) contract.Verdict {
	if v == nil {
		return contract.Verdict{}
	}
	return contract.Verdict{
		Flow:       FlowFromProto(v.GetFlow()),
		Scope:      contract.ScopeKey(v.GetScope()),
		Tier:       contract.Tier(v.GetTier()),
		Mode:       contract.EnforcementMode(v.GetMode()),
		Score:      v.GetScore(),
		Calibrated: v.GetCalibrated(),
	}
}

// StingOutcomeToProto converts a contract.StingOutcome to its proto form. The
// int fields narrow to int32 on the wire; attrition's depth/done-reason are small
// bounded enums/counters, never near the int32 ceiling.
func StingOutcomeToProto(s contract.StingOutcome) *pb.StingOutcome {
	return &pb.StingOutcome{
		Mechanism:      s.Mechanism,
		TimeHeldSec:    s.TimeHeldSec,
		BytesServed:    s.BytesServed,
		RequestsAbsrb:  s.RequestsAbsrb,
		TokenCostProxy: s.TokenCostProxy,
		DepthReached:   int32(s.DepthReached),
		DoneReason:     int32(s.DoneReason),
		// Five-axis fields (AX0 spine). Thread ALL of them — convert.go has no
		// reflection guard, so a missed field would silently zero over gRPC; the
		// round-trip literals in convert_test.go set every one to catch that.
		Axes:               uint32(s.Axes),
		TimeToDisengageSec: s.TimeToDisengageSec,
		PoisonClass:        s.PoisonClass,
		PoisonReached:      int32(s.PoisonReached),
		ExploitsObserved:   s.ExploitsObserved,
		ExposureSignals:    s.ExposureSignals,
		DisengageReason:    int32(s.DisengageReason),
	}
}

// StingOutcomeFromProto converts a proto StingOutcome (possibly nil) to the
// contract type.
func StingOutcomeFromProto(s *pb.StingOutcome) contract.StingOutcome {
	if s == nil {
		return contract.StingOutcome{}
	}
	return contract.StingOutcome{
		Mechanism:          s.GetMechanism(),
		TimeHeldSec:        s.GetTimeHeldSec(),
		BytesServed:        s.GetBytesServed(),
		RequestsAbsrb:      s.GetRequestsAbsrb(),
		TokenCostProxy:     s.GetTokenCostProxy(),
		DepthReached:       int(s.GetDepthReached()),
		DoneReason:         int(s.GetDoneReason()),
		Axes:               contract.AttritionAxis(s.GetAxes()),
		TimeToDisengageSec: s.GetTimeToDisengageSec(),
		PoisonClass:        s.GetPoisonClass(),
		PoisonReached:      int(s.GetPoisonReached()),
		ExploitsObserved:   s.GetExploitsObserved(),
		ExposureSignals:    s.GetExposureSignals(),
		DisengageReason:    int(s.GetDisengageReason()),
	}
}

// OutcomeToProto converts a contract.OutcomeRecord to its proto form.
func OutcomeToProto(o contract.OutcomeRecord) *pb.OutcomeRecord {
	return &pb.OutcomeRecord{
		SocketCookie:    o.SocketCookie,
		Scope:           string(o.Scope),
		StingOutcome:    StingOutcomeToProto(o.Outcome),
		TimestampUnixMs: o.TimestampUnixMs,
	}
}

// OutcomeFromProto converts a proto OutcomeRecord (possibly nil) to the contract
// type.
func OutcomeFromProto(o *pb.OutcomeRecord) contract.OutcomeRecord {
	if o == nil {
		return contract.OutcomeRecord{}
	}
	return contract.OutcomeRecord{
		SocketCookie:    o.GetSocketCookie(),
		Scope:           contract.ScopeKey(o.GetScope()),
		Outcome:         StingOutcomeFromProto(o.GetStingOutcome()),
		TimestampUnixMs: o.GetTimestampUnixMs(),
	}
}
