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
