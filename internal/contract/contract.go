// Package contract defines the single contract between CanarySting's layers:
// a flow identity plus a signal event in, a verdict out.
//
// This package is the source of truth for cross-layer types. It must NOT import
// from engine, canary, sting, or adapters. Dependencies point toward this
// package, never out of it. See docs/ARCHITECTURE.md and CLAUDE.md.
package contract

import "time"

// FlowIdentity identifies a single network flow across the L7/kernel boundary.
//
// The SocketCookie is the join key between L7 identity (seen by the proxy) and
// kernel identity (seen by eBPF). Any cross-boundary attribution MUST key on it.
// See docs/IDENTITY.md.
type FlowIdentity struct {
	// SocketCookie is the join key. Required for any flow that may be enforced
	// against. A zero value means the flow is unattributable; do not enforce.
	SocketCookie uint64

	// Kernel-side identifiers, available to eBPF. Used for coarse-grained
	// actions (e.g. cgroup-wide throttle) only.
	CgroupID uint64
	PID      uint32

	// L7-side identity, available to the proxy adapter. Optional; informational
	// for scoring context. Never used as the cross-boundary join key.
	SPIFFEID string
	// L7Attributes holds opaque proxy-supplied context (headers, JWT claims).
	// The engine may read these for scoring but must not depend on any specific
	// proxy's shape.
	L7Attributes map[string]string
}

// ScopeKey is the isolation boundary for all learned state. Every store of
// learned state is partitioned by it. See docs/SCOPE.md. A flow belongs to
// exactly one scope.
type ScopeKey string

// CanaryType identifies a kind of decoy (fake secret, bucket, credential,
// file, endpoint...). It is the stable key the engine weights against.
// Defined by the canary catalog; see docs/CANARY.md.
type CanaryType string

// SignalEvent is emitted by an adapter when a flow interacts with a canary.
// It is the engine's only input. See docs/CANARY.md and docs/ADAPTERS.md.
type SignalEvent struct {
	Flow      FlowIdentity
	Canary    CanaryType
	Scope     ScopeKey  // resolved scope, or empty if the engine must resolve it
	Timestamp time.Time // the engine windows on this
}

// Tier is the response level. See docs/ARCHITECTURE.md §4.
type Tier int

const (
	TierObserve   Tier = 0 // log, attribute, score; no action
	TierTag       Tier = 1 // mark suspicious, feed richer decoys; no blocking
	TierContain   Tier = 2 // rate-limit / tarpit in kernel; attrition may begin
	TierJail      Tier = 3 // hard deny / jail, or full adversarial attrition
)

// EnforcementMode is where a verdict is enforced. Tier 0-1 are always async.
// Tier 2-3 are operator-chosen. Async MUST enforce in the kernel because the
// proxy has already released the flow. See docs/ENGINE.md.
type EnforcementMode int

const (
	ModeAsync  EnforcementMode = iota // enforce on subsequent packets, in kernel
	ModeInline                         // hold the request for the verdict
)

// StingFloor is the operator-selected maximum aggressiveness of attrition.
// The default is conservative; aggressive is reached only by explicit config.
// See docs/STING.md.
type StingFloor int

const (
	FloorPassive    StingFloor = iota // slow responses / tarpit only
	FloorModerate                      // plausible fake resources, keep them looping
	FloorAggressive                    // full adversarial, token-maximizing
)

// Verdict is the engine's output for a flow. Adapters and the sting layer act
// on it; neither re-derives identity or re-decides the tier.
type Verdict struct {
	Flow  FlowIdentity
	Scope ScopeKey
	Tier  Tier
	Mode  EnforcementMode

	// Score is the current suspicion score that produced the tier.
	Score float64

	// Calibrated reports whether the deciding scope is in calibrated mode.
	// When false, the verdict rests on documented static defaults, not a
	// learned, FP-target-honoring threshold. See docs/ENGINE.md.
	Calibrated bool
}

// Engine is the contract an engine implementation satisfies. Adapters depend on
// this interface, never on the concrete engine package.
type Engine interface {
	// Submit ingests a signal event and returns the current verdict for the
	// flow. For async tiers the verdict is advisory to the adapter and the
	// authoritative enforcement is programmed into the kernel out of band.
	Submit(SignalEvent) (Verdict, error)
}

// FeedbackLabel is an analyst confirmation that a Tier 2/3 action was correct
// or wrong. It is the single calibration signal. See docs/ENGINE.md.
type FeedbackLabel struct {
	Flow         FlowIdentity
	Scope        ScopeKey
	Tier         Tier
	WasMalicious bool
	// CanariesTouched lets calibration attribute weight to the canary types
	// this flow interacted with on its way up the tiers.
	CanariesTouched []CanaryType
	Timestamp       time.Time
}

// FeedbackSink receives analyst labels. Implemented by the engine's feedback
// intake. See internal/engine/feedback.
type FeedbackSink interface {
	Label(FeedbackLabel) error
}
