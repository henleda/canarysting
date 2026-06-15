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

// AttrSourceAddress is the well-known L7Attributes key under which an adapter MAY
// stamp the observed source address (the caller's IP) of a flow. It is context,
// never the cross-boundary join key (that is always SocketCookie — rule 4). The
// M7 staged ground-truth labeler reads it to attribute a canary-touch decision
// to a declared legit/attacker identity; production scoring does not depend on
// it, and it is never persisted as a raw address (rule 9).
const AttrSourceAddress = "canarysting.source_address"

// AttrRequestPath and AttrRequestMethod are the well-known L7Attributes keys
// under which an adapter MAY stamp the L7 request line of a canary-touching flow
// (the HTTP :path — query included — and :method). Like AttrSourceAddress they
// are SCORING-IRRELEVANT context, NEVER the cross-boundary join key (that is
// always SocketCookie — rule 4): production scoring must not depend on them, and
// they MUST NOT be persisted to the addressless cross-customer egress event
// (intelligence.AdversaryInteractionEvent stays byte-for-byte addressless —
// rule 9). They exist so the deployment-LOCAL enriched touch-record can capture
// the L7 context the egress event discards; that store lives behind the egress
// import guard and never crosses a deployment boundary.
const (
	AttrRequestPath   = "canarysting.request_path"
	AttrRequestMethod = "canarysting.request_method"
)

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
	TierObserve Tier = 0 // log, attribute, score; no action
	TierTag     Tier = 1 // mark suspicious, feed richer decoys; no blocking
	TierContain Tier = 2 // rate-limit / tarpit in kernel; attrition may begin
	TierJail    Tier = 3 // hard deny / jail, or full adversarial attrition
)

// EnforcementMode is where a verdict is enforced. Tier 0-1 are always async.
// Tier 2-3 are operator-chosen. Async MUST enforce in the kernel because the
// proxy has already released the flow. See docs/ENGINE.md.
type EnforcementMode int

const (
	ModeAsync  EnforcementMode = iota // enforce on subsequent packets, in kernel
	ModeInline                        // hold the request for the verdict
)

// StingFloor is the operator-selected maximum aggressiveness of attrition.
// The default is conservative; aggressive is reached only by explicit config.
// See docs/STING.md.
type StingFloor int

const (
	FloorPassive    StingFloor = iota // slow responses / tarpit only
	FloorModerate                     // plausible fake resources, keep them looping
	FloorAggressive                   // full adversarial, token-maximizing
)

// AttritionAxis is a bitset of the cost dimensions an attrition session imposes.
// Multi-dimensional attrition composes several on one flow (a single generator can
// land on more than one), so this is a SET, never one value. Every axis imposes
// opportunity cost on a velocity-dependent adversary regardless of how the attacker
// is hosted; the dollar/metered framing never leads. See docs/STING.md and
// docs/ATTRITION_FIVE_AXIS_DESIGN.md.
type AttritionAxis uint32

const (
	AxisVelocity    AttritionAxis = 1 << iota // latency / tarpit
	AxisPoison                                // information poisoning (fabricated environmental state)
	AxisOppCost                               // opportunity-cost injection (subsumes token-burning)
	AxisExploitBurn                           // exploit-inventory burn
	AxisOpExposure                            // operational exposure
)

// Axes returns the set of attrition axes an operator floor unlocks. This is the
// single source of truth for the floor→axis map. It lives here, not in the engine:
// the engine emits only a Tier and never sees the floor (rules 1/2); the floor is
// bound into the Attritor at the composition root. Passive unlocks velocity only,
// so an unset (zero-value) floor can never silently reach the aggressive axes.
func (f StingFloor) Axes() AttritionAxis {
	switch f {
	case FloorAggressive:
		return AxisVelocity | AxisPoison | AxisOppCost | AxisExploitBurn | AxisOpExposure
	case FloorModerate:
		return AxisVelocity | AxisPoison
	default: // FloorPassive (the zero value)
		return AxisVelocity
	}
}

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

// StingOutcome is the cost-meter record of one attrition session, carried over
// the OutcomeRecord path back to the engine for durable capture. Its cost fields
// (Mechanism, TimeHeldSec, BytesServed, RequestsAbsrb, TokenCostProxy,
// DepthReached) mirror intelligence.StingOutcome and attrition.Outcome; it ALSO
// carries DoneReason, which intelligence.StingOutcome intentionally omits —
// DoneReason is attrition-internal control flow (why the stream ended) used on
// the adapter/engine path and is NOT persisted to the durable store. The
// composition root copies between these types WITHOUT any of those packages
// importing each other (dependencies point inward, toward this contract). This
// package imports only "time", so it never reaches outward to
// intelligence/attrition.
type StingOutcome struct {
	Mechanism      string  // one of the attrition Mech* labels
	TimeHeldSec    float64 // attacker wall-time imposed (real elapsed hold)
	BytesServed    int64   // real fake bytes served
	RequestsAbsrb  int64   // requests absorbed (Next calls that returned data)
	TokenCostProxy float64 // estimated attacker tokens imposed
	DepthReached   int     // deepest maze/nesting level reached
	DoneReason     int     // attrition.DoneReason int value (why the stream ended)

	// Five-axis carriers (added once by the AX0 spine; see
	// docs/ATTRITION_FIVE_AXIS_DESIGN.md §9.1). All additive ⇒ gob/proto3-forward-
	// safe (old blobs zero-fill, the live M7 window is safe). Today only Axes is
	// populated; the rest are written by the axis milestones (AX1–AX5) and the
	// adapter disengage classifier, and stay zero until then.
	Axes               AttritionAxis // union of the active generators' axes (OVERLAPPING — never a partition that sums to the total)
	TimeToDisengageSec float64       // attacker-initiated disengage time; non-zero ONLY when the attacker disconnected (adapter classifier, AX1/D7)
	PoisonClass        string        // information-poisoning reaction class (credential|topology|success); "" until AX2
	PoisonReached      int           // deepest poison-field stage the attacker consumed (AX2)
	ExploitsObserved   int64         // exploits fired at decoys, captured in-perimeter (AX4); deployment-local-only until the egress filter (rule 9)
	ExposureSignals    int64         // operational-exposure signals captured (AX5); deployment-local-only until the egress filter (rule 9)
	DisengageReason    int           // adapter disengage classification: attacker-disengaged | generator-exhausted | defender-capped (AX1/D7)
}

// DriverObservation is a structured digest of an attacker's inbound interaction
// that the driver (the Envoy adapter) MAY feed into Stream.Observe to supply the
// future axis-4 (exploit-inventory burn) and axis-5 (operational exposure)
// reaction signals. It MUST carry counts/bools/enums ONLY — never raw bytes,
// addresses, headers, or decoy/payload contents (rule 9; the same "no raw payload"
// invariant StingOutcome holds). TestDriverObservationCarriesNoRawData asserts it
// has no byte-slice or address-shaped field. It ships as a defined-but-unused seam
// (AX0); it is populated only when the axis-4/5 generators land.
type DriverObservation struct {
	RequestCount     int  // requests the attacker made on this flow (a count, never the requests)
	DistinctDecoys   int  // distinct decoys touched — coarse enumeration breadth (a count, never the paths)
	SuspectedExploit bool // the inbound shape matched a known exploit structural marker (a bool, never the payload) — AX4
	ToolingExposed   bool // the inbound shape carried a known automation-tool/C2 fingerprint (user-agent / header-set) — a bool, never the raw UA/headers (AX5 operational exposure)
}

// DisengageReason classifies WHY an attrition session ended, from the DRIVER's
// vantage, and is the value carried in StingOutcome.DisengageReason. The attrition
// stream cannot tell a client disconnect from the defender's own max-hold deadline
// — both surface to Stream.Next as a cancelled context (DoneKilled) — so the
// classification is the adapter's job (it holds the hold context; see
// docs/ATTRITION_FIVE_AXIS_DESIGN.md §8.1 / decision D7). This is a transport-fact
// mapping, not detection logic (rule 1). TimeToDisengageSec is non-zero ONLY for
// DisengageAttacker (the engagement signal — the attacker gave up before we did).
const (
	DisengageUnknown        = 0 // not classified (async / non-adapter path)
	DisengageAttacker       = 1 // attacker disconnected before any defender bound — the engagement signal
	DisengageGeneratorDone  = 2 // the generator reached its natural bounded end
	DisengageDefenderCapped = 3 // the defender stopped it (per-flow budget / host ceiling / max-hold / kill)
)

// OutcomeRecord is the post-attrition report the adapter sends to the engine so
// the durable interaction event gains a real StingOutcome (the verdict-time
// Submit committed the event with a zero outcome; attrition runs later, adapter-
// side). It travels over the rpc ReportOutcome. The join key is SocketCookie
// (rule 4); Scope partitions the durable store (rule 5); TimestampUnixMs matches
// the originating SignalEvent so the engine amends the right event under a cookie.
type OutcomeRecord struct {
	SocketCookie    uint64
	Scope           ScopeKey
	Outcome         StingOutcome
	TimestampUnixMs int64
}

// OutcomeReporter is the engine-side intake for adapter-side attrition outcomes.
// The engine's capturing layer implements it and amends the durable event store;
// the adapter never implements it (it only reports, over the gRPC client).
type OutcomeReporter interface {
	ReportOutcome(OutcomeRecord) error
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
