package siem

import (
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/l7events"
)

// SchemaVersion is the canonical SIEM event schema version. It is INDEPENDENT of
// persist.SchemaVersion (the durable baseline format) — this versions only the
// operator-facing wire shape a SOC parser binds to.
//
// STABILITY CONTRACT: this schema is ADD-ONLY. New fields may be appended in a
// later version; an existing field is NEVER repurposed or removed and its JSON tag
// never changes meaning. A SOC parser written against v1 keeps working against a
// later emitter. Bump SchemaVersion only when fields are ADDED, and document the
// addition — never to repurpose.
const SchemaVersion = 1

// EventTypeCanaryTouch is the base event type: a decoy was touched and the engine
// took a (sub-jail) action.
const EventTypeCanaryTouch = "canary-touch"

// EventTypeKernelJail is derived when the touch drove a Tier-3 (Jail) VERDICT. It
// denotes the engine's DECISION at capture time, NOT a confirmed kernel enforcement:
// the actual jail runs asynchronously adapter-side after this record is written, so at
// this point only the verdict is known (the record's StingMechanism is typically still
// empty — see l7events store.go). A SOC should read it as "the engine returned a jail
// verdict for this touch", not "a kernel jail was executed". Likewise the event's
// `action` field is the tier-derived engine decision, not a confirmed effect. Derived
// from the verdict tier, never a second signal.
const EventTypeKernelJail = "kernel-jail"

// SiemEvent is the canonical, stable, versioned serialization of one EnrichedTouchRecord
// + the engine verdict it drove, mapped onto the fields the record CAN fill today.
// It is LOCAL-RICH and un-anonymized (raw src/path/SPIFFE): it is the deployment's own
// "a decoy was touched" alert for the operator's OWN SIEM/SOAR — it is NOT the
// cross-customer egress feed and MUST NOT travel through internal/intelligence/network.
//
// Fields the slice-1 record does not capture yet (east-west path beyond hashed
// adjacency, the attrition five-axis axes when no sting outcome is known) are OMITTED
// (omitempty / pointer-nil), never faked — so a SOC never parses an invented value.
//
// JSON is the canonical wire form (webhook body + Splunk-HEC event + an OCSF-aligned
// base). The CEF formatter is a single-line view over the same struct.
type SiemEvent struct {
	// SchemaVersion lets a parser branch on shape; always set to the package const.
	SchemaVersion int `json:"schema_version"`

	// EventID is the stable dedup/correlation id from the record (scope+cookie+first-seen).
	EventID string `json:"event_id"`
	// EventType is "canary-touch", or "kernel-jail" when the verdict tier is Jail.
	EventType string `json:"event_type"`
	// Scope is the resolved scope (rule 5) the touch was isolated under.
	Scope string `json:"scope"`

	// Timestamp is the LastSeen wall clock (RFC3339) — when this touch event last
	// occurred. FirstSeen + HitCount carry the recurrence context.
	Timestamp time.Time `json:"timestamp"`
	FirstSeen time.Time `json:"first_seen"`
	HitCount  uint64    `json:"hit_count"`

	// --- source identity (local-rich, raw) ---
	// SourceAddress is the raw caller IP[:port]; omitted when unattributable.
	SourceAddress string `json:"src,omitempty"`
	// SPIFFEID is the peer mTLS identity (the actor identity); omitted when none.
	SPIFFEID string `json:"actor_spiffe_id,omitempty"`

	// --- L7 request line (raw, query included) ---
	Method string `json:"http_method,omitempty"`
	Path   string `json:"http_path,omitempty"`

	// SocketCookie is the kernel/L7 join key (rule 4).
	SocketCookie uint64 `json:"socket_cookie"`

	// CanaryType is which decoy type was touched (one of the 5 catalog constants).
	CanaryType string `json:"canary_type"`
	// AttackTechniques is the ATT&CK technique id(s) for that decoy type; OMITTED
	// entirely for an unmapped/empty type (never guessed).
	AttackTechniques []string `json:"att_ck,omitempty"`

	// --- engine decision (read off the record; never re-derived) ---
	Tier    int     `json:"tier"`
	Verdict string  `json:"verdict"` // observe/tag/contain/jail (the action)
	Action  string  `json:"action"`  // alias of Verdict for SOC field-name familiarity
	Score   float64 `json:"score"`   // suspicion score (B x M)
	// Calibrated reports whether the deciding scope was calibrated (confidence context).
	Calibrated bool `json:"calibrated"`

	// NoveltyFingerprint is the baseline novelty/deviation vector at touch time; OMITTED
	// when the record carried no features (nil/empty), never faked as a zero vector.
	NoveltyFingerprint map[string]float64 `json:"novelty_fingerprint,omitempty"`

	// BytesRealDataCrossed is the structural fact: a canary touch crosses ZERO bytes of
	// real data (the decoy is fake by construction). Always 0; emitted explicitly so a
	// SOC reads the fact rather than inferring it. Not omitempty — the 0 is load-bearing.
	BytesRealDataCrossed int64 `json:"bytes_real_data_crossed"`
}

// FromRecord maps an EnrichedTouchRecord onto the canonical SiemEvent. It is a pure
// projection: it reads the verdict fields the record already mirrored at capture
// (never re-deriving the tier/score), derives EventType from the tier, attaches the
// ATT&CK technique(s) for the canary type (omitted when unmapped), and leaves
// not-yet-captured fields zero/nil so JSON omitempty drops them.
func FromRecord(r l7events.EnrichedTouchRecord) SiemEvent {
	ev := SiemEvent{
		SchemaVersion:        SchemaVersion,
		EventID:              r.EventID,
		EventType:            eventTypeForTier(r.Tier),
		Scope:                r.Scope,
		Timestamp:            r.LastSeen,
		FirstSeen:            r.FirstSeen,
		HitCount:             r.HitCount,
		SourceAddress:        r.SourceAddress,
		SPIFFEID:             r.SPIFFEID,
		Method:               r.Method,
		Path:                 r.Path,
		SocketCookie:         r.SocketCookie,
		CanaryType:           r.CanaryType,
		AttackTechniques:     techniquesFor(contract.CanaryType(r.CanaryType)),
		Tier:                 r.Tier,
		Verdict:              r.Verdict,
		Action:               r.Verdict,
		Score:                r.Score,
		Calibrated:           r.Calibrated,
		BytesRealDataCrossed: r.BytesRealDataCrossed, // always 0 by construction
	}
	if len(r.Features) > 0 {
		// copy so the emitted event does not alias the snapshot's map
		f := make(map[string]float64, len(r.Features))
		for k, v := range r.Features {
			f[k] = v
		}
		ev.NoveltyFingerprint = f
	}
	return ev
}

// eventTypeForTier derives the event type from the engine tier: a Jail verdict is a
// kernel-jail event, everything else (tag/contain) is a canary-touch. Derived, not a
// second signal (rule 8: nothing here arms).
func eventTypeForTier(tier int) string {
	if tier == int(contract.TierJail) {
		return EventTypeKernelJail
	}
	return EventTypeCanaryTouch
}
