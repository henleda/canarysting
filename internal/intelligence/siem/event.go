package siem

import (
	"encoding/hex"
	"strconv"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
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
//
// v1 -> v2 (audit-anchor, ADD-ONLY): appended the five audit_* fields below and the
// EventTypeAuditAnchor event_type, for the external-witness anchor (a per-scope audit-
// chain high-water-mark published to the operator's OWN SIEM). NO v1 field was removed
// or repurposed and NO JSON tag changed meaning, so a v1 canary-touch event is byte-
// identical except schema_version=2 (the new fields are omitempty and zero for a
// touch). A SOC parser MUST range-check the version (>=1), not exact-match ==1.
// persist.SchemaVersion (the durable baseline format) is a DIFFERENT, independent
// version and is UNCHANGED.
const SchemaVersion = 2

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

// EventTypeAuditAnchor is the EXTERNAL-WITNESS anchor (v2, ADD-ONLY): a periodic per-
// scope publish of the tamper-evident audit chain's HIGH-WATER-MARK (head hash +
// record count + latest seq + algo/keyed markers) to the operator's OWN SIEM. It is a
// THIRD discriminator value on the existing EventType field — a v1 SOC parser that
// branches on event_type simply sees a new type and ignores it; nothing existing is
// repurposed. It carries NO touch PII (no src/path/SPIFFE/tier/score/cookie) — only
// chain metadata about the operator's own deployment.
//
// It exists so the SOC can detect the two residuals the engine CANNOT detect in-band
// (truncate-to-a-valid-prefix + whole-scope-erasure; see internal/intelligence/audit
// THREAT MODEL): the SOC holds the last-published anchor and compares it against the
// live chain (a later "scope empty, or shorter / different head than the witness saw
// N records" is a provable deletion/truncation). This is PUBLISH-then-detect-AT-SOC,
// NOT in-engine auto-detection — the SIEM emitter is one-way; the engine never reads
// it back (rule 8).
const EventTypeAuditAnchor = "audit-anchor"

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

	// --- audit-anchor fields (v2, ADD-ONLY) ----------------------------------
	//
	// These five fields are ONLY set on an EventTypeAuditAnchor event (the external-
	// witness anchor). They are omitempty, so a canary-touch / kernel-jail event drops
	// them entirely (byte-identical to v1 except schema_version=2). They carry the per-
	// scope audit-chain high-water-mark — chain metadata about the operator's OWN
	// deployment, NOT touch PII. The rest of an anchor's tuple reuses the existing
	// SchemaVersion / Scope / Timestamp v1 fields.

	// AuditHeadHash is the hex of the chain head (the Hash of the latest record).
	AuditHeadHash string `json:"audit_head_hash,omitempty"`
	// AuditRecordCount is the number of records in the scope's chain.
	AuditRecordCount int `json:"audit_record_count,omitempty"`
	// AuditLatestSeq is the latest (highest) per-scope seq — the monotonic truncation
	// signal the SOC compares against (regression => provable truncation).
	AuditLatestSeq uint64 `json:"audit_latest_seq,omitempty"`
	// AuditAlgo is the chain link function ("sha256" | "hmac-sha256").
	AuditAlgo string `json:"audit_algo,omitempty"`
	// AuditKeyed reports whether the chain is HMAC-keyed.
	AuditKeyed bool `json:"audit_keyed,omitempty"`
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

// FromHighWaterMark is the pure projector for the external-witness anchor (sibling to
// FromRecord). It maps a per-scope audit-chain high-water-mark onto an
// EventTypeAuditAnchor SiemEvent: it sets the v2 audit_* fields (head hash hex-encoded,
// count, latest seq, algo, keyed), reuses the existing SchemaVersion / Scope /
// Timestamp v1 fields, and mints a DETERMINISTIC-but-distinguishable EventID
// ("audit-anchor|<scope>|<latestSeq>") so the drop-on-outage log line (siem.go) reads
// sanely and a SOC can dedup — successive hourly anchors for the same scope advance
// the seq, so they are distinct events, never dedup'd into one.
//
// It leaves ALL touch-specific fields (src/path/SPIFFE/tier/score/socket_cookie/
// canary_type/hit_count/first_seen) zero so JSON omitempty drops them — an anchor
// carries NO touch PII, only chain metadata about the operator's OWN deployment.
// BytesRealDataCrossed is intentionally left 0 (the load-bearing structural zero that
// is always present on the wire). Rule 8: this is a pure read-side projection; it
// arms nothing.
func FromHighWaterMark(hwm audit.HighWaterMark) SiemEvent {
	return SiemEvent{
		SchemaVersion:    SchemaVersion,
		EventID:          EventTypeAuditAnchor + "|" + string(hwm.Scope) + "|" + strconv.FormatUint(hwm.LatestSeq, 10),
		EventType:        EventTypeAuditAnchor,
		Scope:            string(hwm.Scope),
		Timestamp:        hwm.Timestamp,
		AuditHeadHash:    hex.EncodeToString(hwm.Head),
		AuditRecordCount: hwm.Count,
		AuditLatestSeq:   hwm.LatestSeq,
		AuditAlgo:        hwm.Algo,
		AuditKeyed:       hwm.Keyed,
	}
}
