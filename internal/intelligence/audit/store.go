// Package audit is the deployment-LOCAL, scope-isolated, TAMPER-EVIDENT audit-log
// substrate (SLICE A). It records one hash-chained AuditRecord per Tier>=Tag
// canary-touch DECISION (and, via Append, per operator action a later slice wires
// in), capturing the action facts plus the raw L7 + identity context at decision
// time — and links every record into a per-scope hash chain so any later edit,
// removal, or reorder of a record is detectable.
//
// LOCAL-RICH / EXPORT-COARSE (docs/INTELLIGENCE.md rule 9): like l7events, an
// AuditRecord holds the RAW source address / :method / :path / SPIFFE id — it is
// the examiner's case file, deployment-LOCAL, and NEVER crosses a boundary. The
// cross-customer egress event (intelligence.AdversaryInteractionEvent) stays
// byte-for-byte addressless and is a structurally separate type in a separate
// package, so this rich record can never widen it. The egress import guard
// (internal/intelligence/network/egress_importguard_test.go) forbids the egress
// filter from transitively importing this package, so a raw path/addr/SPIFFE is
// physically unreachable from a deployment boundary — anonymization is structural,
// not a runtime check.
//
// TAMPER-EVIDENCE (the hash chain): each record carries PrevHash + Hash, where
// Hash = link(PrevHash || canonical-JSON-of-the-record-without-its-hash). The
// per-scope chain head is the Hash of the latest record; an append computes the
// new record's Hash from the current head and sets it as the new head. The chain
// is PER-SCOPE (rule 5), and that isolation is CRYPTOGRAPHIC, not merely storage-
// location: each scope has its own independent chain seeded from a per-scope,
// key-bound genesis (genesis(key,scope) = HMAC-SHA256(key, "canarysting-audit-
// genesis\x00"||scope) when keyed, sha256(...) when unkeyed), AND every record
// carries its resolved Scope in the hashed preimage which Verify checks against the
// scope it is verifying. A chain lifted from one scope's bucket into another's (the
// cross-scope relocation forgery) therefore fails Verify two ways: the per-record
// Scope field no longer matches the verifying scope (the primary in-band check), and
// even if that check were removed the relocated first record's PrevHash (the source
// scope's genesis) does not equal the destination scope's genesis, so the chain
// breaks at seq 1. Verify recomputes the chain start-to-head and reports the seq of
// the FIRST broken/altered/missing/relocated link; Export serializes the full chain +
// the verify result as the IR-handoff case report.
//
// THE LINK FUNCTION IS KEYED OR UNKEYED (the two threat models — see below):
//   - UNKEYED (HMACKey nil, the back-compat default): link = sha256(prevHead ||
//     canonical(record)). The chain construction is PUBLIC, so anyone with
//     baseline.db write access can recompute every valid link.
//   - KEYED (HMACKey set, from -audit-hmac-key): link = HMAC-SHA256(key, prevHead
//     || canonical(record)), where the key is held OUTSIDE baseline.db. Verify
//     recomputes with the SAME key, so a writer WITHOUT the key cannot forge a
//     chain that Verify accepts.
//
// Each record stamps a Keyed flag + Algo marker (both part of the hashed preimage,
// so neither can be flipped without breaking recompute) so Verify/Export STATE the
// mode an examiner is trusting. The key itself is never stored.
//
// THREAT MODEL — read this before claiming "tamper-evident". The adversary of
// concern is one with baseline.db WRITE access (a host-level attacker editing the
// file directly, around the engine).
//
//	KEYED (HMACKey set): tamper-EVIDENT against that adversary AS LONG AS they lack
//	the key. Editing a record, removing/reordering one, RELOCATING a chain across
//	scopes (lifting scope-B's records+head into scope-A's bucket), or re-forging the
//	chain (edit + recompute every downstream link + the head) are all DETECTED — the
//	recomputed MACs will not match, because the attacker cannot compute valid MACs
//	without the key (and a relocated chain additionally fails the per-record scope
//	check + the per-scope genesis seed; see THE CHAIN above). Tail truncation is
//	detected whenever the persisted head still attests the original count (the
//	recomputed keyed head over the surviving prefix differs).
//
//	THE TWO HONEST RESIDUALS (both need an EXTERNAL WITNESS, not the key — they are
//	out-of-band by nature, since a fresh Store sees a consistent-but-incomplete state
//	and there is nothing in-band left to recompute against):
//	  (a) TRUNCATE-TO-A-VALID-PREFIX + HEAD-REWRITE: truncating the tail AND rewriting
//	      the head to a SURVIVING record's already-valid (validly-keyed) hash is NOT
//	      distinguishable in-band — the attacker reuses a legitimate keyed link, not a
//	      forged one, so the recomputed head over the surviving prefix matches.
//	  (b) WHOLE-SCOPE ERASURE: deleting a scope's entire chain (records + head) leaves
//	      nothing to recompute, so Verify sees a fresh/empty scope and reports Intact.
//	Detecting either needs an EXTERNAL witness — a per-scope head / high-water-mark
//	periodically published to the SIEM emitter or a WORM sink, so a later "scope is
//	empty / shorter than the witness saw N records" is a provable deletion. That
//	witness is ROADMAP (see Verify); this package does NOT claim to detect (a) or (b).
//	Cross-scope relocation is NOT in this residual set — it is now detected (above).
//
//	UNKEYED (HMACKey nil): detects only ACCIDENTAL corruption and NAIVE edits that
//	do not re-run the public chain. It is NOT tamper-evident against a knowledgeable
//	DB-write adversary: such an attacker can edit a record and recompute every
//	downstream sha256 link + the head (over the PUBLIC, recomputable per-scope seed),
//	producing a chain Verify accepts. Unkeyed mode buys integrity-against-corruption
//	and an honest tamper-EVIDENT story only for an attacker who does not know how the
//	chain is built — nothing stronger. (The per-scope genesis + per-record scope
//	check still stop a NAIVE relocation unkeyed, but not a knowledgeable re-forge.)
//
// RULE 8 (record-only): this store records a DECISION the engine already made on a
// real canary touch (or, via Append, an operator action). Nothing here arms,
// escalates, scores, or feeds back into a verdict — it is pure, append-only
// evidence. SchemaVersion is unchanged (the chain rides a tolerant new bbolt
// bucket).
//
// HONESTY (what a Submit-seam record attests): at the capture seam the engine sees
// a DECISION, not an OUTCOME or the operator attrition posture. So a Capture record
// honestly attests the tier/verdict/score/scope/identity-context AT DECISION TIME
// and the verdict-level posture available there (Mode, Calibrated). It does NOT
// attest the five-axis StingOutcome (still zero at Submit; the real outcome lands
// later at ReportOutcome) nor the operator StingFloor (never reaches the engine —
// bound into the Attritor at the composition root, rules 1/2). The structural fact
// BytesRealDataCrossed=0 is always present (a canary touch transfers zero real
// bytes by construction).
package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"hash"
	"hash/fnv"
	"math"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

// hashLen is the byte length of the chain hash. Both link functions emit a
// 32-byte digest: sha256 (unkeyed) and HMAC-SHA256 (keyed) are both sha256-wide.
const hashLen = sha256.Size

// Algo markers stamped on each record (and surfaced on Verify/Export) so a reader
// knows which link function the chain was built with — and therefore which threat
// model applies (see the package doc THREAT MODEL).
const (
	AlgoSHA256     = "sha256"      // unkeyed link: sha256(prevHead || canonical(record))
	AlgoHMACSHA256 = "hmac-sha256" // keyed link: HMAC-SHA256(key, prevHead || canonical(record))
)

// genesisLabel is the domain-separation tag mixed into every per-scope genesis seed
// (the NUL terminator keeps it an unambiguous prefix of the scope bytes that follow).
const genesisLabel = "canarysting-audit-genesis\x00"

// genesis is the per-scope chain seed: the PrevHash of the FIRST record in a scope's
// chain. An absent on-disk head (a fresh scope, or a baseline.db that predates the
// audit bucket) is treated as this genesis — never as a nil hash — so the first
// record after upgrade chains from a well-known, scope-bound constant rather than
// from undefined state.
//
// FIX A (relocation, defense-in-depth): the seed is BOUND TO THE SCOPE so a chain
// lifted from scope-B into scope-A's bucket cannot even chain from the right seed —
// scope-A's first-record recompute uses genesis("scope-a"), which differs from the
// genesis("scope-b") the relocated record's PrevHash carries, so Verify breaks at
// seq 1 on the prev-hash check EVEN IF the per-record Scope field-check (the primary
// defense in Verify) were ever removed. The seed is also KEYED when the store is
// keyed: HMAC-SHA256(key, genesisLabel||scope) so a file-only attacker lacking the
// key cannot recompute a valid scope seed either. Unkeyed it is sha256(genesisLabel
// ||scope) — a deterministic, documented, per-scope constant (its integrity, like
// every link, rests on recomputation, not on secrecy of the seed).
func genesis(key []byte, scope contract.ScopeKey) []byte {
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
	h.Write([]byte(genesisLabel))
	h.Write([]byte(scope))
	return h.Sum(nil)
}

// AuditRecord is one tamper-evident, hash-chained audit-log entry. It is
// LOCAL-RICH: it holds the RAW (un-hashed) L7 + identity context, kept
// deployment-LOCAL. All fields are exported for gob (durable blob) and JSON
// (Export / the canonical hash preimage). The record never crosses a deployment
// boundary.
type AuditRecord struct {
	// Seq is the per-scope monotonic chain position (1-based, assigned by the
	// durable append). It is the position Verify reports a break at, and the order
	// the chain is recomputed in.
	Seq uint64

	// EventID is a stable per-record id (scope + cookie + record wall nanos), so a
	// downstream examiner can reference a record without re-deriving identity.
	EventID string

	// Timestamp is the record's WALL clock (the decision/action time supplied by
	// the caller — ev.Timestamp at the Submit seam).
	Timestamp time.Time

	// Scope is the RESOLVED scope (rule 5) — never the wire scope. The capture seam
	// keys this on the engine-resolved verdict scope (the B1 fix). Each scope has its
	// own independent chain.
	Scope string

	// Kind distinguishes a decision record (the per-Submit capture) from an
	// operator-action record (the slice-B Append API). It is part of the hashed
	// preimage, so a forged kind breaks the chain.
	Kind string

	// --- the ACTION facts -----------------------------------------------------

	// CanaryType is which decoy type was touched ("" for an operator-action record).
	CanaryType string
	// SocketCookie is the rule-4 L7/kernel join key (0 for an operator action with
	// no flow).
	SocketCookie uint64
	// Tier/Verdict are the engine decision (Verdict is the tier name). Action is the
	// human-facing action label (the tier name for a decision; a caller-supplied
	// label for an operator action).
	Tier    int
	Verdict string
	Action  string
	// Score is the suspicion score that produced the tier.
	Score float64
	// StingMechanism is the attrition/containment mechanism IF already known at
	// record time. At the Submit seam the StingOutcome is still zero (attrition runs
	// later, adapter-side), so this is usually "" for a decision record — the field
	// exists so a later amendment/operator-action record can carry it.
	StingMechanism string

	// --- the operator POSTURE available at decision time ----------------------
	//
	// Mode (inline vs async) and Calibrated are the verdict-level posture the seam
	// CAN honestly attest. The operator StingFloor is NOT recorded: it never reaches
	// the engine (bound into the Attritor at the composition root, rules 1/2), so the
	// seam cannot honestly attest it. Posture holds any additional reachable
	// posture/flag captured by the caller (e.g. a demo-data flag), never invented.

	// Mode is the enforcement mode of the verdict (contract.EnforcementMode value).
	Mode int
	// Calibrated reports whether the deciding scope was in calibrated mode.
	Calibrated bool
	// Posture holds any extra deployment-posture facts reachable at the seam
	// (key->value), e.g. a demo-data flag. nil/empty when none — never fabricated.
	Posture map[string]string

	// --- the L7 + identity context (local-rich, RAW) -------------------------

	// SourceAddress is the raw caller IP[:port] as the adapter observed it. "" when
	// the source tuple was unattributable.
	SourceAddress string
	// Method / Path are the raw HTTP :method and :path (query INCLUDED). "" when not
	// an L7 touch.
	Method string
	Path   string
	// SPIFFEID is the peer's L7 identity (mTLS), "" when none.
	SPIFFEID string

	// Features is the baseline novelty/deviation vector at decision time, copied
	// verbatim. May be nil.
	Features map[string]float64

	// BytesRealDataCrossed is the structural fact that a canary touch transfers ZERO
	// bytes of real data (the decoy is fake by construction). It is ALWAYS 0 — an
	// explicit field so a consumer reads the fact rather than inferring it.
	BytesRealDataCrossed int64

	// --- the hash chain (tamper-evidence) -------------------------------------

	// Keyed records whether this link was computed with the keyed HMAC anchor (true)
	// or the unkeyed sha256 chain (false). Algo names the link function (AlgoSHA256
	// or AlgoHMACSHA256). BOTH are part of the hashed preimage (canonicalPreimage
	// keeps them), so an attacker cannot downgrade a keyed record to unkeyed — or
	// re-label the algo — without breaking recompute. Verify recomputes with the
	// link function the STORE is configured with and additionally rejects a record
	// whose stamped Keyed/Algo disagree with that mode (a swapped-in record from a
	// chain built under the other mode).
	Keyed bool
	Algo  string

	// PrevHash is the chain head BEFORE this record (the genesis seed for the first
	// record in a scope). Hash is link(PrevHash || canonical-JSON(this record with
	// Hash zeroed)) — sha256 when unkeyed, HMAC-SHA256(key, ...) when keyed. Both are
	// part of the durable blob; Hash is EXCLUDED from its own preimage (see
	// canonicalPreimage).
	PrevHash []byte
	Hash     []byte
}

// Kind labels.
const (
	KindDecision = "decision" // a Tier>=Tag canary-touch verdict captured at the Submit seam
	KindOperator = "operator" // an operator action (slice-B Append), e.g. a kill-switch toggle
)

// canonicalPreimage is the stable byte encoding of a record EXCLUDING its own Hash,
// over which Hash is computed. It zeroes Hash (so Hash is never part of its own
// preimage) but KEEPS PrevHash, Seq, and every other field — so editing ANY field,
// or reordering/removing a record (which changes the PrevHash the next record must
// chain from), breaks recomputation from that point. JSON with sorted keys
// (encoding/json sorts map keys and marshals struct fields in declaration order) is
// a deterministic canonical form independent of the gob wire layout.
//
// FIX 3 — non-finite floats are REJECTED here, not silently dropped. encoding/json
// errors on NaN/±Inf, so a pathological Score or Feature value would otherwise
// surface as an opaque marshal error (or, worse, a swallowed write that leaves a
// real Tier>=Tag decision UNRECORDED). We pre-scan Score + every Feature and return
// a SPECIFIC, surfaced error so the caller (Capture) propagates a hard failure
// rather than a silent gap. validateFinite must run BEFORE marshal so the message
// names the offending field.
func canonicalPreimage(r *AuditRecord) ([]byte, error) {
	if err := validateFinite(r); err != nil {
		return nil, err
	}
	cp := *r
	cp.Hash = nil // exclude Hash from its own preimage; PrevHash stays in
	return json.Marshal(&cp)
}

// validateFinite rejects a record carrying a non-finite (NaN/±Inf) Score or Feature
// value. A canary touch's suspicion score and novelty vector come from real engine
// math; a non-finite value is a corruption/poisoning signal, and JSON cannot encode
// it deterministically anyway. Surfacing it as a hard error (vs canonicalizing to a
// sentinel) means a poisoned value can NEVER make a real decision go unrecorded — it
// fails loudly at Capture instead.
func validateFinite(r *AuditRecord) error {
	if math.IsNaN(r.Score) || math.IsInf(r.Score, 0) {
		return fmt.Errorf("audit: refusing to record non-finite Score (%v) — a poisoned/pathological value must not silently drop a real decision", r.Score)
	}
	for k, v := range r.Features {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("audit: refusing to record non-finite Feature %q (%v) — a poisoned/pathological value must not silently drop a real decision", k, v)
		}
	}
	return nil
}

// computeHash returns the chain link over (prevHead || canonicalPreimage(r)). With
// key==nil it is sha256(prevHead || preimage) (the unkeyed, public, back-compat
// chain); with a key it is HMAC-SHA256(key, prevHead || preimage) — the keyed
// anchor a file-only attacker (lacking the key) cannot recompute. The record's
// PrevHash field MUST already be set to prevHead (it is part of the preimage too,
// belt-and-suspenders against a reorder), and Keyed/Algo MUST already be stamped to
// match key (they are in the preimage, so a downgrade breaks recompute).
func computeHash(key, prevHead []byte, r *AuditRecord) ([]byte, error) {
	pre, err := canonicalPreimage(r)
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
	h.Write(prevHead)
	h.Write(pre)
	return h.Sum(nil), nil
}

// Store is the per-scope tamper-evident audit-chain store. It holds the
// authoritative in-memory per-scope head and appends each record to the durable
// persist.Store so the chain CONTINUES across a reboot. The head update and the
// record append commit in ONE bbolt transaction (persist.AppendAuditAndHead), so a
// crash never leaves the head and the record inconsistent. All head access is
// under s.mu; records are never written on the observe hot path (only from the
// engine Submit capture seam, which already runs serially per flow, and from the
// slice-B Append API).
type Store struct {
	mu    sync.Mutex
	heads map[contract.ScopeKey][]byte // per-scope current chain head (in-memory mirror of the durable head)

	store *persist.Store // durable backing; nil => in-memory only (tests)

	// hmacKey is the optional keyed-anchor key (FIX 1). When non-empty the chain
	// links are HMAC-SHA256(key, ...) and a file-only attacker lacking this key
	// cannot forge a chain Verify accepts; when empty the chain is the unkeyed,
	// public sha256 chain (back-compat). Held in memory only — NEVER persisted to
	// baseline.db (that is the whole point: an attacker with the DB must not have
	// the key). A defensive copy of the caller's key.
	hmacKey []byte

	// mem holds the full in-memory chain per scope when store == nil (no DB / tests).
	// With a durable store this stays nil and the records live on disk (read by
	// Verify/Export via the persist range); only the head mirror (heads) is in memory.
	mem map[contract.ScopeKey]*memChain
}

// memChain is one scope's in-memory chain, used only in the no-DB mode.
type memChain struct {
	records []*AuditRecord
}

// Config configures an audit Store. The zero value is the unkeyed, back-compat
// chain (sha256 links). Set HMACKey to enable the keyed anchor (HMAC-SHA256 links,
// FIX 1) — held outside baseline.db so a file-only attacker cannot recompute valid
// links. The key is sourced at boot from -audit-hmac-key (a key FILE, not the DB);
// it is never stored.
type Config struct {
	// HMACKey, when non-empty, keys the chain with HMAC-SHA256. nil/empty => the
	// unkeyed sha256 chain (the default). The Store keeps a private copy.
	HMACKey []byte
}

// New returns an UNKEYED audit Store backed by store (nil => in-memory only, for
// tests) — the back-compat constructor (sha256 links). Use NewWithConfig to enable
// the keyed anchor. New panics only if rehydration surfaces a read error (see
// NewWithConfig, which returns it); New keeps the historical never-error signature
// for existing callers by logging+ignoring a rehydrate error is NOT acceptable for
// an integrity-bearing store, so New delegates and treats a rehydrate error as a
// boot-fatal panic. Prefer NewWithConfig in new code so the caller handles it.
func New(store *persist.Store) *Store {
	s, err := NewWithConfig(store, Config{})
	if err != nil {
		// An unreadable audit chain on boot is integrity-bearing: refuse rather than
		// silently disable truncation detection (FIX 2). New's signature predates the
		// error return; NewWithConfig is the error-returning constructor new callers use.
		panic(fmt.Sprintf("audit: New: rehydrate failed (integrity-bearing): %v", err))
	}
	return s
}

// NewWithConfig returns an audit Store backed by store (nil => in-memory only) with
// cfg applied. It rehydrates the durable per-scope chain heads so an appended record
// continues the existing chain across a reboot, and SURFACES a rehydrate read error
// (FIX 2) rather than swallowing it — the chain is integrity-bearing, so a failure
// to read the persisted heads must not silently disable truncation detection.
func NewWithConfig(store *persist.Store, cfg Config) (*Store, error) {
	s := &Store{
		heads: map[contract.ScopeKey][]byte{},
		store: store,
	}
	if len(cfg.HMACKey) > 0 {
		s.hmacKey = append([]byte(nil), cfg.HMACKey...)
	}
	if store == nil {
		s.mem = map[contract.ScopeKey]*memChain{}
	}
	if err := s.rehydrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Keyed reports whether this Store keys its chain with the HMAC anchor. Surfaced so
// a caller / test can assert the configured threat model.
func (s *Store) Keyed() bool { return len(s.hmacKey) > 0 }

// algoName returns the link-function marker for this store's mode.
func (s *Store) algoName() string {
	if s.Keyed() {
		return AlgoHMACSHA256
	}
	return AlgoSHA256
}

// rehydrate loads the durable per-scope chain heads into memory on boot (mirror of
// l7events.rehydrate). A scope with no persisted head is simply absent here; its
// first append seeds from genesis. The chain RECORDS stay on disk and are read
// only by Verify/Export — only the head is needed in memory to continue the chain.
//
// FIX 2: a GetAuditHead error is SURFACED (returned), never swallowed. The chain is
// integrity-bearing — if the persisted head for a scope cannot be read, the in-
// memory head mirror would be silently absent and Verify's tail-truncation check
// (which compares the recomputed head against the tracked head) would be disabled
// for that scope, hiding a truncation. A read error on boot is therefore fatal to
// the caller (NewWithConfig returns it), not best-effort.
func (s *Store) rehydrate() error {
	if s.store == nil {
		return nil
	}
	var firstErr error
	rerr := s.store.RangeAuditChainScopes(func(sc contract.ScopeKey) error {
		head, ok, err := s.store.GetAuditHead(sc)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("audit: rehydrate head for scope %q: %w", sc, err)
			}
			return err
		}
		if ok {
			s.heads[sc] = head
		}
		return nil
	})
	if firstErr != nil {
		return firstErr
	}
	if rerr != nil {
		return fmt.Errorf("audit: rehydrate audit chain scopes: %w", rerr)
	}
	return nil
}

// DecisionInput is the action+identity+posture context captured for one Tier>=Tag
// decision at the engine Submit seam. The caller (internal/boot) fills it from the
// resolved verdict, the canary touched, the join cookie, the L7/identity context,
// the feature vector, and any reachable posture — all of which are already in hand
// at the seam (no second store read).
type DecisionInput struct {
	Scope        contract.ScopeKey
	Canary       contract.CanaryType
	SocketCookie uint64
	Verdict      contract.Verdict
	// L7 + identity context (raw, deployment-local), pulled by the caller from the
	// flow (mirror of l7events.FromFlow).
	SourceAddress string
	Method        string
	Path          string
	SPIFFEID      string
	Features      map[string]float64
	// StingMechanism is the attrition/containment mechanism if known at the seam
	// (usually "" — the outcome is still zero at Submit).
	StingMechanism string
	// Posture holds any extra reachable posture facts (never fabricated). nil => none.
	Posture map[string]string
	// Now is the decision wall-clock (ev.Timestamp).
	Now time.Time
}

// Capture appends one tamper-evident DECISION record for a Tier>=Tag verdict. It is
// the SLICE-A capture API, called from the engine Submit seam (internal/boot)
// beside the existing CaptureVerdict + l7events.Capture, on the SAME (ev, v,
// feats). It is GATED to actual touches (Tier>=Tag — the SAME gate as
// boltevents.CaptureVerdict / l7events.Capture); an Observe-tier touch is not
// recorded. in.Scope MUST be the RESOLVED scope (v.Scope after the B1 correction),
// never the wire scope (rule 5).
//
// Unlike the best-effort siblings, a chain-write error is RETURNED, not swallowed:
// the chain is integrity-bearing, so a lost head update would silently break later
// verification. The caller decides what to do with the error (log it); it must not
// be silently dropped. Returns nil (no error) when not retained (Tier<Tag) or when
// scope is empty (refuse unscoped) — those are not failures.
func (s *Store) Capture(in DecisionInput) error {
	v := in.Verdict
	if v.Tier < contract.TierTag {
		return nil // Observe-tier touches are not retained (mirror boltevents/l7events)
	}
	if in.Scope == "" {
		return nil // never store unscoped
	}
	rec := &AuditRecord{
		EventID:              eventID(in.Scope, in.SocketCookie, in.Now),
		Timestamp:            in.Now,
		Scope:                string(in.Scope),
		Kind:                 KindDecision,
		CanaryType:           string(in.Canary),
		SocketCookie:         in.SocketCookie,
		Tier:                 int(v.Tier),
		Verdict:              tierName(v.Tier),
		Action:               tierName(v.Tier),
		Score:                v.Score,
		StingMechanism:       in.StingMechanism,
		Mode:                 int(v.Mode),
		Calibrated:           v.Calibrated,
		Posture:              copyStrings(in.Posture),
		SourceAddress:        in.SourceAddress,
		Method:               in.Method,
		Path:                 in.Path,
		SPIFFEID:             in.SPIFFEID,
		Features:             copyFeatures(in.Features),
		BytesRealDataCrossed: 0, // structural: a canary touch crosses zero real bytes
	}
	return s.append(in.Scope, rec)
}

// OperatorAction is the slice-B operator-action input: an action the OPERATOR took
// (e.g. a kill-switch toggle) that should be recorded into the SAME per-scope chain
// as the decision records, so the chain is a single tamper-evident timeline of both
// engine decisions and operator actions. SLICE A only PROVIDES this API; no
// operator action is wired into it in this slice.
type OperatorAction struct {
	Scope contract.ScopeKey
	// Action is the human-facing action label (e.g. "kill_switch_on").
	Action string
	// SocketCookie / SourceAddress / SPIFFEID are optional identity context for an
	// action scoped to a flow/actor (0/"" when the action is deployment-wide).
	SocketCookie  uint64
	SourceAddress string
	SPIFFEID      string
	// Posture holds any posture facts to record with the action (never fabricated).
	Posture map[string]string
	// Now is the action wall-clock.
	Now time.Time
}

// Append records one OPERATOR-ACTION record into the same per-scope chain (slice-B
// API). It is the seam slice B writes operator actions through; SLICE A wires no
// operator action into it. Refuses an empty scope (never store unscoped). A
// chain-write error is returned (integrity-bearing, not best-effort).
func (s *Store) Append(a OperatorAction) error {
	if a.Scope == "" {
		return fmt.Errorf("audit: operator action has no scope; refusing to store unscoped")
	}
	rec := &AuditRecord{
		EventID:              eventID(a.Scope, a.SocketCookie, a.Now),
		Timestamp:            a.Now,
		Scope:                string(a.Scope),
		Kind:                 KindOperator,
		SocketCookie:         a.SocketCookie,
		Verdict:              a.Action,
		Action:               a.Action,
		Posture:              copyStrings(a.Posture),
		SourceAddress:        a.SourceAddress,
		SPIFFEID:             a.SPIFFEID,
		BytesRealDataCrossed: 0,
	}
	return s.append(a.Scope, rec)
}

// append is the single chain-advance path shared by Capture and Append: it reads
// the current per-scope head, computes the new record's Hash from it, and commits
// the record + the new head atomically. The read-of-prev-head and the write happen
// inside one bbolt transaction (persist.AppendAuditAndHead) so concurrent appends
// in the same scope cannot fork the chain. The in-memory head mirror is updated
// only AFTER the durable commit succeeds.
func (s *Store) append(scope contract.ScopeKey, rec *AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// FIX A (write-side assert, defense-in-depth): the record's Scope MUST equal the
	// bucket scope it is being appended into. Capture/Append set rec.Scope from the
	// same scope they pass here, so a mismatch can only come from internal mis-wiring
	// (a future caller threading the wrong scope) — refuse loudly rather than write a
	// record whose Scope field disagrees with its chain location (which Verify would
	// later flag as a cross-scope break). Cheap, and it catches the bug at write time.
	if rec.Scope != string(scope) {
		return fmt.Errorf("audit: refusing to append record stamped scope %q into scope %q bucket (rule 5 scope-binding)", rec.Scope, scope)
	}

	if s.store == nil {
		return s.appendInMemory(scope, rec)
	}

	// Stamp the mode marker into the record BEFORE hashing so it is part of the
	// preimage (a downgrade/algo-swap then breaks recompute).
	rec.Keyed = s.Keyed()
	rec.Algo = s.algoName()

	// FIX 3: validate finiteness BEFORE entering the bbolt transaction so a non-
	// finite Score/Feature is a clean, surfaced failure that touches no on-disk
	// state — never a half-applied append or a silent drop.
	if err := validateFinite(rec); err != nil {
		return err
	}

	var newHead []byte
	var mkErr error
	_, err := s.store.AppendAuditAndHead(scope, func(prevHead []byte, seq uint64) (recordBlob, nh []byte, err error) {
		if prevHead == nil {
			prevHead = genesis(s.hmacKey, scope) // per-scope genesis seed for a fresh scope / pre-upgrade db
		}
		// Seq is assigned inside the transaction and is part of the hashed preimage,
		// so a record's position is bound into its hash (a reorder breaks recompute).
		rec.Seq = seq
		rec.PrevHash = prevHead
		h, err := computeHash(s.hmacKey, prevHead, rec)
		if err != nil {
			mkErr = err
			return nil, nil, err
		}
		rec.Hash = h
		newHead = h
		blob, err := encodeRecord(rec)
		if err != nil {
			mkErr = err
			return nil, nil, err
		}
		return blob, h, nil
	})
	if err != nil {
		if mkErr != nil {
			// Surface the build error (e.g. a non-finite value caught in the preimage)
			// rather than the generic bbolt wrapper, so the caller sees the real cause.
			return mkErr
		}
		return fmt.Errorf("audit: append chain record: %w", err)
	}
	s.heads[scope] = newHead
	return nil
}

// appendInMemory advances a scope's chain in the no-DB mode. It mirrors the
// durable semantics exactly (same genesis, same hashing, same 1-based monotonic
// seq) so the chain validates identically. The caller holds s.mu.
func (s *Store) appendInMemory(scope contract.ScopeKey, rec *AuditRecord) error {
	prev := s.heads[scope]
	if prev == nil {
		prev = genesis(s.hmacKey, scope)
	}
	mc := s.mem[scope]
	if mc == nil {
		mc = &memChain{}
		s.mem[scope] = mc
	}
	rec.Seq = uint64(len(mc.records)) + 1
	rec.PrevHash = prev
	rec.Keyed = s.Keyed()
	rec.Algo = s.algoName()
	h, err := computeHash(s.hmacKey, prev, rec)
	if err != nil {
		return fmt.Errorf("audit: append chain record (in-memory): %w", err)
	}
	rec.Hash = h
	// Store a deep copy so a caller mutating the passed record cannot retro-alter
	// the stored chain (matches the durable path, which serializes to a blob).
	stored := *rec
	stored.Features = copyFeatures(rec.Features)
	stored.Posture = copyStrings(rec.Posture)
	mc.records = append(mc.records, &stored)
	s.heads[scope] = h
	return nil
}

// --- chain read APIs (slice B / report view consume these) ------------------

// VerifyResult is the outcome of recomputing a scope's chain start-to-head.
type VerifyResult struct {
	Scope string `json:"scope"`
	// Intact is true iff every link recomputes (no edited/removed/reordered record).
	Intact bool `json:"intact"`
	// Count is the number of records walked.
	Count int `json:"count"`
	// BrokenAtSeq is the Seq of the FIRST broken link when !Intact (0 when intact).
	// A break at seq N means the record at chain position N (or the link into it)
	// does not recompute — every record from N onward is suspect.
	BrokenAtSeq uint64 `json:"broken_at_seq,omitempty"`
	// Reason is a short human-readable cause for the first break ("" when intact).
	Reason string `json:"reason,omitempty"`
	// Keyed states whether the VERIFYING store used the keyed HMAC anchor, and Algo
	// names its link function. They make the threat model explicit in the result: an
	// "Intact: true" from a KEYED verify is tamper-evidence against a file-only
	// adversary lacking the key; from an UNKEYED verify it is only corruption /
	// naive-edit evidence (see the package THREAT MODEL). They report the verifier's
	// mode, not a per-record claim — a record whose stamped Keyed/Algo disagree with
	// the verifier is reported as a break.
	Keyed bool   `json:"keyed"`
	Algo  string `json:"algo"`
}

// chainRecords returns one scope's full chain in ascending seq order. With a
// durable store it reads the persisted blobs; in the no-DB mode it copies the
// in-memory chain. The returned records are owned by the caller (deep-copied).
func (s *Store) chainRecords(scope contract.ScopeKey) ([]*AuditRecord, error) {
	if s.store == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		mc := s.mem[scope]
		if mc == nil {
			return nil, nil
		}
		out := make([]*AuditRecord, 0, len(mc.records))
		for _, r := range mc.records {
			cp := *r
			cp.Features = copyFeatures(r.Features)
			cp.Posture = copyStrings(r.Posture)
			out = append(out, &cp)
		}
		return out, nil
	}
	var out []*AuditRecord
	err := s.store.RangeAuditChain(scope, func(seq uint64, blob []byte) error {
		r, err := decodeRecord(blob)
		if err != nil {
			// An undecodable blob is a chain break we surface (NOT skip-not-silent):
			// the chain is integrity-bearing, so a missing/garbled record must show up
			// as a break, not be silently dropped. Carry the seq so Verify reports it.
			// Stamp the placeholder with the verifying scope + the store's mode marker so
			// the FIX-A scope-binding and mode-marker pre-checks pass and the break lands
			// on the more-specific "hash does not recompute" step (the real fault is a
			// garbled record, not a relocation/mode-swap).
			out = append(out, &AuditRecord{Seq: seq, Scope: string(scope), Keyed: s.Keyed(), Algo: s.algoName(), Hash: nil, PrevHash: nil, Verdict: "<undecodable>"})
			return nil
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

// Verify recomputes scope's chain from genesis to head and reports whether it is
// intact and, if not, the seq of the FIRST broken/altered/missing/reordered/
// relocated link. It is the examiner / slice-B tamper-detection read: any edited
// record (its Hash no longer matches its recomputed preimage), any removed record
// (the seq sequence jumps), any reorder (a record's PrevHash no longer equals the
// prior record's Hash), or any cross-scope relocation (a record's Scope field, and
// its chain-from-genesis seed, no longer match the verifying scope) breaks
// recomputation from that point. An empty chain is intact (trivially).
//
// THREAT MODEL — what an "Intact: true" actually attests depends on the store mode
// (VerifyResult.Keyed/Algo report which):
//
//	KEYED (this store has HMACKey): recompute uses HMAC-SHA256 with the SAME key. A
//	writer with baseline.db access but WITHOUT the key cannot produce links Verify
//	accepts, so an edit, removal, reorder, cross-scope relocation, or full re-forge
//	(edit + recompute downstream + head) is DETECTED — the recomputed MACs will not
//	match the forged ones (and a relocation also fails the per-record scope check +
//	the per-scope genesis seed). A tail truncation is detected when the persisted head
//	still attests the original count. An "Intact: true" here is tamper-evidence
//	against a knowledgeable file-only adversary, MODULO the two residuals below.
//
//	UNKEYED (no HMACKey): recompute uses public sha256. An "Intact: true" attests
//	only that the chain has not suffered accidental corruption or a NAIVE edit (one
//	that did not re-run the public chain). A knowledgeable DB-write adversary can
//	edit a record and recompute every downstream sha256 link + the head (over the
//	public, recomputable per-scope seed), and this Verify will still report Intact. Do
//	NOT read an unkeyed Intact as tamper-evidence against such an adversary.
//
//	THE TWO RESIDUALS not detected in EITHER mode, both needing an EXTERNAL WITNESS:
//	  (a) TRUNCATE-TO-A-VALID-PREFIX + HEAD-REWRITE: drop the tail AND rewrite the head
//	      to a surviving record's already-valid hash — the recomputed head over the
//	      surviving prefix matches, so it is indistinguishable in-band.
//	  (b) WHOLE-SCOPE ERASURE: delete a scope's entire chain (records + head) — nothing
//	      is left to recompute, so Verify reports a fresh/empty scope as Intact.
//	Detecting either requires an EXTERNAL witness — a per-scope head / high-water-mark
//	periodically published to the SIEM emitter or a WORM sink, so a later "scope empty
//	or shorter than the witness saw N records" is provable. ROADMAP, not provided here.
//	(Cross-scope relocation is NOT a residual — it is now detected; see check (0).)
//
// FIX 2: if a scope holds RECORDS but the store has NO tracked head for it, that is
// itself reported as a BREAK (not Intact, not skipped) — once a chain has records an
// absent head is evidence of head loss/tampering/corruption (and would otherwise
// silently disable the tail-truncation check below).
func (s *Store) Verify(scope contract.ScopeKey) (VerifyResult, error) {
	recs, err := s.chainRecords(scope)
	if err != nil {
		return VerifyResult{Scope: string(scope), Keyed: s.Keyed(), Algo: s.algoName()}, err
	}
	res := VerifyResult{Scope: string(scope), Intact: true, Count: len(recs), Keyed: s.Keyed(), Algo: s.algoName()}
	wantAlgo := s.algoName()
	wantKeyed := s.Keyed()
	prevHead := genesis(s.hmacKey, scope) // FIX A: per-scope, key-bound seed
	var expectedSeq uint64 = 1
	for _, r := range recs {
		// (0) FIX A (relocation, PRIMARY defense): every record is BOUND to its scope —
		// the record's own Scope field must equal the scope being verified. A chain
		// lifted into another scope's bucket (the cross-scope relocation forgery)
		// carries the ORIGINAL scope in this field, so it fails here immediately. This
		// is the in-band field-check; the per-scope-seeded genesis above is the
		// defense-in-depth layer that breaks the relocated chain at the prev-hash step
		// even if this check were removed.
		if r.Scope != string(scope) {
			return brokenAt(res, r.Seq, fmt.Sprintf("cross-scope relocation: record stamped scope %q found in scope %q's chain (rule 5 scope-binding)", r.Scope, scope)), nil
		}
		// (1) seq must be contiguous and monotonic from 1 — a removed record leaves a
		// gap; a reorder breaks monotonicity.
		if r.Seq != expectedSeq {
			return brokenAt(res, r.Seq, fmt.Sprintf("seq gap/reorder: expected %d, found %d", expectedSeq, r.Seq)), nil
		}
		// (2) the record's stamped mode must match the verifier's mode. A keyed store
		// re-hashing an unkeyed record (or vice-versa) would never recompute, but we
		// report the SPECIFIC cause so an examiner sees a mode mismatch (e.g. a record
		// spliced in from a chain built under the other mode), not a generic alteration.
		if r.Keyed != wantKeyed || r.Algo != wantAlgo {
			return brokenAt(res, r.Seq, fmt.Sprintf("record mode marker mismatch: record keyed=%v algo=%q, verifier keyed=%v algo=%q", r.Keyed, r.Algo, wantKeyed, wantAlgo)), nil
		}
		// (3) the link must chain: this record's PrevHash must equal the prior head.
		if subtle.ConstantTimeCompare(r.PrevHash, prevHead) != 1 {
			return brokenAt(res, r.Seq, "prev-hash does not match prior record's hash (reordered/removed/edited prior link)"), nil
		}
		// (4) the record's own Hash must recompute from link(key, prevHead || preimage)
		// — a genuine recompute with the verifier's key, so any edited field surfaces
		// here, and (keyed) a forger lacking the key cannot satisfy it.
		want, herr := computeHash(s.hmacKey, prevHead, r)
		if herr != nil {
			return brokenAt(res, r.Seq, "record could not be canonically re-encoded"), nil
		}
		if subtle.ConstantTimeCompare(want, r.Hash) != 1 {
			return brokenAt(res, r.Seq, "record hash does not recompute (record altered or not produced with the verifying key)"), nil
		}
		prevHead = r.Hash
		expectedSeq++
	}
	// The recomputed final head must match the store's tracked head (a truncation —
	// removing the LAST record(s) — leaves the seq contiguous and every remaining
	// link valid, so it is caught only here, against the persisted head). FIX 2:
	// records-present-but-no-tracked-head is itself a break.
	head, ok := s.headFor(scope)
	if len(recs) > 0 && !ok {
		return brokenAt(res, expectedSeq, "chain has records but the store has no tracked/persisted head (head lost/tampered — truncation detection would otherwise be silently disabled)"), nil
	}
	if ok {
		if len(recs) == 0 || subtle.ConstantTimeCompare(prevHead, head) != 1 {
			return brokenAt(res, expectedSeq, "chain shorter than the persisted head (record(s) truncated from the tail)"), nil
		}
	}
	return res, nil
}

// headFor returns the store's tracked head for a scope (the in-memory mirror /
// durable head). ok=false when the scope has no chain (genesis).
func (s *Store) headFor(scope contract.ScopeKey) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.heads[scope]
	return h, ok
}

func brokenAt(res VerifyResult, seq uint64, reason string) VerifyResult {
	res.Intact = false
	res.BrokenAtSeq = seq
	res.Reason = reason
	return res
}

// CaseReport is the stable JSON shape Export serializes — the IR-handoff case
// report slice B / the report view consume. It is the full chain (records WITH
// their hashes) plus the verify result, so an examiner gets both the evidence and
// its integrity verdict in one document.
type CaseReport struct {
	Scope   string        `json:"scope"`
	Records []AuditRecord `json:"records"`
	Verify  VerifyResult  `json:"verify"`
}

// Export serializes scope's full chain (records + their hashes + the verify
// result) as the stable-JSON IR-handoff case report. It is READ-SIDE ONLY (rule 8)
// and LOCAL-ONLY (rule 9): the raw addresses/paths stay in the deployment; this
// accessor lives in a package the egress filter is structurally forbidden to
// import. The verify result is recomputed at export time so the report carries a
// fresh integrity verdict (an examiner never trusts a stale "intact" flag).
func (s *Store) Export(scope contract.ScopeKey) ([]byte, error) {
	recs, err := s.chainRecords(scope)
	if err != nil {
		return nil, err
	}
	vr, err := s.Verify(scope)
	if err != nil {
		return nil, err
	}
	out := make([]AuditRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, *r)
	}
	report := CaseReport{Scope: string(scope), Records: out, Verify: vr}
	return json.MarshalIndent(report, "", "  ")
}

// Scopes returns the set of scopes that currently hold a chain — the enumerator a
// reader uses to discover which scopes to verify/export. Rule 5: it lists the
// scope KEYS the store already partitions on; it never merges across scopes.
func (s *Store) Scopes() []contract.ScopeKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]contract.ScopeKey, 0, len(s.heads))
	for sc := range s.heads {
		out = append(out, sc)
	}
	return out
}

func encodeRecord(r *AuditRecord) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeRecord(blob []byte) (*AuditRecord, error) {
	r := &AuditRecord{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(r); err != nil {
		return nil, err
	}
	return r, nil
}

func copyFeatures(f map[string]float64) map[string]float64 {
	if f == nil {
		return nil
	}
	out := make(map[string]float64, len(f))
	for k, v := range f {
		out[k] = v
	}
	return out
}

func copyStrings(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// eventID builds a stable per-record id from the resolved scope, the join cookie,
// and the record wall nanos. It is deployment-local and identity-bearing only in
// the same sense as the rest of the record (it never crosses the egress path).
func eventID(scope contract.ScopeKey, cookie uint64, at time.Time) string {
	h := fnv.New64a()
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], cookie)
	binary.BigEndian.PutUint64(b[8:16], uint64(at.UnixNano()))
	_, _ = h.Write(b[:])
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], h.Sum64())
	return string(scope) + ":" + hexEncode(out[:])
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

func tierName(t contract.Tier) string {
	switch t {
	case contract.TierObserve:
		return "observe"
	case contract.TierTag:
		return "tag"
	case contract.TierContain:
		return "contain"
	case contract.TierJail:
		return "jail"
	default:
		return "unknown"
	}
}
