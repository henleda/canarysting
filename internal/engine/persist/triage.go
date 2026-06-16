package persist

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/canarysting/canarysting/internal/contract"
)

// DEVIANT TRIAGE OVERLAY (the operator ACK/SUPPRESS store). This is a SEPARATE
// per-scope overlay keyed by the deviant CANONICAL RECURRENCE KEY (the byte string
// from observebaseline.deviantKey) -> a small triage record. It is the durable home
// of an operator's "I've seen this, keep showing it" (acked) or "this is
// known-benign, hide it from the default list" (suppressed) decision on a deviant
// PATTERN.
//
// LIFECYCLE DECOUPLING (load-bearing): the overlay is INDEPENDENT of bktDeviants.
// A DeviantFlowRecord is mutated on recapture, destroyed on cap-evict/TTL-reap, and
// re-created with HitCount=1 on recurrence — so it is NOT a stable identity. The
// canonical recurrence key IS the stable identity, and the overlay is keyed by it.
// An overlay row is NEVER deleted when its underlying DeviantFlowRecord is reaped or
// evicted; it is deleted ONLY by an explicit operator unsuppress/un-ack
// (DeleteDeviantTriage). So a suppressed pattern that goes quiet for 30d, is
// TTL-reaped from bktDeviants, then recurs (re-created under the identical key) is
// STILL suppressed. The overlay gets its own optional GC (or none), never the
// 30-day record TTL.
//
// RULE 8 (load-bearing): this overlay is read ONLY on the DISPLAY/read side (the
// dashboard tap + backend view). It is NEVER in the dependency closure of the
// verdict path — it is not a scoring.BenignExcluder and not an
// observebaseline.MaliciousSet, so suppressing a deviant CANNOT exclude it from
// detection, change scoring/baseline, or touch arming. A suppressed mover that
// later touches a canary STILL arms. The triage_importguard_test asserts no
// internal/engine scoring/baseline/observebaseline package reaches this accessor.
//
// RULE 9 (local): like every other store here the overlay holds local data
// (the attributed SrcAddr is display-only) and never crosses a deployment boundary;
// the egress import guard already forbids the egress filter from importing persist.

// bktDeviantTriage is the top-level bucket for the operator triage overlay. It is
// added the SAME tolerant way as bktTopology/bktDeviants/bktL7Touches/bktAuditChain
// (CreateBucketIfNotExists in Open) and is intentionally NOT gated behind a
// SchemaVersion bump: an existing multi-week baseline.db that predates it must keep
// opening (the create is a no-op when present, a fresh empty bucket when absent —
// never a re-decode of stale blobs). Layout: scope -> {deviantKey -> gob blob of
// DeviantTriageRecord}.
var bktDeviantTriage = []byte("deviant_triage")

// Triage state strings. These mirror the wire/display states the dashboard and
// canaryctl use. The absence of an overlay row is the implicit "" (normal) state;
// only "acked" and "suppressed" are ever stored.
const (
	// TriageAcked = SEEN-BUT-KEEP-SHOWING. The operator looked at the pattern; it
	// stays in the default ranked list, just badged and demoted within its group.
	TriageAcked = "acked"
	// TriageSuppressed = KNOWN-BENIGN-HIDE. Excluded from the default ranked list
	// (still counted in the summary, still visible behind the view-suppressed toggle).
	TriageSuppressed = "suppressed"
)

// DeviantTriageRecord is one operator triage decision on a deviant recurrence key.
// It is gob-encoded under (scope, deviantKey). All fields are facts of the operator
// action (never fabricated). SrcAddr is the attributed initiator address at the time
// of the action — display/attribution ONLY, never part of the key (the same key
// shape collides across dst/port/peak-dim, so SrcAddr cannot be the identity).
type DeviantTriageRecord struct {
	State string    // "acked" | "suppressed"
	By    string    // verified-or-advisory operator name (boot.OperatorIdentity.Name)
	When  time.Time // wall-clock of the action
	Why   string    // operator-supplied reason, recorded for the trail
	// SrcAddr is the attributed initiator address (display only). It is NOT the join
	// key — the join key is the deviantKey the row is stored under.
	SrcAddr string
}

// encodeTriage / decodeTriage are the gob (de)serializers for the overlay blob,
// mirroring encodeDeviant/decodeDeviant.
func encodeTriage(r DeviantTriageRecord) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeDeviantTriage decodes one overlay blob. Exported so the display side (the
// tap) can decode a blob handed back by RangeDeviantTriage without importing the
// gob wire shape twice.
func DecodeDeviantTriage(blob []byte) (DeviantTriageRecord, error) {
	var r DeviantTriageRecord
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&r); err != nil {
		return DeviantTriageRecord{}, err
	}
	return r, nil
}

// PutDeviantTriage writes one overlay record (acked|suppressed) for (scope, key) in
// its OWN small transaction. It mirrors the out-of-band single-transaction shape of
// PutL7Touches rather than wedging into the fold-tick PutBucketsAndHeartbeat batch —
// an operator triage action is interactive and low-frequency, not a hot-path fold.
// This is a SECOND writer, but to a SEPARATE bucket, so it does not touch the
// single-writer invariant of bktDeviants itself. The blob is the gob-encoded
// DeviantTriageRecord. Refused on a read-only store and on an empty scope/key.
func (s *Store) PutDeviantTriage(scope contract.ScopeKey, key []byte, rec DeviantTriageRecord) error {
	if s.readOnly {
		return ErrReadOnly
	}
	if scope == "" {
		// Defended one layer down (putNested -> scopeSub refuses an empty scope), but
		// reject explicitly for symmetry with DeleteDeviantTriage and a clear error.
		return errors.New("persist: empty scope in triage write")
	}
	if len(key) == 0 {
		return errors.New("persist: empty deviant key in triage write")
	}
	if rec.State != TriageAcked && rec.State != TriageSuppressed {
		return errors.New("persist: triage state must be \"acked\" or \"suppressed\"")
	}
	blob, err := encodeTriage(rec)
	if err != nil {
		return err
	}
	return s.putNested(bktDeviantTriage, scope, key, blob)
}

// DeleteDeviantTriage removes the overlay row for (scope, key) — the unsuppress /
// un-ack path, which CLEARS the triage state by deleting the row (absent = normal).
// Idempotent: deleting an absent key is a no-op success. Refused on a read-only
// store. This is the ONLY way an overlay row is removed (it is decoupled from the
// bktDeviants TTL/cap reaper, so a reaped-then-recurring suppressed pattern stays
// suppressed until the operator explicitly clears it here).
func (s *Store) DeleteDeviantTriage(scope contract.ScopeKey, key []byte) error {
	if s.readOnly {
		return ErrReadOnly
	}
	if len(key) == 0 {
		return errors.New("persist: empty deviant key in triage delete")
	}
	if scope == "" {
		return errors.New("persist: empty scope in triage delete")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktDeviantTriage, scope, false)
		if err != nil || sb == nil {
			return err // absent scope sub-bucket => nothing to delete
		}
		return sb.Delete(append([]byte(nil), key...))
	})
}

// GetDeviantTriage returns the overlay record for (scope, key), ok=false if there is
// no triage row (the implicit "" normal state). Used by the admin handler to report
// the resulting state back to the operator after a write/delete.
func (s *Store) GetDeviantTriage(scope contract.ScopeKey, key []byte) (DeviantTriageRecord, bool, error) {
	blob, ok, err := s.getNested(bktDeviantTriage, scope, key)
	if err != nil || !ok {
		return DeviantTriageRecord{}, false, err
	}
	rec, derr := DecodeDeviantTriage(blob)
	if derr != nil {
		return DeviantTriageRecord{}, false, derr
	}
	return rec, true, nil
}

// RangeDeviantTriage calls fn for every (deviantKey, DeviantTriageRecord) under
// scope. It is the read accessor the tap loads the overlay through at
// snapshot/build time to join triage state onto each surfaced deviant row. A decode
// error on any row is returned (the overlay is small and operator-written; a
// corrupt row is a fault to surface, not silently skip). blob bytes are decoded into
// an owned value before fn is called, so fn may retain the record.
func (s *Store) RangeDeviantTriage(scope contract.ScopeKey, fn func(key []byte, rec DeviantTriageRecord) error) error {
	return s.rangeNested(bktDeviantTriage, scope, func(k, v []byte) error {
		rec, err := DecodeDeviantTriage(v)
		if err != nil {
			return err
		}
		return fn(append([]byte(nil), k...), rec)
	})
}

// RangeDeviantTriageScopes calls fn for every scope that has any persisted triage
// overlay row, independently of baseline-bucket presence (the overlay accrues
// through its own write path). Mirrors RangeDeviantScopes.
func (s *Store) RangeDeviantTriageScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktDeviantTriage)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}
