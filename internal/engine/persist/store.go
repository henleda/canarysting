package persist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/canarysting/canarysting/internal/contract"
)

// SchemaVersion is bumped on any breaking change to a persisted blob layout.
// On open, a mismatch is reported so the caller can decide to migrate or discard
// (it never silently mis-decodes a stale gob blob). See Open.
const SchemaVersion = 1

// Top-level bbolt buckets. Each (except meta) nests one sub-bucket per scope key,
// so scope isolation (CLAUDE.md rule 5) is enforced by the storage layout itself.
var (
	bktBaseline   = []byte("baseline")   // scope -> {windowBucketKey -> aggregate gob blob}
	bktMalicious  = []byte("malicious")  // scope -> {8-byte idHash -> 1} (confirmed-malicious identities)
	bktEvents     = []byte("events")     // scope -> {8-byte seq -> event gob blob}
	bktTopology   = []byte("topology")   // scope -> {edgeKey|nodeKey -> gob record blob} (F1 learned east-west topology, local-rich)
	bktDeviants   = []byte("deviants")   // scope -> {deviantKey -> gob record blob} (F2 rich non-tripwire deviant log, local-rich)
	bktL7Touches  = []byte("l7touches")  // scope -> {touchKey -> gob record blob} (slice-1 enriched canary-touch record, local-rich)
	bktAuditChain = []byte("auditchain") // scope -> { "records" sub-bucket: 8-byte seq -> audit record blob ; "head" key -> 32-byte chain head } (SLICE-A tamper-evident hash-chained audit log, local-rich)
	bktMeta       = []byte("meta")       // global -> {metaKey -> blob} (heartbeat, schema)
)

// Keys WITHIN a per-scope audit-chain bucket (bktAuditChain/<scope>). The chain
// records ride a nested "records" sub-bucket so they own a private monotonic
// sequence (NextSequence) independent of any other store; the per-scope chain
// head is a single fixed value key alongside it. Head and the appended record
// commit in ONE transaction (AppendAuditAndHead) so a crash can never leave the
// head ahead of (or behind) the record it attests.
var (
	auditRecordsSub = []byte("records") // sub-bucket under bktAuditChain/<scope>: 8-byte seq -> record blob
	auditHeadKey    = []byte("head")    // value key under bktAuditChain/<scope>: the 32-byte chain head
)

// Meta keys under bktMeta (global, not scope-partitioned — these are about the
// window process lifecycle, not learned state).
const (
	metaSchemaVersion   = "schema_version"
	metaLastObserveSeen = "last_observe_seen" // heartbeat: last successful observe fold
)

// Store is the durable, scope-partitioned bbolt store. All methods are safe for
// concurrent use (bbolt serializes writes; reads use a read transaction).
type Store struct {
	db       *bolt.DB
	readOnly bool
}

// Open opens (creating if needed) the durable store at path and ensures the
// top-level buckets exist. It returns the persisted SchemaVersion (0 on a fresh
// store) so the caller can detect an incompatible on-disk layout. A returned
// mismatch is advisory: the caller decides whether to migrate or discard.
func Open(path string) (*Store, int, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, 0, fmt.Errorf("persist: open %q: %w", path, err)
	}
	s := &Store{db: db}
	found := 0
	err = db.Update(func(tx *bolt.Tx) error {
		// bktTopology and bktDeviants are added the SAME tolerant way as the others
		// (CreateBucketIfNotExists). They are intentionally NOT gated behind a
		// SchemaVersion bump: an existing multi-week baseline.db that predates either
		// bucket must keep opening (the create is a no-op when present and a fresh
		// empty bucket when absent — never a re-decode of stale blobs). See
		// docs/TOPOLOGY_AND_DEVIANTS.md §3 (topology) and §4 (deviants).
		// bktL7Touches (the slice-1 enriched canary-touch record, local-rich) is added
		// the SAME tolerant way and for the same reason: a live M7 baseline.db that
		// predates it must keep opening (no SchemaVersion bump — the create is a no-op
		// when present, a fresh empty bucket when absent).
		// bktAuditChain (the SLICE-A tamper-evident hash-chained audit log, local-rich)
		// is added the SAME tolerant way and for the same reason: a multi-week live
		// baseline.db that predates it must keep opening (NO SchemaVersion bump; the
		// create is a no-op when present, a fresh empty bucket when absent). An absent
		// per-scope head then seeds from genesis on the first audit append for that
		// scope after upgrade.
		for _, name := range [][]byte{bktBaseline, bktMalicious, bktEvents, bktTopology, bktDeviants, bktL7Touches, bktAuditChain, bktMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		mb := tx.Bucket(bktMeta)
		if v := mb.Get([]byte(metaSchemaVersion)); v != nil {
			found = int(binary.BigEndian.Uint64(v))
		} else {
			found = 0 // fresh store
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(SchemaVersion))
			if err := mb.Put([]byte(metaSchemaVersion), buf[:]); err != nil {
				return err
			}
			found = SchemaVersion
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, 0, fmt.Errorf("persist: init %q: %w", path, err)
	}
	return s, found, nil
}

// OpenReadOnly opens the store read-only for OFFLINE inspection (e.g. a
// healthcheck or operator tool run while the engine is stopped). It CANNOT
// coexist with a running engine: bbolt takes an exclusive file lock for a
// read-write handle, so opening read-only against a live writer blocks for
// Options.Timeout and then returns bolt.ErrTimeout. To observe a live window,
// read an engine-produced snapshot/status, not the live DB. Write methods on a
// read-only Store return ErrReadOnly.
func OpenReadOnly(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("persist: open read-only %q: %w", path, err)
	}
	return &Store{db: db, readOnly: true}, nil
}

// ErrReadOnly is returned by write methods on a read-only Store.
var ErrReadOnly = errors.New("persist: store is read-only")

// StampSchemaVersion (re)writes the current SchemaVersion, discarding the record
// of a prior incompatible version. The caller uses this on an explicit, logged
// "reset on schema mismatch" — never silently. Refused on a read-only store.
func (s *Store) StampSchemaVersion() error {
	if s.readOnly {
		return ErrReadOnly
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(SchemaVersion))
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put([]byte(metaSchemaVersion), buf[:])
	})
}

// Close flushes and closes the store. Durability is bbolt's: every successful
// write is already committed and fsync'd, so there is no clean-vs-dirty close
// distinction to record — a crash loses nothing committed, and a downtime gap is
// detected from the heartbeat (CoverageGap), not from a shutdown marker.
func (s *Store) Close() error {
	return s.db.Close()
}

// --- per-scope baseline aggregates -----------------------------------------

// PutBucket stores the opaque aggregate blob for (scope, windowBucketKey).
func (s *Store) PutBucket(scope contract.ScopeKey, bucketKey string, blob []byte) error {
	return s.putNested(bktBaseline, scope, []byte(bucketKey), blob)
}

// GetBucket returns the aggregate blob for (scope, windowBucketKey), ok=false if
// absent.
func (s *Store) GetBucket(scope contract.ScopeKey, bucketKey string) (blob []byte, ok bool, err error) {
	return s.getNested(bktBaseline, scope, []byte(bucketKey))
}

// RangeBuckets calls fn for every (windowBucketKey, blob) under scope. fn must
// not retain blob past the call (it points into the read transaction).
func (s *Store) RangeBuckets(scope contract.ScopeKey, fn func(bucketKey string, blob []byte) error) error {
	return s.rangeNested(bktBaseline, scope, func(k, v []byte) error {
		return fn(string(k), v)
	})
}

// RangeScopes calls fn for every scope key that has any baseline data. Used on
// startup to rehydrate every known scope.
func (s *Store) RangeScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktBaseline)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// BucketWrite is one (scope, windowBucketKey) aggregate blob to persist. A batch
// of these plus the heartbeat commits in a single transaction (PutBucketsAndHeartbeat).
type BucketWrite struct {
	Scope contract.ScopeKey
	Key   string
	Blob  []byte
}

// TopologyWrite is one (scope, recordKey) F1 topology record (an edge or node
// blob) to persist. It rides the SAME single fold-tick transaction as the
// baseline buckets (PutBucketsAndHeartbeat), so a topology upsert adds no extra
// fsync and is never done while the aggregator holds its in-memory lock
// (docs/TOPOLOGY_AND_DEVIANTS.md §3, Rule 6). A Delete entry (Blob == nil)
// removes the key — that is how the reaper's evictions are persisted in the same
// batch. The bucket layout is per-scope (scopeSub), so isolation is by layout
// (Rule 5) exactly like the baseline.
type TopologyWrite struct {
	Scope  contract.ScopeKey
	Key    []byte
	Blob   []byte // nil => delete this key (a reaper eviction)
	Delete bool   // explicit delete flag (Blob may be nil for an empty record too)
}

// DeviantWrite is one (scope, recordKey) F2 deviant-flow record to persist. It
// rides the SAME single fold-tick transaction as the baseline + topology writes
// (PutBucketsAndHeartbeat), so a deviant upsert adds no extra fsync and is never
// done while the aggregator holds its in-memory lock (docs/TOPOLOGY_AND_DEVIANTS.md
// §4, Rule 6). A Delete entry (Blob == nil) removes the key — that is how the
// reaper's evictions are persisted in the same batch. The bucket layout is
// per-scope (scopeSub), so isolation is by layout (Rule 5) exactly like the
// baseline and topology. Mirrors TopologyWrite field-for-field.
type DeviantWrite struct {
	Scope  contract.ScopeKey
	Key    []byte
	Blob   []byte // nil => delete this key (a reaper eviction)
	Delete bool   // explicit delete flag (Blob may be nil for an empty record too)
}

// PutBucketsAndHeartbeat writes every BucketWrite, every TopologyWrite, every
// DeviantWrite, AND the heartbeat in ONE bbolt transaction (one fsync), instead
// of one transaction per bucket. The aggregator calls it once per fold tick with
// only the buckets dirtied since the last tick (and the topology + deviant
// records touched/evicted this tick), so disk I/O is bounded and is never done
// while holding the in-memory lock. The topology and deviant writes are applied
// AFTER the baseline writes within the same commit; ordering within a single
// transaction is immaterial (it commits atomically), but keeping baseline first
// preserves the original write's intent.
func (s *Store) PutBucketsAndHeartbeat(writes []BucketWrite, topo []TopologyWrite, deviants []DeviantWrite, now time.Time) error {
	if s.readOnly {
		return ErrReadOnly
	}
	hb, err := now.MarshalBinary()
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktBaseline)
		for _, w := range writes {
			if w.Scope == "" {
				return errors.New("persist: empty scope in batch write")
			}
			sb, err := root.CreateBucketIfNotExists([]byte(w.Scope))
			if err != nil {
				return err
			}
			if err := sb.Put([]byte(w.Key), append([]byte(nil), w.Blob...)); err != nil {
				return err
			}
		}
		troot := tx.Bucket(bktTopology)
		for _, w := range topo {
			if w.Scope == "" {
				return errors.New("persist: empty scope in topology write")
			}
			sb, err := troot.CreateBucketIfNotExists([]byte(w.Scope))
			if err != nil {
				return err
			}
			if w.Delete || w.Blob == nil {
				if err := sb.Delete(append([]byte(nil), w.Key...)); err != nil {
					return err
				}
				continue
			}
			if err := sb.Put(append([]byte(nil), w.Key...), append([]byte(nil), w.Blob...)); err != nil {
				return err
			}
		}
		droot := tx.Bucket(bktDeviants)
		for _, w := range deviants {
			if w.Scope == "" {
				return errors.New("persist: empty scope in deviant write")
			}
			sb, err := droot.CreateBucketIfNotExists([]byte(w.Scope))
			if err != nil {
				return err
			}
			if w.Delete || w.Blob == nil {
				if err := sb.Delete(append([]byte(nil), w.Key...)); err != nil {
					return err
				}
				continue
			}
			if err := sb.Put(append([]byte(nil), w.Key...), append([]byte(nil), w.Blob...)); err != nil {
				return err
			}
		}
		return tx.Bucket(bktMeta).Put([]byte(metaLastObserveSeen), hb)
	})
}

// --- per-scope malicious identity set (rule-9: hashed identity only) --------

// MarkMalicious records idHash (an FNV hash of a source identity, never a raw
// address) as confirmed-malicious within scope. Idempotent.
func (s *Store) MarkMalicious(scope contract.ScopeKey, idHash uint64) error {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], idHash)
	return s.putNested(bktMalicious, scope, key[:], []byte{1})
}

// IsMalicious reports whether idHash is in scope's confirmed-malicious set.
func (s *Store) IsMalicious(scope contract.ScopeKey, idHash uint64) (bool, error) {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], idHash)
	_, ok, err := s.getNested(bktMalicious, scope, key[:])
	return ok, err
}

// RangeMalicious calls fn for every malicious idHash under scope (used to
// rehydrate the in-memory exclusion set).
func (s *Store) RangeMalicious(scope contract.ScopeKey, fn func(idHash uint64) error) error {
	return s.rangeNested(bktMalicious, scope, func(k, _ []byte) error {
		if len(k) != 8 {
			return nil
		}
		return fn(binary.BigEndian.Uint64(k))
	})
}

// RangeMaliciousScopes calls fn for every scope that has a persisted malicious
// set, INDEPENDENTLY of whether that scope has any baseline buckets. The
// exclusion set and the baseline accrue through separate write paths, so
// rehydration must not key one off the other (a scope marked malicious before it
// ever folds a flow must still restore its exclusion across a reboot).
func (s *Store) RangeMaliciousScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktMalicious)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// --- per-scope append-only event log ---------------------------------------

// AppendEvent appends an opaque event blob to scope's log with a monotonic
// per-scope sequence number, returning the assigned seq.
func (s *Store) AppendEvent(scope contract.ScopeKey, blob []byte) (uint64, error) {
	if s.readOnly {
		return 0, ErrReadOnly
	}
	var seq uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktEvents, scope, true)
		if err != nil {
			return err
		}
		seq, err = sb.NextSequence()
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		return sb.Put(key[:], append([]byte(nil), blob...))
	})
	return seq, err
}

// RangeEvents calls fn for every (seq, blob) under scope in ascending seq order.
// blob must not be retained past the call.
func (s *Store) RangeEvents(scope contract.ScopeKey, fn func(seq uint64, blob []byte) error) error {
	return s.rangeNested(bktEvents, scope, func(k, v []byte) error {
		if len(k) != 8 {
			return nil
		}
		return fn(binary.BigEndian.Uint64(k), v)
	})
}

// RangeEventsRecent calls fn for up to maxN of scope's MOST-RECENT events —
// highest sequence numbers first (reverse insertion order) — then stops. Events
// are keyed by a monotonic per-scope sequence (see AppendEvent), so the newest
// records live at the end of the bucket; walking the bbolt cursor backward from
// Last() and capping at maxN bounds a recent-window query to O(maxN) decodes
// instead of scanning the whole (possibly days-deep) event log. This is the
// difference between a sub-millisecond and a multi-second hot-path Submit once a
// scope has accrued a large history. maxN <= 0 means "no cap" (full reverse scan).
// blob must not be retained past the call.
//
// fn receives records NEWEST-FIRST. A caller that needs ascending order must
// reverse its own collected output (see boltevents.Store.Query). If a scope has
// more than maxN records, the oldest are not visited — callers must size maxN so
// the cap comfortably spans their lookback window (it is a cost ceiling, not a
// correctness boundary: the recent window is what the caller filters to anyway).
func (s *Store) RangeEventsRecent(scope contract.ScopeKey, maxN int, fn func(seq uint64, blob []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktEvents, scope, false)
		if err != nil || sb == nil {
			return err
		}
		c := sb.Cursor()
		n := 0
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if v == nil {
				continue // nested bucket, not a value (defensive; events bucket has none)
			}
			if len(k) != 8 {
				continue
			}
			if err := fn(binary.BigEndian.Uint64(k), v); err != nil {
				return err
			}
			n++
			if maxN > 0 && n >= maxN {
				return nil
			}
		}
		return nil
	})
}

// --- per-scope F1 topology records ------------------------------------------
//
// The topology bucket holds the LOCAL-RICH learned east-west map: directed edges
// and node-catalog entries keyed by their canonical (un-hashed) key. It is
// scope-isolated by layout (scopeSub) like every other store, and is LOCAL-ONLY
// — nothing here ever feeds internal/intelligence/network (the cross-customer
// egress path stays coarse/hashed; docs/TOPOLOGY_AND_DEVIANTS.md §6). Writes ride
// PutBucketsAndHeartbeat (one fsync per fold tick); these accessors are read-only
// rehydrate/inspection helpers.

// RangeTopology calls fn for every (recordKey, blob) under scope in key order.
// blob must not be retained past the call (it points into the read transaction).
func (s *Store) RangeTopology(scope contract.ScopeKey, fn func(key, blob []byte) error) error {
	return s.rangeNested(bktTopology, scope, fn)
}

// RangeTopologyScopes calls fn for every scope that has any persisted topology
// record, independently of baseline-bucket presence (the two accrue via the same
// batched write but a scope could in principle have one and not the other).
func (s *Store) RangeTopologyScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktTopology)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// --- per-scope F2 deviant-flow records --------------------------------------
//
// The deviants bucket holds the LOCAL-RICH forensic log of top non-tripwire
// baseline deviants: anomalous flows that touched NO canary (Rule 8 — observing
// or logging a flow is not a response). Records hold the RAW flow identity
// (addresses/ports) keyed by a canonical behavioral key, so a repeat deviant from
// the same pattern bumps a HitCount rather than writing a new record. It is
// scope-isolated by layout (scopeSub) like every other store, and is LOCAL-ONLY —
// nothing here ever feeds internal/intelligence/network (the cross-customer
// egress path stays coarse/hashed; docs/TOPOLOGY_AND_DEVIANTS.md §6). Writes ride
// PutBucketsAndHeartbeat (one fsync per fold tick); these accessors are read-only
// rehydrate/inspection helpers for the future deviants tap.

// RangeDeviants calls fn for every (recordKey, blob) under scope in key order.
// blob must not be retained past the call (it points into the read transaction).
func (s *Store) RangeDeviants(scope contract.ScopeKey, fn func(key, blob []byte) error) error {
	return s.rangeNested(bktDeviants, scope, fn)
}

// RangeDeviantScopes calls fn for every scope that has any persisted deviant
// record, independently of baseline-bucket presence (the two accrue via the same
// batched write but a scope could in principle have one and not the other).
func (s *Store) RangeDeviantScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktDeviants)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// --- per-scope slice-1 enriched touch records -------------------------------
//
// The l7touches bucket holds the LOCAL-RICH enriched canary-touch record: one
// record per canary touch (Tier>=Tag) capturing the L7 + identity context the
// addressless cross-customer egress event (intelligence.AdversaryInteractionEvent)
// discards — the raw source address, :method, :path, and SPIFFE id, kept
// un-hashed and deployment-LOCAL. It is scope-isolated by layout (scopeSub) like
// every other store, and is LOCAL-ONLY: nothing here ever feeds
// internal/intelligence/network (the cross-customer egress path stays
// coarse/hashed/addressless; rule 9). The egress import guard
// (internal/intelligence/network/egress_importguard_test.go) forbids the egress
// filter from transitively importing persist, so the raw record is structurally
// unreachable from a deployment boundary.
//
// Writes happen at engine Submit time (the capture seam, internal/boot), NOT on
// the observe fold tick, so PutL7Touch is a single small keyed put — bbolt
// commits it in its own transaction. A Delete entry (Blob == nil) removes a key
// (a cap/TTL reaper eviction). These accessors are otherwise read-only
// rehydrate/inspection helpers for the future slice-2 SIEM emitter / tap.

// L7TouchWrite is one (scope, key) enriched-touch record to persist. A Delete
// entry (Blob == nil) removes the key — that is how a cap/TTL reaper eviction is
// persisted alongside the inserting put in one transaction. Mirrors DeviantWrite.
type L7TouchWrite struct {
	Scope  contract.ScopeKey
	Key    []byte
	Blob   []byte // nil => delete this key (a reaper eviction)
	Delete bool   // explicit delete flag
}

// PutL7Touches writes a batch of enriched-touch puts/deletes in ONE transaction
// (one fsync). The capture seam uses it to commit the inserted record together
// with any record evicted by the per-scope cap in the same touch, so the on-disk
// set never exceeds the in-memory cap.
func (s *Store) PutL7Touches(writes []L7TouchWrite) error {
	if s.readOnly {
		return ErrReadOnly
	}
	if len(writes) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktL7Touches)
		for _, w := range writes {
			if w.Scope == "" {
				return errors.New("persist: empty scope in l7touch write")
			}
			sb, err := root.CreateBucketIfNotExists([]byte(w.Scope))
			if err != nil {
				return err
			}
			if w.Delete || w.Blob == nil {
				if err := sb.Delete(append([]byte(nil), w.Key...)); err != nil {
					return err
				}
				continue
			}
			if err := sb.Put(append([]byte(nil), w.Key...), append([]byte(nil), w.Blob...)); err != nil {
				return err
			}
		}
		return nil
	})
}

// RangeL7Touches calls fn for every (key, blob) under scope in key order. blob
// must not be retained past the call (it points into the read transaction).
func (s *Store) RangeL7Touches(scope contract.ScopeKey, fn func(key, blob []byte) error) error {
	return s.rangeNested(bktL7Touches, scope, fn)
}

// RangeL7TouchScopes calls fn for every scope that has any persisted enriched
// touch record, independently of baseline-bucket presence.
func (s *Store) RangeL7TouchScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktL7Touches)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// --- per-scope tamper-evident audit chain (SLICE A) -------------------------
//
// The auditchain bucket holds the LOCAL-RICH, tamper-evident hash-chained audit
// log: one record per Tier>=Tag decision (and, via the slice-B Append API, per
// operator action) capturing the action facts AND the raw L7 + identity context
// at decision time. Each per-scope chain is independent (rule 5); records ride a
// private monotonic sequence in a nested "records" sub-bucket and the per-scope
// chain head sits beside them at auditHeadKey. It is scope-isolated by layout
// (the scope sub-bucket) like every other store, and is LOCAL-ONLY: nothing here
// ever feeds internal/intelligence/network (the cross-customer egress path stays
// coarse/hashed/addressless; rule 9). The egress import guard forbids the egress
// filter from transitively importing persist, so the raw record is structurally
// unreachable from a deployment boundary.

// AppendAuditAndHead atomically advances one scope's hash chain: it reads the
// CURRENT per-scope head, reserves the next monotonic seq, calls mk(prevHead, seq)
// to build the record blob (the caller embeds seq in the record and computes
// newHead = H(prevHead || record-without-hash), so seq is part of the hashed
// preimage), appends the blob under that seq, and writes newHead as the new
// per-scope head — ALL in ONE bbolt transaction (one fsync). bbolt serializes
// writers, and the read-of-prev-head + the seq reservation happen INSIDE that same
// write transaction, so two concurrent Submits in the same scope cannot read the
// same prev head / seq and fork the chain (the second sees the first's committed
// head). An absent head (a fresh scope, or a baseline.db that predates this bucket)
// is reported to mk as the empty genesis (nil), which the caller seeds from a fixed
// genesis constant. Returns the assigned seq. Refused on a read-only store.
func (s *Store) AppendAuditAndHead(scope contract.ScopeKey, mk func(prevHead []byte, seq uint64) (recordBlob, newHead []byte, err error)) (uint64, error) {
	if s.readOnly {
		return 0, ErrReadOnly
	}
	if scope == "" {
		return 0, errors.New("persist: empty scope in audit append")
	}
	var seq uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktAuditChain, scope, true)
		if err != nil {
			return err
		}
		var prevHead []byte
		if h := sb.Get(auditHeadKey); h != nil {
			prevHead = append([]byte(nil), h...) // copy out of the tx-owned slice
		}
		recs, err := sb.CreateBucketIfNotExists(auditRecordsSub)
		if err != nil {
			return err
		}
		seq, err = recs.NextSequence()
		if err != nil {
			return err
		}
		recordBlob, newHead, err := mk(prevHead, seq)
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		if err := recs.Put(key[:], append([]byte(nil), recordBlob...)); err != nil {
			return err
		}
		return sb.Put(auditHeadKey, append([]byte(nil), newHead...))
	})
	return seq, err
}

// GetAuditHead returns one scope's current chain head, ok=false if the scope has
// no chain yet (genesis). It is the rehydrate read mirrored on boot.
func (s *Store) GetAuditHead(scope contract.ScopeKey) (head []byte, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktAuditChain, scope, false)
		if err != nil || sb == nil {
			return err
		}
		if h := sb.Get(auditHeadKey); h != nil {
			head = append([]byte(nil), h...)
			ok = true
		}
		return nil
	})
	return head, ok, err
}

// AuditChainStat returns one scope's audit-chain HIGH-WATER-MARK cheaply: the chain
// head, the record count, and the latest seq — WITHOUT decoding any record. It is a
// single read transaction that reads the per-scope head (like GetAuditHead), the
// records sub-bucket's KeyN (its record count, O(1) from bbolt's bucket stats), and
// the sub-bucket's monotonic Sequence (the last NextSequence value handed out — the
// latest assigned seq). ok=false when the scope has no chain yet (no head and no
// records), so the caller skips an empty/genesis scope.
//
// It is the read accessor the external-witness anchor rides on: the witness publishes
// (head, count, latestSeq) per scope to the operator's SIEM so the SOC can later
// compare the live chain against the last-seen high-water-mark (whole-scope erasure /
// truncate-to-valid-prefix are detectable AT THE SOC by that comparison; see
// audit.Store.HighWaterMark and docs). It adds NO bucket, NO key, NO schema field —
// it only reads layout AppendAuditAndHead already wrote, so persist.SchemaVersion is
// unchanged.
//
// INTEGRITY COUPLING: count and latestSeq are returned independently and are equal
// ONLY because the audit chain is APPEND-ONLY (AppendAuditAndHead never deletes a
// record and assigns a contiguous 1-based seq via NextSequence). If a future TTL/cap
// reaper is ever added to the audit chain, count and latestSeq will DIVERGE and the
// SOC-side truncation signal must use latestSeq (monotonic) — never count. bbolt's
// Sequence() persists the high-water sequence even if records were deleted, so it
// stays the right monotonic truncation signal under a hypothetical future reaper.
func (s *Store) AuditChainStat(scope contract.ScopeKey) (head []byte, count int, latestSeq uint64, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		sb, e := scopeSub(tx, bktAuditChain, scope, false)
		if e != nil || sb == nil {
			return e
		}
		if h := sb.Get(auditHeadKey); h != nil {
			head = append([]byte(nil), h...)
			ok = true
		}
		recs := sb.Bucket(auditRecordsSub)
		if recs != nil {
			count = recs.Stats().KeyN
			latestSeq = recs.Sequence()
			if count > 0 {
				ok = true
			}
		}
		return nil
	})
	return head, count, latestSeq, ok, err
}

// RangeAuditChain calls fn for every (seq, blob) in scope's chain in ascending
// seq order (chain order, oldest first) — the order Verify/Export walk. blob must
// not be retained past the call (it points into the read transaction).
func (s *Store) RangeAuditChain(scope contract.ScopeKey, fn func(seq uint64, blob []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, bktAuditChain, scope, false)
		if err != nil || sb == nil {
			return err
		}
		recs := sb.Bucket(auditRecordsSub)
		if recs == nil {
			return nil
		}
		return recs.ForEach(func(k, v []byte) error {
			if v == nil || len(k) != 8 {
				return nil
			}
			return fn(binary.BigEndian.Uint64(k), v)
		})
	})
}

// RangeAuditChainScopes calls fn for every scope that has an audit chain,
// independently of baseline-bucket presence — the rehydrate enumerator (mirror of
// RangeL7TouchScopes).
func (s *Store) RangeAuditChainScopes(fn func(scope contract.ScopeKey) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bktAuditChain)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(k []byte) error {
			return fn(contract.ScopeKey(append([]byte(nil), k...)))
		})
	})
}

// --- window lifecycle metadata (global) ------------------------------------

// Heartbeat records now as the last successful observe fold. The aggregator
// calls it every tick; the gap between it and a later Open is downtime.
func (s *Store) Heartbeat(now time.Time) error { return s.putMetaTime(metaLastObserveSeen, now) }

// LastObserveSeen returns the last heartbeat time, ok=false if never recorded.
func (s *Store) LastObserveSeen() (time.Time, bool, error) { return s.getMetaTime(metaLastObserveSeen) }

// CoverageGap reports how long the window was unobserved before now: now minus
// the last heartbeat. ok=false on a fresh store with no prior heartbeat. A gap
// larger than the operator's tolerance means the window has a hole that must be
// re-bridged with fresh data before the baseline may be trusted again (the
// aggregator forces STALE until then) — an attacker's downtime is never silently
// backfilled as normal.
func (s *Store) CoverageGap(now time.Time) (time.Duration, bool, error) {
	last, ok, err := s.LastObserveSeen()
	if err != nil || !ok {
		return 0, false, err
	}
	gap := now.Sub(last)
	if gap < 0 {
		gap = 0
	}
	return gap, true, nil
}

// --- internal helpers -------------------------------------------------------

// scopeSub returns the per-scope sub-bucket under a top bucket, creating it if
// create is true. This is the single chokepoint that enforces scope isolation:
// every nested access is by an explicit scope key, so no method can read across
// scopes by accident.
func scopeSub(tx *bolt.Tx, top []byte, scope contract.ScopeKey, create bool) (*bolt.Bucket, error) {
	if scope == "" {
		return nil, errors.New("persist: empty scope; refusing to store unscoped state")
	}
	root := tx.Bucket(top)
	if root == nil {
		return nil, fmt.Errorf("persist: missing top bucket %q", top)
	}
	if create {
		return root.CreateBucketIfNotExists([]byte(scope))
	}
	return root.Bucket([]byte(scope)), nil
}

func (s *Store) putNested(top []byte, scope contract.ScopeKey, key, blob []byte) error {
	if s.readOnly {
		return ErrReadOnly
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, top, scope, true)
		if err != nil {
			return err
		}
		return sb.Put(append([]byte(nil), key...), append([]byte(nil), blob...))
	})
}

func (s *Store) getNested(top []byte, scope contract.ScopeKey, key []byte) ([]byte, bool, error) {
	var out []byte
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, top, scope, false)
		if err != nil || sb == nil {
			return err
		}
		if v := sb.Get(key); v != nil {
			out = append([]byte(nil), v...)
			ok = true
		}
		return nil
	})
	return out, ok, err
}

func (s *Store) rangeNested(top []byte, scope contract.ScopeKey, fn func(k, v []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		sb, err := scopeSub(tx, top, scope, false)
		if err != nil || sb == nil {
			return err
		}
		return sb.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil // nested bucket, not a value
			}
			return fn(k, v)
		})
	})
}

func (s *Store) putMetaTime(key string, t time.Time) error {
	if s.readOnly {
		return ErrReadOnly
	}
	b, err := t.MarshalBinary()
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put([]byte(key), b)
	})
}

func (s *Store) getMetaTime(key string) (time.Time, bool, error) {
	var out time.Time
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bktMeta).Get([]byte(key))
		if v == nil {
			return nil
		}
		if err := out.UnmarshalBinary(v); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return out, ok, err
}
