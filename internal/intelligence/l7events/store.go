// Package l7events is the deployment-LOCAL, scope-isolated store of the SLICE-1
// enriched touch-record: one rich record per canary TOUCH (Tier>=Tag) and the
// engine action it drove, capturing the L7 + identity context that the
// cross-customer egress event (intelligence.AdversaryInteractionEvent)
// deliberately discards.
//
// LOCAL-RICH / EXPORT-COARSE (docs/INTELLIGENCE.md rule 9): the egress-bound
// AdversaryInteractionEvent stays byte-for-byte ADDRESSLESS — it carries only the
// scope key, the socket cookie, the canary type, the tier/verdict/score, and the
// structured baseline-feature vector. This package is its SIBLING: it keeps the
// RAW source address, :method, :path, and SPIFFE id un-hashed, LOCAL to the
// deployment. The two are structurally separate types in separate packages, so
// the rich type can never widen the addressless one by accident. The egress
// import guard (internal/intelligence/network/egress_importguard_test.go) forbids
// the egress filter from transitively importing this package, so a raw path/addr
// is physically unreachable from a deployment boundary — anonymization is
// structural, not a runtime check.
//
// RULE 8 (observe/forensic only): this store records a canary-TOUCHER's L7
// context AFTER the engine has already decided the tier on a real canary touch.
// Nothing here arms, escalates, or feeds back into scoring; it is pure capture
// for the future SIEM emitter (slice 2) and the deviant drill-down L7 path.
//
// RULE 4 (join key): records are KEYED on the socket cookie (the only
// cross-boundary join key). The path/method/SPIFFE are stored as context and are
// NEVER the key. RULE 5 (scope isolation): every record is partitioned per scope,
// in memory and in the durable store; a read never crosses a scope.
package l7events

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"hash/fnv"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

const (
	// touchCapDefault bounds each per-scope record set's cardinality. A path-keyed
	// store is a spray target: an attacker hitting many DISTINCT canary paths can
	// manufacture many distinct keys (the same blow-up the deviant log guards
	// against). The cap is what stops a spray from growing the store without bound.
	// Eviction is oldest-LastSeen (a one-off spray artifact ages out; a recurring
	// toucher survives by refreshing LastSeen + bumping HitCount). Mirrors
	// observebaseline.deviantCapDefault.
	touchCapDefault = 4096

	// touchTTLDefault is the wall-clock TTL after which a stale record ages out even
	// below the cap, so a multi-week window does not accumulate one-off touches
	// forever. Measured against LastSeen. Mirrors observebaseline.deviantTTLDefault.
	touchTTLDefault = 30 * 24 * time.Hour
)

// EnrichedTouchRecord is one durable, forensic record of a canary touch and the
// engine action it drove. It is LOCAL-RICH: it holds the RAW (un-hashed) L7 +
// identity context, and is a SIBLING to the egress-bound, addressless
// intelligence.AdversaryInteractionEvent (it does NOT widen it). All fields are
// exported for gob and for the future slice-2 emitter/tap; the record never
// crosses a deployment boundary.
type EnrichedTouchRecord struct {
	// EventID is a stable per-record id (scope + cookie + first-seen nanos), so the
	// future emitter can de-duplicate and reference a touch without leaking identity.
	EventID string

	// Scope is the RESOLVED scope (rule 5) — never the wire scope. The capture seam
	// keys this on the engine-resolved verdict scope (the B1 fix).
	Scope string

	// SocketCookie is the L7/kernel join key (rule 4): the recurrence key AND the
	// join-back handle to the addressless egress event's FlowID. Cookies are
	// per-connection/reused, so a NEW touch from a reused cookie that lands on the
	// same (cookie, path, method) recurrence key bumps HitCount rather than forking.
	SocketCookie uint64

	// CanaryType is which decoy type was touched.
	CanaryType string

	// Tier/Verdict/Score are the engine decision this touch drove.
	Tier    int
	Verdict string
	Score   float64

	// Calibrated reports whether the deciding scope was in calibrated mode.
	Calibrated bool

	// Mode is the enforcement mode of the verdict (inline vs async), as an int
	// (contract.EnforcementMode value).
	Mode int

	// StingMechanism is the attrition/containment mechanism this touch drove, IF
	// one is already known at capture time. At engine-Submit time the flow's
	// StingOutcome is still zero (attrition runs later, adapter-side), so this is
	// usually "" in slice 1 — the field exists so slice 2 can amend it. The
	// tier-derived action label is in Verdict.
	StingMechanism string

	// --- the L7 + identity context the egress event discards (local-rich, RAW) ---

	// SourceAddress is the raw caller IP[:port] as the adapter observed it
	// (contract.AttrSourceAddress). "" when the source tuple was unattributable.
	SourceAddress string
	// Method / Path are the raw HTTP :method and :path (query INCLUDED — the query
	// is load-bearing context and stays deployment-local). "" when not an L7 touch.
	Method string
	Path   string
	// SPIFFEID is the peer's L7 identity (mTLS), "" when none.
	SPIFFEID string

	// Features is the baseline novelty/deviation dimensions at touch time (the same
	// structured vector the egress event carries), copied verbatim. May be nil.
	Features map[string]float64

	// BytesRealDataCrossed is the structural fact that a canary touch transfers ZERO
	// bytes of real data (the decoy is fake by construction). It is ALWAYS 0 — kept
	// as an explicit field so a downstream consumer reads the fact rather than
	// inferring it.
	BytesRealDataCrossed int64

	// FirstSeen / LastSeen are WALL-CLOCK (the capture seam's clock). HitCount is how
	// many times this (cookie, path, method) recurrence key has been seen.
	FirstSeen time.Time
	LastSeen  time.Time
	HitCount  uint64
}

// --- canonical recurrence key ----------------------------------------------
//
// The recurrence key joins on the socket cookie (rule 4) PLUS the L7 request line
// (method, path) so a toucher repeating the same request collapses onto one
// record (bumping HitCount) rather than flooding the log, while a toucher hitting
// DIFFERENT canary paths produces distinct records (the spray the cap bounds). A
// 1-byte kind discriminator keeps the bucket walkable and never collides with
// another store's keys.
//
// Layout: [0x01][cookie BE u64][method bytes][0x00][path bytes]

const touchKind byte = 0x01

func touchKey(cookie uint64, method, path string) string {
	b := make([]byte, 0, 1+8+len(method)+1+len(path))
	b = append(b, touchKind)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], cookie)
	b = append(b, c[:]...)
	b = append(b, method...)
	b = append(b, 0x00) // separator: method and path are distinct fields
	b = append(b, path...)
	return string(b)
}

// scopeRecords is one scope's in-memory record set, guarded by the parent Store's
// lock.
type scopeRecords struct {
	records map[string]*EnrichedTouchRecord // touchKey -> record
}

func newScopeRecords() *scopeRecords {
	return &scopeRecords{records: map[string]*EnrichedTouchRecord{}}
}

// Store is the per-scope enriched-touch accumulator. It holds the authoritative
// in-memory map (cap + TTL) and mirrors every change to the durable persist.Store
// so the record survives a reboot. All map access is under s.mu; the record is
// never touched on the observe hot path (it is written only from the engine
// Submit capture seam, which already runs serially per flow).
type Store struct {
	mu      sync.Mutex
	byScope map[contract.ScopeKey]*scopeRecords

	store *persist.Store // durable backing; nil => in-memory only (tests)

	cap     int
	ttl     time.Duration
	evicted uint64 // observable: records dropped by the cap or TTL reaper
}

// New returns an enriched-touch Store backed by store (nil => in-memory only, for
// tests). It rehydrates the durable per-scope records so the local-rich record
// survives a reboot.
func New(store *persist.Store) *Store {
	s := &Store{
		byScope: map[contract.ScopeKey]*scopeRecords{},
		store:   store,
		cap:     touchCapDefault,
		ttl:     touchTTLDefault,
	}
	s.rehydrate()
	return s
}

// rehydrate loads the durable per-scope records into memory on boot (mirrors the
// deviant-log rehydrate). An undecodable blob is skipped, never failing the whole
// window.
func (s *Store) rehydrate() {
	if s.store == nil {
		return
	}
	_ = s.store.RangeL7TouchScopes(func(sc contract.ScopeKey) error {
		sr := newScopeRecords()
		_ = s.store.RangeL7Touches(sc, func(key, blob []byte) error {
			if len(key) == 0 {
				return nil
			}
			r, err := decodeRecord(blob)
			if err != nil {
				return nil // lost local detail; skip-not-silent (the baseline is unaffected)
			}
			sr.records[string(key)] = r
			return nil
		})
		s.byScope[sc] = sr
		return nil
	})
}

// Capture records one canary touch. It is the SLICE-1 capture API, called from
// the engine Submit seam (internal/boot) IMMEDIATELY AFTER the addressless
// CaptureVerdict, on the SAME (ev, v, feats). It is GATED to actual touches
// (Tier>=Tag — the same set the addressless event retains); an Observe-tier
// touch is not recorded. scope MUST be the RESOLVED scope (v.Scope/ev.Scope after
// the B1 correction), never the wire scope (rule 5). l7 carries the raw context
// pulled from ev.Flow.L7Attributes / SPIFFEID by the caller (nil-safe). now is
// the capture wall-clock.
//
// A repeat touch on the same (cookie, method, path) recurrence key bumps HitCount
// + LastSeen + refreshes the live tier/score snapshot rather than writing a new
// record, so a toucher repeating the same request does not flood the log. Returns
// without error when not retained (Tier<Tag) or when scope is empty (refuse
// unscoped). The durable mirror is best-effort: a persist error is swallowed (the
// in-memory record is authoritative and the surface is forensic, not load-bearing).
func (s *Store) Capture(scope contract.ScopeKey, cookie uint64, canary contract.CanaryType, v contract.Verdict, l7 L7Context, feats map[string]float64, now time.Time) {
	if v.Tier < contract.TierTag {
		return // Observe-tier touches are not retained (mirror boltevents.CaptureVerdict)
	}
	if scope == "" {
		return // never store unscoped
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sr := s.byScope[scope]
	if sr == nil {
		sr = newScopeRecords()
		s.byScope[scope] = sr
	}

	key := touchKey(cookie, l7.Method, l7.Path)
	var evictedKey string
	var haveEviction bool

	if r := sr.records[key]; r != nil {
		r.HitCount++
		r.LastSeen = now
		// SourceAddress/SPIFFEID are intentionally pinned to first-seen and NOT
		// refreshed here: the socket cookie is per-connection (rule 4), so a recurrence
		// on the same (cookie, method, path) key is the same source identity.
		// Refresh the live decision snapshot (the identity/L7 key is unchanged).
		r.Tier = int(v.Tier)
		r.Verdict = tierName(v.Tier)
		r.Score = v.Score
		r.Calibrated = v.Calibrated
		r.Mode = int(v.Mode)
		r.Features = copyFeatures(feats)
	} else {
		if ek, ok := sr.evictOldestIfFull(s.cap); ok {
			evictedKey, haveEviction = ek, true
			s.evicted++
		}
		first := now
		sr.records[key] = &EnrichedTouchRecord{
			EventID:              eventID(scope, cookie, first, l7.Method, l7.Path),
			Scope:                string(scope),
			SocketCookie:         cookie,
			CanaryType:           string(canary),
			Tier:                 int(v.Tier),
			Verdict:              tierName(v.Tier),
			Score:                v.Score,
			Calibrated:           v.Calibrated,
			Mode:                 int(v.Mode),
			SourceAddress:        l7.SourceAddress,
			Method:               l7.Method,
			Path:                 l7.Path,
			SPIFFEID:             l7.SPIFFEID,
			Features:             copyFeatures(feats),
			BytesRealDataCrossed: 0, // structural: a canary touch crosses zero real bytes
			FirstSeen:            first,
			LastSeen:             first,
			HitCount:             1,
		}
	}

	// Mirror to disk: the inserted/bumped record plus any cap eviction, in one
	// transaction so the on-disk set never exceeds the cap. Best-effort.
	if s.store != nil {
		var writes []persist.L7TouchWrite
		if haveEviction {
			writes = append(writes, persist.L7TouchWrite{Scope: scope, Key: []byte(evictedKey), Delete: true})
		}
		if blob, err := encodeRecord(sr.records[key]); err == nil {
			writes = append(writes, persist.L7TouchWrite{Scope: scope, Key: []byte(key), Blob: blob})
		}
		_ = s.store.PutL7Touches(writes)
	}
}

// L7Context is the raw, deployment-local L7 + identity context the caller pulls
// from contract.FlowIdentity (L7Attributes / SPIFFEID) at the capture seam. All
// fields are optional ("" when absent) — the map is nil for unattributed/non-tuple
// flows, so the caller nil-guards the read (see FromFlow).
type L7Context struct {
	SourceAddress string
	Method        string
	Path          string
	SPIFFEID      string
}

// FromFlow extracts the raw L7 context from a flow identity, nil-guarding the
// L7Attributes map (it is nil for unattributed/non-tuple flows). It is the single
// place the well-known attribute keys are read on the capture side, mirroring the
// adapter's stamp side.
func FromFlow(flow contract.FlowIdentity) L7Context {
	c := L7Context{SPIFFEID: flow.SPIFFEID}
	if flow.L7Attributes != nil {
		c.SourceAddress = flow.L7Attributes[contract.AttrSourceAddress]
		c.Method = flow.L7Attributes[contract.AttrRequestMethod]
		c.Path = flow.L7Attributes[contract.AttrRequestPath]
	}
	return c
}

// Reap evicts every record whose LastSeen is older than the TTL relative to now,
// persisting each removal. It is the off-hot-path TTL reaper; a caller runs it on a
// timer. Returns the number removed (observable). NOTE (slice 1): there is no
// production caller yet — at runtime the store is bounded ONLY by the per-scope cap
// (oldest-LastSeen eviction); the 30d TTL is enforced on rehydrate-after-reboot and
// will be driven on the slice-2 emitter's tick (which owns the read/emit side). A
// stale one-off touch below the cap therefore persists until then.
func (s *Store) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-s.ttl)
	removed := 0
	for sc, sr := range s.byScope {
		var writes []persist.L7TouchWrite
		for k, r := range sr.records {
			if r.LastSeen.Before(cutoff) {
				delete(sr.records, k)
				removed++
				s.evicted++
				writes = append(writes, persist.L7TouchWrite{Scope: sc, Key: []byte(k), Delete: true})
			}
		}
		if s.store != nil && len(writes) > 0 {
			_ = s.store.PutL7Touches(writes)
		}
	}
	return removed
}

// Evicted returns the cumulative count of records dropped by the cap or TTL reaper
// — observable lost-detail, so eviction is never silent (mirrors DeviantsEvicted).
func (s *Store) Evicted() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// evictOldestIfFull drops the oldest-LastSeen record when the set is at cap,
// returning the evicted key. A spray of one-off touches ages out; a recurring
// toucher survives by refreshing LastSeen.
func (sr *scopeRecords) evictOldestIfFull(cap int) (string, bool) {
	if cap <= 0 || len(sr.records) < cap {
		return "", false
	}
	var victim string
	var oldest time.Time
	first := true
	for k, r := range sr.records {
		if first || r.LastSeen.Before(oldest) {
			victim, oldest, first = k, r.LastSeen, false
		}
	}
	delete(sr.records, victim)
	return victim, true
}

// Snapshot returns a decoded, copied view of the live in-memory records for one
// scope — the read accessor the future slice-2 SIEM emitter / tap consumes. It is
// READ-SIDE ONLY (rule 8) and LOCAL-ONLY (rule 9): the raw addresses/paths stay
// in the deployment; this accessor lives in a package the egress filter is
// structurally forbidden to import. Empty for a scope with no records. The caller
// owns the returned values; no package-private pointer escapes (Features is
// deep-copied).
func (s *Store) Snapshot(scope contract.ScopeKey) []EnrichedTouchRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.byScope[scope]
	if sr == nil {
		return nil
	}
	out := make([]EnrichedTouchRecord, 0, len(sr.records))
	for _, r := range sr.records {
		cp := *r
		cp.Features = copyFeatures(r.Features)
		out = append(out, cp)
	}
	return out
}

// Scopes returns the set of scopes that currently hold at least one in-memory
// record — the enumerator the slice-2 SIEM emitter uses to discover which scopes
// to drain (Snapshot requires a scope arg, so without this it could only drain a
// hardcoded boundary). It copies out under s.mu (the byScope map is lock-guarded);
// the live map never escapes. Order is unspecified (map iteration). Rule 5: this
// only lists the scope KEYS the local store already partitions on; it never merges
// records across scopes.
func (s *Store) Scopes() []contract.ScopeKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]contract.ScopeKey, 0, len(s.byScope))
	for sc := range s.byScope {
		out = append(out, sc)
	}
	return out
}

// LookupByCookie returns the records for one scope whose socket cookie matches —
// the by-cookie join-back the deviant drill-down L7 path will use (rule 4). A
// single cookie can carry several records if it touched distinct request lines.
func (s *Store) LookupByCookie(scope contract.ScopeKey, cookie uint64) []EnrichedTouchRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.byScope[scope]
	if sr == nil {
		return nil
	}
	var out []EnrichedTouchRecord
	for _, r := range sr.records {
		if r.SocketCookie == cookie {
			cp := *r
			cp.Features = copyFeatures(r.Features)
			out = append(out, cp)
		}
	}
	return out
}

// --- helpers ----------------------------------------------------------------

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

// eventID builds a stable per-record id from the resolved scope, the join cookie,
// and the first-seen wall nanos. It is deployment-local and identity-bearing only
// in the same sense the rest of the record is (it never crosses the egress path).
// eventID is unique per stored record: it folds the recurrence key (cookie +
// request line method/path) in with the first-seen nanos, so two distinct request
// lines on the same cookie in the same nanosecond still get distinct ids (the
// slice-2 emitter may treat EventID as a dedup key).
func eventID(scope contract.ScopeKey, cookie uint64, first time.Time, method, path string) string {
	h := fnv.New64a()
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], cookie)
	binary.BigEndian.PutUint64(b[8:16], uint64(first.UnixNano()))
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(method))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(path))
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

func encodeRecord(r *EnrichedTouchRecord) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeRecord(blob []byte) (*EnrichedTouchRecord, error) {
	r := &EnrichedTouchRecord{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(r); err != nil {
		return nil, err
	}
	return r, nil
}
