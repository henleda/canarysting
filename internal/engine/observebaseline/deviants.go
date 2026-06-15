package observebaseline

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
)

// F2 — rich non-tripwire deviant log (engine-side capture). This is the second
// LOCAL-RICH store of the local-rich / export-coarse posture
// (docs/TOPOLOGY_AND_DEVIANTS.md §1, §4): beside the FNV-hashed novelty counts the
// baseline keeps (UNCHANGED; they still drive all scoring), we ADDITIONALLY keep a
// durable, forensic record of the flows that look anomalous-from-baseline but
// touched NO canary — the hunting data the future deviants page reads. Logging an
// anomaly locally is neither a Rule-8 (response) nor a Rule-9 (export) act: nothing
// here arms a response (the record is of a flow that touched no canary), and
// nothing here is reachable from internal/intelligence/network, which stays
// coarse/hashed/default-deny (the egress guard enforces this structurally — see
// internal/intelligence/network/egress_importguard_test.go).
//
// Capture is folded once per COMPLETED flow inside foldCompleted, inheriting the
// aggregator's a.live/a.folded fold-once bookkeeping — no new hot-path state — and
// is GATED to deviant + non-armed flows (see deviantFloor + the armed predicate).
// We keep NO dossier on normal (low-novelty) traffic; we record anomalies only.
// FirstSeen/LastSeen are WALL-CLOCK from a.clock() at fold time, NEVER the kernel
// bpf_ktime monotonic FirstSeenNs/LastSeenNs.
//
// L7/SPIFFE FUSION IS DEFERRED to a later L7-threading slice: this record is the
// E/W-side rich half (raw 4-tuple + novelty dims + score). The fused L7+SPIFFE
// identity (contract.FlowIdentity.SPIFFEID + the adapter's L7Attributes,
// cookie-joined per Rule 4) is added when that slice lands; the cross-customer
// egress event (intelligence.AdversaryInteractionEvent) stays addressless and is
// NOT widened by this work.

const (
	// deviantFloor is the peak-novelty above which a NON-canary-touching flow is
	// durably recorded as a deviant (observed, NOT actioned — Rule 8). It mirrors
	// the dashboard tap's reconLiveNoticeFloor (internal/dashboard/tap/tap.go, 0.3):
	// the same load-bearing distinction the recon surface already draws — below it a
	// flow is a normal-looking neighbor we keep no dossier on; at-or-above it the
	// flow is anomalous-from-baseline and worth a forensic record. Defined here
	// (rather than imported) because the tap imports observebaseline, not the other
	// way around; the value is kept in lockstep with the tap by this comment.
	deviantFloor = 0.3

	// deviantCapDefault bounds each per-scope deviant log's cardinality the same way
	// freqCapDefault / topoEdgeCapDefault bound their maps: a methodical scanner
	// collapses into a few records via the recurrence key, but a port-sweep or
	// source-spoof across many distinct identities can still manufacture many
	// distinct deviant keys. The cap is what stops a scan from blowing up the store.
	// Eviction is lowest-HitCount / oldest-LastSeen (the bumpCapped discipline), so
	// recurring deviants survive and one-off artifacts age out.
	deviantCapDefault = 4096

	// deviantTTLDefault is the wall-clock TTL after which a stale deviant record ages
	// out even below the cap, so a multi-week window does not accumulate one-off
	// anomalies forever. Measured against LastSeen with the aggregator's a.clock().
	deviantTTLDefault = 30 * 24 * time.Hour
)

// DeviantFlowRecord is one durable, forensic record of a non-tripwire baseline
// deviant: an anomalous flow that touched NO canary. It is LOCAL-RICH — it holds
// the RAW captured flow identity (the same bytes hashAdjacency folds, kept
// un-hashed) — and is a SIBLING to the egress-bound intelligence.AdversaryInteractionEvent,
// which stays structurally addressless so the cross-customer path cannot regress
// (docs/TOPOLOGY_AND_DEVIANTS.md §4). All fields are exported for gob and for the
// future deviants tap to read; the record never crosses a deployment boundary.
type DeviantFlowRecord struct {
	// Raw flow identity (local-rich), straight from the live observe.FlowStats.
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Family  uint16

	// SocketCookie is the per-connection L7/kernel join key (Rule 4) of the flow
	// that produced THIS observation. It is recorded for forensic join-back, but it
	// is NEVER the recurrence key (cookies are reused/evicted — see deviantKey).
	SocketCookie uint64

	// The 5 baseline novelty dimensions at capture, as floats in [0,1] (the same
	// dims that feed M). PeakDim/PeakLabel name the strongest, which is what made
	// the flow "look anomalous from baseline".
	IdentityNovelty  float64
	AdjacencyNovelty float64
	PortNovelty      float64
	VolumeDeviation  float64
	CadenceDeviation float64
	PeakNovelty      float64
	PeakLabel        string

	// Score is the engine suspicion score this flow carried at capture (0 here when
	// the capture seam has none — the fold path scores no base without a canary
	// touch). Recorded for the hunting surface's sort/rank.
	Score float64

	// FirstSeen / LastSeen are WALL-CLOCK (a.clock()), used for operator display and
	// the TTL reaper. HitCount is the approximate recurrence count: how many times a
	// deviant matching this record's canonical behavioral key has been seen
	// ("pattern seen ~N times"), so a sweeping scanner collapses into few records.
	FirstSeen time.Time
	LastSeen  time.Time
	HitCount  uint64
}

// deviants is the in-memory per-scope deviant accumulator for one scope. The
// aggregator holds one per scope under its existing lock; all reads and writes
// happen under a.mu (the map is never touched on the request hot path). Persisted
// via gob blobs under bktDeviants on the batched fold-tick write.
type deviants struct {
	records map[string]*DeviantFlowRecord // deviantKey -> record
}

func newDeviants() *deviants {
	return &deviants{records: map[string]*DeviantFlowRecord{}}
}

// --- canonical recurrence key ----------------------------------------------
//
// The deviant recurrence key is a canonical BEHAVIORAL/IDENTITY key per §4: the
// flow identity (initiator + reached service endpoint) PLUS the peak novelty
// DIMENSION (which kind of anomaly it is — new identity vs new adjacency vs
// cadence). Two deviants from the same pattern (same identity, same reached
// endpoint, same anomaly kind) collapse onto one record and bump HitCount/LastSeen
// — so a methodical scanner does not flood the log; counts are APPROXIMATE
// ("pattern seen ~N times"). It is DELIBERATELY NOT keyed on the socket cookie
// (cookies are per-connection, reused/evicted; keying on one would defeat dedup
// entirely). The peak NOVELTY VALUE is intentionally NOT in the key: as a
// recurring deviant gradually teaches the baseline (its novelty decays toward the
// middle), keying on the value would fork one pattern into many records — so the
// key uses the stable peak DIMENSION, not the moving value.
//
// Layout (a 1-byte kind discriminator keeps the bucket walkable and never
// collides with another store's keys):
//
//	[0x01][family BE u16][srcAddr (4|16)][dstAddr (4|16)][dstPort BE u16][peakDim u8]
//
// The address canonicalization (family-prefixed, v4 = 4 bytes, v6 = 16 bytes)
// matches derive.go's writeAddr and topology.go's edgeKey, so all three agree on
// what "the same edge/identity" is.

const deviantKind byte = 0x01

// peakDimCode is the small int code for a peak novelty dimension, used in the
// recurrence key and the PeakLabel.
type peakDimCode uint8

const (
	dimIdentity  peakDimCode = 1
	dimAdjacency peakDimCode = 2
	dimPort      peakDimCode = 3
	dimVolume    peakDimCode = 4
	dimCadence   peakDimCode = 5
)

func (d peakDimCode) label() string {
	switch d {
	case dimIdentity:
		return "new identity"
	case dimAdjacency:
		return "new adjacency"
	case dimPort:
		return "new port"
	case dimVolume:
		return "volume deviation"
	case dimCadence:
		return "cadence deviation"
	default:
		return "unknown"
	}
}

// peakNoveltyDim returns the strongest baseline-deviation dimension of a derived
// feature vector, its value, and a human label. It mirrors the tap's peakNovelty
// over the same dims (adding PortNovelty, which the fold path also derives).
func peakNoveltyDim(f baseline.Features) (peakDimCode, float64, string) {
	best, code := f.IdentityNovelty, dimIdentity
	if f.AdjacencyNovelty > best {
		best, code = f.AdjacencyNovelty, dimAdjacency
	}
	if f.PortNovelty > best {
		best, code = f.PortNovelty, dimPort
	}
	if f.VolumeDeviation > best {
		best, code = f.VolumeDeviation, dimVolume
	}
	if f.CadenceDeviation > best {
		best, code = f.CadenceDeviation, dimCadence
	}
	return code, best, code.label()
}

// deviantKey is the canonical recurrence key for a deviant flow: the identity
// edge tuple plus the stable peak anomaly DIMENSION (not the moving novelty value).
func deviantKey(fs observe.FlowStats, peak peakDimCode) string {
	n := addrLen(fs.Family)
	b := make([]byte, 0, 1+2+n+n+2+1)
	b = append(b, deviantKind)
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], fs.Family)
	b = append(b, fam[:]...)
	b = appendAddr(b, fs.Family, fs.SrcIP) // initiator
	b = appendAddr(b, fs.Family, fs.DstIP) // reached workload
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], fs.DstPort)
	b = append(b, port[:]...)
	b = append(b, byte(peak))
	return string(b)
}

// --- folding ---------------------------------------------------------------

// fold upserts one DEVIANT, NON-ARMED completed flow into the log, stamping
// wall-clock now (NEVER kernel ns). A repeat deviant matching an existing
// recurrence key bumps HitCount + LastSeen + refreshes the live novelty/score
// snapshot, instead of writing a new record. Caps are enforced here on insert
// (lowest-HitCount / oldest-LastSeen eviction); the TTL reaper runs separately on
// the fold tick. Returns the key inserted-or-bumped, plus any key evicted to make
// room (so the persist layer can delete it in the same fsync).
func (d *deviants) fold(fs observe.FlowStats, cookie uint64, feat baseline.Features, score float64, now time.Time) (touched string, evicted []string) {
	peakCode, peakNov, peakLabel := peakNoveltyDim(feat)
	key := deviantKey(fs, peakCode)
	if r := d.records[key]; r != nil {
		r.HitCount++
		r.LastSeen = now
		// Refresh the live snapshot so the surfaced novelty/score tracks the most
		// recent observation of the pattern (the identity key is unchanged).
		r.SocketCookie = cookie
		r.IdentityNovelty = feat.IdentityNovelty
		r.AdjacencyNovelty = feat.AdjacencyNovelty
		r.PortNovelty = feat.PortNovelty
		r.VolumeDeviation = feat.VolumeDeviation
		r.CadenceDeviation = feat.CadenceDeviation
		r.PeakNovelty = peakNov
		r.PeakLabel = peakLabel
		r.Score = score
		return key, nil
	}
	if ev, ok := d.evictIfFull(now); ok {
		evicted = append(evicted, ev)
	}
	d.records[key] = &DeviantFlowRecord{
		SrcIP:            fs.SrcIP,
		DstIP:            fs.DstIP,
		SrcPort:          fs.SrcPort,
		DstPort:          fs.DstPort,
		Family:           fs.Family,
		SocketCookie:     cookie,
		IdentityNovelty:  feat.IdentityNovelty,
		AdjacencyNovelty: feat.AdjacencyNovelty,
		PortNovelty:      feat.PortNovelty,
		VolumeDeviation:  feat.VolumeDeviation,
		CadenceDeviation: feat.CadenceDeviation,
		PeakNovelty:      peakNov,
		PeakLabel:        peakLabel,
		Score:            score,
		FirstSeen:        now,
		LastSeen:         now,
		HitCount:         1,
	}
	return key, evicted
}

// --- cap eviction (lowest-HitCount, oldest-LastSeen tiebreak) ---------------

func (d *deviants) evictIfFull(now time.Time) (string, bool) {
	if len(d.records) < deviantCapDefault {
		return "", false
	}
	var victim string
	var bestCount uint64 = ^uint64(0)
	var bestSeen time.Time
	for k, r := range d.records {
		if r.HitCount < bestCount || (r.HitCount == bestCount && r.LastSeen.Before(bestSeen)) {
			victim, bestCount, bestSeen = k, r.HitCount, r.LastSeen
		}
	}
	delete(d.records, victim)
	return victim, true
}

// reap evicts every record whose LastSeen is older than ttl relative to now
// (wall-clock). It returns the keys removed so the caller can delete them in the
// same batched fsync as the fold writes, and the count so eviction is observable
// (the aggregator bumps a lost-count metric, mirroring TopologyEvicted /
// RehydrateSkipped). Runs on the fold tick under the aggregator lock, off the hot
// path.
func (d *deviants) reap(now time.Time, ttl time.Duration) []string {
	cutoff := now.Add(-ttl)
	var removed []string
	for k, r := range d.records {
		if r.LastSeen.Before(cutoff) {
			delete(d.records, k)
			removed = append(removed, k)
		}
	}
	return removed
}

// --- gob (de)serialization for the batched write ---------------------------

func encodeDeviant(r *DeviantFlowRecord) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeDeviant(blob []byte) (*DeviantFlowRecord, error) {
	r := &DeviantFlowRecord{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(r); err != nil {
		return nil, err
	}
	return r, nil
}

// blobForKey gob-encodes the in-memory deviant record addressed by key, or returns
// ok=false if the key is no longer present (it was evicted) — in which case the
// caller persists a delete.
func (d *deviants) blobForKey(key string) (blob []byte, ok bool, err error) {
	r := d.records[key]
	if r == nil {
		return nil, false, nil
	}
	b, err := encodeDeviant(r)
	return b, err == nil, err
}

// --- read-side snapshot (FEATURE-3 — the /raw/deviants data path) -----------
//
// DeviantSnapshot exposes a DECODED, copied view of the live in-memory per-scope
// deviant log so the dashboard tap can resolve identity labels and emit the
// deviants view (docs/TOPOLOGY_AND_DEVIANTS.md §4). It mirrors TopologySnapshot
// EXACTLY: snapshot under a.mu (read lock), then hand back plain value structs the
// caller owns — the package-private *DeviantFlowRecord pointers and the gob types
// NEVER escape this package.
//
// This is READ-SIDE ONLY (Rule 8 — nothing here arms a response; the records are
// of flows that touched NO canary) and LOCAL-ONLY (Rule 9 — the raw addresses stay
// in the deployment; this accessor lives in observebaseline, which the egress
// filter is structurally forbidden to import — see
// internal/intelligence/network/egress_importguard_test.go). The addresses it
// returns are the un-hashed local-rich identity; coarsening happens only at the
// egress boundary, never here.

// DeviantFlowRecordView is one deviant record, decoded for the read side. SrcIP/
// DstIP are the canonical 4- or 16-byte address slices (length follows Family).
// FirstSeen/LastSeen are wall-clock (a.clock()). It is a plain value the caller
// owns; no package-private pointer or fixed [16]byte buffer escapes — the address
// bytes are deep-copied at snapshot time (mirrors TopologySnapshot's edge addrs).
type DeviantFlowRecordView struct {
	SrcIP   []byte
	DstIP   []byte
	SrcPort uint16
	DstPort uint16
	Family  uint16

	SocketCookie uint64

	IdentityNovelty  float64
	AdjacencyNovelty float64
	PortNovelty      float64
	VolumeDeviation  float64
	CadenceDeviation float64
	PeakNovelty      float64
	PeakLabel        string

	Score float64

	FirstSeen time.Time
	LastSeen  time.Time
	HitCount  uint64
}

// DeviantSnap is the decoded deviant records for one scope.
type DeviantSnap struct {
	Records []DeviantFlowRecordView
}

// DeviantSnapshot returns a decoded, copied snapshot of the live in-memory deviant
// log for sc (the CURRENT map — the source of truth, rehydrated on boot and folded
// each tick). Empty (zero-value) for a scope with no accrued deviants. Safe for
// concurrent reads; takes only the read lock and copies every field out (the
// address bytes deep-copied to length-of-family slices so the internal [16]byte
// buffers never alias), so the caller never touches package-private state.
func (a *Aggregator) DeviantSnapshot(sc contract.ScopeKey) DeviantSnap {
	a.mu.RLock()
	defer a.mu.RUnlock()
	dv := a.deviants[sc]
	if dv == nil {
		return DeviantSnap{}
	}
	out := make([]DeviantFlowRecordView, 0, len(dv.records))
	for _, r := range dv.records {
		n := addrLen(r.Family)
		out = append(out, DeviantFlowRecordView{
			SrcIP:            append([]byte(nil), r.SrcIP[:n]...),
			DstIP:            append([]byte(nil), r.DstIP[:n]...),
			SrcPort:          r.SrcPort,
			DstPort:          r.DstPort,
			Family:           r.Family,
			SocketCookie:     r.SocketCookie,
			IdentityNovelty:  r.IdentityNovelty,
			AdjacencyNovelty: r.AdjacencyNovelty,
			PortNovelty:      r.PortNovelty,
			VolumeDeviation:  r.VolumeDeviation,
			CadenceDeviation: r.CadenceDeviation,
			PeakNovelty:      r.PeakNovelty,
			PeakLabel:        r.PeakLabel,
			Score:            r.Score,
			FirstSeen:        r.FirstSeen,
			LastSeen:         r.LastSeen,
			HitCount:         r.HitCount,
		})
	}
	return DeviantSnap{Records: out}
}
