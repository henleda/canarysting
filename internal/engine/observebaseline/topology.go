package observebaseline

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
)

// F1 — learned east-west topology (engine-side capture). This is the LOCAL-RICH
// half of the local-rich / export-coarse posture (docs/TOPOLOGY_AND_DEVIANTS.md
// §1, §3): beside the FNV-hashed novelty counts the baseline keeps (which are
// UNCHANGED and still drive all scoring), we ADDITIONALLY keep the raw directed
// edge and a node catalog — un-hashed — so an operator can see a real map of
// their OWN deployment. These stores are LOCAL-ONLY: nothing here is reachable
// from internal/intelligence/network, which stays coarse/hashed/default-deny
// (Rule 9 coarsens at the egress boundary, not at capture).
//
// Both maps are folded once per COMPLETED flow inside foldCompleted, inheriting
// the aggregator's a.live/a.folded fold-once bookkeeping — no new hot-path
// state. FirstSeen/LastSeen are WALL-CLOCK from a.clock() at fold time, NEVER the
// kernel bpf_ktime monotonic FirstSeenNs/LastSeenNs.

const (
	// topoEdgeCapDefault / topoNodeCapDefault bound each per-scope map's
	// cardinality the same way freqCapDefault bounds the baseline frequency maps:
	// a normal mesh is sparse (dozens-to-low-hundreds of nodes, hundreds-to-a-few-
	// thousand directed edges), but a port-sweep or source-spoof can manufacture
	// huge edge/identity counts. The cap is what stops a scan from blowing up the
	// store. Eviction is lowest-FlowCount / oldest-LastSeen (the bumpCapped
	// discipline), so frequent normal edges survive and rare scan artifacts age
	// out; an evicted edge looked up later correctly reads as novel.
	topoEdgeCapDefault = 4096
	topoNodeCapDefault = 4096

	// topoTTLDefault is the wall-clock TTL after which a stale edge/node ages out
	// even below the cap, so a multi-week window does not accumulate one-off
	// artifacts forever. Measured against LastSeen with the aggregator's a.clock().
	topoTTLDefault = 30 * 24 * time.Hour
)

// nodeRole tags a catalog entry as the initiator side (the caller's SrcIP) or the
// service side (a reached (DstIP, DstPort) endpoint). Stored as a small int for
// gob compactness.
type nodeRole uint8

const (
	roleInitiator nodeRole = 1
	roleService   nodeRole = 2
)

func (r nodeRole) String() string {
	switch r {
	case roleInitiator:
		return "initiator"
	case roleService:
		return "service"
	default:
		return "unknown"
	}
}

// topoEdge is one directed east-west adjacency: who reached which service, with
// the observed volume. SrcIP/DstIP are the RAW captured addresses (local-rich) —
// these are the bytes hashAdjacency folds, kept un-hashed. FirstSeen/LastSeen are
// wall-clock (a.clock()), used both for operator display and for the TTL reaper.
// All fields are exported solely for gob; treat the type as package-private.
type topoEdge struct {
	SrcIP      [16]byte
	DstIP      [16]byte
	DstPort    uint16
	Family     uint16
	FlowCount  uint64
	TotalBytes uint64
	TotalPkts  uint64
	FirstSeen  time.Time // wall-clock at first fold of this edge
	LastSeen   time.Time // wall-clock at most recent fold of this edge
}

// topoNode is one identity in the catalog: an initiator (SrcIP) or a service
// endpoint (DstIP, DstPort). Addr holds the raw address bytes; for a service the
// Port is the listen port that disambiguates it. FirstSeen/LastSeen wall-clock.
type topoNode struct {
	Addr      [16]byte
	Port      uint16 // 0 for an initiator node; the listen port for a service node
	Family    uint16
	Role      nodeRole
	FlowCount uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// topology is the in-memory per-scope edge accumulator + node catalog for one
// scope. The aggregator holds one per scope under its existing lock; all reads
// and writes happen under a.mu (the maps are never touched on the request hot
// path). Persisted via gob blobs under bktTopology on the batched fold-tick
// write.
type topology struct {
	edges map[string]*topoEdge // edgeKey -> edge
	nodes map[string]*topoNode // nodeKey -> node
}

func newTopology() *topology {
	return &topology{
		edges: map[string]*topoEdge{},
		nodes: map[string]*topoNode{},
	}
}

// --- canonical key encoding -------------------------------------------------
//
// The edge key is the canonical (SrcIP bytes, DstIP bytes, DstPort, Family)
// tuple, encoded the SAME family-prefixed way derive.go's writeAddr canonicalizes
// (family big-endian, v4 = first 4 bytes, v6 = 16 bytes) so the un-hashed key and
// the FNV adjacency hash agree on what "the same edge" is. Layout:
//
//	edge: [0x01][family BE u16][srcAddr (4|16)][dstAddr (4|16)][dstPort BE u16]
//	node: [0x02][role u8][family BE u16][addr (4|16)][port BE u16]
//
// A 1-byte kind discriminator (0x01 edge, 0x02 node) lets edges and nodes share
// the one per-scope bbolt sub-bucket without colliding, and a bbolt range can
// still walk them in a stable order.

const (
	topoKindEdge byte = 0x01
	topoKindNode byte = 0x02
)

func addrLen(family uint16) int {
	if family == observe.AFInet {
		return 4
	}
	return 16
}

func appendAddr(b []byte, family uint16, ip [16]byte) []byte {
	return append(b, ip[:addrLen(family)]...)
}

// edgeKey is the canonical directed-edge key for a flow.
func edgeKey(fs observe.FlowStats) string {
	n := addrLen(fs.Family)
	b := make([]byte, 0, 1+2+n+n+2)
	b = append(b, topoKindEdge)
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], fs.Family)
	b = append(b, fam[:]...)
	b = appendAddr(b, fs.Family, fs.SrcIP) // initiator
	b = appendAddr(b, fs.Family, fs.DstIP) // reached workload
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], fs.DstPort)
	b = append(b, port[:]...)
	return string(b)
}

// initiatorNodeKey is the catalog key for the initiator identity (SrcIP only).
func initiatorNodeKey(fs observe.FlowStats) string {
	return nodeKey(roleInitiator, fs.Family, fs.SrcIP, 0)
}

// serviceNodeKey is the catalog key for the reached service endpoint (DstIP, DstPort).
func serviceNodeKey(fs observe.FlowStats) string {
	return nodeKey(roleService, fs.Family, fs.DstIP, fs.DstPort)
}

func nodeKey(role nodeRole, family uint16, ip [16]byte, port uint16) string {
	n := addrLen(family)
	b := make([]byte, 0, 1+1+2+n+2)
	b = append(b, topoKindNode, byte(role))
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], family)
	b = append(b, fam[:]...)
	b = appendAddr(b, family, ip)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	b = append(b, p[:]...)
	return string(b)
}

// --- folding ---------------------------------------------------------------

// fold upserts one COMPLETED flow into the edge accumulator and the node catalog,
// stamping wall-clock now (NEVER kernel ns). It records which keys changed so the
// caller can persist only the touched records on the batched write. Caps are
// enforced here on insert (lowest-FlowCount / oldest-LastSeen eviction); the TTL
// reaper runs separately on the fold tick. Returns the edge key and node keys
// that were inserted-or-bumped, plus any keys evicted to make room (so the
// persist layer can delete them in the same fsync).
func (t *topology) fold(fs observe.FlowStats, now time.Time) (touched []string, evicted []string) {
	ek := edgeKey(fs)
	bytesTot := fs.TotalBytes()
	pktsTot := fs.TotalPackets()
	if e := t.edges[ek]; e != nil {
		e.FlowCount++
		e.TotalBytes += bytesTot
		e.TotalPkts += pktsTot
		e.LastSeen = now
	} else {
		if ev, ok := t.evictEdgeIfFull(now); ok {
			evicted = append(evicted, ev)
		}
		t.edges[ek] = &topoEdge{
			SrcIP:      fs.SrcIP,
			DstIP:      fs.DstIP,
			DstPort:    fs.DstPort,
			Family:     fs.Family,
			FlowCount:  1,
			TotalBytes: bytesTot,
			TotalPkts:  pktsTot,
			FirstSeen:  now,
			LastSeen:   now,
		}
	}
	touched = append(touched, ek)

	ik := initiatorNodeKey(fs)
	if ev, ok := t.foldNode(ik, roleInitiator, fs.Family, fs.SrcIP, 0, now); ok {
		evicted = append(evicted, ev)
	}
	touched = append(touched, ik)

	sk := serviceNodeKey(fs)
	if ev, ok := t.foldNode(sk, roleService, fs.Family, fs.DstIP, fs.DstPort, now); ok {
		evicted = append(evicted, ev)
	}
	touched = append(touched, sk)
	return touched, evicted
}

func (t *topology) foldNode(key string, role nodeRole, family uint16, ip [16]byte, port uint16, now time.Time) (evictedKey string, didEvict bool) {
	if n := t.nodes[key]; n != nil {
		n.FlowCount++
		n.LastSeen = now
		return "", false
	}
	if ev, ok := t.evictNodeIfFull(now); ok {
		evictedKey, didEvict = ev, true
	}
	t.nodes[key] = &topoNode{
		Addr:      ip,
		Port:      port,
		Family:    family,
		Role:      role,
		FlowCount: 1,
		FirstSeen: now,
		LastSeen:  now,
	}
	return evictedKey, didEvict
}

// --- cap eviction (lowest-FlowCount, oldest-LastSeen tiebreak) --------------

func (t *topology) evictEdgeIfFull(now time.Time) (string, bool) {
	if len(t.edges) < topoEdgeCapDefault {
		return "", false
	}
	var victim string
	var bestCount uint64 = ^uint64(0)
	var bestSeen time.Time
	for k, e := range t.edges {
		if e.FlowCount < bestCount || (e.FlowCount == bestCount && e.LastSeen.Before(bestSeen)) {
			victim, bestCount, bestSeen = k, e.FlowCount, e.LastSeen
		}
	}
	delete(t.edges, victim)
	return victim, true
}

func (t *topology) evictNodeIfFull(now time.Time) (string, bool) {
	if len(t.nodes) < topoNodeCapDefault {
		return "", false
	}
	var victim string
	var bestCount uint64 = ^uint64(0)
	var bestSeen time.Time
	for k, n := range t.nodes {
		if n.FlowCount < bestCount || (n.FlowCount == bestCount && n.LastSeen.Before(bestSeen)) {
			victim, bestCount, bestSeen = k, n.FlowCount, n.LastSeen
		}
	}
	delete(t.nodes, victim)
	return victim, true
}

// reap evicts every edge and node whose LastSeen is older than ttl relative to
// now (wall-clock). It returns the keys removed so the caller can delete them in
// the same batched fsync as the fold writes, and the count so eviction is
// observable (the aggregator bumps a lost-count metric, mirroring
// RehydrateSkipped). Runs on the fold tick under the aggregator lock, off the hot
// path.
func (t *topology) reap(now time.Time, ttl time.Duration) []string {
	cutoff := now.Add(-ttl)
	var removed []string
	for k, e := range t.edges {
		if e.LastSeen.Before(cutoff) {
			delete(t.edges, k)
			removed = append(removed, k)
		}
	}
	for k, n := range t.nodes {
		if n.LastSeen.Before(cutoff) {
			delete(t.nodes, k)
			removed = append(removed, k)
		}
	}
	return removed
}

// --- gob (de)serialization for the batched write ---------------------------

func encodeEdge(e *topoEdge) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(e); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeEdge(blob []byte) (*topoEdge, error) {
	e := &topoEdge{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(e); err != nil {
		return nil, err
	}
	return e, nil
}

func encodeNode(n *topoNode) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(n); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeNode(blob []byte) (*topoNode, error) {
	n := &topoNode{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(n); err != nil {
		return nil, err
	}
	return n, nil
}

// blobForKey gob-encodes the in-memory record (edge or node) addressed by key, or
// returns ok=false if the key is no longer present (it was evicted) — in which
// case the caller persists a delete. The key's kind byte selects the record type.
func (t *topology) blobForKey(key string) (blob []byte, ok bool, err error) {
	if len(key) == 0 {
		return nil, false, nil
	}
	switch key[0] {
	case topoKindEdge:
		e := t.edges[key]
		if e == nil {
			return nil, false, nil
		}
		b, err := encodeEdge(e)
		return b, err == nil, err
	case topoKindNode:
		n := t.nodes[key]
		if n == nil {
			return nil, false, nil
		}
		b, err := encodeNode(n)
		return b, err == nil, err
	default:
		return nil, false, nil
	}
}
