package tap

// F2 rich non-tripwire deviant log — the READ-SIDE data path (FEATURE-3; see
// docs/TOPOLOGY_AND_DEVIANTS.md §4). GET /raw/deviants emits a DeviantsView built
// from TWO local-only sources, per-scope (Rule 5):
//
//   1. the engine's live in-memory deviant log (the un-hashed flow identity + the
//      5 baseline novelty dims + peak label + hit-count + score) via
//      Aggregator.DeviantSnapshot — flows that DEVIATED from the learned baseline
//      but touched NO canary, captured for hunting;
//   2. the node-identity resolver (internal/topology/identity), which turns the
//      raw SRC/DST IP+port into a human-legible {label, kind}. The resolver is
//      OPERATOR-DECLARED metadata, NOT an engine verdict, and is nil-tolerant: a
//      nil resolver degrades every endpoint to its IP label (staged_labels=false).
//      An UNFAMILIAR identity (one the operator never registered — e.g. a fresh
//      careful-mover) resolves to UNKNOWN / raw-IP, which is itself the signal.
//
// RULES (load-bearing):
//   - Rule 8 (read-side only): NOTHING here arms a response. By construction every
//     record is of a flow that touched NO canary, so it never entered the response
//     pipeline; surfacing it on a hunting page takes no new action. These are
//     "logged for hunting", NEVER "confirmed adversaries".
//   - Rule 9 (local): the raw IPs/labels stay in the deployment. This path lives in
//     the tap + observebaseline; the cross-customer egress filter
//     (internal/intelligence/network) is STRUCTURALLY forbidden to import them (see
//     its egress_importguard_test.go) and nothing here is wired into it. This file
//     MUST NOT import internal/intelligence/network.
//   - Rule 5 (scope): per-scope. The snapshot is read for s.Scope only.

import (
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/topology/identity"
)

// maxDeviantRows caps the surfaced hunting list so a port-sweep / source-spoof that
// manufactured many distinct deviant records cannot flood the page. The engine
// store is already cap-bounded (deviantCapDefault); this is the presentation cap
// on top of the ranked view.
const maxDeviantRows = 50

// DeviantsView is the wire contract for GET /raw/deviants, mirrored 1:1 in the
// frontend (dashboard/app/lib/types.ts). The dashboard backend validates + serves
// the SAME shape (plus a derived honesty caption) at GET /api/deviants. See
// docs/TOPOLOGY_AND_DEVIANTS.md §4.
type DeviantsView struct {
	Scope string `json:"scope"`
	// StagedLabels is true when the endpoint NAMES came from an operator-supplied
	// registry (vs an IP-label fallback). Drives the same honesty caption the
	// topology view uses; an UNKNOWN endpoint is honest either way.
	StagedLabels bool `json:"staged_labels"`
	// Simulated marks the demo posture (s.SimulatedPeers): the synthetic-peer demo
	// is running. The DEVIANT FLOWS themselves are real local observations; the flag
	// only discloses the cross-customer demo context, surfaced as a ⚠ badge.
	Simulated bool         `json:"simulated"`
	Rows      []DeviantRow `json:"rows"`
}

// DeviantEndpoint is one resolved end of a deviant flow.
type DeviantEndpoint struct {
	Label string `json:"label"` // operator-declared name, SPIFFE-derived name, or (on a miss) the IP
	Kind  string `json:"kind"`  // "service" | "caller" | "decoy" | "external" | "unknown"
	Addr  string `json:"addr"`  // the raw IP string (local-rich; never crosses a boundary)
	Port  uint16 `json:"port"`  // 0 on the src (initiator), the reached service port on the dst
}

// DeviantRow is one ranked deviant flow: the fingerprint (src -> dst with identity),
// the 5 baseline novelty dims, the peak dim that made it look anomalous, the
// recurrence count, and the wall-clock window. NOTHING here is a verdict — it is
// a hunting record of a flow that touched no canary (Rule 8).
type DeviantRow struct {
	Src DeviantEndpoint `json:"src"`
	Dst DeviantEndpoint `json:"dst"`

	// The 5 baseline novelty dimensions at capture, floats in [0,1].
	IdentityNovelty  float64 `json:"identity_novelty"`
	AdjacencyNovelty float64 `json:"adjacency_novelty"`
	PortNovelty      float64 `json:"port_novelty"`
	VolumeDeviation  float64 `json:"volume_deviation"`
	CadenceDeviation float64 `json:"cadence_deviation"`

	// PeakDim is the human label of the strongest dim ("new identity" / "new
	// adjacency" / …) — the headline "why it looked anomalous"; PeakValue is its
	// magnitude in [0,1].
	PeakDim   string  `json:"peak_dim"`
	PeakValue float64 `json:"peak_value"`

	HitCount  uint64  `json:"hit_count"`  // approximate recurrence count ("seen ~N times")
	FirstSeen string  `json:"first_seen"` // RFC3339 wall-clock
	LastSeen  string  `json:"last_seen"`  // RFC3339 wall-clock
	Score     float64 `json:"score"`      // engine suspicion score at capture (0 on the fold seam)
}

// handleDeviants serves GET /raw/deviants: the per-scope deviant hunting log.
func (s *Source) handleDeviants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.buildDeviants())
}

// buildDeviants assembles the DeviantsView from the live in-memory deviant log and
// the node resolver. It is total: a nil aggregator yields an empty list, a nil
// resolver degrades every endpoint to its IP label, and the rows are RANKED by
// HitCount desc, then PeakValue desc, then LastSeen desc — so a recurring
// careful-mover (whose per-hit novelty may DECAY as it teaches the baseline) stays
// pinned at the top by its growing hit-count. Capped at maxDeviantRows.
func (s *Source) buildDeviants() DeviantsView {
	view := DeviantsView{
		Scope:        string(s.Scope),
		StagedLabels: s.Resolver != nil, // the ORIGINAL resolver, not the degraded one
		Simulated:    s.SimulatedPeers,
		Rows:         []DeviantRow{},
	}
	resolver := s.Resolver
	if resolver == nil {
		resolver = identity.NewResolver(nil) // degrade to IP labels; never panics
	}
	if s.Aggregator == nil {
		return view
	}

	snap := s.Aggregator.DeviantSnapshot(s.Scope)
	rows := make([]DeviantRow, 0, len(snap.Records))
	for _, r := range snap.Records {
		srcIP := addrFrom(r.SrcIP)
		dstIP := addrFrom(r.DstIP)
		// Resolve the SRC as an initiator (port 0 — its egress side) and the DST as a
		// service on DstPort (its reached/listen side). A fresh identity the operator
		// never registered resolves UNKNOWN/raw-IP — which is the "unfamiliar
		// identity" signal, not an error.
		srcNode := resolver.Resolve(srcIP, 0, "", "")
		dstNode := resolver.Resolve(dstIP, r.DstPort, "", "")
		rows = append(rows, DeviantRow{
			Src: DeviantEndpoint{
				Label: srcNode.Label,
				Kind:  srcNode.Kind.String(),
				Addr:  addrString(srcIP),
				Port:  0,
			},
			Dst: DeviantEndpoint{
				Label: dstNode.Label,
				Kind:  dstNode.Kind.String(),
				Addr:  addrString(dstIP),
				Port:  r.DstPort,
			},
			IdentityNovelty:  r.IdentityNovelty,
			AdjacencyNovelty: r.AdjacencyNovelty,
			PortNovelty:      r.PortNovelty,
			VolumeDeviation:  r.VolumeDeviation,
			CadenceDeviation: r.CadenceDeviation,
			PeakDim:          r.PeakLabel,
			PeakValue:        r.PeakNovelty,
			HitCount:         r.HitCount,
			FirstSeen:        r.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:         r.LastSeen.UTC().Format(time.RFC3339),
			Score:            r.Score,
		})
	}

	// Rank: recurring deviants first (HitCount), then by how anomalous (PeakValue),
	// then most-recent (LastSeen). sort.SliceStable so equal rows keep map-order
	// stability across the (already-nondeterministic) snapshot.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].HitCount != rows[j].HitCount {
			return rows[i].HitCount > rows[j].HitCount
		}
		if rows[i].PeakValue != rows[j].PeakValue {
			return rows[i].PeakValue > rows[j].PeakValue
		}
		return rows[i].LastSeen > rows[j].LastSeen // RFC3339 sorts lexicographically by time
	})
	if len(rows) > maxDeviantRows {
		rows = rows[:maxDeviantRows]
	}
	view.Rows = rows
	return view
}

// addrString renders a netip.Addr as its string, or "" for an invalid address (an
// odd-length/empty snapshot slice) — never the "invalid IP" sentinel.
func addrString(a netip.Addr) string {
	if a.IsValid() {
		return a.String()
	}
	return ""
}
