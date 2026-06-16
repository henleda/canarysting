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

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/topology/identity"
)

// DeviantTriageReader is the NARROW read-only view of the operator ACK/SUPPRESS
// overlay the tap needs to JOIN triage state onto each surfaced deviant row. It is
// satisfied by *persist.Store. The tap takes this READ-ONLY surface (no Put/Delete)
// so the display side can never accidentally MUTATE triage state — the only write
// path is the token-gated admin endpoint (Rule 8 / display-only fence). It is read
// ONLY here on the display side; nothing on the verdict path consults it.
type DeviantTriageReader interface {
	RangeDeviantTriage(scope contract.ScopeKey, fn func(key []byte, rec persist.DeviantTriageRecord) error) error
}

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

	// Key is the canonical deviant RECURRENCE KEY (deviantKey bytes) hex-encoded — the
	// JOIN identity to the operator triage overlay AND the value canaryctl deviant -key
	// consumes. It comes straight from observebaseline.DeviantFlowRecordView.Key (the
	// hex of the record's authoritative map key), so the operator can copy it from a
	// row to suppress/ack the pattern. Local-rich (it encodes raw addr bytes), so it
	// stays in the deployment (Rule 9) like the rest of this surface.
	Key string `json:"key"`

	// TriageState is the operator triage overlay state joined onto this row: ""
	// (normal, no overlay row) | "acked" (seen-but-keep-showing) | "suppressed"
	// (known-benign-hidden-by-default). The tap is a PASS-THROUGH that ranks/demotes —
	// it does NOT filter suppressed rows out; the BACKEND owns hide-by-default and the
	// view-suppressed toggle, so the suppressed rows remain available here for it.
	TriageState string `json:"triage_state"`

	// SrcFamiliarity is the hunting headline keyed on the SRC (initiator) identity:
	// "unfamiliar" when the SRC resolves UNKNOWN (an identity the operator never
	// registered — e.g. a fresh careful-mover or recon node, the prime hunting lead),
	// "known" when it resolves to a declared caller/external/etc. It drives the
	// unfamiliar-first ranking (see buildDeviants) and the page's unfamiliar/known chip.
	SrcFamiliarity string `json:"src_familiarity"`

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

// srcTier ranks a deviant row by the FAMILIARITY of its SRC (initiator) identity, so
// the genuine hunting leads top the list. It keys on the resolved SRC kind token
// (NodeKind.String()):
//
//	tier 0 — UNFAMILIAR ("unknown"): an identity the operator never registered (a
//	         fresh careful-mover, recon node) — the prime hunting target.
//	tier 1 — declared CALLER ("caller"): a known host that deviates is a lower-priority
//	         but honest lead — demoted below the unfamiliar.
//	tier 2 — everything else (e.g. "external"): a legit off-mesh peer — demoted.
//	tier 3 — declared SERVICE ("service"): a mesh service INITIATING a genuinely-novel
//	         east-west flow. Every row here already cleared the engine's novelty floor
//	         AGAINST that service's own learned baseline, so it is NOT "the system
//	         talking to itself" (that is low-novelty and never captured once the scope
//	         is live) — it is exactly a compromised-service / lateral-movement pivot.
//	         So it is KEPT (ranked last, lowest priority), NOT dropped: hiding it would
//	         silently bury the highest-value east-west lead.
//
// No SRC kind is dropped — the surface is exhaustive of the captured log (capped at
// maxDeviantRows for display), just ranked unfamiliar-first.
func srcTier(srcKind string) int {
	switch srcKind {
	case identity.KindUnknown.String():
		return 0
	case identity.KindCaller.String():
		return 1
	case identity.KindService.String():
		return 3
	default:
		return 2
	}
}

// buildDeviants assembles the DeviantsView from the live in-memory deviant log and
// the node resolver into an UNFAMILIAR-FIRST hunting surface. It is total: a nil
// aggregator yields an empty list, a nil resolver degrades every endpoint to its IP
// label.
//
// RANKING: rows are ranked UNFAMILIAR-SRC FIRST (KindUnknown — the careful-mover /
// recon lead), then declared callers, then others (srcTier); WITHIN a tier the prior
// HitCount desc -> PeakValue desc -> LastSeen desc order holds — so a recurring
// careful-mover (whose per-hit novelty may DECAY as it teaches the baseline) stays
// pinned at the top of its tier by its growing hit-count.
//
// NO row is dropped: every captured deviant is shown (capped at maxDeviantRows for
// display), just RANKED unfamiliar-first. A declared SERVICE source is demoted to the
// lowest tier (srcTier 3) rather than dropped — by the time a row reaches here it has
// already cleared the engine's novelty floor against that service's own learned
// baseline (the mesh's normal east-west is low-novelty and is never captured once the
// scope is live), so a service-initiated row is a genuine lateral-movement lead, not
// "the system talking to itself" — hiding it would bury the highest-value east-west
// signal. The caption frames the surface as ranked-by-unfamiliarity (views/deviants.go).
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

	// Load the per-scope operator triage overlay (acked|suppressed by canonical
	// deviantKey) so each row can be badged/partitioned downstream. NIL-TOLERANT: a
	// nil Triage reader (older wiring, or a DB-less engine) yields an empty overlay —
	// every row reads triage_state="" (normal). The overlay is read ONLY here on the
	// display side (Rule 8 / display-only fence). The map is keyed by the HEX of the
	// deviantKey so it joins to DeviantFlowRecordView.Key byte-for-byte.
	overlay := s.loadTriageOverlay()
	view.Rows = rankDeviantRows(s.Aggregator.DeviantSnapshot(s.Scope).Records, resolver, overlay)
	return view
}

// loadTriageOverlay reads the per-scope ACK/SUPPRESS overlay into a map keyed by the
// HEX deviantKey -> state ("acked"|"suppressed"). Nil-tolerant (nil reader => empty
// map). A range error degrades to whatever was loaded so far (the surface stays
// total — a transient overlay read fault must not 500 the hunting page; rows simply
// read normal). LOCAL + DISPLAY-ONLY (Rule 8/9).
func (s *Source) loadTriageOverlay() map[string]string {
	out := map[string]string{}
	if s.Triage == nil {
		return out
	}
	_ = s.Triage.RangeDeviantTriage(s.Scope, func(key []byte, rec persist.DeviantTriageRecord) error {
		out[hexKey(key)] = rec.State
		return nil
	})
	return out
}

// rankDeviantRows resolves each captured deviant record's src/dst identity, builds the
// wire rows, and ranks them UNFAMILIAR-SRC FIRST (srcTier) with the prior
// HitCount->PeakValue->LastSeen tiebreak within a tier, capped at maxDeviantRows. It
// is extracted from buildDeviants so the tiering / familiarity / drop-vs-demote logic
// is unit-testable with synthetic records (the Source.Aggregator is a concrete type).
func rankDeviantRows(records []observebaseline.DeviantFlowRecordView, resolver *identity.Resolver, overlay map[string]string) []DeviantRow {
	rows := make([]DeviantRow, 0, len(records))
	for _, r := range records {
		srcIP := addrFrom(r.SrcIP)
		dstIP := addrFrom(r.DstIP)
		// Resolve the SRC as an initiator (port 0 — its egress side) and the DST as a
		// service on DstPort (its reached/listen side). A fresh identity the operator
		// never registered resolves UNKNOWN/raw-IP — which is the "unfamiliar
		// identity" signal, not an error.
		srcNode := resolver.Resolve(srcIP, 0, "", "")
		dstNode := resolver.Resolve(dstIP, r.DstPort, "", "")
		// All sources are KEPT and tier-ranked (srcTier): unfamiliar first, a declared
		// SERVICE source demoted last (a genuinely-novel service-initiated flow is a
		// lateral-movement lead, not noise — see srcTier). Decoy never appears as a SRC.
		familiarity := "known"
		if srcNode.Kind == identity.KindUnknown {
			familiarity = "unfamiliar"
		}
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
			// Key is the row's canonical recurrence key (already hex on the view); join
			// the operator triage overlay by it (absent => "" normal). The tap does NOT
			// drop suppressed rows — it surfaces the state and lets the backend hide.
			Key:              r.Key,
			TriageState:      overlay[r.Key],
			SrcFamiliarity:   familiarity,
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

	// Rank UNFAMILIAR-SRC FIRST (srcTier asc): the careful-mover / recon lead tops the
	// list, then declared callers, then others, then demoted mesh services — so the
	// genuine hunting targets stay on top. WITHIN a tier keep the prior order:
	// recurring deviants first (HitCount desc), then how anomalous (PeakValue desc),
	// then most-recent (LastSeen desc). sort.SliceStable so equal rows keep map-order
	// stability across the (already-nondeterministic) snapshot.
	sort.SliceStable(rows, func(i, j int) bool {
		if ti, tj := srcTier(rows[i].Src.Kind), srcTier(rows[j].Src.Kind); ti != tj {
			return ti < tj
		}
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
	return rows
}

// hexKey renders the raw overlay key bytes as lowercase hex — the ONE pinned
// encoding shared with DeviantFlowRecordView.Key / the admin route, so the overlay
// map join is byte-for-byte aligned with the row Key.
func hexKey(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// addrString renders a netip.Addr as its string, or "" for an invalid address (an
// odd-length/empty snapshot slice) — never the "invalid IP" sentinel.
func addrString(a netip.Addr) string {
	if a.IsValid() {
		return a.String()
	}
	return ""
}
