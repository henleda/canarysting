package views

import (
	"net/netip"
	"sort"
)

// F2 rich non-tripwire deviant log — the dashboard-backend view (FEATURE-3; see
// docs/TOPOLOGY_AND_DEVIANTS.md §4). The backend fetches the tap's
// GET /raw/deviants, validates/normalizes the shape here, and serves it at
// GET /api/deviants. This is the read-side mirror of the tap's DeviantsView; the
// backend talks to the engine ONLY over HTTP, so it keeps a LOCAL mirror of the
// wire types rather than importing the tap package (read-only by construction).
//
// HONESTY (load-bearing): the view carries a persistent Caption that states plainly
// these flows DEVIATED from the learned baseline but touched NO canary, so NO
// response was armed (Rule 8) — they are logged for hunting, NEVER actioned and
// never "confirmed adversaries". A separate ⚠-simulated note is driven by the
// Simulated flag (the synthetic-peer demo posture); the deviant flows themselves
// are real local observations.

// deviantsCaption is the persistent on-screen honesty fence for the deviants page.
// It is verbatim the fence the panel will test. It states the hunting-only,
// never-armed posture (Rule 8) without ever implying these are confirmed
// adversaries or that the page took any action.
const deviantsCaption = "These flows DEVIATED from the learned baseline — an unfamiliar identity, a new adjacency, a volume or cadence shift — but touched NO canary, so NO response was armed (Rule 8). They are logged for threat-hunting, never actioned, and are NOT confirmed adversaries. The list is ranked by UNFAMILIARITY: unregistered movers first (the prime hunting leads), then known callers, with mesh services that initiated a novel flow last; the platform's own management-plane traffic — loopback (127.0.0.0/8) and the box talking to itself — is demoted to the bottom, never dropped. Identities are resolved from the operator registry where named; the rest fall back to raw IP. Local to this deployment; addresses never cross a boundary (Rule 9)."

// deviantsSimulatedNote is appended-as-a-separate-badge note when Simulated is true:
// the synthetic-peer demo posture is running. The deviant flows are still real
// local observations; only the cross-customer demo context is synthetic.
const deviantsSimulatedNote = "Demo posture: synthetic-peer cross-customer context is simulated. The deviant flows shown are real local observations."

// DeviantEndpointView is one resolved end of a deviant flow.
type DeviantEndpointView struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
}

// DeviantRowView mirrors the tap's DeviantRow on the wire. Timestamps are RFC3339
// strings; kept as strings (the backend validates and passes the shape through).
type DeviantRowView struct {
	Src DeviantEndpointView `json:"src"`
	Dst DeviantEndpointView `json:"dst"`

	// SrcFamiliarity mirrors the tap's src_familiarity ("unfamiliar" | "known"): the
	// hunting headline keyed on the SRC identity. Passed through unchanged.
	SrcFamiliarity string `json:"src_familiarity"`

	IdentityNovelty  float64 `json:"identity_novelty"`
	AdjacencyNovelty float64 `json:"adjacency_novelty"`
	PortNovelty      float64 `json:"port_novelty"`
	VolumeDeviation  float64 `json:"volume_deviation"`
	CadenceDeviation float64 `json:"cadence_deviation"`

	PeakDim   string  `json:"peak_dim"`
	PeakValue float64 `json:"peak_value"`

	HitCount  uint64  `json:"hit_count"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
	Score     float64 `json:"score"`
}

// DeviantsTapView mirrors the tap's wire shape (GET /raw/deviants) for decoding.
type DeviantsTapView struct {
	Scope        string           `json:"scope"`
	StagedLabels bool             `json:"staged_labels"`
	Simulated    bool             `json:"simulated"`
	Rows         []DeviantRowView `json:"rows"`
}

// DeviantsView is the served shape at GET /api/deviants. It is the validated tap
// view plus the derived honesty Caption (and the simulated note). It IS the
// contract the Next.js frontend consumes (dashboard/app/lib/types.ts).
type DeviantsView struct {
	Scope         string           `json:"scope"`
	StagedLabels  bool             `json:"staged_labels"`
	Simulated     bool             `json:"simulated"`
	Caption       string           `json:"caption"`
	SimulatedNote string           `json:"simulated_note"`
	Rows          []DeviantRowView `json:"rows"`
}

// DeriveDeviants validates/normalizes the tap's raw deviants view into the served
// DeviantsView. It is total: a nil rows slice becomes empty (never JSON null), it
// drops any row missing both endpoints' addr/label (a shapeless row the frontend
// cannot render), and it attaches the persistent honesty caption. The data itself
// is never fabricated — only shape-validated. The simulated note is set only when
// the simulated flag is on.
func DeriveDeviants(raw DeviantsTapView) DeviantsView {
	v := DeviantsView{
		Scope:        raw.Scope,
		StagedLabels: raw.StagedLabels,
		Simulated:    raw.Simulated,
		Caption:      deviantsCaption,
		Rows:         []DeviantRowView{},
	}
	if raw.Simulated {
		v.SimulatedNote = deviantsSimulatedNote
	}
	for _, r := range raw.Rows {
		// A row with no usable identity on EITHER end (no label and no addr) is a
		// shapeless artifact the frontend cannot render meaningfully; drop it. A row
		// where one end resolves UNKNOWN/raw-IP is KEPT — an unfamiliar identity is
		// the signal, not a defect.
		if r.Src.Label == "" && r.Src.Addr == "" && r.Dst.Label == "" && r.Dst.Addr == "" {
			continue
		}
		v.Rows = append(v.Rows, r)
	}
	// Read-side re-rank (Rule 8: a re-ordering of a logged view, never an action).
	// The platform's own management-plane traffic — a loopback SRC (127.0.0.0/8 or
	// ::1) or the box talking to itself (src.addr == dst.addr) — is the deployment's
	// own infra noise, not a hunting lead. STABLE-push those rows to the BOTTOM so the
	// genuine external movers (non-loopback src, src != dst) stay on top, while the
	// tap's existing unfamiliar-first order is preserved within each group. We DEMOTE,
	// never drop: a loopback-source flow could still be a real signal, just lowest
	// priority.
	sort.SliceStable(v.Rows, func(i, j int) bool {
		mi, mj := isManagementPlane(v.Rows[i]), isManagementPlane(v.Rows[j])
		if mi != mj {
			// A non-management-plane row sorts BEFORE a management-plane one.
			return !mi
		}
		// Same management-plane flag: defer to the tap's existing order (return false
		// so SliceStable keeps the incoming relative order).
		return false
	})
	return v
}

// isManagementPlane reports whether a deviant row is the deployment's own
// management-plane noise rather than a hunting lead. It is true when the SRC addr
// is loopback (127.0.0.0/8 or ::1) or when the row is self-talk (src.addr ==
// dst.addr — e.g. the box at 10.20.1.24 talking to itself). The SRC/DST addrs are
// RAW IP STRINGS on the wire (the backend mirrors the tap over HTTP), so we parse
// them with net/netip before testing loopback. A parse failure is treated as NOT
// management-plane: a non-empty, unparseable lead is left in place rather than
// demoted on a parse miss. The self-talk test guards against empty addrs (an empty
// SRC is not "talking to itself").
func isManagementPlane(r DeviantRowView) bool {
	src, srcErr := netip.ParseAddr(r.Src.Addr)
	if srcErr == nil && src.IsLoopback() {
		return true
	}
	// Self-talk (the box reaching itself). Compare canonically so textually-distinct
	// but equal addresses (::1 vs 0:0:0:0:0:0:0:1, IPv4-mapped forms) still match; fall
	// back to raw-string equality only when an end does not parse.
	if r.Src.Addr == "" {
		return false
	}
	if dst, dstErr := netip.ParseAddr(r.Dst.Addr); srcErr == nil && dstErr == nil {
		return src.Compare(dst) == 0
	}
	return r.Src.Addr == r.Dst.Addr
}
