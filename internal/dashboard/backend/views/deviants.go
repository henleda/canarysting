package views

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
const deviantsCaption = "These flows DEVIATED from the learned baseline — an unfamiliar identity, a new adjacency, a volume or cadence shift — but touched NO canary, so NO response was armed (Rule 8). They are logged for threat-hunting, never actioned, and are NOT confirmed adversaries. The list is ranked by UNFAMILIARITY: unregistered movers first (the prime hunting leads), then known callers, with mesh services that initiated a novel flow last. Identities are resolved from the operator registry where named; the rest fall back to raw IP. Local to this deployment; addresses never cross a boundary (Rule 9)."

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
	return v
}
