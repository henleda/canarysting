package views

import (
	"net/netip"
	"sort"
	"time"
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
const deviantsCaption = "These flows DEVIATED from the learned baseline — an unfamiliar identity, a new adjacency, a volume or cadence shift — but touched NO canary, so NO response was armed (Rule 8). They are logged for threat-hunting, never actioned, and are NOT confirmed adversaries. The list is ranked by UNFAMILIARITY: unregistered movers first (the prime hunting leads), then known callers, with mesh services that initiated a novel flow last; the platform's own management-plane traffic — loopback (127.0.0.0/8) and the box talking to itself — is demoted to the bottom, never dropped. Operator triage applies on top: a pattern an operator ACKED stays in the list (badged, demoted within its group); a pattern an operator SUPPRESSED as known-benign is HIDDEN from this default list but is still COUNTED in the summary and is viewable via the view-suppressed toggle — hidden, never silently dropped. Identities are resolved from the operator registry where named; the rest fall back to raw IP. Local to this deployment; addresses never cross a boundary (Rule 9)."

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

	// Key mirrors the tap's `key`: the canonical deviant recurrence key (hex). The
	// JOIN identity AND the canaryctl deviant -key argument. Passed through unchanged.
	Key string `json:"key"`
	// TriageState mirrors the tap's `triage_state`: "" (normal) | "acked" |
	// "suppressed". The backend HIDES suppressed from v.Rows by default (still counted
	// + shipped in v.Suppressed); acked rows STAY in v.Rows, badged + demoted.
	TriageState string `json:"triage_state"`

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

// DeviantsSummary is the volume/triage summary chip on the deviants page. Counts are
// over the SURFACED deviant set — the tap caps at maxDeviantRows (top-N by
// unfamiliarity), so on a high-cardinality scope Total is the surfaced top-N, NOT the
// full population, and PerDay is the rate over that surfaced set (the leading "~" on the
// wire signals it is approximate). Total = all surfaced (kept-after-shapeless);
// Shown = len(Rows) (default-visible = total minus suppressed); Suppressed = hidden
// count; Acked = badged count (a subset of Shown); PerDay = the deviant recurrence
// rate (deviants/day) derived from HitCount over the FirstSeen..LastSeen wall-clock
// span on the wire. The Suppressed count is the load-bearing HONESTY disclosure:
// hiding suppressed rows by default is only honest because the chip says how many
// were hidden.
type DeviantsSummary struct {
	Total      int     `json:"total"`
	Shown      int     `json:"shown"`
	Suppressed int     `json:"suppressed"`
	Acked      int     `json:"acked"`
	PerDay     float64 `json:"per_day"`
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
	// Suppressed are the rows HIDDEN from the default list (triage_state=="suppressed").
	// Shipped INLINE so the page's view-suppressed toggle needs no second fetch. Never
	// JSON null (empty slice when none).
	Suppressed []DeviantRowView `json:"suppressed"`
	// Summary is the volume/triage chip (total/shown/suppressed/acked/per_day).
	Summary DeviantsSummary `json:"summary"`
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
		Suppressed:   []DeviantRowView{},
	}
	if raw.Simulated {
		v.SimulatedNote = deviantsSimulatedNote
	}
	// Partition the kept-after-shapeless set by triage state:
	//   - "suppressed" => HIDDEN from the default list, shipped in v.Suppressed (still
	//     COUNTED in the summary, available behind the toggle). Hidden, never dropped.
	//   - "acked"      => STAYS in v.Rows (badged + demoted within its group below).
	//   - ""  (normal) => STAYS in v.Rows.
	// kept is the honest denominator for the summary (total = every row that survived
	// the shapeless drop, including suppressed).
	var keptCount, suppressedCount, ackedCount int
	for _, r := range raw.Rows {
		// A row with no usable identity on EITHER end (no label and no addr) is a
		// shapeless artifact the frontend cannot render meaningfully; drop it. A row
		// where one end resolves UNKNOWN/raw-IP is KEPT — an unfamiliar identity is
		// the signal, not a defect.
		if r.Src.Label == "" && r.Src.Addr == "" && r.Dst.Label == "" && r.Dst.Addr == "" {
			continue
		}
		keptCount++
		switch r.TriageState {
		case "suppressed":
			suppressedCount++
			v.Suppressed = append(v.Suppressed, r)
		case "acked":
			ackedCount++
			v.Rows = append(v.Rows, r)
		default:
			v.Rows = append(v.Rows, r)
		}
	}
	// Read-side re-rank (Rule 8: a re-ordering of a logged view, never an action).
	// TWO demotions, applied as a single stable sort with a 4-way precedence so the
	// tap's existing unfamiliar-first order is preserved WITHIN each bucket:
	//   1. management-plane LAST (a loopback SRC or self-talk — the deployment's own
	//      infra noise, not a hunting lead);
	//   2. WITHIN the non-management group, ACKED rows AFTER non-acked (an operator
	//      who acked a pattern said "seen — keep showing but lower"; it stays, just
	//      demoted below the un-triaged leads).
	// We DEMOTE, never drop: a loopback-source or acked flow could still be a real
	// signal, just lower priority. (Suppressed rows are already out of v.Rows.)
	sort.SliceStable(v.Rows, func(i, j int) bool {
		mi, mj := isManagementPlane(v.Rows[i]), isManagementPlane(v.Rows[j])
		if mi != mj {
			// A non-management-plane row sorts BEFORE a management-plane one.
			return !mi
		}
		// Same management-plane flag: within the (non-management) group, an un-acked row
		// sorts BEFORE an acked one. (For the management group this is also applied but
		// is immaterial — both are already at the bottom.)
		ai, aj := v.Rows[i].TriageState == "acked", v.Rows[j].TriageState == "acked"
		if ai != aj {
			return !ai
		}
		// Same flags: defer to the tap's existing order (return false so SliceStable
		// keeps the incoming relative order).
		return false
	})
	v.Summary = DeviantsSummary{
		Total:      keptCount,
		Shown:      len(v.Rows),
		Suppressed: suppressedCount,
		Acked:      ackedCount,
		PerDay:     deviantsPerDay(raw.Rows),
	}
	return v
}

// deviantsPerDay derives the deviant RECURRENCE RATE (deviants/day) from the rows'
// HitCount over the union FirstSeen..LastSeen wall-clock span already on the wire. It
// sums every row's HitCount (the approximate "pattern seen ~N times" counters) and
// divides by the span in days between the earliest FirstSeen and latest LastSeen
// across all rows. It is computed over ALL kept rows (suppressed included) — the rate
// is a volume fact about the deployment's deviant traffic, independent of what the
// operator chose to hide. A span under one day (or unparseable/zero) floors the
// divisor at one day so a fresh window reports "~N/day" rather than dividing by ~0
// and reporting a meaningless spike. Returns 0 with no rows.
func deviantsPerDay(rows []DeviantRowView) float64 {
	var totalHits uint64
	var earliest, latest time.Time
	for _, r := range rows {
		totalHits += r.HitCount
		if fs, err := time.Parse(time.RFC3339, r.FirstSeen); err == nil {
			if earliest.IsZero() || fs.Before(earliest) {
				earliest = fs
			}
		}
		if ls, err := time.Parse(time.RFC3339, r.LastSeen); err == nil {
			if latest.IsZero() || ls.After(latest) {
				latest = ls
			}
		}
	}
	if totalHits == 0 {
		return 0
	}
	days := 1.0
	if !earliest.IsZero() && !latest.IsZero() && latest.After(earliest) {
		if d := latest.Sub(earliest).Hours() / 24.0; d > 1.0 {
			days = d
		}
	}
	return float64(totalHits) / days
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
