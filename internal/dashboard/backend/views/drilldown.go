package views

// drilldown.go holds the pure derivation logic for the interactive console's
// four drill-down endpoints (flow detail, flows table, attacker-cost breakdown,
// recon timeline). Same discipline as Derive(): no I/O, no clock — the handler
// passes events + now. It reuses the home-wall helpers (groupByFlow,
// computeMaxMAndPeak, normalizeSpark, DeriveFingerprint, the recon cluster/
// description helpers) so the drill-downs and the wall never disagree.
//
// SESSION-SPLITTING (decision E): socket cookies are kernel-recycled, so over a
// long window the same cookie can map to distinct connections. A "flow" in the
// console is therefore a SESSION — a cookie's events split wherever consecutive
// touches are more than sessionGap apart. This keeps reuse from conflating two
// real sessions into one row, without any store change (view-layer only).

import (
	"fmt"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/cost"
	"github.com/canarysting/canarysting/internal/intelligence/recon"
)

// sessionGap is the idle threshold that separates two sessions on the same
// socket cookie. A silence longer than this is almost certainly the cookie value
// being reused by a new connection (the old socket closed). ~10m is comfortably
// longer than any realistic intra-session think time yet short enough to split
// genuinely distinct sessions.
const sessionGap = 10 * time.Minute

// maxCostBuckets caps the cost time-series length. parseSince clamps ?since= to
// 24h and BucketDurFor keeps bucketDur in [1m,1h], so a real request yields well
// under this; the cap is a hard backstop and, when hit, keeps the NEWEST buckets.
const maxCostBuckets = 1440

// --- view structs (the frontend wire contract; mirror 1:1 in types.ts) ---

// TouchEvent is one canary touch in a flow's ordered timeline.
type TouchEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	CanaryType  string    `json:"canary_type"`
	Tier        int       `json:"tier"`
	Verdict     string    `json:"verdict"`
	Score       float64   `json:"score"` // 0 = pre-Score event; UI renders "—"
	M           float64   `json:"m"`     // MFromFeatures for THIS touch; 1.0 if none
	TimeHeldSec float64   `json:"time_held_sec"`
	BytesServed int64     `json:"bytes_served"`
	Requests    int64     `json:"requests"` // from Sting.RequestsAbsrb
	TokenCost   float64   `json:"token_cost"`
	Mechanism   string    `json:"mechanism"` // "" → UI: "kernel-enforced · cost not attributed"
}

// MContribution is one feature's contribution to the baseline multiplier M.
type MContribution struct {
	Feature  string  `json:"feature"`
	RawValue float64 `json:"raw_value"`
	Capped   float64 `json:"capped"` // min(max(raw,0), CMax)
	Label    string  `json:"label"`
}

// MBreakdown explains the peak-event multiplier on the flow-detail page. NOTE:
// it deliberately includes ALL FIVE features capped at CMax (the home wall's
// featureBars shows only four, clamped to [0,1]) so the detail view is complete.
type MBreakdown struct {
	M             float64         `json:"m"`
	Contributions []MContribution `json:"contributions"`
	GateNote      string          `json:"gate_note"`
}

// FlowDetail is one SESSION's full record. SessionIndex/Count expose cookie
// reuse: "session 2 of 3" means this cookie carried three distinct sessions.
type FlowDetail struct {
	FlowIDHex    string           `json:"flow_id_hex"`
	FlowID       uint64           `json:"flow_id"`
	SessionStart time.Time        `json:"session_start"`
	SessionIndex int              `json:"session_index"` // 1-based within the cookie
	SessionCount int              `json:"session_count"` // total sessions for this cookie in the window
	TouchCount   int              `json:"touch_count"`
	PeakTier     int              `json:"peak_tier"`
	Verdict      string           `json:"verdict"`
	Score        float64          `json:"score"` // latest; 0 if none
	FirstSeen    time.Time        `json:"first_seen"`
	LastSeen     time.Time        `json:"last_seen"`
	Timeline     []TouchEvent     `json:"timeline"` // ascending timestamp
	Fingerprint  *FlowFingerprint `json:"fingerprint,omitempty"`
	MBreakdown   *MBreakdown      `json:"m_breakdown,omitempty"`
	SparkSeries  []float64        `json:"spark_series"`
}

// FlowCost is an aggregate cost tuple (a session's, a mechanism's, or the total).
type FlowCost struct {
	TimeHeldSec float64 `json:"time_held_sec"`
	BytesServed int64   `json:"bytes_served"`
	Requests    int64   `json:"requests"`
	TokenCost   float64 `json:"token_cost"`
}

// FlowRow is one SESSION row in the flows table / cost by-flow list.
type FlowRow struct {
	FlowIDHex    string    `json:"flow_id_hex"`
	FlowID       uint64    `json:"flow_id"`
	SessionStart time.Time `json:"session_start"`
	SessionIndex int       `json:"session_index"`
	SessionCount int       `json:"session_count"`
	PeakTier     int       `json:"peak_tier"`
	Verdict      string    `json:"verdict"`
	TouchCount   int       `json:"touch_count"`
	Score        float64   `json:"score"`  // latest; 0 if none
	BaseM        float64   `json:"base_m"` // max M across the session
	TotalCost    FlowCost  `json:"total_cost"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// FlowsList is the flows-table payload.
type FlowsList struct {
	Flows      []FlowRow `json:"flows"`       // peak tier desc, then last_seen desc
	TotalCount int       `json:"total_count"` // sessions before tier filter
	Filtered   int       `json:"filtered"`    // == len(Flows)
}

// FlowFunnelView is the FleetWall windowed funnel: DISTINCT flows (sessions),
// counted by CUMULATIVE REACH — each flow is counted in every stage it reached
// (maxTier >= N), within this events window. A funnel drawn with › arrows is a
// "reached at least tier N" cohort, NOT an exact-peak histogram: flows escalate
// THROUGH containment to the jail, so an exact-peak-T2 count would read ~0 even
// when most flows passed through containment. It is the two-rail companion to the
// cumulative T0 observed rail (CompletedFolds) — the two are NEVER summed into one
// denominator (see Derive's EscalationView caption).
//
// HONESTY (distinct-jailed discipline): Jailed here is the count of DISTINCT
// flows whose peak tier >= 3 — the ONLY honest headline "jailed" number. It is
// NOT attacker_cost.jailed (= cost.Summary.TierCounts[3], a per-EVENT count),
// which is FORBIDDEN as a headline because one flow can emit many T3 events.
//
// DecoyTouched is every session (reached tier >= 1) — a "decoy-armed flow" is a
// DISTINCT session, NOT a unique attacker (cookies recycle; sessions split at the
// 10-min idle gap). DistinctActive == len(sessions) == DecoyTouched by
// construction (boltevents stores only Tier>=1, so every stored session reached
// tier >= 1).
type FlowFunnelView struct {
	// DecoyTouched = sessions that reached tier >= 1 (touched a decoy). Equals DeriveFlowsList(events,-1).TotalCount and equals DistinctActive.
	DecoyTouched int `json:"decoy_touched"`
	// Contained = sessions that reached tier >= 2 (containment / active response) this window. Equals FlowsReached(events,2).Filtered.
	Contained int `json:"contained"`
	// Jailed = sessions that reached tier >= 3 (kernel jail) this window. Equals DeriveFlowsList(events,3).Filtered (== exact peak 3, since 3 is the top tier).
	// The ONLY honest headline jailed number; never attacker_cost.jailed (per-event).
	Jailed int `json:"jailed"`
	// DistinctActive = total distinct sessions in the window (== DecoyTouched).
	DistinctActive int `json:"distinct_active"`
}

// DeriveFlowFunnel builds the windowed DISTINCT-flow funnel by CUMULATIVE REACH.
// It reuses the SAME session grouping + per-session peak-tier semantics as
// DeriveFlowsList (the forward pass in buildFlowRow uses Tier >= maxTier), so the
// equalities below hold by construction and the funnel can never disagree with the
// flows table:
//
//	DecoyTouched   == DeriveFlowsList(events,-1).TotalCount   (all sessions, reached>=1)
//	Contained      == FlowsReached(events, 2).Filtered        (reached>=2)
//	Jailed         == FlowsReached(events, 3).Filtered        (reached>=3 == exact peak 3)
//	DistinctActive == len(sessions)
//
// Each flow is counted in EVERY stage it reached — this is a cumulative-reach
// per-FLOW funnel, not a per-event tier histogram (the per-event TierCounts live
// in cost.Summary).
func DeriveFlowFunnel(events []intelligence.AdversaryInteractionEvent) FlowFunnelView {
	sessions := groupByFlowSessions(events)
	var fv FlowFunnelView
	fv.DistinctActive = len(sessions)
	for _, s := range sessions {
		// Per-session peak tier: identical forward pass to buildFlowRow (Tier >= maxTier),
		// so this matches DeriveFlowsList's PeakTier exactly.
		peak := 0
		for _, e := range s.Events {
			if e.Tier >= peak {
				peak = e.Tier
			}
		}
		if peak >= 1 {
			fv.DecoyTouched++ // reached tier >= 1 (every stored session, by construction)
		}
		if peak >= 2 {
			fv.Contained++ // reached tier >= 2 — escalated into containment/active response
		}
		if peak >= 3 {
			fv.Jailed++ // reached tier >= 3 — distinct sockets dropped in-kernel
		}
	}
	return fv
}

// MechanismCost is one row of the by-mechanism cost rollup.
type MechanismCost struct {
	Mechanism   string  `json:"mechanism"`
	EventCount  int     `json:"event_count"`
	TimeHeldSec float64 `json:"time_held_sec"`
	BytesServed int64   `json:"bytes_served"`
	Requests    int64   `json:"requests"`
	TokenCost   float64 `json:"token_cost"`
}

// CostBucket is one zero-filled time-series bucket.
type CostBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	TimeHeldSec float64   `json:"time_held_sec"`
	TokenCost   float64   `json:"token_cost"`
	EventCount  int       `json:"event_count"`
}

// CostBreakdown is the /api/cost payload.
type CostBreakdown struct {
	Total       FlowCost         `json:"total"`
	ByFlow      []FlowRow        `json:"by_flow"`      // TimeHeldSec desc
	ByMechanism []MechanismCost  `json:"by_mechanism"` // empty-mechanism events omitted (decision J)
	TimeSeries  []CostBucket     `json:"time_series"`  // zero-filled
	BucketSec   int              `json:"bucket_sec"`
	Engagement  EngagementView   `json:"engagement"` // the engagement contest (median/p90/longest + disengage split)
	Reactions   AxisReactionView `json:"reactions"`  // AX2/AX4/AX5 deception-reaction signals
}

// ReconRow is one T1 early-warning row, scoped to its SESSION's escalation.
// SessionStart lets the UI deep-link to the exact session this touch belongs to
// (a reused cookie has several sessions; without it the link would land on the
// latest one).
type ReconRow struct {
	FlowIDHex     string    `json:"flow_id_hex"`
	FlowID        uint64    `json:"flow_id"`
	SessionStart  time.Time `json:"session_start"`
	Timestamp     time.Time `json:"timestamp"`
	OffsetLabel   string    `json:"offset_label"`
	CanaryType    string    `json:"canary_type"`
	Severity      string    `json:"severity"` // "recon" | "surfaced"
	Description   string    `json:"description"`
	Escalated     bool      `json:"escalated"`      // this flow's SESSION later reached Tier>=2
	EscalatedTier int       `json:"escalated_tier"` // session peak tier; 0 if not escalated past T1
}

// ReconTimeline is the /api/recon payload.
type ReconTimeline struct {
	Rows       []ReconRow `json:"rows"`        // oldest first (decision H)
	TotalRecon int        `json:"total_recon"` // total T1 in window
}

// --- session splitting (decision E) ---

// flowSession is one session: a cookie's events run with no gap > sessionGap.
type flowSession struct {
	FlowID       uint64
	SessionStart time.Time
	Index        int // 1-based within the cookie
	Count        int // total sessions for this cookie
	Events       []intelligence.AdversaryInteractionEvent
}

// groupByFlowSessions groups events by cookie, then splits each cookie's events
// into sessions wherever a consecutive gap exceeds sessionGap. Events within a
// session are ascending by timestamp.
func groupByFlowSessions(events []intelligence.AdversaryInteractionEvent) []flowSession {
	byFlow := groupByFlow(events)
	var out []flowSession
	for _, id := range sortedFlowIDs(byFlow) {
		grp := append([]intelligence.AdversaryInteractionEvent(nil), byFlow[id]...)
		sort.SliceStable(grp, func(i, j int) bool { return grp[i].Timestamp.Before(grp[j].Timestamp) })

		var sessions [][]intelligence.AdversaryInteractionEvent
		cur := []intelligence.AdversaryInteractionEvent{grp[0]}
		for k := 1; k < len(grp); k++ {
			if grp[k].Timestamp.Sub(grp[k-1].Timestamp) > sessionGap {
				sessions = append(sessions, cur)
				cur = nil
			}
			cur = append(cur, grp[k])
		}
		sessions = append(sessions, cur)

		n := len(sessions)
		for i, s := range sessions {
			out = append(out, flowSession{
				FlowID:       id,
				SessionStart: s[0].Timestamp,
				Index:        i + 1,
				Count:        n,
				Events:       s,
			})
		}
	}
	return out
}

// --- derivations ---

// DeriveFlowDetail builds the detail for ONE session of a cookie. sessionSel is
// the session's start time as Unix seconds; 0 selects the latest session. Returns
// nil if the cookie has no events (404) or no session matches a non-zero selector.
func DeriveFlowDetail(flowID uint64, events []intelligence.AdversaryInteractionEvent, now time.Time, sessionSel int64) *FlowDetail {
	var mine []intelligence.AdversaryInteractionEvent
	for _, e := range events {
		if e.FlowID == flowID {
			mine = append(mine, e)
		}
	}
	if len(mine) == 0 {
		return nil
	}
	sessions := groupByFlowSessions(mine) // all belong to flowID
	if len(sessions) == 0 {
		return nil
	}
	sel := sessions[len(sessions)-1] // default: latest
	if sessionSel > 0 {
		found := false
		for _, s := range sessions {
			if s.SessionStart.Unix() == sessionSel {
				sel = s
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	ordered := sel.Events // already ascending
	maxTier, verdict := 0, ""
	var firstSeen, lastSeen time.Time
	var latestScore float64
	rawScores := make([]float64, 0, len(ordered))
	timeline := make([]TouchEvent, 0, len(ordered))
	p := baseline.DefaultParams()
	for i, e := range ordered {
		if e.Tier >= maxTier {
			maxTier = e.Tier
			verdict = e.Verdict
		}
		if i == 0 || e.Timestamp.Before(firstSeen) {
			firstSeen = e.Timestamp
		}
		if e.Timestamp.After(lastSeen) {
			lastSeen = e.Timestamp
		}
		latestScore = e.Score
		rawScores = append(rawScores, e.Score)
		timeline = append(timeline, TouchEvent{
			Timestamp:   e.Timestamp,
			CanaryType:  e.CanaryType,
			Tier:        e.Tier,
			Verdict:     e.Verdict,
			Score:       e.Score,
			M:           baseline.MFromFeatures(featuresFromMap(e.Features), p),
			TimeHeldSec: e.Sting.TimeHeldSec,
			BytesServed: e.Sting.BytesServed,
			Requests:    e.Sting.RequestsAbsrb,
			TokenCost:   e.Sting.TokenCostProxy,
			Mechanism:   e.Sting.Mechanism,
		})
	}

	return &FlowDetail{
		FlowIDHex:    fmt.Sprintf("0x%x", flowID),
		FlowID:       flowID,
		SessionStart: sel.SessionStart,
		SessionIndex: sel.Index,
		SessionCount: sel.Count,
		TouchCount:   len(ordered),
		PeakTier:     maxTier,
		Verdict:      verdict,
		Score:        latestScore,
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		Timeline:     timeline,
		Fingerprint:  DeriveFingerprint(flowID, ordered),
		MBreakdown:   mBreakdownFromEvents(ordered),
		SparkSeries:  normalizeSpark(rawScores, ordered),
	}
}

// mBreakdownFromEvents builds the M breakdown from the peak-M event. Returns nil
// if no event has any derivable features.
func mBreakdownFromEvents(events []intelligence.AdversaryInteractionEvent) *MBreakdown {
	p := baseline.DefaultParams()
	hasFeatures := false
	for _, e := range events {
		if len(e.Features) > 0 {
			hasFeatures = true
			break
		}
	}
	if !hasFeatures {
		return nil
	}
	_, peak := computeMaxMAndPeak(events)
	clamp := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > p.CMax {
			return p.CMax
		}
		return v
	}
	contribs := []MContribution{
		{Feature: featAdjacency, RawValue: peak.AdjacencyNovelty, Capped: clamp(peak.AdjacencyNovelty), Label: "adjacency nov."},
		{Feature: featIdentity, RawValue: peak.IdentityNovelty, Capped: clamp(peak.IdentityNovelty), Label: "identity nov."},
		{Feature: featPort, RawValue: peak.PortNovelty, Capped: clamp(peak.PortNovelty), Label: "port nov."},
		{Feature: featVolume, RawValue: peak.VolumeDeviation, Capped: clamp(peak.VolumeDeviation), Label: "volume dev."},
		{Feature: featCadence, RawValue: peak.CadenceDeviation, Capped: clamp(peak.CadenceDeviation), Label: "cadence dev."},
	}
	note := "M derived from peak event · DefaultParams"
	allZero := peak == (baseline.Features{})
	if allZero {
		note = "no features · M=1.0 (neutral)"
	}
	return &MBreakdown{
		M:             baseline.MFromFeatures(peak, p),
		Contributions: contribs,
		GateNote:      note,
	}
}

// DeriveFlowsList builds the flows table. Each SESSION is a row. tierFilter >= 0
// keeps only rows whose PeakTier == tierFilter (EXACT peak); -1 keeps all.
func DeriveFlowsList(events []intelligence.AdversaryInteractionEvent, tierFilter int) FlowsList {
	return flowsListFiltered(events, func(peak int) bool {
		return tierFilter < 0 || peak == tierFilter
	})
}

// FlowsReached builds the flows table filtered to sessions that REACHED at least
// minTier (PeakTier >= minTier) — the cumulative-reach companion to
// DeriveFlowsList's exact-peak filter, backing the funnel's reached stages. It
// reuses the exact same session-building/sorting path as DeriveFlowsList, so
// TotalCount is the same total distinct-session count and the equalities hold by
// construction:
//
//	FlowsReached(events, 1).Filtered == DeriveFlowsList(events,-1).TotalCount (all sessions, reached>=1)
//	FlowsReached(events, 3).Filtered == DeriveFlowsList(events, 3).Filtered   (reached>=3 == exact peak 3)
func FlowsReached(events []intelligence.AdversaryInteractionEvent, minTier int) FlowsList {
	return flowsListFiltered(events, func(peak int) bool {
		return peak >= minTier
	})
}

// flowsListFiltered is the shared session-build + sort path for the flows table.
// keep decides, from a session's peak tier, whether its row is retained. Both
// DeriveFlowsList (exact peak) and FlowsReached (cumulative reach) route through
// here so the two can never disagree on TotalCount or row shape/order.
func flowsListFiltered(events []intelligence.AdversaryInteractionEvent, keep func(peak int) bool) FlowsList {
	sessions := groupByFlowSessions(events)
	rows := make([]FlowRow, 0, len(sessions))
	for _, s := range sessions {
		row := buildFlowRow(s)
		if !keep(row.PeakTier) {
			continue
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PeakTier != rows[j].PeakTier {
			return rows[i].PeakTier > rows[j].PeakTier
		}
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
	return FlowsList{Flows: rows, TotalCount: len(sessions), Filtered: len(rows)}
}

// buildFlowRow does the forward pass for one session.
func buildFlowRow(s flowSession) FlowRow {
	maxTier, verdict := 0, ""
	var firstSeen, lastSeen time.Time
	var latestScore float64
	for i, e := range s.Events {
		if e.Tier >= maxTier {
			maxTier = e.Tier
			verdict = e.Verdict
		}
		if i == 0 || e.Timestamp.Before(firstSeen) {
			firstSeen = e.Timestamp
		}
		if e.Timestamp.After(lastSeen) {
			lastSeen = e.Timestamp
		}
		latestScore = e.Score
	}
	return FlowRow{
		FlowIDHex:    fmt.Sprintf("0x%x", s.FlowID),
		FlowID:       s.FlowID,
		SessionStart: s.SessionStart,
		SessionIndex: s.Index,
		SessionCount: s.Count,
		PeakTier:     maxTier,
		Verdict:      verdict,
		TouchCount:   len(s.Events),
		Score:        latestScore,
		BaseM:        computeMaxM(s.Events),
		TotalCost:    costFromEvents(s.Events),
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
	}
}

// costFromEvents sums the Sting cost across events.
func costFromEvents(events []intelligence.AdversaryInteractionEvent) FlowCost {
	var c FlowCost
	for _, e := range events {
		c.TimeHeldSec += e.Sting.TimeHeldSec
		c.BytesServed += e.Sting.BytesServed
		c.Requests += e.Sting.RequestsAbsrb
		c.TokenCost += e.Sting.TokenCostProxy
	}
	return c
}

// DeriveCostBreakdown builds the attacker-cost breakdown over the window.
func DeriveCostBreakdown(events []intelligence.AdversaryInteractionEvent, now time.Time, bucketDur time.Duration) CostBreakdown {
	cb := CostBreakdown{
		Total:       costFromEvents(events),
		BucketSec:   int(bucketDur.Seconds()),
		ByFlow:      []FlowRow{},       // non-nil → JSON [] not null (the TS contract is a non-optional array)
		ByMechanism: []MechanismCost{}, // non-nil → JSON []
	}

	// ByFlow: one row per session, TimeHeldSec desc.
	for _, s := range groupByFlowSessions(events) {
		cb.ByFlow = append(cb.ByFlow, buildFlowRow(s))
	}
	sort.SliceStable(cb.ByFlow, func(i, j int) bool {
		return cb.ByFlow[i].TotalCost.TimeHeldSec > cb.ByFlow[j].TotalCost.TimeHeldSec
	})

	// ByMechanism: group by Sting.Mechanism, skip "" (decision J).
	byMech := map[string]*MechanismCost{}
	var mechOrder []string
	for _, e := range events {
		m := e.Sting.Mechanism
		if m == "" {
			continue
		}
		mc := byMech[m]
		if mc == nil {
			mc = &MechanismCost{Mechanism: m}
			byMech[m] = mc
			mechOrder = append(mechOrder, m)
		}
		mc.EventCount++
		mc.TimeHeldSec += e.Sting.TimeHeldSec
		mc.BytesServed += e.Sting.BytesServed
		mc.Requests += e.Sting.RequestsAbsrb
		mc.TokenCost += e.Sting.TokenCostProxy
	}
	sort.SliceStable(mechOrder, func(i, j int) bool {
		return byMech[mechOrder[i]].TokenCost > byMech[mechOrder[j]].TokenCost
	})
	for _, m := range mechOrder {
		cb.ByMechanism = append(cb.ByMechanism, *byMech[m])
	}

	cb.TimeSeries = buildCostTimeSeries(events, now, bucketDur)

	// Engagement + the AX2/AX4/AX5 reaction signals, from the same rollup the home
	// wall uses (so the drill-down never disagrees with the Overview).
	sum := cost.Rollup(events)
	cb.Engagement = engagementView(sum)
	cb.Reactions = reactionView(sum)
	return cb
}

// buildCostTimeSeries zero-fills cost buckets from the earliest event to now.
func buildCostTimeSeries(events []intelligence.AdversaryInteractionEvent, now time.Time, bucketDur time.Duration) []CostBucket {
	if len(events) == 0 || bucketDur <= 0 {
		return []CostBucket{} // non-nil → JSON [] not null (CostView maps it unconditionally)
	}
	earliest := events[0].Timestamp
	for _, e := range events {
		if e.Timestamp.Before(earliest) {
			earliest = e.Timestamp
		}
	}
	bucketStart := earliest.Truncate(bucketDur)
	bucketEnd := now.Truncate(bucketDur).Add(bucketDur)
	n := int(bucketEnd.Sub(bucketStart) / bucketDur)
	if n < 1 {
		n = 1
	}
	if n > maxCostBuckets {
		// Keep the NEWEST buckets (anchor the window at now) so an over-range request
		// never silently drops the recent end of the chart while rendering stale older
		// buckets. parseSince clamps ?since= to 24h, so this is defense-in-depth.
		bucketStart = bucketEnd.Add(-time.Duration(maxCostBuckets) * bucketDur)
		n = maxCostBuckets
	}
	buckets := make([]CostBucket, n)
	for i := range buckets {
		buckets[i].BucketStart = bucketStart.Add(time.Duration(i) * bucketDur)
	}
	for _, e := range events {
		idx := int(e.Timestamp.Sub(bucketStart) / bucketDur)
		if idx < 0 || idx >= n {
			continue
		}
		buckets[idx].TimeHeldSec += e.Sting.TimeHeldSec
		buckets[idx].TokenCost += e.Sting.TokenCostProxy
		buckets[idx].EventCount++
	}
	return buckets
}

// bucketDurFor picks a ~24-bucket resolution for the window, clamped [1m,1h].
func BucketDurFor(sinceSec int) time.Duration {
	d := time.Duration(sinceSec) * time.Second / 24
	if d < time.Minute {
		d = time.Minute
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d.Truncate(time.Minute)
}

// DeriveReconTimeline lists all T1 (recon) touches oldest-first, each annotated
// with its SESSION's peak escalation and session start (session-scoped, decision
// E). It walks the sessions ONCE — each T1 event is emitted from the session it
// actually belongs to, so escalation/session_start are exact and the cost is
// O(events), not O(sessions × events).
func DeriveReconTimeline(events []intelligence.AdversaryInteractionEvent, now time.Time) ReconTimeline {
	sessions := groupByFlowSessions(events)

	// The recon SIGNAL (which T1 touches, their cluster membership + severity +
	// description) comes from the single D4 source over ALL the scope's events, so the
	// timeline and the home-wall feed never disagree. The timeline ADDS its view-layer
	// framing: per-session escalation context (decision E).
	sigByKey := map[string]recon.ReconSignal{}
	for _, s := range recon.DeriveReconSignal(events) {
		sigByKey[s.Key()] = s
	}
	if len(sigByKey) == 0 {
		return ReconTimeline{Rows: []ReconRow{}, TotalRecon: 0}
	}

	rows := []ReconRow{}
	for _, s := range sessions {
		peak := 0
		for _, e := range s.Events {
			if e.Tier > peak {
				peak = e.Tier
			}
		}
		// EscalatedTier honors its documented contract: 0 unless the session actually
		// escalated past T1 (peak >= 2). A T1-only session reports 0, not 1, so a
		// future consumer can trust "0 == not escalated".
		escTier := 0
		if peak >= 2 {
			escTier = peak
		}
		for _, e := range s.Events {
			if e.Tier != 1 {
				continue
			}
			sig := sigByKey[fmt.Sprintf("%d:%d", e.FlowID, e.Timestamp.UnixNano())]
			offset := -now.Sub(e.Timestamp).Seconds()
			rows = append(rows, ReconRow{
				FlowIDHex:     fmt.Sprintf("0x%x", e.FlowID),
				FlowID:        e.FlowID,
				SessionStart:  s.SessionStart, // the exact session this T1 belongs to
				Timestamp:     e.Timestamp,
				OffsetLabel:   offsetLabel(offset),
				CanaryType:    e.CanaryType,
				Severity:      sig.Severity,
				Description:   sig.Description,
				Escalated:     peak >= 2,
				EscalatedTier: escTier,
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Timestamp.Before(rows[j].Timestamp) }) // oldest first
	return ReconTimeline{Rows: rows, TotalRecon: len(rows)}
}
