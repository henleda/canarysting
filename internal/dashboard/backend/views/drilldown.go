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
// keeps only rows whose PeakTier == tierFilter; -1 keeps all.
func DeriveFlowsList(events []intelligence.AdversaryInteractionEvent, tierFilter int) FlowsList {
	sessions := groupByFlowSessions(events)
	rows := make([]FlowRow, 0, len(sessions))
	for _, s := range sessions {
		row := buildFlowRow(s)
		if tierFilter >= 0 && row.PeakTier != tierFilter {
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

	// Cluster detection runs over ALL T1 events across sessions (cross-flow).
	var allT1 []intelligence.AdversaryInteractionEvent
	for _, s := range sessions {
		for _, e := range s.Events {
			if e.Tier == 1 {
				allT1 = append(allT1, e)
			}
		}
	}
	if len(allT1) == 0 {
		return ReconTimeline{Rows: []ReconRow{}, TotalRecon: 0}
	}
	clustered := clusterMembers(allT1)

	rows := []ReconRow{}
	for _, s := range sessions {
		peak := 0
		for _, e := range s.Events {
			if e.Tier > peak {
				peak = e.Tier
			}
		}
		// EscalatedTier honors its documented contract: 0 unless the session
		// actually escalated past T1 (peak >= 2). A T1-only session reports 0,
		// not 1, so a future consumer can trust "0 == not escalated".
		escTier := 0
		if peak >= 2 {
			escTier = peak
		}
		for _, e := range s.Events {
			if e.Tier != 1 {
				continue
			}
			offset := -now.Sub(e.Timestamp).Seconds()
			adj := e.Features[featAdjacency]
			isCluster := clustered[clusterKey(e)]
			severity := "recon"
			if adj >= reconAdjacencyThreshold || isCluster {
				severity = "surfaced"
			}
			rows = append(rows, ReconRow{
				FlowIDHex:     fmt.Sprintf("0x%x", e.FlowID),
				FlowID:        e.FlowID,
				SessionStart:  s.SessionStart, // the exact session this T1 belongs to
				Timestamp:     e.Timestamp,
				OffsetLabel:   offsetLabel(offset),
				CanaryType:    e.CanaryType,
				Severity:      severity,
				Description:   reconDescription(e, adj, isCluster),
				Escalated:     peak >= 2,
				EscalatedTier: escTier,
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Timestamp.Before(rows[j].Timestamp) }) // oldest first
	return ReconTimeline{Rows: rows, TotalRecon: len(rows)}
}
