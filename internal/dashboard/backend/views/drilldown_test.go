package views

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence"
)

// evSting is ev with a Sting outcome and an explicit score.
func evSting(flowID uint64, tier int, verdict, canary string, offsetSec int, sting intelligence.StingOutcome, score float64) intelligence.AdversaryInteractionEvent {
	e := ev(flowID, tier, verdict, canary, offsetSec, sting, nil)
	e.Score = score
	return e
}

// --- FlowDetail ---

func TestDeriveFlowDetailEmpty(t *testing.T) {
	if d := DeriveFlowDetail(0x10, nil, base, 0); d != nil {
		t.Fatalf("want nil for no events, got %+v", d)
	}
	// cookie not present among events
	evs := []intelligence.AdversaryInteractionEvent{evScore(0x20, 1, "tag", ".env", 0, 1)}
	if d := DeriveFlowDetail(0x10, evs, base, 0); d != nil {
		t.Fatalf("want nil for absent cookie, got %+v", d)
	}
}

func TestDeriveFlowDetailTimeline(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		evScore(0x10, 0, "observe", ".env", 0, 1),
		evScore(0x10, 1, "tag", ".aws/credentials", 10, 2),
		evSting(0x10, 2, "contain", "backup/db.sql", 20, intelligence.StingOutcome{Mechanism: "fake_tree", TimeHeldSec: 8, BytesServed: 8000, RequestsAbsrb: 3, TokenCostProxy: 2000}, 3),
	}
	d := DeriveFlowDetail(0x10, evs, base.Add(time.Minute), 0)
	if d == nil {
		t.Fatal("want detail")
	}
	if d.FlowIDHex != "0x10" || d.TouchCount != 3 {
		t.Fatalf("hex/count wrong: %+v", d)
	}
	if d.PeakTier != 2 || d.Verdict != "contain" {
		t.Fatalf("peak/verdict wrong: tier=%d verdict=%s", d.PeakTier, d.Verdict)
	}
	if d.Score != 3 {
		t.Fatalf("latest score should be 3, got %v", d.Score)
	}
	if len(d.Timeline) != 3 || !d.Timeline[0].Timestamp.Before(d.Timeline[2].Timestamp) {
		t.Fatalf("timeline not ascending: %+v", d.Timeline)
	}
	last := d.Timeline[2]
	if last.Mechanism != "fake_tree" || last.TimeHeldSec != 8 || last.Requests != 3 || last.TokenCost != 2000 {
		t.Fatalf("timeline sting fields wrong: %+v", last)
	}
	if d.SessionCount != 1 || d.SessionIndex != 1 {
		t.Fatalf("single session expected, got %d of %d", d.SessionIndex, d.SessionCount)
	}
}

func TestDeriveFlowDetailScoreZeroGraceful(t *testing.T) {
	// all-zero scores (pre-Score records) → spark falls back to tier ladder, not flat 0
	evs := []intelligence.AdversaryInteractionEvent{
		evScore(0x10, 1, "tag", ".env", 0, 0),
		evScore(0x10, 2, "contain", ".aws/credentials", 10, 0),
	}
	d := DeriveFlowDetail(0x10, evs, base.Add(time.Minute), 0)
	if d.Score != 0 {
		t.Fatalf("score should be honest 0, got %v", d.Score)
	}
	allZero := true
	for _, s := range d.SparkSeries {
		if s != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Fatal("spark should fall back to tier ladder, not be all zero")
	}
}

func TestDeriveFlowDetailMBreakdownNilWhenNoFeatures(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{evScore(0x10, 1, "tag", ".env", 0, 1)}
	d := DeriveFlowDetail(0x10, evs, base.Add(time.Minute), 0)
	if d.MBreakdown != nil {
		t.Fatalf("want nil MBreakdown with no features, got %+v", d.MBreakdown)
	}
}

func TestDeriveFlowDetailMBreakdown(t *testing.T) {
	feats := map[string]float64{featAdjacency: 0.8, featIdentity: 0.5, featPort: 0.2, featVolume: 0.3, featCadence: 0.1}
	e := ev(0x10, 2, "contain", ".env", 0, intelligence.StingOutcome{}, feats)
	d := DeriveFlowDetail(0x10, []intelligence.AdversaryInteractionEvent{e}, base.Add(time.Minute), 0)
	if d.MBreakdown == nil {
		t.Fatal("want MBreakdown with features")
	}
	if len(d.MBreakdown.Contributions) != 5 {
		t.Fatalf("want all 5 feature contributions, got %d", len(d.MBreakdown.Contributions))
	}
	if d.MBreakdown.M <= 1.0 {
		t.Fatalf("M should exceed 1.0 with novelty, got %v", d.MBreakdown.M)
	}
}

// --- session splitting (decision E) ---

func TestSessionSplitOnGap(t *testing.T) {
	// same cookie, two clusters separated by > sessionGap → two sessions
	evs := []intelligence.AdversaryInteractionEvent{
		evScore(0x10, 1, "tag", ".env", 0, 1),
		evScore(0x10, 2, "contain", ".aws/credentials", 30, 2),
		// gap of 20 minutes -> new session
		evScore(0x10, 1, "tag", "backup/db.sql", 30+1200, 1),
		evScore(0x10, 1, "tag", "internal/buckets", 30+1230, 2),
	}
	// flows list should show TWO sessions for the one cookie
	fl := DeriveFlowsList(evs, -1)
	if fl.TotalCount != 2 {
		t.Fatalf("want 2 sessions from cookie reuse, got %d (%+v)", fl.TotalCount, fl.Flows)
	}
	// detail: latest session (sessionSel=0) is the second cluster
	d := DeriveFlowDetail(0x10, evs, base.Add(time.Hour), 0)
	if d.SessionCount != 2 || d.SessionIndex != 2 {
		t.Fatalf("latest session should be 2 of 2, got %d of %d", d.SessionIndex, d.SessionCount)
	}
	if d.TouchCount != 2 || d.PeakTier != 1 {
		t.Fatalf("latest session should have 2 touches peak T1, got count=%d peak=%d", d.TouchCount, d.PeakTier)
	}
	// detail by explicit session selector: first session
	firstStart := base.Unix() // first event at offset 0
	d1 := DeriveFlowDetail(0x10, evs, base.Add(time.Hour), firstStart)
	if d1 == nil || d1.SessionIndex != 1 || d1.PeakTier != 2 {
		t.Fatalf("first session should be index 1 peak T2, got %+v", d1)
	}
	// bogus selector → nil
	if DeriveFlowDetail(0x10, evs, base.Add(time.Hour), 99) != nil {
		t.Fatal("bogus session selector should yield nil")
	}
}

func TestNoSplitWithinGap(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		evScore(0x10, 1, "tag", ".env", 0, 1),
		evScore(0x10, 2, "contain", ".aws/credentials", 60, 2), // 1m later, same session
	}
	if fl := DeriveFlowsList(evs, -1); fl.TotalCount != 1 {
		t.Fatalf("want 1 session within gap, got %d", fl.TotalCount)
	}
}

// --- FlowsList ---

func TestDeriveFlowsListEmpty(t *testing.T) {
	fl := DeriveFlowsList(nil, -1)
	if fl.TotalCount != 0 || len(fl.Flows) != 0 {
		t.Fatalf("want empty, got %+v", fl)
	}
}

func TestDeriveFlowsListTierFilterAndSort(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		evScore(0x10, 1, "tag", ".env", 0, 1),
		evScore(0x20, 2, "contain", ".env", 5, 2),
		evScore(0x30, 3, "jail", ".env", 10, 3),
	}
	all := DeriveFlowsList(evs, -1)
	if all.TotalCount != 3 || len(all.Flows) != 3 {
		t.Fatalf("want 3, got %+v", all)
	}
	// sorted peak desc
	if all.Flows[0].PeakTier != 3 || all.Flows[2].PeakTier != 1 {
		t.Fatalf("not sorted by peak desc: %+v", all.Flows)
	}
	// tier filter
	t2 := DeriveFlowsList(evs, 2)
	if t2.Filtered != 1 || t2.Flows[0].PeakTier != 2 || t2.TotalCount != 3 {
		t.Fatalf("tier filter wrong: %+v", t2)
	}
	if none := DeriveFlowsList(evs, 0); none.Filtered != 0 {
		t.Fatalf("want 0 T0 rows, got %d", none.Filtered)
	}
}

// --- AttackerFlowCards (the wall's live-attacker strip) ---

// TestAttackerFlowCards pins the live-feed contract: rows come back LastSeen desc
// (most-recent first), every row carries a non-empty per-flow spark, the result is
// capped, and — unlike DeriveFlowsList's peak-tier sort — the mixed Tag/Contain/Jail
// tier mix is PRESERVED in arrival order rather than collapsed to only the top tier.
func TestAttackerFlowCards(t *testing.T) {
	// Mixed-tier fleet, distinct cookies, arriving oldest→newest as T3, T1, T2 so a
	// peak-tier sort (T3,T2,T1) would REORDER them — recency must keep T2,T1,T3 desc.
	evs := []intelligence.AdversaryInteractionEvent{
		// 0x30: jails first (oldest)
		evScore(0x30, 2, "contain", ".env", 0, 4),
		evScore(0x30, 3, "jail", ".aws/credentials", 5, 9),
		// 0x10: a lone Tag a bit later
		evScore(0x10, 1, "tag", ".env", 20, 2),
		// 0x20: contains last (most-recent)
		evScore(0x20, 1, "tag", ".env", 30, 1),
		evScore(0x20, 2, "contain", "backup/db.sql", 40, 5),
	}
	cards := AttackerFlowCards(evs, 24)
	if len(cards) != 3 {
		t.Fatalf("want 3 cards (one per session), got %d: %+v", len(cards), cards)
	}
	// Recency order: 0x20 (last_seen 40s) → 0x10 (20s) → 0x30 (5s).
	wantOrder := []string{"0x20", "0x10", "0x30"}
	for i, want := range wantOrder {
		if cards[i].FlowIDHex != want {
			t.Fatalf("card %d = %s, want %s (recency desc): %+v", i, cards[i].FlowIDHex, want, cards)
		}
	}
	// LastSeen strictly descending.
	for i := 1; i < len(cards); i++ {
		if cards[i-1].LastSeen.Before(cards[i].LastSeen) {
			t.Fatalf("cards not LastSeen-desc at %d: %+v", i, cards)
		}
	}
	// Tier mix preserved (NOT only the top tier): T1 + T2 + T3 all present.
	mix := map[int]bool{}
	for _, c := range cards {
		mix[c.PeakTier] = true
		// Every card has its own non-empty spark.
		if len(c.SparkSeries) == 0 {
			t.Fatalf("card %s has empty spark series; every card must carry its own", c.FlowIDHex)
		}
	}
	if !mix[1] || !mix[2] || !mix[3] {
		t.Fatalf("tier mix not preserved (want T1,T2,T3 all present), got %+v", mix)
	}
	// Per-flow spark reflects THAT flow's climb: the lone Tag (0x10) has a single
	// sample; the Jail (0x30) climbs over two events to its peak (1.0).
	var tag, jail FlowRow
	for _, c := range cards {
		if c.FlowIDHex == "0x10" {
			tag = c
		}
		if c.FlowIDHex == "0x30" {
			jail = c
		}
	}
	if len(tag.SparkSeries) != 1 {
		t.Fatalf("Tag flow spark should have one sample (one event), got %+v", tag.SparkSeries)
	}
	if len(jail.SparkSeries) != 2 || jail.SparkSeries[len(jail.SparkSeries)-1] != 1.0 {
		t.Fatalf("Jail flow spark should climb across 2 events to peak 1.0, got %+v", jail.SparkSeries)
	}
	// Row fields still match DeriveFlowsList semantics (same buildFlowRow path).
	if jail.PeakTier != 3 || jail.Verdict != "jail" || jail.Score != 9 || jail.TouchCount != 2 {
		t.Fatalf("jail row fields wrong: %+v", jail)
	}
}

// TestAttackerFlowCardsCap pins the cap (keeps the most-recent `cap` rows).
func TestAttackerFlowCardsCap(t *testing.T) {
	var evs []intelligence.AdversaryInteractionEvent
	for i := 0; i < 30; i++ {
		// distinct cookies, increasing timestamps so cookie i is the i-th most recent
		evs = append(evs, evScore(uint64(0x100+i), 1, "tag", ".env", i*5, 1))
	}
	cards := AttackerFlowCards(evs, 24)
	if len(cards) != 24 {
		t.Fatalf("want capped at 24, got %d", len(cards))
	}
	// Capped to the MOST-RECENT 24: the newest cookie (0x100+29) must be first.
	if cards[0].FlowID != uint64(0x100+29) {
		t.Fatalf("cap should keep the most-recent rows; first = 0x%x, want 0x%x", cards[0].FlowID, 0x100+29)
	}
}

func TestAttackerFlowCardsEmpty(t *testing.T) {
	if cards := AttackerFlowCards(nil, 24); len(cards) != 0 {
		t.Fatalf("want no cards for no events, got %+v", cards)
	}
}

// --- FlowFunnel (FleetWall windowed distinct-flow funnel) ---

// TestDeriveFlowFunnelMatchesFlowsList is the CI gate: the funnel stages MUST equal
// the flows-table reach-filtered counts (CUMULATIVE reach — a flow is counted in
// every stage it reached), so the headline funnel can never drift from the
// drill-down table. This pins the distinct-jailed discipline at the type level.
func TestDeriveFlowFunnelMatchesFlowsList(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		// 0x10: peaks at T1 (decoy touched, not contained, not jailed)
		evScore(0x10, 1, "tag", ".env", 0, 1),
		// 0x20: peaks at T2 (reached containment) — multiple T2 events, still ONE distinct flow
		evScore(0x20, 1, "tag", ".env", 5, 1),
		evScore(0x20, 2, "contain", ".aws/credentials", 10, 2),
		evScore(0x20, 2, "contain", "backup/db.sql", 15, 3),
		// 0x30: peaks at T3 (jailed; also reached containment en route) — multiple T3 events, still ONE distinct flow
		evScore(0x30, 2, "contain", ".env", 20, 2),
		evScore(0x30, 3, "jail", ".aws/credentials", 25, 4),
		evScore(0x30, 3, "jail", "internal/buckets", 30, 5),
		// 0x40: also peaks at T3
		evScore(0x40, 3, "jail", ".env", 35, 6),
	}
	fv := DeriveFlowFunnel(evs)

	if got, want := fv.DecoyTouched, DeriveFlowsList(evs, -1).TotalCount; got != want {
		t.Fatalf("DecoyTouched=%d, want DeriveFlowsList(-1).TotalCount=%d", got, want)
	}
	if got, want := fv.Contained, FlowsReached(evs, 2).Filtered; got != want {
		t.Fatalf("Contained=%d, want FlowsReached(2).Filtered=%d", got, want)
	}
	if got, want := fv.Jailed, FlowsReached(evs, 3).Filtered; got != want {
		t.Fatalf("Jailed=%d, want FlowsReached(3).Filtered=%d", got, want)
	}
	// reached>=3 == exact peak 3 (3 is the top tier): the two filters must agree.
	if got, want := FlowsReached(evs, 3).Filtered, DeriveFlowsList(evs, 3).Filtered; got != want {
		t.Fatalf("FlowsReached(3).Filtered=%d, want DeriveFlowsList(3).Filtered=%d", got, want)
	}
	// Distinct-jailed discipline: 2 distinct flows reached the jail, even though there
	// are 3 T3 EVENTS — the per-event count must NOT leak into the headline.
	if fv.Jailed != 2 {
		t.Fatalf("Jailed should be 2 DISTINCT flows reaching T3 (not 3 T3 events), got %d", fv.Jailed)
	}
	// Cumulative reach: 0x20 (peak T2) + 0x30 + 0x40 (both reached T2 on the way to T3)
	// all count as contained.
	if fv.Contained != 3 {
		t.Fatalf("Contained should be 3 distinct flows reaching T2+ (0x20,0x30,0x40), got %d", fv.Contained)
	}
	if fv.DecoyTouched != 4 || fv.DistinctActive != 4 {
		t.Fatalf("want 4 distinct active sessions all decoy-touched, got touched=%d active=%d", fv.DecoyTouched, fv.DistinctActive)
	}
}

// TestDeriveFlowFunnelCumulativeReach: three distinct flows peaking at T1/T2/T3
// (one flow that STOPS at containment, never jails). Cumulative reach means the
// T3 flow is also counted as contained, while the T1 flow is neither — so the
// › funnel reads decoy-touched 3 → contained 2 → jailed 1.
func TestDeriveFlowFunnelCumulativeReach(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		// 0x10: peaks at T1 — touched a decoy, never contained
		evScore(0x10, 1, "tag", ".env", 0, 1),
		// 0x20: peaks at T2 — stops at containment, never jails
		evScore(0x20, 1, "tag", ".env", 5, 1),
		evScore(0x20, 2, "contain", ".aws/credentials", 10, 2),
		// 0x30: peaks at T3 — escalates THROUGH containment to the jail
		evScore(0x30, 2, "contain", ".env", 15, 2),
		evScore(0x30, 3, "jail", "internal/buckets", 20, 3),
	}
	fv := DeriveFlowFunnel(evs)
	if fv.DecoyTouched != 3 {
		t.Fatalf("DecoyTouched should be 3 (all reached T1), got %d", fv.DecoyTouched)
	}
	if fv.Contained != 2 {
		t.Fatalf("Contained should be 2 (the T2 + T3 flows reached T2), got %d", fv.Contained)
	}
	if fv.Jailed != 1 {
		t.Fatalf("Jailed should be 1 (only the T3 flow reached T3), got %d", fv.Jailed)
	}
	if got := FlowsReached(evs, 2).Filtered; got != 2 {
		t.Fatalf("FlowsReached(2).Filtered should be 2, got %d", got)
	}
	if got := FlowsReached(evs, 3).Filtered; got != 1 {
		t.Fatalf("FlowsReached(3).Filtered should be 1, got %d", got)
	}
}

// TestDeriveFlowFunnelEmpty: no events → all zeros, no panic.
func TestDeriveFlowFunnelEmpty(t *testing.T) {
	fv := DeriveFlowFunnel(nil)
	if fv.DecoyTouched != 0 || fv.Contained != 0 || fv.Jailed != 0 || fv.DistinctActive != 0 {
		t.Fatalf("want all-zero funnel for no events, got %+v", fv)
	}
}

// TestDeriveFlowFunnelCookieReuse: a single recycled cookie carrying two sessions
// (split at the 10-min idle gap) counts as TWO distinct flows — distinct_active is
// sessions, not unique cookies/attackers.
func TestDeriveFlowFunnelCookieReuse(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		// session 1 of cookie 0x10: peaks T2
		evScore(0x10, 1, "tag", ".env", 0, 1),
		evScore(0x10, 2, "contain", ".aws/credentials", 30, 2),
		// gap of 20 minutes -> session 2 of the SAME cookie: peaks T1
		evScore(0x10, 1, "tag", "backup/db.sql", 30+1200, 1),
		evScore(0x10, 1, "tag", "internal/buckets", 30+1230, 2),
	}
	fv := DeriveFlowFunnel(evs)
	// distinct_active counts SESSIONS (cookies recycle → split per session), so the
	// one reused cookie is two distinct flows.
	if fv.DistinctActive != 2 {
		t.Fatalf("cookie reuse should yield 2 distinct sessions, got %d", fv.DistinctActive)
	}
	if fv.DistinctActive != fv.DecoyTouched {
		t.Fatalf("distinct_active should equal decoy_touched (every stored session is armed), got active=%d touched=%d", fv.DistinctActive, fv.DecoyTouched)
	}
	if fv.DistinctActive != DeriveFlowsList(evs, -1).TotalCount {
		t.Fatalf("distinct_active should equal DeriveFlowsList(-1).TotalCount=%d, got %d", DeriveFlowsList(evs, -1).TotalCount, fv.DistinctActive)
	}
	// session 1 reached T2 (contained), session 2 peaks T1 → reached>=2 == 1, reached>=3 == 0
	if fv.Contained != 1 || fv.Jailed != 0 {
		t.Fatalf("want contained=1 jailed=0 across the two sessions, got contained=%d jailed=%d", fv.Contained, fv.Jailed)
	}
	// RE-DERIVE the funnel==flows equality (cumulative reach) on the cookie-reuse /
	// multi-session path (not hand-coded constants), so the invariant is proven where
	// a recycled cookie splits into multiple sessions.
	if got, want := fv.Contained, FlowsReached(evs, 2).Filtered; got != want {
		t.Fatalf("Contained=%d, want FlowsReached(2).Filtered=%d", got, want)
	}
	if got, want := fv.Jailed, FlowsReached(evs, 3).Filtered; got != want {
		t.Fatalf("Jailed=%d, want FlowsReached(3).Filtered=%d", got, want)
	}
	if got, want := fv.DecoyTouched, DeriveFlowsList(evs, -1).TotalCount; got != want {
		t.Fatalf("DecoyTouched=%d, want DeriveFlowsList(-1).TotalCount=%d", got, want)
	}
}

// --- CostBreakdown ---

func TestDeriveCostBreakdown(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		evSting(0x10, 2, "contain", ".env", 0, intelligence.StingOutcome{Mechanism: "fake_tree", TimeHeldSec: 8, BytesServed: 8000, RequestsAbsrb: 1, TokenCostProxy: 2000}, 2),
		evSting(0x10, 2, "contain", ".aws/credentials", 10, intelligence.StingOutcome{Mechanism: "token_bait", TimeHeldSec: 4, BytesServed: 4000, RequestsAbsrb: 1, TokenCostProxy: 12000}, 3),
		evSting(0x20, 3, "jail", ".env", 5, intelligence.StingOutcome{}, 5), // zero-Sting (kernel) → omitted from ByMechanism
	}
	cb := DeriveCostBreakdown(evs, base.Add(time.Minute), BucketDurFor(3600))
	if cb.Total.TimeHeldSec != 12 || cb.Total.TokenCost != 14000 {
		t.Fatalf("total wrong: %+v", cb.Total)
	}
	if len(cb.ByMechanism) != 2 {
		t.Fatalf("want 2 mechanisms (empty omitted), got %d: %+v", len(cb.ByMechanism), cb.ByMechanism)
	}
	// token_bait has the higher token cost → sorted first
	if cb.ByMechanism[0].Mechanism != "token_bait" {
		t.Fatalf("by-mechanism not sorted by token cost: %+v", cb.ByMechanism)
	}
	if len(cb.ByFlow) != 2 {
		t.Fatalf("want 2 flow rows, got %d", len(cb.ByFlow))
	}
	if len(cb.TimeSeries) == 0 {
		t.Fatal("want a zero-filled time series")
	}
}

func TestCostTimeSeriesZeroFilled(t *testing.T) {
	// two events far apart → intermediate buckets present with zero cost
	evs := []intelligence.AdversaryInteractionEvent{
		evSting(0x10, 2, "contain", ".env", 0, intelligence.StingOutcome{TimeHeldSec: 8}, 2),
		evSting(0x10, 2, "contain", ".env", 1800, intelligence.StingOutcome{TimeHeldSec: 8}, 2),
	}
	cb := DeriveCostBreakdown(evs, base.Add(40*time.Minute), BucketDurFor(3600))
	if len(cb.TimeSeries) < 3 {
		t.Fatalf("want zero-filled intermediate buckets, got %d", len(cb.TimeSeries))
	}
	// monotonic bucket starts
	for i := 1; i < len(cb.TimeSeries); i++ {
		if !cb.TimeSeries[i-1].BucketStart.Before(cb.TimeSeries[i].BucketStart) {
			t.Fatalf("bucket starts not monotonic at %d", i)
		}
	}
}

// --- ReconTimeline ---

func TestDeriveReconTimelineOldestFirstAndEscalation(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{
		// cookie 0x10: T1 then escalates to T2 (same session) → escalated
		evScore(0x10, 1, "tag", ".env", 0, 1),
		evScore(0x10, 2, "contain", ".aws/credentials", 30, 2),
		// cookie 0x20: only T1, never escalates
		evScore(0x20, 1, "tag", ".env", 60, 1),
	}
	rt := DeriveReconTimeline(evs, base.Add(time.Hour))
	if rt.TotalRecon != 2 {
		t.Fatalf("want 2 T1 rows, got %d", rt.TotalRecon)
	}
	// oldest first
	if !rt.Rows[0].Timestamp.Before(rt.Rows[1].Timestamp) {
		t.Fatalf("recon rows not oldest-first")
	}
	// 0x10's T1 escalated (session peak T2); 0x20's did not
	var got10, got20 ReconRow
	for _, r := range rt.Rows {
		if r.FlowID == 0x10 {
			got10 = r
		}
		if r.FlowID == 0x20 {
			got20 = r
		}
	}
	if !got10.Escalated || got10.EscalatedTier != 2 {
		t.Fatalf("0x10 should be escalated to T2, got %+v", got10)
	}
	if got20.Escalated {
		t.Fatalf("0x20 should NOT be escalated, got %+v", got20)
	}
	// Contract: EscalatedTier is 0 (not the T1 peak) for an unescalated session.
	if got20.EscalatedTier != 0 {
		t.Fatalf("0x20 EscalatedTier should be 0 when not escalated, got %d", got20.EscalatedTier)
	}
}

func TestDeriveReconTimelineEmpty(t *testing.T) {
	evs := []intelligence.AdversaryInteractionEvent{evScore(0x10, 2, "contain", ".env", 0, 2)} // no T1
	rt := DeriveReconTimeline(evs, base.Add(time.Minute))
	if rt.TotalRecon != 0 || len(rt.Rows) != 0 {
		t.Fatalf("want empty recon, got %+v", rt)
	}
}
