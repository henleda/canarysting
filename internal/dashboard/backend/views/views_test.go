package views

import (
	"math"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/cost"
)

// TestBuildAttackerCost pins the AX3 view derivation: PerAxis emits ONLY axes with
// traffic (in ordinal order), and the engagement view derives DisengagedEarlyFraction
// from the disengage buckets. (The per-axis subtotals OVERLAP; this only checks the
// view layer faithfully surfaces the cost.Summary it is handed.)
func TestBuildAttackerCost(t *testing.T) {
	var sum cost.Summary
	sum.Interactions = 4
	sum.TimeImposedSec = 100
	sum.TierCounts = [4]int{0, 0, 3, 1}           // 3 contain + 1 jail
	sum.AxisCount[0], sum.AxisTimeSec[0] = 4, 100 // velocity
	sum.AxisCount[1], sum.AxisTimeSec[1] = 2, 60  // poison
	// opportunity(2)/exploit(3)/exposure(4) stay zero -> must be omitted
	sum.DisengagedEarly, sum.GeneratorExhausted, sum.DefenderCapped = 3, 1, 4
	sum.EngagementMedianSec, sum.EngagementLongestSec = 6, 8

	v := buildAttackerCost(sum)
	if len(v.PerAxis) != 2 {
		t.Fatalf("PerAxis = %d entries, want 2 (only nonzero axes emitted)", len(v.PerAxis))
	}
	if v.PerAxis[0].Axis != cost.AxisNames[0] || v.PerAxis[1].Axis != cost.AxisNames[1] {
		t.Fatalf("PerAxis order/labels wrong: %+v", v.PerAxis)
	}
	if v.PerAxis[0].TimeSec != 100 || v.PerAxis[1].TimeSec != 60 {
		t.Fatalf("PerAxis times wrong: %+v", v.PerAxis)
	}
	if got := v.Engagement.DisengagedEarlyFraction; got < 0.374 || got > 0.376 { // 3/(3+1+4)
		t.Fatalf("DisengagedEarlyFraction = %v, want ~0.375", got)
	}
	if v.Engagement.MedianSec != 6 || v.Engagement.LongestSec != 8 {
		t.Fatalf("engagement median/longest = %v/%v, want 6/8", v.Engagement.MedianSec, v.Engagement.LongestSec)
	}
	if !v.DefenderCostFlat {
		t.Fatal("DefenderCostFlat must always be true")
	}
}

var base = time.Date(2026, 6, 9, 14, 0, 0, 0, time.UTC)

func ev(flowID uint64, tier int, verdict, canary string, offsetSec int, sting intelligence.StingOutcome, feats map[string]float64) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		ScopeKey:   "m7-window",
		FlowID:     flowID,
		CanaryType: canary,
		Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
		Features:   feats,
		Tier:       tier,
		Verdict:    verdict,
		Sting:      sting,
	}
}

// evScore is ev with an explicit engine suspicion score.
func evScore(flowID uint64, tier int, verdict, canary string, offsetSec int, score float64) intelligence.AdversaryInteractionEvent {
	e := ev(flowID, tier, verdict, canary, offsetSec, intelligence.StingOutcome{}, nil)
	e.Score = score
	return e
}

func TestDeriveEmpty(t *testing.T) {
	now := base.Add(time.Minute)
	ov := Derive(TapState{Scope: "m7-window", At: base}, nil, now)

	if ov.Escalation.Flow != nil {
		t.Fatalf("Flow = %+v, want nil for empty input", ov.Escalation.Flow)
	}
	for i, step := range ov.Escalation.TierLadder {
		if step.Count != 0 {
			t.Fatalf("ladder[%d].Count = %d, want 0", i, step.Count)
		}
		if step.Fraction != 0 {
			t.Fatalf("ladder[%d].Fraction = %v, want 0 (no div-by-zero)", i, step.Fraction)
		}
	}
	if ov.Escalation.LadderDenominator != 0 {
		t.Fatalf("denominator = %d, want 0", ov.Escalation.LadderDenominator)
	}
	if ov.AttackerCost.ActiveResponseCount != 0 {
		t.Fatalf("ActiveResponseCount = %d, want 0", ov.AttackerCost.ActiveResponseCount)
	}
	if !ov.Credibility.GuardrailActive {
		t.Fatalf("GuardrailActive = false, want true (structural invariant)")
	}
	if ov.Credibility.BaselineMultiplierM != 1.0 {
		t.Fatalf("BaselineMultiplierM = %v, want 1.0 (honest neutral)", ov.Credibility.BaselineMultiplierM)
	}
	if ov.AdversaryIntel.Fingerprint != nil {
		t.Fatalf("Fingerprint = %+v, want nil", ov.AdversaryIntel.Fingerprint)
	}
	if ov.Calibration.EvidenceFloor != calibration.DefaultEvidenceFloor {
		t.Fatalf("EvidenceFloor = %d, want default %d", ov.Calibration.EvidenceFloor, calibration.DefaultEvidenceFloor)
	}
	if !ov.AttackerCost.DefenderCostFlat {
		t.Fatalf("DefenderCostFlat = false, want true (structural)")
	}
}

func TestDeriveCalibrationAndBaselineGates(t *testing.T) {
	state := TapState{
		Scope:       "m7-window",
		Calibration: calibration.State{Calibrated: true, EvidenceSeen: 50, EvidenceFloor: 50},
		Baseline:    baseline.GateState{Live: true, BucketSufficient: true, Calibrated: true},
		At:          base,
	}
	ov := Derive(state, nil, base)

	if ov.Calibration != (CalibView{Calibrated: true, EvidenceSeen: 50, EvidenceFloor: 50}) {
		t.Fatalf("Calibration = %+v", ov.Calibration)
	}
	if !ov.BaselineLive {
		t.Fatalf("BaselineLive = false, want true")
	}
	if ov.Credibility.BaselineGates != (BaselineGateView{Live: true, BucketSufficient: true, Calibrated: true}) {
		t.Fatalf("BaselineGates = %+v", ov.Credibility.BaselineGates)
	}
	if ov.Credibility.Calibration != ov.Calibration {
		t.Fatalf("Credibility.Calibration mismatch: %+v vs %+v", ov.Credibility.Calibration, ov.Calibration)
	}
}

func TestDeriveTierLadder(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x11, 1, "tag", "b", 1, intelligence.StingOutcome{}, nil),
		ev(0x12, 1, "tag", "c", 2, intelligence.StingOutcome{}, nil),
		ev(0x20, 2, "contain", "d", 3, intelligence.StingOutcome{}, nil),
		ev(0x21, 2, "contain", "e", 4, intelligence.StingOutcome{}, nil),
		ev(0x30, 3, "jail", "f", 5, intelligence.StingOutcome{}, nil),
	}
	state := TapState{Scope: "s", Observe: observebaseline.AggStats{CompletedFolds: 312}}
	ov := Derive(state, events, base.Add(time.Minute))

	l := ov.Escalation.TierLadder
	if l[0].Count != 312 {
		t.Fatalf("T0 count = %d, want 312 (from CompletedFolds)", l[0].Count)
	}
	if l[1].Count != 3 || l[2].Count != 2 || l[3].Count != 1 {
		t.Fatalf("ladder counts = %d/%d/%d, want 3/2/1", l[1].Count, l[2].Count, l[3].Count)
	}
	if ov.Escalation.LadderDenominator != 318 {
		t.Fatalf("denominator = %d, want 318", ov.Escalation.LadderDenominator)
	}
	// T0's fraction is pinned to the full bar (1.0): T0 is cumulative
	// observed-normal traffic, NOT mixed into the windowed attacker subtotal.
	if math.Abs(l[0].Fraction-1.0) > 1e-9 {
		t.Fatalf("T0 fraction = %v, want 1.0 (full observed base)", l[0].Fraction)
	}
	// T1-3 fractions are over the attacker subtotal (3+2+1 = 6), not the mixed denom.
	if math.Abs(l[1].Fraction-3.0/6.0) > 1e-9 {
		t.Fatalf("T1 fraction = %v, want 0.5 (3/6 attacker subtotal)", l[1].Fraction)
	}
	if math.Abs(l[2].Fraction-2.0/6.0) > 1e-9 {
		t.Fatalf("T2 fraction = %v, want 0.333 (2/6 attacker subtotal)", l[2].Fraction)
	}
	if math.Abs(l[3].Fraction-1.0/6.0) > 1e-9 {
		t.Fatalf("T3 fraction = %v, want 0.1667 (1/6 attacker subtotal)", l[3].Fraction)
	}
	if !l[3].IsActive {
		t.Fatalf("T3 IsActive = false, want true (highest occupied tier)")
	}
	if l[0].IsActive || l[1].IsActive || l[2].IsActive {
		t.Fatalf("only T3 should be active: %v/%v/%v", l[0].IsActive, l[1].IsActive, l[2].IsActive)
	}
	if l[2].HasResponse != true || l[2].RespLabel != "counter-attacked" {
		t.Fatalf("T2 resp = %v/%q", l[2].HasResponse, l[2].RespLabel)
	}
	if l[3].HasResponse != true || l[3].RespLabel != "kernel-jailed" {
		t.Fatalf("T3 resp = %v/%q", l[3].HasResponse, l[3].RespLabel)
	}
	if l[1].HasResponse || l[1].RespLabel != "" {
		t.Fatalf("T1 should have no response: %v/%q", l[1].HasResponse, l[1].RespLabel)
	}
	if ov.Escalation.LadderCaption == "" {
		t.Fatalf("LadderCaption empty, want honest T0-cumulative note")
	}
}

func TestDeriveGracefulZeroObserveFolds(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x30, 3, "jail", "f", 1, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{Observe: observebaseline.AggStats{CompletedFolds: 0}}, events, base.Add(time.Minute))
	if ov.Escalation.LadderDenominator != 2 {
		t.Fatalf("denominator = %d, want 2 (events only, no folds)", ov.Escalation.LadderDenominator)
	}
	// no panic / no div-by-zero already exercised; check fraction is finite
	for i, s := range ov.Escalation.TierLadder {
		if math.IsNaN(s.Fraction) || math.IsInf(s.Fraction, 0) {
			t.Fatalf("ladder[%d].Fraction non-finite: %v", i, s.Fraction)
		}
	}
}

func TestDeriveCurrentFlowHighestTier(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xA, 1, "tag", "x", 0, intelligence.StingOutcome{}, nil),
		ev(0xA, 2, "contain", "y", 1, intelligence.StingOutcome{}, nil),
		ev(0xB, 3, "jail", "z", 2, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	if ov.Escalation.Flow == nil {
		t.Fatal("Flow nil")
	}
	if ov.Escalation.Flow.FlowID != 0xB {
		t.Fatalf("current flow = 0x%x, want 0xB (highest tier)", ov.Escalation.Flow.FlowID)
	}
	if ov.Escalation.Flow.FlowIDHex != "0xb" {
		t.Fatalf("FlowIDHex = %q, want 0xb", ov.Escalation.Flow.FlowIDHex)
	}
	if ov.Escalation.Flow.Tier != 3 || ov.Escalation.Flow.Verdict != "jail" {
		t.Fatalf("flow tier/verdict = %d/%q", ov.Escalation.Flow.Tier, ov.Escalation.Flow.Verdict)
	}
	// These events carry no score (ev sets Score=0), so the honest value is 0.
	if ov.Escalation.Flow.Score != 0 {
		t.Fatalf("Score = %v, want 0 (these events carry no score)", ov.Escalation.Flow.Score)
	}
}

// FlowView.Score is the flow's LATEST real engine suspicion score, and the
// SparkSeries is the real per-event score progression normalized to the peak.
func TestDeriveFlowScoreFlowsThrough(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		evScore(0xA, 1, "tag", "x", 0, 1.0),
		evScore(0xA, 2, "contain", "y", 1, 2.0),
		evScore(0xA, 3, "jail", "z", 2, 4.0), // latest + peak
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	f := ov.Escalation.Flow
	if f == nil {
		t.Fatal("nil flow")
	}
	if f.Score != 4.0 {
		t.Fatalf("Score = %v, want 4.0 (latest event's real score)", f.Score)
	}
	// Spark is normalized to the peak (4.0): [0.25, 0.5, 1.0], timestamp order.
	want := []float64{0.25, 0.5, 1.0}
	if len(f.SparkSeries) != len(want) {
		t.Fatalf("SparkSeries = %v, want %v", f.SparkSeries, want)
	}
	for i := range want {
		if math.Abs(f.SparkSeries[i]-want[i]) > 1e-9 {
			t.Fatalf("SparkSeries[%d] = %v, want %v (normalized score progression)", i, f.SparkSeries[i], want[i])
		}
	}
}

// A flow whose EARLY event carries Score=0 (e.g. a legacy/zero-score touch) but a
// LATER event carries Score>0: FlowView.Score must be the later non-zero value
// (latest in timestamp order), and SparkSeries must use the REAL scores (peak>0),
// not the tier fallback. This proves a mixed flow does not silently drop to the
// tier ladder just because one early event lacked a score.
func TestDeriveFlowScoreLatestNonZeroAndRealSpark(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		evScore(0xA, 1, "tag", "x", 0, 0.0),     // early: no score
		evScore(0xA, 2, "contain", "y", 1, 5.0), // later: real score (latest + peak)
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	f := ov.Escalation.Flow
	if f == nil {
		t.Fatal("nil flow")
	}
	if f.Score != 5.0 {
		t.Fatalf("Score = %v, want 5.0 (latest non-zero real score)", f.Score)
	}
	// Spark uses real scores normalized to the peak (5.0): [0.0, 1.0]. The tier
	// fallback would instead be tier/3 => [1/3, 2/3], so this distinguishes them.
	want := []float64{0.0, 1.0}
	if len(f.SparkSeries) != len(want) {
		t.Fatalf("SparkSeries = %v, want %v", f.SparkSeries, want)
	}
	for i := range want {
		if math.Abs(f.SparkSeries[i]-want[i]) > 1e-9 {
			t.Fatalf("SparkSeries[%d] = %v, want %v (real score normalized to peak, NOT tier fallback)", i, f.SparkSeries[i], want[i])
		}
	}
	// Sanity: peak is real (>0), so the spark's max is 1.0 from a real score, not a
	// tier-derived value.
	peak := 0.0
	for _, s := range f.SparkSeries {
		if s > peak {
			peak = s
		}
	}
	if peak <= 0 {
		t.Fatalf("spark peak = %v, want > 0 (real scores, not a flat/fallback line)", peak)
	}
}

// With no scores on any event (legacy pre-M8 records), the spark falls back to the
// tier ladder /3, so it is never a flat zero line.
func TestDeriveSparkFallsBackToTierWhenNoScore(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xA, 1, "tag", "x", 0, intelligence.StingOutcome{}, nil),
		ev(0xA, 2, "contain", "y", 1, intelligence.StingOutcome{}, nil),
		ev(0xA, 3, "jail", "z", 2, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	f := ov.Escalation.Flow
	if f.Score != 0 {
		t.Fatalf("Score = %v, want 0 (no real scores)", f.Score)
	}
	want := []float64{1.0 / 3.0, 2.0 / 3.0, 1.0}
	for i := range want {
		if math.Abs(f.SparkSeries[i]-want[i]) > 1e-9 {
			t.Fatalf("SparkSeries[%d] = %v, want %v (tier/3 fallback)", i, f.SparkSeries[i], want[i])
		}
	}
}

func TestDeriveCurrentFlowRecencyTieBreak(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xA, 3, "jail", "x", 10, intelligence.StingOutcome{}, nil),
		ev(0xB, 3, "jail", "z", 99, intelligence.StingOutcome{}, nil), // more recent
	}
	ov := Derive(TapState{}, events, base.Add(time.Hour))
	if ov.Escalation.Flow.FlowID != 0xB {
		t.Fatalf("tie-break flow = 0x%x, want 0xB (most recent)", ov.Escalation.Flow.FlowID)
	}
}

func TestDeriveCurrentFlowSequenceAndSpark(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xA, 1, "tag", ".env", 2, intelligence.StingOutcome{}, nil),
		ev(0xA, 1, "tag", ".aws/credentials", 0, intelligence.StingOutcome{}, nil),
		ev(0xA, 2, "contain", ".env", 5, intelligence.StingOutcome{}, nil), // dup type, later
		ev(0xA, 3, "jail", "backup/db.sql", 9, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	f := ov.Escalation.Flow
	if f == nil {
		t.Fatal("nil flow")
	}
	wantTouches := []string{".aws/credentials", ".env", "backup/db.sql"}
	if len(f.CanaryTouches) != len(wantTouches) {
		t.Fatalf("CanaryTouches = %v, want %v", f.CanaryTouches, wantTouches)
	}
	for i := range wantTouches {
		if f.CanaryTouches[i] != wantTouches[i] {
			t.Fatalf("CanaryTouches[%d] = %q, want %q", i, f.CanaryTouches[i], wantTouches[i])
		}
	}
	if f.TouchCount != 4 {
		t.Fatalf("TouchCount = %d, want 4", f.TouchCount)
	}
	// These events carry no score, so the spark falls back to the tier ladder /3,
	// in timestamp order: tiers 1,1,2,3 => [1/3, 1/3, 2/3, 1].
	wantSpark := []float64{1.0 / 3.0, 1.0 / 3.0, 2.0 / 3.0, 1.0}
	for i := range wantSpark {
		if math.Abs(f.SparkSeries[i]-wantSpark[i]) > 1e-9 {
			t.Fatalf("SparkSeries = %v, want %v", f.SparkSeries, wantSpark)
		}
	}
}

func TestDeriveAttackerCost(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x20, 2, "contain", "a", 0, intelligence.StingOutcome{TimeHeldSec: 10, TokenCostProxy: 100, RequestsAbsrb: 5, BytesServed: 1000}, nil),
		ev(0x21, 2, "contain", "b", 1, intelligence.StingOutcome{TimeHeldSec: 20, TokenCostProxy: 200, RequestsAbsrb: 7, BytesServed: 2000}, nil),
		ev(0x22, 2, "contain", "c", 2, intelligence.StingOutcome{TimeHeldSec: 30, TokenCostProxy: 300, RequestsAbsrb: 9, BytesServed: 3000}, nil),
		ev(0x30, 3, "jail", "d", 3, intelligence.StingOutcome{TimeHeldSec: 40, TokenCostProxy: 400, RequestsAbsrb: 11, BytesServed: 4000}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	ac := ov.AttackerCost
	if ac.ActiveResponseCount != 4 {
		t.Fatalf("ActiveResponseCount = %d, want 4", ac.ActiveResponseCount)
	}
	if ac.Jailed != 1 {
		t.Fatalf("Jailed = %d, want 1", ac.Jailed)
	}
	if ac.CounterAttacked != 3 {
		t.Fatalf("CounterAttacked = %d, want 3", ac.CounterAttacked)
	}
	if ac.TimeImposedSec != 100 {
		t.Fatalf("TimeImposedSec = %v, want 100", ac.TimeImposedSec)
	}
	if ac.TokensBurned != 1000 {
		t.Fatalf("TokensBurned = %v, want 1000", ac.TokensBurned)
	}
	if ac.RequestsAbsorbed != 32 {
		t.Fatalf("RequestsAbsorbed = %d, want 32", ac.RequestsAbsorbed)
	}
	if ac.BytesServed != 10000 {
		t.Fatalf("BytesServed = %d, want 10000", ac.BytesServed)
	}
	if math.Abs(ac.AttackerCostFraction-1.0) > 1e-9 {
		t.Fatalf("AttackerCostFraction = %v, want 1.0 (all 4 active)", ac.AttackerCostFraction)
	}
}

func TestDeriveReconFeed(t *testing.T) {
	feats := func(adj float64) map[string]float64 { return map[string]float64{featAdjacency: adj} }
	events := []intelligence.AdversaryInteractionEvent{
		// cluster: 3 T1 from flow 0xC within 90s
		ev(0xC, 1, "tag", "internal/buckets", 0, intelligence.StingOutcome{}, feats(0.1)),
		ev(0xC, 1, "tag", "internal/buckets", 30, intelligence.StingOutcome{}, feats(0.1)),
		ev(0xC, 1, "tag", "internal/buckets", 60, intelligence.StingOutcome{}, feats(0.1)),
		// lone high-adjacency T1
		ev(0xD, 1, "tag", ".env", 100, intelligence.StingOutcome{}, feats(0.9)),
		// lone low-adjacency T1
		ev(0xE, 1, "tag", "readme", 120, intelligence.StingOutcome{}, feats(0.2)),
		// higher tiers must NOT appear in recon
		ev(0xF, 3, "jail", "secret", 130, intelligence.StingOutcome{}, feats(1.0)),
		ev(0xF, 2, "contain", "secret", 131, intelligence.StingOutcome{}, feats(1.0)),
	}
	now := base.Add(10 * time.Minute)
	ov := Derive(TapState{}, events, now)
	feed := ov.AdversaryIntel.ReconFeed

	if len(feed) != 5 {
		t.Fatalf("recon feed len = %d, want 5 (T1 only)", len(feed))
	}
	// newest first => offset for first is the largest (closest to 0)
	for i := 1; i < len(feed); i++ {
		if feed[i-1].OffsetSec < feed[i].OffsetSec {
			t.Fatalf("recon not newest-first: %v then %v", feed[i-1].OffsetSec, feed[i].OffsetSec)
		}
	}
	// find by canary
	sev := map[string]string{}
	for _, r := range feed {
		sev[r.CanaryType] = r.Severity
	}
	if sev[".env"] != "surfaced" {
		t.Fatalf(".env severity = %q, want surfaced (high adjacency)", sev[".env"])
	}
	if sev["internal/buckets"] != "surfaced" {
		t.Fatalf("cluster severity = %q, want surfaced", sev["internal/buckets"])
	}
	if sev["readme"] != "recon" {
		t.Fatalf("lone low-adjacency severity = %q, want recon", sev["readme"])
	}
}

func TestDeriveCredibilityFeatureBars(t *testing.T) {
	feats := map[string]float64{
		featAdjacency: 1.0,
		featIdentity:  1.0,
		featPort:      0.5,
		featVolume:    0.62,
		featCadence:   0.31,
	}
	low := map[string]float64{featAdjacency: 0.1}
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, low),
		ev(0x20, 2, "contain", "b", 1, intelligence.StingOutcome{}, feats), // peak M event
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	cred := ov.Credibility

	wantM := baseline.MFromFeatures(baseline.Features{
		AdjacencyNovelty: 1, IdentityNovelty: 1, PortNovelty: 0.5, VolumeDeviation: 0.62, CadenceDeviation: 0.31,
	}, baseline.DefaultParams())
	if math.Abs(cred.BaselineMultiplierM-wantM) > 1e-9 {
		t.Fatalf("BaselineMultiplierM = %v, want %v", cred.BaselineMultiplierM, wantM)
	}
	if cred.BaselineMultiplierM <= 1.0 {
		t.Fatalf("M = %v, want > 1.0 for abnormal features", cred.BaselineMultiplierM)
	}
	if len(cred.FeatureBars) != 4 {
		t.Fatalf("FeatureBars len = %d, want 4", len(cred.FeatureBars))
	}
	byName := map[string]float64{}
	for _, b := range cred.FeatureBars {
		byName[b.Name] = b.Value
	}
	if byName["adjacency nov."] != 1.0 {
		t.Fatalf("adjacency bar = %v, want 1.0 (from peak event)", byName["adjacency nov."])
	}
	if math.Abs(byName["volume dev."]-0.62) > 1e-9 {
		t.Fatalf("volume bar = %v, want 0.62", byName["volume dev."])
	}
	if math.Abs(byName["cadence dev."]-0.31) > 1e-9 {
		t.Fatalf("cadence bar = %v, want 0.31", byName["cadence dev."])
	}
}

func TestDeriveAttackerCostFractionMixed(t *testing.T) {
	// cost.Rollup counts only stored events (Tier>=1). A realistic stored set of
	// 2×T1 + 1×T2 + 1×T3 => activeResponse=2, interactions=4, fraction=0.5.
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x11, 1, "tag", "b", 1, intelligence.StingOutcome{}, nil),
		ev(0x20, 2, "contain", "c", 2, intelligence.StingOutcome{}, nil),
		ev(0x30, 3, "jail", "d", 3, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	ac := ov.AttackerCost
	if ac.ActiveResponseCount != 2 {
		t.Fatalf("ActiveResponseCount = %d, want 2 (1×T2 + 1×T3)", ac.ActiveResponseCount)
	}
	if math.Abs(ac.AttackerCostFraction-0.5) > 1e-9 {
		t.Fatalf("AttackerCostFraction = %v, want 0.5 (2 active of 4 interactions)", ac.AttackerCostFraction)
	}
}

func TestDeriveAttackerCostAllT1(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x11, 1, "tag", "b", 1, intelligence.StingOutcome{}, nil),
		ev(0x12, 1, "tag", "c", 2, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	ac := ov.AttackerCost
	if ac.ActiveResponseCount != 0 {
		t.Fatalf("ActiveResponseCount = %d, want 0 (all T1)", ac.ActiveResponseCount)
	}
	if ac.Jailed != 0 {
		t.Fatalf("Jailed = %d, want 0 (all T1)", ac.Jailed)
	}
	if ac.AttackerCostFraction != 0.0 {
		t.Fatalf("AttackerCostFraction = %v, want 0.0 (no active response)", ac.AttackerCostFraction)
	}
}

func TestDeriveLadderStrayT0NotDoubleCounted(t *testing.T) {
	// A stray Tier=0 event in the events slice must NOT inflate ladder[0].Count
	// (T0 count comes from CompletedFolds only) nor the denominator.
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x00, 0, "observe", "noise", 0, intelligence.StingOutcome{}, nil), // stray T0
		ev(0x10, 1, "tag", "a", 1, intelligence.StingOutcome{}, nil),
		ev(0x20, 2, "contain", "b", 2, intelligence.StingOutcome{}, nil),
	}
	state := TapState{Observe: observebaseline.AggStats{CompletedFolds: 100}}
	ov := Derive(state, events, base.Add(time.Minute))
	l := ov.Escalation.TierLadder
	if l[0].Count != 100 {
		t.Fatalf("ladder[0].Count = %d, want 100 (CompletedFolds only, stray T0 ignored)", l[0].Count)
	}
	// denom = CompletedFolds(100) + T1(1) + T2(1) + T3(0) = 102; the stray T0 event
	// must not be double-counted into the denominator.
	if ov.Escalation.LadderDenominator != 102 {
		t.Fatalf("denominator = %d, want 102 (stray T0 not double-counted)", ov.Escalation.LadderDenominator)
	}
}

func TestDeriveLadderFractionsAttackerSubtotal(t *testing.T) {
	// counts T1=3, T2=2, T3=1; CompletedFolds=312. Fractions over the attacker
	// subtotal (6): 0.5, 0.333, 0.1667. T0 pinned to 1.0.
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x10, 1, "tag", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x11, 1, "tag", "b", 1, intelligence.StingOutcome{}, nil),
		ev(0x12, 1, "tag", "c", 2, intelligence.StingOutcome{}, nil),
		ev(0x20, 2, "contain", "d", 3, intelligence.StingOutcome{}, nil),
		ev(0x21, 2, "contain", "e", 4, intelligence.StingOutcome{}, nil),
		ev(0x30, 3, "jail", "f", 5, intelligence.StingOutcome{}, nil),
	}
	ov := Derive(TapState{Observe: observebaseline.AggStats{CompletedFolds: 312}}, events, base.Add(time.Minute))
	l := ov.Escalation.TierLadder
	if math.Abs(l[1].Fraction-0.5) > 1e-9 {
		t.Fatalf("ladder[1].Fraction = %v, want 0.5", l[1].Fraction)
	}
	if math.Abs(l[2].Fraction-1.0/3.0) > 1e-9 {
		t.Fatalf("ladder[2].Fraction = %v, want 0.3333", l[2].Fraction)
	}
	if math.Abs(l[3].Fraction-1.0/6.0) > 1e-9 {
		t.Fatalf("ladder[3].Fraction = %v, want 0.1667", l[3].Fraction)
	}
	if l[0].Fraction != 1.0 {
		t.Fatalf("ladder[0].Fraction = %v, want 1.0", l[0].Fraction)
	}
}

func TestDeriveReconClusterBoundary(t *testing.T) {
	feats := func(adj float64) map[string]float64 { return map[string]float64{featAdjacency: adj} }

	// Exactly 2 T1 touches from one flow within 90s => below reconClusterMin (3),
	// so both are "recon", NOT "surfaced".
	t.Run("two_touches_recon", func(t *testing.T) {
		events := []intelligence.AdversaryInteractionEvent{
			ev(0xC, 1, "tag", "internal/buckets", 0, intelligence.StingOutcome{}, feats(0.1)),
			ev(0xC, 1, "tag", "internal/buckets", 80, intelligence.StingOutcome{}, feats(0.1)),
		}
		ov := Derive(TapState{}, events, base.Add(10*time.Minute))
		feed := ov.AdversaryIntel.ReconFeed
		if len(feed) != 2 {
			t.Fatalf("feed len = %d, want 2", len(feed))
		}
		for _, r := range feed {
			if r.Severity != "recon" {
				t.Fatalf("severity = %q, want recon (2 touches < cluster min)", r.Severity)
			}
		}
	})

	// Exactly 3 T1 touches at offsets 0/45/90s => the 90s window is inclusive, so
	// all three are within reconClusterWindowSec of the first => "surfaced".
	t.Run("three_touches_inclusive_90s_surfaced", func(t *testing.T) {
		events := []intelligence.AdversaryInteractionEvent{
			ev(0xC, 1, "tag", "internal/buckets", 0, intelligence.StingOutcome{}, feats(0.1)),
			ev(0xC, 1, "tag", "internal/buckets", 45, intelligence.StingOutcome{}, feats(0.1)),
			ev(0xC, 1, "tag", "internal/buckets", 90, intelligence.StingOutcome{}, feats(0.1)),
		}
		ov := Derive(TapState{}, events, base.Add(10*time.Minute))
		feed := ov.AdversaryIntel.ReconFeed
		if len(feed) != 3 {
			t.Fatalf("feed len = %d, want 3", len(feed))
		}
		for _, r := range feed {
			if r.Severity != "surfaced" {
				t.Fatalf("severity = %q, want surfaced (3 touches in inclusive 90s window)", r.Severity)
			}
		}
	})
}

func TestDeriveCalibrationColdStart(t *testing.T) {
	// Cold start: EvidenceFloor 0 is replaced by the documented default; Calibrated
	// stays false.
	state := TapState{
		Calibration: calibration.State{Calibrated: false, EvidenceSeen: 0, EvidenceFloor: 0},
	}
	ov := Derive(state, nil, base)
	if ov.Calibration.EvidenceFloor != calibration.DefaultEvidenceFloor {
		t.Fatalf("EvidenceFloor = %d, want default %d", ov.Calibration.EvidenceFloor, calibration.DefaultEvidenceFloor)
	}
	if ov.Calibration.Calibrated {
		t.Fatal("Calibrated = true, want false (cold start)")
	}

	// Not-yet-calibrated with a real non-zero floor propagates verbatim.
	state2 := TapState{
		Calibration: calibration.State{Calibrated: false, EvidenceSeen: 23, EvidenceFloor: 50},
	}
	ov2 := Derive(state2, nil, base)
	if ov2.Calibration != (CalibView{Calibrated: false, EvidenceSeen: 23, EvidenceFloor: 50}) {
		t.Fatalf("Calibration = %+v, want {false 23 50} verbatim", ov2.Calibration)
	}
}

func TestDeriveKernelContainment(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0x30, 3, "jail", "a", 0, intelligence.StingOutcome{}, nil),
		ev(0x31, 3, "jail", "b", 1, intelligence.StingOutcome{}, nil),
		ev(0x10, 1, "tag", "c", 2, intelligence.StingOutcome{}, nil),
		ev(0x11, 1, "tag", "d", 3, intelligence.StingOutcome{}, nil),
		ev(0x12, 2, "contain", "e", 4, intelligence.StingOutcome{}, nil),
		ev(0x13, 1, "tag", "f", 5, intelligence.StingOutcome{}, nil), // 4th non-jailed: must be capped out
	}
	ov := Derive(TapState{}, events, base.Add(time.Minute))
	kc := ov.KernelContainment
	if len(kc.JailedFlows) != 2 {
		t.Fatalf("JailedFlows = %d, want 2", len(kc.JailedFlows))
	}
	for _, j := range kc.JailedFlows {
		if j.Tier != 3 {
			t.Fatalf("jailed flow tier = %d, want 3", j.Tier)
		}
		if len(j.FlowIDHex) < 3 || j.FlowIDHex[:2] != "0x" {
			t.Fatalf("FlowIDHex = %q, want 0x-prefixed padded", j.FlowIDHex)
		}
	}
	if len(kc.OKFlows) > maxOKFlows {
		t.Fatalf("OKFlows = %d, want <= %d", len(kc.OKFlows), maxOKFlows)
	}
}
