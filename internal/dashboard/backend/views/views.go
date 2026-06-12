// Package views holds the pure derivation logic that turns the engine tap's
// RAW read-only state (calibration + baseline gates + observe folds) and the
// scope's anonymized interaction events into the typed Overview the CISO
// dashboard renders. It is read-only by construction: it imports only the
// engine's exported READ types and pure functions (calibration.State,
// baseline.GateState/Features/MFromFeatures, observebaseline.AggStats,
// intelligence.AdversaryInteractionEvent, cost.Rollup). It NEVER imports any
// store/persist/contract/adapter/bpf package and NEVER writes anything.
//
// Honesty rules baked in here (docs/INTELLIGENCE.md):
//   - FlowView.Score is the flow's latest real engine suspicion score (carried on
//     the event since M8); SparkSeries is the real per-event score progression
//     normalized to the flow's peak. Pre-M8 records decode Score=0, and the spark
//     then falls back to the tier ladder rather than a flat zero line.
//   - boltevents only stores Tier>=1, so the ladder's T0 (Observe) count comes
//     from observebaseline.AggStats.CompletedFolds, never from events; the caption
//     notes T0 is cumulative observed-normal traffic.
//   - Recon is labeled "recon"/"surfaced", never "detected" (early-warning, not
//     enforcement).
//   - Flow identity is the socket-cookie hex only; no fabricated IPs/roles.
package views

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/cost"
	"github.com/canarysting/canarysting/internal/intelligence/recon"
)

// Feature-map keys written into AdversaryInteractionEvent.Features. These mirror
// the baseline.Features struct fields (docs/BASELINE_MULTIPLIER.md §3).
const (
	featAdjacency   = "adjacency_novelty"
	featIdentity    = "identity_novelty"
	featPort        = "port_novelty"
	featVolume      = "volume_deviation"
	featCadence     = "cadence_deviation"
	featFingerprint = "fingerprint_match" // D5 sharpening signal (0 in Phase 1)
)

const (
	// tarpitPersistSec is the TimeHeldSec threshold above which a flow is judged
	// to have "persisted through the tarpit" (a behavioral fingerprint signal).
	tarpitPersistSec = 30.0
	// Recon severity/cluster thresholds now live in internal/intelligence/recon (D4):
	// the dashboard recon feed + timeline are thin views over recon.DeriveReconSignal.
	maxReconItems = 10
	maxOKFlows    = 3
)

// TapState mirrors tap.State (internal/dashboard/tap). It embeds the same
// read-only engine types so the JSON the tap emits round-trips exactly (those
// engine types carry no json tags, so the wire keys are the Go field names).
// Kept as a local mirror to avoid importing the tap package (which pulls in the
// boltevents store).
type TapState struct {
	Scope       string                   `json:"scope"`
	Calibration calibration.State        `json:"calibration"`
	Baseline    baseline.GateState       `json:"baseline"`
	Observe     observebaseline.AggStats `json:"observe"`
	At          time.Time                `json:"at"`
}

// Overview is the complete JSON payload served by GET /api/overview and pushed
// over GET /api/stream. It IS the contract the Next.js frontend consumes.
// Every field traces to a real engine source or is honestly absent/zero.
type Overview struct {
	// Topbar pills.
	Env          string    `json:"env"`
	Scope        string    `json:"scope"`
	At           time.Time `json:"at"`
	TapReachable bool      `json:"tap_reachable"`
	Calibration  CalibView `json:"calibration"`
	BaselineLive bool      `json:"baseline_live"`

	// Hero left: live escalation + tier ladder.
	Escalation EscalationView `json:"escalation"`

	// Hero right: attacker cost.
	AttackerCost AttackerCostView `json:"attacker_cost"`

	// Secondary band.
	KernelContainment KernelContainmentView `json:"kernel_containment"`
	Credibility       CredibilityView       `json:"credibility"`
	AdversaryIntel    AdversaryIntelView    `json:"adversary_intel"`

	// RealAttackCost is the M9 live meter: the attacker's GROUND-TRUTH token/$
	// burn, posted by the llm-attacker and polled from the tap's attack-ledger.
	// It is deliberately SEPARATE from AttackerCost.TokensBurned (the defender's
	// proxy estimate) — the two are shown side by side, never merged. Present is
	// false until an attack run posts a ledger.
	RealAttackCost RealAttackCostView `json:"real_attack_cost"`

	// Journey is the current attacker flow's legible ARC — recon -> escalation
	// (with which axes fired at each tier crossing) -> disengage — as an ordered
	// timeline, so the CISO sees the cascade as a story, not just a tier-count
	// snapshot. Pure derivation over the current flow's events; absent if no flow.
	Journey JourneyView `json:"journey"`
}

// RealAttackCostView is the M9 real-cost meter. It mirrors the tap's
// attack-ledger and adds the cap fraction for the on-screen progress bar. All
// numbers are the attacker's own observed Anthropic usage — not a defender
// estimate.
type RealAttackCostView struct {
	Present             bool    `json:"present"` // false until an attack posts a ledger
	Active              bool    `json:"active"`  // a run is currently posting (not stale)
	Model               string  `json:"model"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	USD                 float64 `json:"usd"`
	HardCapUSD          float64 `json:"hard_cap_usd"`
	CapFraction         float64 `json:"cap_fraction"` // usd/hard_cap, clamped 0..1, for the meter bar
}

// CalibView is the topbar calibration pill.
type CalibView struct {
	Calibrated    bool `json:"calibrated"`
	EvidenceSeen  int  `json:"evidence_seen"`
	EvidenceFloor int  `json:"evidence_floor"`
}

// EscalationView is the hero-left panel: the current attacker flow + tier ladder.
type EscalationView struct {
	// Flow is the current attacker (highest-tier, recency tie-break). Nil if none.
	Flow *FlowView `json:"flow,omitempty"`

	// TierLadder is always length 4 (T0..T3). T0 uses CompletedFolds; T1-3 use
	// windowed event counts.
	TierLadder [4]TierStep `json:"tier_ladder"`

	// LadderDenominator = CompletedFolds + T1 + T2 + T3.
	LadderDenominator int `json:"ladder_denominator"`

	// LadderCaption is the honest note that T0 is cumulative observed-normal
	// traffic while T1-3 are windowed canary-interacting flows.
	LadderCaption string `json:"ladder_caption"`
}

// FlowView is the currently-tracked attacker flow shown in the live panel.
type FlowView struct {
	FlowID        uint64    `json:"flow_id"`      // socket cookie
	FlowIDHex     string    `json:"flow_id_hex"`  // "0x%x"
	SourceLabel   string    `json:"source_label"` // empty for now (future registry join)
	Tier          int       `json:"tier"`
	Verdict       string    `json:"verdict"`
	Score         float64   `json:"score"`          // latest real engine suspicion score for this flow
	BaseM         float64   `json:"base_m"`         // max M across this flow's events
	CanaryTouches []string  `json:"canary_touches"` // ordered unique CanaryType sequence
	TouchCount    int       `json:"touch_count"`    // total events for this flow
	LastSeen      time.Time `json:"last_seen"`
	SparkSeries   []float64 `json:"spark_series"` // per-event score progression normalized to peak (0..1), timestamp order
}

// JourneyView is the current attacker flow's legible arc: an ordered sequence of
// milestones (recon touch -> tier crossings, with the axes that fired -> disengage),
// derived purely from that flow's events. It turns the tier-count snapshot into the
// narrative a CISO follows in the demo. Present is false when there is no current flow.
type JourneyView struct {
	Present    bool               `json:"present"`
	FlowIDHex  string             `json:"flow_id_hex"`
	Milestones []JourneyMilestone `json:"milestones"`       // oldest-first
	Latest     *JourneyMilestone  `json:"latest,omitempty"` // the "what's happening now" callout (the last milestone)
}

// JourneyMilestone is one beat in the attacker's arc. AxesFiring lists the OVERLAPPING
// attrition axes active at a containment/jail crossing (decoded from the triggering
// event's Sting.Axes via cost.AxesOf) — never a partition. Honest by construction: every
// milestone traces to a real event; nothing is fabricated.
type JourneyMilestone struct {
	OffsetLabel string   `json:"offset_label"` // "−m:ss" relative to now (matches the recon feed)
	Phase       string   `json:"phase"`        // "recon" | "contained" | "jailed" | "disengaged"
	Tier        int      `json:"tier"`
	Title       string   `json:"title"`                 // e.g. "Contained — attrition begins"
	Detail      string   `json:"detail,omitempty"`      // e.g. "velocity + poison" or the disengage reason
	AxesFiring  []string `json:"axes_firing,omitempty"` // overlapping axes active at this crossing
}

// TierStep is one rung of the horizontal tier ladder.
type TierStep struct {
	Tier        int     `json:"tier"`
	Label       string  `json:"label"`
	Description string  `json:"description"`
	Count       int     `json:"count"`
	Fraction    float64 `json:"fraction"`     // count / LadderDenominator; 0 if denom=0
	HasResponse bool    `json:"has_response"` // T2+: active response
	RespLabel   string  `json:"resp_label"`   // "counter-attacked" / "kernel-jailed" / ""
	IsActive    bool    `json:"is_active"`    // highest occupied tier
}

// AttackerCostView is the hero-right panel. Framing (AX3): the headline is
// OPPORTUNITY COST on a velocity-dependent adversary — imposed time + engagement —
// NOT a dollar bill. TokensBurned is a qualified PROXY/estimate, demoted below the
// time/engagement numbers; the M9 RealAttackCost ($) stays SEPARATE (never merged).
type AttackerCostView struct {
	ActiveResponseCount  int            `json:"active_response_count"` // T2+T3
	Jailed               int            `json:"jailed"`                // T3
	CounterAttacked      int            `json:"counter_attacked"`      // T2
	TimeImposedSec       float64        `json:"time_imposed_sec"`      // the headline
	TokensBurned         float64        `json:"tokens_burned"`         // a PROXY/estimate, demoted below time
	RequestsAbsorbed     int64          `json:"requests_absorbed"`
	BytesServed          int64          `json:"bytes_served"`
	AttackerCostFraction float64        `json:"attacker_cost_fraction"` // active / total interactions
	DefenderCostFlat     bool           `json:"defender_cost_flat"`     // structural invariant: always true
	PerAxis              []AxisCostView `json:"per_axis"`               // OVERLAPPING per-axis subtotals — never a partition
	Engagement           EngagementView `json:"engagement"`             // the engagement contest
}

// AxisCostView is one OVERLAPPING per-axis subtotal: an interaction lands on EVERY
// axis its mechanism imposes (fake_tree is poison + opportunity cost), so these are
// independent bars and must NEVER be rendered as a partition summing to the total.
type AxisCostView struct {
	Axis    string  `json:"axis"`
	TimeSec float64 `json:"time_sec"`
	Tokens  float64 `json:"tokens"`
	Count   int     `json:"count"`
}

// EngagementView is the engagement-contest metric: how long attrition held flows
// (the imposed-hold distribution) and how those sessions ended. Time-to-disengage
// is sourced from the REAL imposed hold + the adapter's D7 disengage classifier,
// NOT an event-timestamp span. DisengagedEarly is the engagement signal (the
// attacker gave up before any defender bound). (A "believed-longer-than-detect"
// plausibility fraction is a documented fast-follow — D10/§8 — not shipped here.)
type EngagementView struct {
	MedianSec               float64 `json:"median_sec"`
	P90Sec                  float64 `json:"p90_sec"`
	LongestSec              float64 `json:"longest_sec"`
	DisengagedEarly         int     `json:"disengaged_early"`
	GeneratorExhausted      int     `json:"generator_exhausted"`
	DefenderCapped          int     `json:"defender_capped"`
	DisengagedEarlyFraction float64 `json:"disengaged_early_fraction"`
}

// KernelContainmentView is the secondary-band left panel.
type KernelContainmentView struct {
	JailedFlows []ContainedFlow `json:"jailed_flows"`
	OKFlows     []ContainedFlow `json:"ok_flows"` // sample of non-jailed flows (max 3)
}

// ContainedFlow is one row in the kernel-containment panel.
type ContainedFlow struct {
	FlowIDHex string `json:"flow_id_hex"`
	Tier      int    `json:"tier"`
	Verdict   string `json:"verdict"`
}

// CredibilityView is the secondary-band middle panel.
type CredibilityView struct {
	GuardrailActive     bool             `json:"guardrail_active"`      // architectural invariant: always true
	BaselineMultiplierM float64          `json:"baseline_multiplier_m"` // max M across window; 1.0 if none
	FeatureBars         []FeatureBar     `json:"feature_bars"`
	Calibration         CalibView        `json:"calibration"`
	BaselineGates       BaselineGateView `json:"baseline_gates"`
}

// FeatureBar is one bar in the baseline-multiplier feature display.
type FeatureBar struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// BaselineGateView surfaces the three gates the multiplier ANDs.
type BaselineGateView struct {
	Live             bool `json:"live"`
	BucketSufficient bool `json:"bucket_sufficient"`
	Calibrated       bool `json:"calibrated"`
}

// AdversaryIntelView is the secondary-band right panel (three facets).
type AdversaryIntelView struct {
	KPI         IntelKPIView     `json:"kpi"`
	ReconFeed   []ReconEvent     `json:"recon_feed"`            // T1, newest first, max 10
	Fingerprint *FlowFingerprint `json:"fingerprint,omitempty"` // nil if no current flow
	Reactions   AxisReactionView `json:"reactions"`             // AX2/AX4/AX5 deception-reaction signals
}

// AxisReactionView surfaces the AX2/AX4/AX5 reaction signals — what the attacker DID
// in response to the deception, distinct from the imposed-cost KPI: how far into the
// fabricated environment they walked (poison), how many real exploits they fired at
// decoys, how many times they exposed their tooling. Counts only; deployment-local-
// only (rule 9 — the egress filter gates any cross-boundary use). All zero on a
// passive-floor window (these axes don't fire below their floors).
type AxisReactionView struct {
	ExploitsObserved int64  `json:"exploits_observed"` // AX4: exploits fired at decoys (in-perimeter)
	ExposureSignals  int64  `json:"exposure_signals"`  // AX5: tooling/C2 fingerprints exposed
	PoisonReached    int    `json:"poison_reached"`    // AX2: deepest fabricated-environment stage walked
	PoisonClass      string `json:"poison_class"`      // AX2: class of that deepest stage ("" if none)
}

// IntelKPIView is the attacker-cost KPI card.
type IntelKPIView struct {
	TokensBurned      float64 `json:"tokens_burned"`
	TimeImposedSec    float64 `json:"time_imposed_sec"`
	RequestsAbsorbed  int64   `json:"requests_absorbed"`
	BytesServed       int64   `json:"bytes_served"`
	DefenderCostLabel string  `json:"defender_cost_label"` // "flat" (structural)
}

// ReconEvent is one row in the recon early-warning feed.
type ReconEvent struct {
	FlowIDHex   string  `json:"flow_id_hex"`
	OffsetSec   float64 `json:"offset_sec"`   // negative seconds (in the past)
	OffsetLabel string  `json:"offset_label"` // "−m:ss"
	CanaryType  string  `json:"canary_type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "recon" | "surfaced"
}

// Derive turns raw tap state + the events window into the Overview. Pure: no I/O,
// no goroutines, no clock except the passed-in now.
func Derive(state TapState, events []intelligence.AdversaryInteractionEvent, now time.Time) Overview {
	summary := cost.Rollup(events)

	calib := CalibView{
		Calibrated:    state.Calibration.Calibrated,
		EvidenceSeen:  state.Calibration.EvidenceSeen,
		EvidenceFloor: state.Calibration.EvidenceFloor,
	}
	if calib.EvidenceFloor == 0 {
		calib.EvidenceFloor = calibration.DefaultEvidenceFloor
	}

	flow := selectCurrentFlow(events)
	ladder, denom := buildLadder(summary, state.Observe.CompletedFolds)

	ov := Overview{
		Scope:        state.Scope,
		At:           state.At,
		TapReachable: true,
		Calibration:  calib,
		BaselineLive: state.Baseline.Live,
		Escalation: EscalationView{
			Flow:              flow,
			TierLadder:        ladder,
			LadderDenominator: denom,
			LadderCaption:     "Two windows, not one denominator: T0 = cumulative observed-normal traffic (eBPF folds since start, pinned to the full bar); T1-3 fractions are of the attacker subtotal within the events window only. The two are intentionally not mixed.",
		},
		AttackerCost:      buildAttackerCost(summary),
		KernelContainment: buildKernelContainment(events),
		Credibility:       buildCredibility(state, events, calib),
		AdversaryIntel:    buildAdversaryIntel(summary, events, flow, now),
		Journey:           buildJourney(flow, events, now),
	}
	return ov
}

// selectCurrentFlow picks the "current attacker": the flow with the highest max
// tier, tie-broken by most-recent timestamp. Returns nil for no events.
func selectCurrentFlow(events []intelligence.AdversaryInteractionEvent) *FlowView {
	if len(events) == 0 {
		return nil
	}
	groups := groupByFlow(events)

	var bestID uint64
	var bestTier int
	var bestRecent time.Time
	first := true
	for id, grp := range groups {
		maxTier, recent := 0, time.Time{}
		for _, e := range grp {
			if e.Tier > maxTier {
				maxTier = e.Tier
			}
			if e.Timestamp.After(recent) {
				recent = e.Timestamp
			}
		}
		if first || maxTier > bestTier ||
			(maxTier == bestTier && recent.After(bestRecent)) ||
			(maxTier == bestTier && recent.Equal(bestRecent) && id > bestID) {
			bestID, bestTier, bestRecent = id, maxTier, recent
			first = false
		}
	}
	return buildFlowView(bestID, groups[bestID])
}

func buildFlowView(flowID uint64, grp []intelligence.AdversaryInteractionEvent) *FlowView {
	ordered := append([]intelligence.AdversaryInteractionEvent(nil), grp...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })

	maxTier := 0
	verdict := ""
	var lastSeen time.Time
	var latestScore float64 // the latest event's suspicion score (timestamp order)
	touches := make([]string, 0, len(ordered))
	rawScores := make([]float64, 0, len(ordered))
	seen := map[string]bool{}
	for _, e := range ordered {
		if e.Tier >= maxTier { // >= so the verdict tracks the latest highest-tier event
			maxTier = e.Tier
			verdict = e.Verdict
		}
		if e.Timestamp.After(lastSeen) {
			lastSeen = e.Timestamp
		}
		if e.CanaryType != "" && !seen[e.CanaryType] {
			seen[e.CanaryType] = true
			touches = append(touches, e.CanaryType)
		}
		latestScore = e.Score // ordered ascending => last assignment is the newest
		rawScores = append(rawScores, e.Score)
	}

	return &FlowView{
		FlowID:        flowID,
		FlowIDHex:     fmt.Sprintf("0x%x", flowID),
		Tier:          maxTier,
		Verdict:       verdict,
		Score:         latestScore, // the flow's latest real suspicion score
		BaseM:         computeMaxM(ordered),
		CanaryTouches: touches,
		TouchCount:    len(ordered),
		LastSeen:      lastSeen,
		SparkSeries:   normalizeSpark(rawScores, ordered),
	}
}

// Disengage classification mirrors contract.DisengageReason (kept local so views
// imports no contract package — the same discipline as the TapState mirror). The values
// are the stable engine enum: 1 attacker, 2 generator-exhausted, 3 defender-capped.
const (
	disengageAttacker       = 1
	disengageGeneratorDone  = 2
	disengageDefenderCapped = 3
)

// buildJourney derives the current flow's legible arc from its events: a milestone at
// each tier CROSSING (with the overlapping axes that fired, decoded from the triggering
// event's Sting.Axes), plus a final disengage milestone if the flow gave up / was capped.
// Pure + honest: every milestone traces to a real event. Absent if there is no flow.
func buildJourney(flow *FlowView, events []intelligence.AdversaryInteractionEvent, now time.Time) JourneyView {
	if flow == nil {
		return JourneyView{Present: false}
	}
	grp := groupByFlow(events)[flow.FlowID]
	ordered := append([]intelligence.AdversaryInteractionEvent(nil), grp...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })

	var ms []JourneyMilestone
	maxTier := -1
	disengage := 0
	for _, e := range ordered {
		// The TERMINAL disengage reason (the latest attrition session's outcome), not
		// the worst across the flow: ordered is ascending, so the last non-zero
		// assignment wins. This faithfully reports HOW THE FLOW ENDED — and keeps the
		// D2-2 honesty (the engine only ever sets DisengageAttacker for a real
		// attacker-initiated disengage; a cap/generator-end is its own reason).
		if e.Sting.DisengageReason != 0 {
			disengage = e.Sting.DisengageReason
		}
		if e.Tier > maxTier { // a tier crossing (the highest-tier-so-far advanced)
			maxTier = e.Tier
			ms = append(ms, tierMilestone(e, now))
		}
	}
	if m, ok := disengageMilestone(disengage, ordered, now); ok {
		ms = append(ms, m)
	}

	jv := JourneyView{Present: true, FlowIDHex: flow.FlowIDHex, Milestones: ms}
	if len(ms) > 0 {
		jv.Latest = &ms[len(ms)-1]
	}
	return jv
}

// tierMilestone renders one tier-crossing event into a journey beat. T2/T3 decode the
// OVERLAPPING axes that fired from the event's Sting.Axes (cost.AxesOf).
func tierMilestone(e intelligence.AdversaryInteractionEvent, now time.Time) JourneyMilestone {
	m := JourneyMilestone{OffsetLabel: offsetLabel(-now.Sub(e.Timestamp).Seconds()), Tier: e.Tier}
	switch e.Tier {
	case 0:
		m.Phase, m.Title = "recon", "Probing the negative space"
	case 1:
		m.Phase, m.Title = "recon", "Decoy touched — recon surfaced (not yet a verdict)"
		m.Detail = e.CanaryType
	case 2:
		m.Phase, m.Title = "contained", "Contained — inline attrition begins"
		m.AxesFiring = cost.AxesOf(uint32(e.Sting.Axes))
		m.Detail = strings.Join(m.AxesFiring, " + ")
	case 3:
		m.Phase, m.Title = "jailed", "Jailed in-kernel — socket-cookie precise"
		m.AxesFiring = cost.AxesOf(uint32(e.Sting.Axes))
		m.Detail = strings.Join(m.AxesFiring, " + ")
	default:
		m.Phase, m.Title = "recon", "Interaction"
	}
	return m
}

// disengageMilestone emits the closing beat IF the flow disengaged. The reason is the
// engine's honest classification (D2-2): only an attacker-initiated disengage is "gave
// up"; a defender cap / generator-exhausted is labeled as such, never relabeled.
func disengageMilestone(reason int, ordered []intelligence.AdversaryInteractionEvent, now time.Time) (JourneyMilestone, bool) {
	if reason == 0 || len(ordered) == 0 {
		return JourneyMilestone{}, false
	}
	last := ordered[len(ordered)-1]
	m := JourneyMilestone{OffsetLabel: offsetLabel(-now.Sub(last.Timestamp).Seconds()), Phase: "disengaged", Tier: last.Tier}
	switch reason {
	case disengageAttacker:
		m.Title, m.Detail = "Attacker disengaged", "gave up before any defender bound — the engagement signal"
	case disengageGeneratorDone:
		m.Title, m.Detail = "Session ended", "the fake-resource generator reached its bounded end"
	case disengageDefenderCapped:
		m.Title, m.Detail = "Defender-capped", "we stopped it (per-flow budget / host ceiling / max-hold)"
	default:
		return JourneyMilestone{}, false
	}
	return m, true
}

// normalizeSpark turns the per-event suspicion-score progression (timestamp
// order) into a 0..1 sparkline shape by dividing by the flow's peak score, so the
// sparkline shows the real escalation curve. When no event carries a score (old
// pre-M8 gob records decode Score=0), it falls back to the tier ladder (0..3
// scaled to 0..1) so the spark is never a flat line of zeros for legacy data.
func normalizeSpark(scores []float64, ordered []intelligence.AdversaryInteractionEvent) []float64 {
	peak := 0.0
	for _, s := range scores {
		if s > peak {
			peak = s
		}
	}
	spark := make([]float64, len(scores))
	if peak > 0 {
		for i, s := range scores {
			spark[i] = s / peak
		}
		return spark
	}
	// Fallback: no real scores (legacy data) — use the tier progression, /3.
	for i, e := range ordered {
		spark[i] = float64(e.Tier) / 3.0
	}
	return spark
}

// buildLadder builds the 4-rung tier ladder. T0 count = completedFolds (real
// observed-normal traffic, never from events); T1-3 = windowed event counts.
func buildLadder(summary cost.Summary, completedFolds uint64) ([4]TierStep, int) {
	counts := [4]int{
		int(completedFolds), // T0: from observe, NOT events (boltevents never stores T0)
		summary.TierCounts[1],
		summary.TierCounts[2],
		summary.TierCounts[3],
	}
	denom := counts[0] + counts[1] + counts[2] + counts[3]

	// highest occupied tier (for IsActive)
	active := -1
	for t := 3; t >= 0; t-- {
		if counts[t] > 0 {
			active = t
			break
		}
	}

	labels := [4]string{"Observe", "Tag", "Contain", "Jail"}
	descs := [4]string{"normal traffic · eBPF", "suspicious · tagged", "contained · attrition", "kernel-jailed"}
	hasResp := [4]bool{false, false, true, true}
	respLabel := [4]string{"", "", "counter-attacked", "kernel-jailed"}

	var ladder [4]TierStep
	for t := 0; t < 4; t++ {
		ladder[t] = TierStep{
			Tier:        t,
			Label:       labels[t],
			Description: descs[t],
			Count:       counts[t],
			HasResponse: hasResp[t],
			RespLabel:   respLabel[t],
			IsActive:    t == active,
		}
	}

	// Fractions live in TWO windows that must not be mixed in one denominator:
	// T0 is the cumulative observed-normal fold count (huge, unbounded over the
	// learning window) while T1-3 are windowed canary-interacting counts. Mixing
	// them collapses the T1-3 bars to ~0. So T1-3 fractions are computed over the
	// ATTACKER SUBTOTAL only, and T0's fraction is pinned to 1.0 (it is always the
	// full observed base, the bar the attacker climbs out of).
	attackerTotal := counts[1] + counts[2] + counts[3]
	for t := 1; t <= 3; t++ {
		f := 0.0
		if attackerTotal > 0 {
			f = float64(counts[t]) / float64(attackerTotal)
		}
		ladder[t].Fraction = f
	}
	// T0 is the full observed base => fraction 1.0, but stays 0 when the ladder is
	// entirely empty (no folds and no attacker activity) so an empty Overview
	// reports honest zeros rather than a phantom full bar.
	if denom > 0 {
		ladder[0].Fraction = 1.0
	}

	return ladder, denom
}

// engagementView derives the engagement-contest view from a cost summary. Shared by
// the Overview AttackerCost panel and the /cost drill-down so both report it identically.
func engagementView(s cost.Summary) EngagementView {
	classified := s.DisengagedEarly + s.GeneratorExhausted + s.DefenderCapped
	earlyFrac := 0.0
	if classified > 0 {
		earlyFrac = float64(s.DisengagedEarly) / float64(classified)
	}
	return EngagementView{
		MedianSec:               s.EngagementMedianSec,
		P90Sec:                  s.EngagementP90Sec,
		LongestSec:              s.EngagementLongestSec,
		DisengagedEarly:         s.DisengagedEarly,
		GeneratorExhausted:      s.GeneratorExhausted,
		DefenderCapped:          s.DefenderCapped,
		DisengagedEarlyFraction: earlyFrac,
	}
}

// reactionView derives the AX2/AX4/AX5 deception-reaction view from a cost summary.
// Shared by the AdversaryIntelligence panel and the /cost drill-down.
func reactionView(s cost.Summary) AxisReactionView {
	return AxisReactionView{
		ExploitsObserved: s.ExploitsObserved,
		ExposureSignals:  s.ExposureSignals,
		PoisonReached:    s.PoisonReachedMax,
		PoisonClass:      s.PoisonClassDeepest,
	}
}

func buildAttackerCost(summary cost.Summary) AttackerCostView {
	frac := 0.0
	if summary.Interactions > 0 {
		frac = float64(summary.ActiveResponse()) / float64(summary.Interactions)
	}
	// Per-axis OVERLAPPING subtotals — emit only axes that actually saw traffic
	// (honest empty otherwise). Order follows the axis ordinal.
	var perAxis []AxisCostView
	for i := 0; i < cost.NumAxes; i++ {
		if summary.AxisCount[i] > 0 {
			perAxis = append(perAxis, AxisCostView{
				Axis:    cost.AxisNames[i],
				TimeSec: summary.AxisTimeSec[i],
				Tokens:  summary.AxisTokens[i],
				Count:   summary.AxisCount[i],
			})
		}
	}
	return AttackerCostView{
		ActiveResponseCount:  summary.ActiveResponse(),
		Jailed:               summary.Jailed(),
		CounterAttacked:      summary.TierCounts[2],
		TimeImposedSec:       summary.TimeImposedSec,
		TokensBurned:         summary.TokensBurned,
		RequestsAbsorbed:     summary.RequestsAbsorbed,
		BytesServed:          summary.BytesServed,
		AttackerCostFraction: frac,
		DefenderCostFlat:     true,
		PerAxis:              perAxis,
		Engagement:           engagementView(summary),
	}
}

// buildKernelContainment lists Tier-3 (jailed) flows and a sample of non-jailed
// (T1/T2) flows. One row per flow (deduped on cookie), deterministic order.
func buildKernelContainment(events []intelligence.AdversaryInteractionEvent) KernelContainmentView {
	groups := groupByFlow(events)
	ids := sortedFlowIDs(groups)

	var jailed, ok []ContainedFlow
	for _, id := range ids {
		// Sort the flow's events ascending by timestamp into a local copy, then a
		// single forward pass (matches buildFlowView): the verdict tracks the
		// latest highest-tier event and never gets corrupted by out-of-order input.
		grp := append([]intelligence.AdversaryInteractionEvent(nil), groups[id]...)
		sort.SliceStable(grp, func(i, j int) bool { return grp[i].Timestamp.Before(grp[j].Timestamp) })
		maxTier := 0
		verdict := ""
		for _, e := range grp {
			if e.Tier >= maxTier {
				maxTier = e.Tier
				verdict = e.Verdict
			}
		}
		row := ContainedFlow{
			FlowIDHex: fmt.Sprintf("0x%x", id),
			Tier:      maxTier,
			Verdict:   verdict,
		}
		if maxTier >= 3 {
			jailed = append(jailed, row)
		} else if maxTier >= 1 && len(ok) < maxOKFlows {
			ok = append(ok, row)
		}
	}
	return KernelContainmentView{JailedFlows: jailed, OKFlows: ok}
}

// buildCredibility builds the guardrail/baseline-M/calibration panel. M is the
// max MFromFeatures over the window's events; FeatureBars come from the
// highest-M event. Honest neutral (M=1.0, capped 0-bars) when no features.
func buildCredibility(state TapState, events []intelligence.AdversaryInteractionEvent, calib CalibView) CredibilityView {
	maxM, peak := computeMaxMAndPeak(events)
	return CredibilityView{
		GuardrailActive:     true,
		BaselineMultiplierM: maxM,
		FeatureBars:         featureBars(peak),
		Calibration:         calib,
		BaselineGates: BaselineGateView{
			Live:             state.Baseline.Live,
			BucketSufficient: state.Baseline.BucketSufficient,
			Calibrated:       state.Baseline.Calibrated,
		},
	}
}

func buildAdversaryIntel(summary cost.Summary, events []intelligence.AdversaryInteractionEvent, flow *FlowView, now time.Time) AdversaryIntelView {
	var fp *FlowFingerprint
	if flow != nil {
		groups := groupByFlow(events)
		fp = DeriveFingerprint(flow.FlowID, groups[flow.FlowID])
	}
	return AdversaryIntelView{
		KPI: IntelKPIView{
			TokensBurned:      summary.TokensBurned,
			TimeImposedSec:    summary.TimeImposedSec,
			RequestsAbsorbed:  summary.RequestsAbsorbed,
			BytesServed:       summary.BytesServed,
			DefenderCostLabel: "flat",
		},
		ReconFeed:   buildReconFeed(events, now, maxReconItems),
		Fingerprint: fp,
		Reactions:   reactionView(summary),
	}
}

// buildReconFeed surfaces Tier-1 events (the lowest stored tier = quiet probes
// in negative space) as the early-warning feed: newest first, max maxItems.
// Severity escalates to "surfaced" on high adjacency novelty or cluster
// membership; otherwise "recon". Never "detected".
func buildReconFeed(events []intelligence.AdversaryInteractionEvent, now time.Time, maxItems int) []ReconEvent {
	sigs := recon.DeriveReconSignal(events) // the D4 signal (oldest-first); severity/cluster/description derived once
	if len(sigs) == 0 {
		return nil
	}
	// Home-wall feed framing: newest first, capped at maxItems.
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].Timestamp.After(sigs[j].Timestamp) })
	feed := make([]ReconEvent, 0, maxItems)
	for _, s := range sigs {
		if len(feed) >= maxItems {
			break
		}
		offset := -now.Sub(s.Timestamp).Seconds()
		feed = append(feed, ReconEvent{
			FlowIDHex:   fmt.Sprintf("0x%x", s.FlowID),
			OffsetSec:   offset,
			OffsetLabel: offsetLabel(offset),
			CanaryType:  s.CanaryType,
			Description: s.Description,
			Severity:    s.Severity,
		})
	}
	return feed
}

func offsetLabel(offsetSec float64) string {
	s := int(-offsetSec)
	if s < 0 {
		s = 0
	}
	return fmt.Sprintf("−%d:%02d", s/60, s%60)
}

// computeMaxM returns the max MFromFeatures across the events. 1.0 if none have
// derivable features (honest neutral, the multiplier floor-of-one).
func computeMaxM(events []intelligence.AdversaryInteractionEvent) float64 {
	m, _ := computeMaxMAndPeak(events)
	return m
}

func computeMaxMAndPeak(events []intelligence.AdversaryInteractionEvent) (float64, baseline.Features) {
	maxM := 1.0
	var peak baseline.Features
	p := baseline.DefaultParams()
	for _, e := range events {
		f := featuresFromMap(e.Features)
		m := baseline.MFromFeatures(f, p)
		if m > maxM {
			maxM = m
			peak = f
		}
	}
	return maxM, peak
}

func featuresFromMap(m map[string]float64) baseline.Features {
	if m == nil {
		return baseline.Features{}
	}
	return baseline.Features{
		AdjacencyNovelty: m[featAdjacency],
		IdentityNovelty:  m[featIdentity],
		PortNovelty:      m[featPort],
		VolumeDeviation:  m[featVolume],
		CadenceDeviation: m[featCadence],
		FingerprintMatch: m[featFingerprint], // 0 for pre-D5 events (missing key)
	}
}

// featureBars maps the four primary feature contributions (capped 0..1) to the
// dashboard's display names. Values are clamped to [0,1] for the bar widths.
func featureBars(f baseline.Features) []FeatureBar {
	clamp := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > 1 {
			return 1
		}
		return v
	}
	return []FeatureBar{
		{Name: "adjacency nov.", Value: clamp(f.AdjacencyNovelty)},
		{Name: "identity nov.", Value: clamp(f.IdentityNovelty)},
		{Name: "volume dev.", Value: clamp(f.VolumeDeviation)},
		{Name: "cadence dev.", Value: clamp(f.CadenceDeviation)},
	}
}

func groupByFlow(events []intelligence.AdversaryInteractionEvent) map[uint64][]intelligence.AdversaryInteractionEvent {
	groups := map[uint64][]intelligence.AdversaryInteractionEvent{}
	for _, e := range events {
		groups[e.FlowID] = append(groups[e.FlowID], e)
	}
	return groups
}

func sortedFlowIDs(groups map[uint64][]intelligence.AdversaryInteractionEvent) []uint64 {
	ids := make([]uint64, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
