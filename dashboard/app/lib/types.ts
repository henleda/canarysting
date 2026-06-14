// TypeScript mirror of the Go `Overview` payload served by GET /api/overview and
// pushed over GET /api/stream (event: overview). This is a 1:1 port of
// internal/dashboard/backend/views/views.go + fingerprint.go — every field uses
// the Go struct's json tag (snake_case) and matches its Go type. This file IS
// the wire contract; do not invent fields.

// CalibView is the topbar / credibility calibration pill.
export interface CalibView {
  calibrated: boolean;
  evidence_seen: number;
  evidence_floor: number;
}

// FlowView is the currently-tracked attacker flow shown in the live panel.
// Identity is the socket-cookie hex only (flow_id_hex like "0x118"); there are
// no source IPs/roles in the data — source_label is empty for now.
export interface FlowView {
  flow_id: number; // socket cookie (uint64)
  flow_id_hex: string; // "0x%x"
  source_label: string; // empty for now (future registry join)
  tier: number;
  verdict: string;
  score: number; // latest real engine suspicion score for this flow
  base_m: number; // max M across this flow's events
  canary_touches: string[]; // ordered unique CanaryType sequence
  touch_count: number; // total events for this flow
  last_seen: string; // RFC3339 timestamp
  spark_series: number[]; // per-event score progression normalized to peak (0..1), timestamp order
}

// TierStep is one rung of the horizontal tier ladder.
export interface TierStep {
  tier: number;
  label: string;
  description: string;
  count: number;
  fraction: number; // count / LadderDenominator; 0 if denom=0
  has_response: boolean; // T2+: active response
  resp_label: string; // "counter-attacked" / "kernel-jailed" / ""
  is_active: boolean; // highest occupied tier
}

// EscalationView is the hero-left panel: the current attacker flow + tier ladder.
export interface EscalationView {
  flow?: FlowView | null; // nil if none (json: omitempty)
  tier_ladder: [TierStep, TierStep, TierStep, TierStep]; // always length 4 (T0..T3)
  ladder_denominator: number;
  ladder_caption: string;
}

// AxisCostView is one OVERLAPPING per-axis subtotal: a flow lands on EVERY axis its
// mechanism imposes, so these are independent bars — NEVER a partition that sums to
// the total.
export interface AxisCostView {
  axis: string;
  time_sec: number;
  tokens: number;
  count: number;
}

// EngagementView is the engagement-contest metric: how long attrition held flows
// (imposed-hold distribution) and how those sessions ended. Time-to-disengage comes
// from the REAL imposed hold + the adapter's disengage classifier, not a timestamp span.
export interface EngagementView {
  median_sec: number;
  p90_sec: number;
  longest_sec: number;
  disengaged_early: number;
  generator_exhausted: number;
  defender_capped: number;
  disengaged_early_fraction: number;
}

// AttackerCostView is the hero-right panel. Framing (AX3): the headline is
// OPPORTUNITY COST on a velocity-dependent adversary — imposed time + engagement —
// not a dollar bill. tokens_burned is a qualified PROXY, demoted below time.
export interface AttackerCostView {
  active_response_count: number; // T2+T3
  jailed: number; // T3
  counter_attacked: number; // T2
  time_imposed_sec: number; // the headline
  tokens_burned: number; // a PROXY/estimate, demoted below time
  requests_absorbed: number;
  bytes_served: number;
  attacker_cost_fraction: number; // active / total interactions
  defender_cost_flat: boolean; // structural invariant: always true
  per_axis: AxisCostView[] | null; // OVERLAPPING per-axis subtotals — never a partition
  engagement: EngagementView; // the engagement contest
}

// RealAttackCostView is the M9 live cost meter: the attacker's GROUND-TRUTH
// Anthropic token/$ burn (posted by the llm-attacker, polled from the tap's
// attack-ledger). Deliberately SEPARATE from AttackerCostView.tokens_burned
// (the defender's proxy estimate) — shown side by side, never merged.
export interface RealAttackCostView {
  present: boolean; // false until an attack run posts a ledger
  active: boolean; // a run is currently posting (not stale)
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  total_tokens: number;
  usd: number;
  hard_cap_usd: number;
  cap_fraction: number; // usd/hard_cap, 0..1, for the meter bar
}

// ContainedFlow is one row in the kernel-containment panel.
export interface ContainedFlow {
  flow_id_hex: string;
  tier: number;
  verdict: string;
}

// KernelContainmentView is the secondary-band left panel.
export interface KernelContainmentView {
  jailed_flows: ContainedFlow[] | null;
  ok_flows: ContainedFlow[] | null; // sample of non-jailed flows (max 3)
}

// FeatureBar is one bar in the baseline-multiplier feature display.
export interface FeatureBar {
  name: string;
  value: number;
}

// BaselineGateView surfaces the three gates the multiplier ANDs.
export interface BaselineGateView {
  live: boolean;
  bucket_sufficient: boolean;
  calibrated: boolean;
}

// CredibilityView is the secondary-band middle panel.
export interface CredibilityView {
  guardrail_active: boolean; // architectural invariant: always true
  baseline_multiplier_m: number; // max M across window; 1.0 if none
  feature_bars: FeatureBar[] | null;
  calibration: CalibView;
  baseline_gates: BaselineGateView;
}

// IntelKPIView is the attacker-cost KPI card.
export interface IntelKPIView {
  tokens_burned: number;
  time_imposed_sec: number;
  requests_absorbed: number;
  bytes_served: number;
  defender_cost_label: string; // "flat" (structural)
}

// ReconEvent is one row in the recon early-warning feed.
export interface ReconEvent {
  flow_id_hex: string;
  offset_sec: number; // negative seconds (in the past)
  offset_label: string; // "−m:ss"
  canary_type: string;
  description: string;
  severity: 'recon' | 'surfaced' | string;
}

// FlowFingerprint is the adversary behavioral fingerprint for one flow.
export interface FlowFingerprint {
  flow_id: number;
  flow_id_hex: string; // "0x%x" — deep-link with THIS (flow_id as a JS number loses precision > 2^53)
  ordered_types: string[] | null; // CanaryType sequence in timestamp order (with dupes)
  cadence_sec: number; // median inter-arrival; 0 if < 2 events
  cadence_jitter: number; // MAD of inter-arrivals; 0 if < 3 events
  adjacency_nov: number; // max adjacency_novelty across events
  identity_nov: number; // max identity_novelty across events
  persists_tarpit: boolean; // any event with Sting.TimeHeldSec > threshold
  hash: string; // "fp:%04x·%04x·%04x"
}

// AxisReactionView surfaces the AX2/AX4/AX5 reaction signals — what the attacker DID
// in response to the deception, distinct from the imposed-cost KPI. Counts only,
// deployment-local-only; all zero on a passive-floor window (these axes fire only at
// their floors).
export interface AxisReactionView {
  exploits_observed: number; // AX4: exploits fired at decoys (in-perimeter)
  exposure_signals: number; // AX5: tooling/C2 fingerprints exposed
  poison_reached: number; // AX2: deepest fabricated-environment stage walked
  poison_class: string; // AX2: class of that deepest stage ("" if none)
}

// CrossCustomerView is the D6 consumer-side signal: network-confirmed patterns this
// deployment has loaded into detection, the k distinct-enrolled-scopes provenance, and
// whether the current adversary flow matches one (the engine's real matcher).
export interface CrossCustomerView {
  consuming: number; // # network-confirmed patterns loaded into detection
  threshold: number; // k distinct ENROLLED scopes a pattern needed to cross
  flow_id: number; // current adversary flow evaluated (0 = none)
  flow_id_hex: string;
  similarity: number; // best similarity of that flow to a consumed pattern [0,1]
  matched: boolean; // similarity >= threshold
}

// AdversaryIntelView is the secondary-band right panel (three facets).
export interface AdversaryIntelView {
  kpi: IntelKPIView;
  recon_feed: ReconEvent[] | null; // T1, newest first, max 10
  fingerprint?: FlowFingerprint | null; // nil if no current flow (json: omitempty)
  reactions: AxisReactionView; // AX2/AX4/AX5 deception-reaction signals
  cross_customer: CrossCustomerView; // D6: network-confirmed patterns consumed + current-flow match
}

// Overview is the complete JSON payload served by GET /api/overview and pushed
// over GET /api/stream.
export interface Overview {
  // Topbar pills.
  env: string;
  scope: string;
  at: string; // RFC3339 timestamp
  tap_reachable: boolean;
  calibration: CalibView;
  baseline_live: boolean;

  // Hero left: live escalation + tier ladder.
  escalation: EscalationView;

  // Hero right: attacker cost.
  attacker_cost: AttackerCostView;

  // Secondary band.
  kernel_containment: KernelContainmentView;
  credibility: CredibilityView;
  adversary_intel: AdversaryIntelView;

  // M9 live cost meter (the attacker's real, ground-truth Anthropic burn).
  real_attack_cost: RealAttackCostView;

  // The current attacker flow's legible arc (recon → escalation → disengage).
  journey: JourneyView;
}

// JourneyMilestone is one beat in the attacker's arc. axes_firing lists the OVERLAPPING
// attrition axes active at a containment/jail crossing (never a partition).
export interface JourneyMilestone {
  offset_label: string; // "−m:ss"
  phase: string; // "recon" | "contained" | "jailed" | "disengaged"
  tier: number;
  title: string;
  detail?: string;
  axes_firing?: string[];
}

// JourneyView is the current flow's ordered arc; present=false when there is no flow.
export interface JourneyView {
  present: boolean;
  flow_id_hex: string;
  milestones: JourneyMilestone[];
  latest?: JourneyMilestone;
}

// ============================================================================
// Interactive console drill-down types — mirror internal/dashboard/backend/
// views/drilldown.go 1:1 (snake_case). Timestamps are RFC3339 strings.
// A "flow" here is a SESSION: a cookie split on idle gaps (decision E), so
// session_index/session_count expose cookie reuse ("session 2 of 3").
// ============================================================================

export interface TouchEvent {
  timestamp: string;
  canary_type: string;
  tier: number;
  verdict: string;
  score: number; // 0 = pre-Score event — render "—"
  m: number; // M for THIS touch; 1.0 if none
  time_held_sec: number;
  bytes_served: number;
  requests: number;
  token_cost: number;
  mechanism: string; // "" → "kernel-enforced · cost not attributed"
}

export interface MContribution {
  feature: string;
  raw_value: number;
  capped: number;
  label: string;
}

export interface MBreakdown {
  m: number;
  contributions: MContribution[];
  gate_note: string;
}

export interface FlowDetail {
  flow_id_hex: string;
  flow_id: number;
  session_start: string;
  session_index: number;
  session_count: number;
  touch_count: number;
  peak_tier: number;
  verdict: string;
  score: number; // 0 = pre-Score event — render "—"
  first_seen: string;
  last_seen: string;
  timeline: TouchEvent[];
  fingerprint?: FlowFingerprint | null;
  m_breakdown?: MBreakdown | null;
  spark_series: number[];
}

export interface FlowCost {
  time_held_sec: number;
  bytes_served: number;
  requests: number;
  token_cost: number;
}

export interface FlowRow {
  flow_id_hex: string;
  flow_id: number;
  session_start: string;
  session_index: number;
  session_count: number;
  peak_tier: number;
  verdict: string;
  touch_count: number;
  score: number; // 0 = pre-Score event — render "—"
  base_m: number;
  total_cost: FlowCost;
  first_seen: string;
  last_seen: string;
}

export interface FlowsList {
  flows: FlowRow[];
  total_count: number;
  filtered: number;
}

export interface MechanismCost {
  mechanism: string;
  event_count: number;
  time_held_sec: number;
  bytes_served: number;
  requests: number;
  token_cost: number;
}

export interface CostBucket {
  bucket_start: string;
  time_held_sec: number;
  token_cost: number;
  event_count: number;
}

export interface CostBreakdown {
  total: FlowCost;
  by_flow: FlowRow[];
  by_mechanism: MechanismCost[];
  time_series: CostBucket[];
  bucket_sec: number;
  engagement: EngagementView; // the engagement contest (median/p90/longest + disengage split)
  reactions: AxisReactionView; // AX2/AX4/AX5 deception-reaction signals
}

export interface ReconRow {
  flow_id_hex: string;
  flow_id: number;
  session_start: string; // RFC3339; the exact session this T1 belongs to (deep-link &session=)
  timestamp: string;
  offset_label: string;
  canary_type: string;
  severity: 'recon' | 'surfaced' | string;
  description: string;
  escalated: boolean;
  escalated_tier: number;
}

export interface ReconTimeline {
  rows: ReconRow[];
  total_recon: number;
}
