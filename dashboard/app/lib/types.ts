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

// AttackerCostView is the hero-right panel.
export interface AttackerCostView {
  active_response_count: number; // T2+T3
  jailed: number; // T3
  counter_attacked: number; // T2
  time_imposed_sec: number;
  tokens_burned: number;
  requests_absorbed: number;
  bytes_served: number;
  attacker_cost_fraction: number; // active / total interactions
  defender_cost_flat: boolean; // structural invariant: always true
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
  ordered_types: string[] | null; // CanaryType sequence in timestamp order (with dupes)
  cadence_sec: number; // median inter-arrival; 0 if < 2 events
  cadence_jitter: number; // MAD of inter-arrivals; 0 if < 3 events
  adjacency_nov: number; // max adjacency_novelty across events
  identity_nov: number; // max identity_novelty across events
  persists_tarpit: boolean; // any event with Sting.TimeHeldSec > threshold
  hash: string; // "fp:%04x·%04x·%04x"
}

// AdversaryIntelView is the secondary-band right panel (three facets).
export interface AdversaryIntelView {
  kpi: IntelKPIView;
  recon_feed: ReconEvent[] | null; // T1, newest first, max 10
  fingerprint?: FlowFingerprint | null; // nil if no current flow (json: omitempty)
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
}
