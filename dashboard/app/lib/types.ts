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

// KillSwitchView is the deployment-wide enforcement kill-switch posture (B1/B2).
// 1:1 mirror of internal/sting/killswitch/killswitch.go:47-63 (Status struct) — the
// SOURCE OF TRUTH for these json tags. The wire key everywhere is `kill_switch`.
// READ-ONLY on the dashboard: rendered as a posture indicator, never controlled
// here (engage/revive is canaryctl + the token-gated admin endpoint).
//
// AUTHORITATIVE BIT: gate purely on `engaged`. A timed engagement past its expiry
// reports engaged=false on the very next tap poll while operator/reason may still
// echo the last snapshot — never infer "engaged" from the presence of those fields.
//
// ZERO-TIME SENTINEL: engaged_at/expires_at carry Go `omitempty` tags but are
// time.Time STRUCTS, so encoding/json does NOT actually omit them — they serialize
// as '0001-01-01T00:00:00Z' when unset. They are marked optional below for safety,
// but in practice arrive as the year-0001 sentinel string. Treat that sentinel as
// 'not set' (engaged_at) / 'indefinite' (expires_at), never as a real timestamp.
export interface KillSwitchView {
  engaged: boolean; // authoritative halt bit — always present, never omitted
  operator?: string; // who disarmed enforcement (X-Operator; "operator" default)
  reason?: string; // free-text reason for the halt
  engaged_at?: string; // RFC3339; '0001-01-01T00:00:00Z' sentinel == not set
  expires_at?: string; // RFC3339; '0001-01-01T00:00:00Z' sentinel == INDEFINITE (until revived)
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

// FlowFunnelView is the DISTINCT-flow funnel by CUMULATIVE REACH: each flow is
// counted in EVERY tier it reached, within this window — not once at its peak. So a
// jailed flow is ALSO counted in contained (it reached both). Distinct from the
// per-event tier ladder: these are sessions, not events. The › arrows in
// observed › decoy-touched › contained › jailed mean "reached at least".
export interface FlowFunnelView {
  decoy_touched: number; // distinct flows that reached at least a decoy touch (Tier 1) this window (== FlowsList.total_count)
  contained: number; // distinct flows that reached tier >= 2 this window
  jailed: number; // distinct flows that reached tier >= 3 this window (also counted in contained)
  distinct_active: number; // distinct flows currently active this window
}

// EscalationView carries the current attacker flow + tier ladder + the distinct-flow
// funnel. On the current wall: escalation.flow → LiveSpotlight (Row 4 strip);
// flow_funnel/funnel_caption → FleetSafety (Row 2). The tier_ladder is rendered by
// TierLadder where embedded.
export interface EscalationView {
  flow?: FlowView | null; // nil if none (json: omitempty)
  tier_ladder: [TierStep, TierStep, TierStep, TierStep]; // always length 4 (T0..T3)
  ladder_denominator: number;
  ladder_caption: string;
  flow_funnel: FlowFunnelView; // the distinct-flow funnel (sessions, not events)
  funnel_caption: string; // the verbatim two-rails caption
  attacker_flows?: FlowRow[]; // capped ranked armed-flow cards for the live-attacker strip
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

// AttackerCostView powers the /cost page (CostView); it is no longer a hero panel on
// the wall. Framing (AX3): the headline is OPPORTUNITY COST on a velocity-dependent
// adversary — imposed time + engagement — not a dollar bill. tokens_burned is a
// qualified PROXY, demoted below time.
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

// ReconLiveFlow is one currently-live flow that looks anomalous from the learned
// baseline but touched NO canary — surfaced as observe-only early-warning.
export interface ReconLiveFlow {
  flow_id: number;
  flow_id_hex: string;
  novelty: number; // strongest baseline-deviation dim [0,1]
  top_signal: string; // which dim drove it ("new identity" / "new adjacency" / …)
  bytes: number; // coarse traffic (ingress+egress)
  duration_sec: number; // observed lifetime (coarse)
  severity: 'recon' | 'surfaced' | string;
}

// ReconLiveView is the OBSERVE-ONLY recon surface: flows anomalous-from-baseline
// that touched no canary. Its purpose is to make RESTRAINT visible — we see it,
// we don't act (Rule 8: only a canary touch arms a response).
export interface ReconLiveView {
  active: boolean;
  count: number;
  flows: ReconLiveFlow[] | null;
  note: string;
}

// BystanderFlow is one live non-actioned workload still serving (coarse traffic
// only) — shown to prove flow-precise containment: same host, untouched, while an
// attacker socket is kernel-jailed.
export interface BystanderFlow {
  flow_id: number;
  flow_id_hex: string;
  bytes: number;
  duration_sec: number;
}

// BystanderView is the dashboard-native "contain the flow, not the host" proof.
export interface BystanderView {
  active: boolean;
  count: number;
  flows: BystanderFlow[] | null;
  note: string;
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
  simulated: boolean; // consumed patterns are SIMULATED peers (demo "art of the possible")
}

// AdversaryIntelView is the secondary-band right panel (three facets).
export interface AdversaryIntelView {
  kpi: IntelKPIView;
  recon_feed: ReconEvent[] | null; // T1, newest first, max 10
  fingerprint?: FlowFingerprint | null; // nil if no current flow (json: omitempty)
  reactions: AxisReactionView; // AX2/AX4/AX5 deception-reaction signals
  cross_customer: CrossCustomerView; // D6: network-confirmed patterns consumed + current-flow match
}

// ArmedFlowsView is the fleet-band "distinct armed flows" snapshot: distinct
// sessions THIS window that crossed the response threshold (a decoy touch armed a
// response). A snapshot count, not cumulative — cookies recycle, so these are
// sessions, not unique attackers.
export interface ArmedFlowsView {
  distinct_count: number; // distinct armed sessions this window
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

  // Deployment-wide enforcement kill-switch posture (read-only display field).
  // Out-of-band on the dashboard JSON view only — never on the gRPC verdict
  // contract. Gate all UI purely on kill_switch.engaged.
  kill_switch: KillSwitchView;

  // Data-gated simulated disclosure: the whole demo is simdriver traffic, not a
  // live customer fleet. Gates the ⚠ sim-badge on the wall.
  simulated: boolean;

  // Fleet band: distinct armed flows this window (snapshot, not cumulative).
  armed_flows: ArmedFlowsView;

  // escalation.flow → LiveSpotlight (Row 4 strip); escalation.flow_funnel/
  // funnel_caption → FleetSafety (Row 2).
  escalation: EscalationView;

  // Powers the /cost page (CostView); no longer a hero panel on the wall.
  attacker_cost: AttackerCostView;

  // kernel_containment + bystanders → Row 3; credibility → /credibility page.
  kernel_containment: KernelContainmentView;
  credibility: CredibilityView;
  adversary_intel: AdversaryIntelView;

  // M9 live cost meter (the attacker's real, ground-truth Anthropic burn).
  real_attack_cost: RealAttackCostView;

  // The current attacker flow's legible arc (recon → escalation → disengage).
  journey: JourneyView;

  // Observe-only recon: anomalous-from-baseline flows that touched no canary.
  // The "we see it and choose not to act" surface (Rule 8 made visible).
  recon_live: ReconLiveView;

  // Workloads still serving (not actioned) on the same host while an attacker is
  // kernel-jailed — the dashboard-native flow-precision proof.
  bystanders: BystanderView;
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
  spark_series?: number[]; // only populated for escalation.attacker_flows cards (per-flow climb); the /flows table omits it (Go omitempty)
}

export interface FlowsList {
  flows: FlowRow[] | null; // Go nil slice marshals to JSON null on an empty/filtered window
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

// ============================================================================
// F1 learned east-west topology — GET /api/topology (the dashboard backend's
// validated mirror of the tap's GET /raw/topology). Mirrors
// internal/dashboard/backend/views/topology.go 1:1 (snake_case).
//
// HONESTY (load-bearing — render the caption persistently): the graph SHAPE,
// edges, and volumes are REAL observed traffic; only the node NAMES are
// operator-registry metadata (staged_labels). The engine never natively knows
// service names (it knows hashed adjacency), and the map NEVER auto-acts (Rule 8).
// ============================================================================

// TopologyNode is one identity in the learned graph. kind is the resolver token.
export interface TopologyNode {
  id: string;
  label: string; // operator-declared name, SPIFFE-derived name, or (on a miss) the IP
  kind: 'service' | 'caller' | 'decoy' | 'external' | 'unknown' | string;
}

// TopologyEdge is one directed adjacency. class distinguishes a learned baseline
// edge from a live overlay and from the highlighted source->decoy touch edge (the
// only edge that crosses into the decoy ring). first_seen/last_seen are RFC3339.
export interface TopologyEdge {
  src_id: string;
  dst_id: string;
  port: number;
  proto: string; // "tcp" for learned edges; "decoy" for a touch edge
  flow_count: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  class: 'learned' | 'live' | 'decoy_touch' | string;
}

// TopologyView is the GET /api/topology payload. staged_labels drives the
// persistent honesty caption (which the backend also pre-renders into `caption`).
export interface TopologyView {
  scope: string;
  staged_labels: boolean; // node NAMES came from an operator registry (vs IP fallback)
  caption: string; // the persistent honesty fence to render verbatim
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

// ============================================================================
// F2 — deviant hunting log (GET /api/deviants). Flows that DEVIATED from the
// learned baseline but touched NO canary, captured for threat-hunting.
//
// HONESTY (load-bearing — render the caption persistently): these flows are
// logged for hunting, NEVER actioned and NEVER "confirmed adversaries" (Rule 8 —
// only a canary touch arms a response). The identities are operator-registry
// metadata where named; an UNKNOWN/raw-IP end is the unfamiliar-identity signal.
// The raw addresses are local to the deployment and never cross a boundary
// (Rule 9). The ⚠ simulated note reflects the synthetic-peer demo posture; the
// deviant flows themselves are real local observations.
// ============================================================================

// DeviantEndpoint is one resolved end of a deviant flow.
export interface DeviantEndpoint {
  label: string; // operator-declared name, SPIFFE-derived name, or (on a miss) the IP
  kind: 'service' | 'caller' | 'decoy' | 'external' | 'unknown' | string;
  addr: string; // raw IP string (local-rich; never crosses a boundary)
  port: number; // 0 on the src (initiator), the reached service port on the dst
}

// DeviantRow is one ranked deviant flow: the fingerprint (src -> dst with identity),
// the 5 baseline novelty dims, the peak dim that made it look anomalous, the
// recurrence count, and the wall-clock window. NOTHING here is a verdict.
export interface DeviantRow {
  src: DeviantEndpoint;
  dst: DeviantEndpoint;
  // src_familiarity keys on the SRC identity: 'unfamiliar' (SRC resolved UNKNOWN — a
  // fresh careful-mover / recon lead, ranked first) | 'known' (resolved to a declared
  // caller/external). Mesh-internal service SRCs are filtered out of this view.
  src_familiarity: 'unfamiliar' | 'known' | string;
  identity_novelty: number; // [0,1]
  adjacency_novelty: number;
  port_novelty: number;
  volume_deviation: number;
  cadence_deviation: number;
  peak_dim: string; // the headline "why it looked anomalous" ("new identity" / …)
  peak_value: number; // magnitude of the peak dim [0,1]
  hit_count: number; // approximate recurrence ("seen ~N times")
  first_seen: string; // RFC3339
  last_seen: string; // RFC3339
  score: number; // engine suspicion score at capture (0 on the fold seam)
  // key is the canonical deviant RECURRENCE KEY (the deviantKey() bytes, hex-encoded
  // on the wire). It is the stable join identity AND the `canaryctl deviant -key`
  // argument; the DeviantFlowRecord itself is mutated/destroyed/re-created, so this is
  // the only durable handle. Read-only on the dashboard.
  key: string;
  // triage_state is the operator-applied OVERLAY state (a display-only record keyed by
  // (scope, key), NEVER on the verdict path — suppress/ack changes only what a human
  // SEES, never detection/scoring/arming). "" (normal) | "acked" (seen-but-keep-showing,
  // badged + demoted) | "suppressed" (known-benign, hidden from the default list but
  // still counted in the summary and viewable behind the toggle). The dashboard does
  // NOT write this — suppress/ack happen via canaryctl / the operator-admin surface.
  triage_state: '' | 'acked' | 'suppressed' | string;
}

// DeviantSummary is the volume/triage roll-up over the kept-after-shapeless set. It is
// what keeps the page HONEST: suppressed rows are hidden from the default list but the
// `suppressed` count discloses they exist (operator-hidden-but-counted, not dropped).
export interface DeviantSummary {
  total: number; // all kept-after-shapeless deviants (shown + suppressed)
  shown: number; // len(rows) — the default-visible set (acked included)
  suppressed: number; // count hidden by default (operator-suppressed, known-benign)
  acked: number; // count badged + demoted but still shown
  per_day: number; // deviant recurrence rate over the wall-clock span (deviants/day)
}

// DeviantsView is the GET /api/deviants payload. caption is the persistent honesty
// fence; simulated_note is set only when simulated is true. rows is the DEFAULT visible
// set (suppressed excluded, acked included-but-demoted); suppressed carries the hidden
// rows inline so the view-suppressed toggle needs no second fetch; summary is the
// volume/triage roll-up rendered as the chip.
export interface DeviantsView {
  scope: string;
  staged_labels: boolean;
  simulated: boolean;
  caption: string; // the persistent honesty fence to render verbatim
  simulated_note: string; // ⚠ note when simulated; "" otherwise
  rows: DeviantRow[];
  suppressed: DeviantRow[]; // hidden-by-default rows (triage_state==='suppressed')
  summary: DeviantSummary;
}
