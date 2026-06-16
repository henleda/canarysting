// DEV / VISUAL-VERIFICATION ONLY. This is the static, prototype-matching Overview
// used to verify pixel fidelity against dashboard/design/prototype.html. It is
// rendered ONLY when process.env.NEXT_PUBLIC_FIXTURE === '1' (see page.tsx).
// It is NEVER the production render path — production always uses useOverview().
// Do not import this from any component or the live data layer.

import type { Overview } from './types';

// Spark series modeled on the prototype's generated shape (48 bars, rising at
// the end), normalized to 0..1 — matches FlowView.spark_series semantics.
const sparkSeries: number[] = Array.from({ length: 48 }, (_, i) => {
  const v = 10 + Math.abs(Math.sin(i / 3.2)) * 55 + (i > 34 ? (i - 34) * 2.4 : 0);
  return Math.min(1, v / 100);
});

export const fixtureOverview: Overview = {
  env: 'staged-range · aws',
  scope: 'm7-window',
  at: '2026-06-09T00:00:00Z',
  tap_reachable: true,
  baseline_live: true,
  // simulated:true keeps the ⚠ sim-badge always visible on the fixture — the whole
  // demo is simdriver traffic, never a live customer fleet (data-gated disclosure).
  simulated: true,
  calibration: { calibrated: true, evidence_seen: 50, evidence_floor: 50 },

  // FIXTURE-ONLY sample (NEXT_PUBLIC_FIXTURE=1) — an ENGAGED kill-switch so the
  // banner + topbar pill render in the pixel-fidelity check. In production this
  // comes from the live tap; the normal armed posture is engaged:false (quiet).
  // engaged_at/expires_at are real timestamps here (a 1-hour timed engagement);
  // set expires_at to '0001-01-01T00:00:00Z' to exercise the INDEFINITE path.
  kill_switch: {
    engaged: true,
    operator: 'ir-oncall',
    reason: 'IR drill',
    engaged_at: '2026-06-09T00:00:00Z',
    expires_at: '2026-06-09T01:00:00Z',
  },

  // Fleet band: distinct armed flows this window (snapshot, not cumulative).
  // Internally consistent with the cumulative-reach invariants: decoy_touched ==
  // distinct_count == distinct_active == fixtureFlowsList.total_count (3 = rows reaching
  // tier >= 1).
  armed_flows: { distinct_count: 3 },

  escalation: {
    flow: {
      flow_id: 0x118,
      flow_id_hex: '0x118',
      source_label: '',
      tier: 3,
      verdict: 'jail',
      score: 5.0,
      base_m: 2.5,
      canary_touches: ['.aws/credentials', '.env', 'backup/db.sql', 'internal/buckets', 'admin/metrics'],
      touch_count: 14,
      last_seen: '2026-06-09T00:00:00Z',
      spark_series: sparkSeries,
    },
    ladder_denominator: 381,
    ladder_caption:
      'Two windows, not one denominator: T0 = cumulative observed-normal traffic (eBPF folds since start, pinned to the full bar); T1-3 fractions are of the attacker subtotal within the events window only. The two are intentionally not mixed.',
    // The DISTINCT-flow funnel by CUMULATIVE REACH: each flow counted in every
    // stage it reached, within this window (sessions, not events). decoy_touched ==
    // distinct_count == distinct_active == fixtureFlowsList.total_count (3 = rows with
    // peak >= 1); contained == rows with peak >= 2 (2: the T2 + T3 rows); jailed ==
    // rows with peak >= 3 (1 = kernel_containment.jailed_flows length). So
    // /flows?min_tier=2 shows 2 rows and /flows?tier=3 shows 1.
    flow_funnel: { decoy_touched: 3, contained: 2, jailed: 1, distinct_active: 3 },
    funnel_caption:
      'Two rails, not one denominator: T0 observed is cumulative since engine start (its own rail, never summed); the funnel stages count DISTINCT flows that reached at least that tier within this window — a flow is counted in each stage it reached, not per event.',
    tier_ladder: [
      {
        tier: 0,
        label: 'Observe',
        description: 'normal traffic · eBPF',
        count: 312,
        fraction: 1.0,
        has_response: false,
        resp_label: '',
        is_active: false,
      },
      {
        tier: 1,
        label: 'Tag',
        description: 'suspicious · tagged',
        count: 47,
        fraction: 47 / 69,
        has_response: false,
        resp_label: '',
        is_active: false,
      },
      {
        tier: 2,
        label: 'Contain',
        description: 'contained · attrition',
        count: 18,
        fraction: 18 / 69,
        has_response: true,
        resp_label: 'counter-attacked',
        is_active: false,
      },
      {
        tier: 3,
        label: 'Jail',
        description: 'kernel-jailed',
        count: 4,
        fraction: 4 / 69,
        has_response: true,
        resp_label: 'kernel-jailed',
        is_active: true,
      },
    ],
  },

  attacker_cost: {
    active_response_count: 22,
    jailed: 4,
    counter_attacked: 18,
    time_imposed_sec: 252, // 4:12
    tokens_burned: 38420, // 38.4k
    requests_absorbed: 1204,
    bytes_served: 12163481, // ~11.6 MiB
    attacker_cost_fraction: 0.0019, // 0.19%
    defender_cost_flat: true,
    // OVERLAPPING per-axis subtotals — velocity+poison sum to more than the flat
    // time_imposed because a flow lands on every axis it triggers (fake_tree is both).
    per_axis: [
      { axis: 'velocity', time_sec: 252, tokens: 9100, count: 22 },
      { axis: 'poison', time_sec: 188, tokens: 21300, count: 17 },
      { axis: 'opportunity', time_sec: 96, tokens: 30100, count: 9 },
    ],
    engagement: {
      median_sec: 6.4,
      p90_sec: 8.0,
      longest_sec: 8.0,
      disengaged_early: 7,
      generator_exhausted: 2,
      defender_capped: 13,
      disengaged_early_fraction: 0.318,
    },
  },

  kernel_containment: {
    jailed_flows: [{ flow_id_hex: '0x118', tier: 3, verdict: 'jail' }],
    ok_flows: [
      { flow_id_hex: '0x0a4', tier: 1, verdict: 'tag' },
      { flow_id_hex: '0x0b1', tier: 1, verdict: 'tag' },
    ],
  },

  credibility: {
    guardrail_active: true,
    baseline_multiplier_m: 2.5,
    feature_bars: [
      { name: 'adjacency nov.', value: 1.0 },
      { name: 'identity nov.', value: 1.0 },
      { name: 'volume dev.', value: 0.62 },
      { name: 'cadence dev.', value: 0.31 },
    ],
    calibration: { calibrated: true, evidence_seen: 50, evidence_floor: 50 },
    baseline_gates: { live: true, bucket_sufficient: true, calibrated: true },
  },

  adversary_intel: {
    kpi: {
      tokens_burned: 38420,
      time_imposed_sec: 252,
      requests_absorbed: 1204,
      bytes_served: 12163481,
      defender_cost_label: 'flat',
    },
    recon_feed: [
      {
        flow_id_hex: '0x118',
        offset_sec: -362,
        offset_label: '−6:02',
        canary_type: 'internal/buckets',
        description: 'quiet probe · internal/buckets',
        severity: 'recon',
      },
      {
        flow_id_hex: '0x118',
        offset_sec: -248,
        offset_label: '−4:08',
        canary_type: 'api',
        description: 'new adjacency · 0x118→api',
        severity: 'surfaced',
      },
      {
        flow_id_hex: '0x118',
        offset_sec: -175,
        offset_label: '−2:55',
        canary_type: 'admin/metrics',
        description: 'cluster · 0x118 repeated probing',
        severity: 'surfaced',
      },
    ],
    fingerprint: {
      flow_id: 0x118,
      flow_id_hex: '0x118',
      ordered_types: ['.aws/credentials', '.env', 'backup/db.sql'],
      cadence_sec: 12,
      cadence_jitter: 1.2,
      adjacency_nov: 1.0,
      identity_nov: 1.0,
      persists_tarpit: true,
      hash: 'fp:a3f1·9c08·b27d',
    },
    // AX2/AX4/AX5 reaction signals (demo posture: the attacker walked all the way into
    // the fabricated env, fired real exploits at decoys, and exposed tooling).
    reactions: {
      exploits_observed: 6,
      exposure_signals: 11,
      poison_reached: 3,
      poison_class: 'success',
    },
    // D6 cross-customer: this deployment has consumed a network-confirmed pattern, and
    // the current adversary flow matches it (the engine's real matcher).
    cross_customer: {
      consuming: 1,
      threshold: 3,
      flow_id: 0x118,
      flow_id_hex: '0x118',
      similarity: 0.86,
      matched: true,
      simulated: true,
    },
  },

  // M9 live cost meter (fixture: a run mid-burn at ~$2.31 of a $5 cap).
  real_attack_cost: {
    present: true,
    active: true,
    model: 'claude-opus-4-8',
    input_tokens: 312_400,
    output_tokens: 41_220,
    cache_read_tokens: 188_000,
    cache_creation_tokens: 540,
    total_tokens: 542_160,
    usd: 2.31,
    hard_cap_usd: 5.0,
    cap_fraction: 0.462,
  },
  journey: {
    present: true,
    flow_id_hex: '0x5713c0ffee',
    milestones: [
      { offset_label: '−2:40', phase: 'recon', tier: 1, title: 'Decoy touched — recon surfaced (not yet a verdict)', detail: '.env' },
      { offset_label: '−2:05', phase: 'contained', tier: 2, title: 'Contained — inline attrition begins', detail: 'velocity + poison', axes_firing: ['velocity', 'poison'] },
      { offset_label: '−1:12', phase: 'jailed', tier: 3, title: 'Jailed in-kernel — socket-cookie precise', detail: 'velocity + poison + opportunity + exploit + exposure', axes_firing: ['velocity', 'poison', 'opportunity', 'exploit', 'exposure'] },
      { offset_label: '−0:48', phase: 'disengaged', tier: 3, title: 'Attacker disengaged', detail: 'gave up before any defender bound — the engagement signal' },
    ],
    latest: { offset_label: '−0:48', phase: 'disengaged', tier: 3, title: 'Attacker disengaged', detail: 'gave up before any defender bound — the engagement signal' },
  },
  recon_live: {
    active: true,
    count: 2,
    flows: [
      { flow_id: 0x4a2c, flow_id_hex: '0x4a2c', novelty: 0.92, top_signal: 'new identity', bytes: 1840, duration_sec: 14, severity: 'surfaced' },
      { flow_id: 0x51d0, flow_id_hex: '0x51d0', novelty: 0.61, top_signal: 'new adjacency', bytes: 640, duration_sec: 6, severity: 'recon' },
    ],
    note: 'Surfaced, not actioned — these flows look anomalous from the learned baseline; none has armed a response (only a decoy touch that crosses the threshold can — Rule 8).',
  },
  bystanders: {
    active: true,
    count: 3,
    flows: [
      { flow_id: 0x101, flow_id_hex: '0x101', bytes: 124000, duration_sec: 312 },
      { flow_id: 0x102, flow_id_hex: '0x102', bytes: 88400, duration_sec: 268 },
      { flow_id: 0x103, flow_id_hex: '0x103', bytes: 156200, duration_sec: 401 },
    ],
    note: "Same host, still serving — the kernel jail dropped only the attacker's socket; every other flow here is untouched by the response and keeps returning traffic. We contain the flow, not the host.",
  },
};

// ---- Interactive console drill-down fixtures (NEXT_PUBLIC_FIXTURE=1) ----
import type { FlowDetail, FlowsList, CostBreakdown, ReconTimeline } from './types';

export const fixtureFlowDetail: FlowDetail = {
  flow_id_hex: '0x118',
  flow_id: 0x118,
  session_start: '2026-06-09T13:54:00Z',
  session_index: 2,
  session_count: 3,
  touch_count: 5,
  peak_tier: 3,
  verdict: 'jail',
  score: 5.0,
  first_seen: '2026-06-09T13:54:00Z',
  last_seen: '2026-06-09T13:58:12Z',
  timeline: [
    { timestamp: '2026-06-09T13:54:00Z', canary_type: '.env', tier: 1, verdict: 'tag', score: 1, m: 1.2, time_held_sec: 0, bytes_served: 0, requests: 0, token_cost: 0, mechanism: '' },
    { timestamp: '2026-06-09T13:55:10Z', canary_type: '.aws/credentials', tier: 1, verdict: 'tag', score: 2, m: 1.8, time_held_sec: 0, bytes_served: 0, requests: 0, token_cost: 0, mechanism: '' },
    { timestamp: '2026-06-09T13:56:30Z', canary_type: 'backup/db.sql', tier: 2, verdict: 'contain', score: 3, m: 2.4, time_held_sec: 8, bytes_served: 8836, requests: 1, token_cost: 2209, mechanism: 'fake_tree' },
    { timestamp: '2026-06-09T13:57:20Z', canary_type: 'internal/buckets', tier: 2, verdict: 'contain', score: 4, m: 2.6, time_held_sec: 8, bytes_served: 8836, requests: 1, token_cost: 2209, mechanism: 'fake_tree' },
    { timestamp: '2026-06-09T13:58:12Z', canary_type: 'admin/metrics', tier: 3, verdict: 'jail', score: 5, m: 2.6, time_held_sec: 0, bytes_served: 0, requests: 0, token_cost: 0, mechanism: '' },
  ],
  fingerprint: {
    flow_id: 0x118,
    flow_id_hex: '0x118',
    ordered_types: ['.env', '.aws/credentials', 'backup/db.sql', 'internal/buckets', 'admin/metrics'],
    cadence_sec: 70,
    cadence_jitter: 8,
    adjacency_nov: 0.9,
    identity_nov: 0.7,
    persists_tarpit: true,
    hash: 'fp:a3f1·9c08·b27d',
  },
  m_breakdown: {
    m: 2.6,
    contributions: [
      { feature: 'adjacency_novelty', raw_value: 0.9, capped: 0.9, label: 'adjacency nov.' },
      { feature: 'identity_novelty', raw_value: 0.7, capped: 0.7, label: 'identity nov.' },
      { feature: 'port_novelty', raw_value: 0.2, capped: 0.2, label: 'port nov.' },
      { feature: 'volume_deviation', raw_value: 0.5, capped: 0.5, label: 'volume dev.' },
      { feature: 'cadence_deviation', raw_value: 0.3, capped: 0.3, label: 'cadence dev.' },
    ],
    gate_note: 'M derived from peak event · DefaultParams',
  },
  spark_series: [0.2, 0.4, 0.6, 0.8, 1.0],
};

export const fixtureFlowsList: FlowsList = {
  total_count: 3,
  filtered: 3,
  flows: [
    { flow_id_hex: '0x118', flow_id: 0x118, session_start: '2026-06-09T13:54:00Z', session_index: 2, session_count: 3, peak_tier: 3, verdict: 'jail', touch_count: 5, score: 5, base_m: 2.6, total_cost: { time_held_sec: 16, bytes_served: 17672, requests: 2, token_cost: 4418 }, first_seen: '2026-06-09T13:54:00Z', last_seen: '2026-06-09T13:58:12Z' },
    { flow_id_hex: '0x2a', flow_id: 0x2a, session_start: '2026-06-09T13:40:00Z', session_index: 1, session_count: 1, peak_tier: 2, verdict: 'contain', touch_count: 3, score: 3, base_m: 1.9, total_cost: { time_held_sec: 8, bytes_served: 8054, requests: 1, token_cost: 2014 }, first_seen: '2026-06-09T13:40:00Z', last_seen: '2026-06-09T13:41:30Z' },
    { flow_id_hex: '0x7c', flow_id: 0x7c, session_start: '2026-06-09T13:30:00Z', session_index: 1, session_count: 1, peak_tier: 1, verdict: 'tag', touch_count: 1, score: 1, base_m: 1.0, total_cost: { time_held_sec: 0, bytes_served: 0, requests: 0, token_cost: 0 }, first_seen: '2026-06-09T13:30:00Z', last_seen: '2026-06-09T13:30:00Z' },
  ],
};

// Feed the fixture's live-attacker strip the existing 3 ranked armed-flow rows so
// the strip render path shows cards (the 0x118 row dedups against escalation.flow).
fixtureOverview.escalation.attacker_flows = fixtureFlowsList.flows ?? [];

export const fixtureCostBreakdown: CostBreakdown = {
  total: { time_held_sec: 24, bytes_served: 25726, requests: 3, token_cost: 6432 },
  by_flow: (fixtureFlowsList.flows ?? []).filter((f) => f.total_cost.time_held_sec > 0),
  by_mechanism: [
    { mechanism: 'fake_tree', event_count: 3, time_held_sec: 24, bytes_served: 25726, requests: 3, token_cost: 6432 },
  ],
  time_series: Array.from({ length: 24 }, (_, i) => ({
    bucket_start: `2026-06-09T13:${String(i % 60).padStart(2, '0')}:00Z`,
    time_held_sec: i % 5 === 0 ? 8 : 0,
    token_cost: i % 5 === 0 ? 2000 : 0,
    event_count: i % 5 === 0 ? 1 : 0,
  })),
  bucket_sec: 150,
  engagement: {
    median_sec: 6.4,
    p90_sec: 8.0,
    longest_sec: 8.0,
    disengaged_early: 7,
    generator_exhausted: 2,
    defender_capped: 13,
    disengaged_early_fraction: 0.318,
  },
  reactions: { exploits_observed: 6, exposure_signals: 11, poison_reached: 3, poison_class: 'success' },
};

// ---- F1 learned topology fixture (NEXT_PUBLIC_FIXTURE=1) ----
// The DECLARED east-west fabric of the M7 mesh, matched to the new LIVE shape so
// NEXT_PUBLIC_FIXTURE renders the same thing /api/topology serves. The distinct-
// identity scheme (each service LISTENs on AND dials from its own 127.0.1.<K>; the
// ingress Envoy originates 127.0.2.1) means the tap names each endpoint by IDENTITY
// and coalesces a service's egress/listen sides into ONE node. So node ids are the
// tap's IDENTITY-keyed scheme 'id:<kind>:<label>' for named nodes (services,
// callers, the ingress-gateway), and the tap's own ids for the decoy ring
// ('decoy:<canary_type>') and the touch source ('touch-src:0x<cookie>').
//
// Shape: named callers -> the ingress-gateway entry point -> frontend, then the
// multi-tier service->service fabric (edge -> app -> service -> data tier, matching
// deploy/m7-window/server-compose.yml), the 5 canary decoys in the negative-space
// ring (zero learned in-edges), and ONE bright source->decoy touch edge (the money
// shot). Only 'learned' + 'decoy_touch' classes — exactly what the slice-3 live
// /api/topology emits (no 'live'/deviant edge until F2). The caller set mirrors the
// simdriver's benign identities + the prober. Names come from the staging operator
// registry (deploy/m7-window/topology-identities.json) — staged_labels.
import type { TopologyView, DeviantsView } from './types';

const TOPO_FIRST = '2026-06-09T13:30:00Z';
const TOPO_LAST = '2026-06-09T13:58:12Z';

export const fixtureTopology: TopologyView = {
  scope: 'm7-window',
  staged_labels: true,
  caption:
    'Declared east-west fabric: edges connect the operator-registry services, callers, and ingress gateway; unresolved management-plane flows are omitted for clarity. Node NAMES come from the operator registry; the engine baseline is hashed and the graph SHAPE/edges are real observed traffic. In production this is drawn from your own service registry, not ours.',
  nodes: [
    // Callers (left column) — named external initiators from the staging registry.
    { id: 'id:caller:reporting-worker', label: 'reporting-worker', kind: 'caller' },
    { id: 'id:caller:batch-client', label: 'batch-client', kind: 'caller' },
    { id: 'id:caller:web-client', label: 'web-client', kind: 'caller' },
    { id: 'id:caller:mobile-gateway', label: 'mobile-gateway', kind: 'caller' },
    { id: 'id:caller:partner-api', label: 'partner-api', kind: 'caller' },
    { id: 'id:caller:ci-runner', label: 'ci-runner', kind: 'caller' },
    { id: 'id:caller:etl-scheduler', label: 'etl-scheduler', kind: 'caller' },
    { id: 'id:caller:support-console', label: 'support-console', kind: 'caller' },
    { id: 'id:caller:ops-dashboard', label: 'ops-dashboard', kind: 'caller' },
    { id: 'id:caller:prober', label: 'prober', kind: 'caller' },
    // The ingress gateway (kind 'external') — the entry point. Both Envoy endpoints
    // (the accept address + the upstream-bind source) coalesce into this one node.
    { id: 'id:external:ingress-gateway', label: 'ingress-gateway', kind: 'external' },
    // Services (middle column) — each named by its distinct identity; the egress
    // and listen sides coalesce, so each appears exactly once.
    { id: 'id:service:frontend', label: 'frontend', kind: 'service' },
    { id: 'id:service:cdn-edge', label: 'cdn-edge', kind: 'service' },
    { id: 'id:service:api', label: 'api', kind: 'service' },
    { id: 'id:service:auth', label: 'auth', kind: 'service' },
    { id: 'id:service:db', label: 'db', kind: 'service' },
    { id: 'id:service:cache', label: 'cache', kind: 'service' },
    { id: 'id:service:payments', label: 'payments', kind: 'service' },
    { id: 'id:service:search', label: 'search', kind: 'service' },
    { id: 'id:service:ledger', label: 'ledger', kind: 'service' },
    { id: 'id:service:db-replica', label: 'db-replica', kind: 'service' },
    { id: 'id:service:session-store', label: 'session-store', kind: 'service' },
    // Canary decoys (right ring) — the 5 catalog types, zero learned in-edges.
    // Tap emits these with the 'decoy:<canary_type>' id (NOT the identity scheme).
    { id: 'decoy:planted_credential', label: 'planted_credential', kind: 'decoy' },
    { id: 'decoy:fake_secret', label: 'fake_secret', kind: 'decoy' },
    { id: 'decoy:decoy_file', label: 'decoy_file', kind: 'decoy' },
    { id: 'decoy:fake_bucket', label: 'fake_bucket', kind: 'decoy' },
    { id: 'decoy:fake_endpoint', label: 'fake_endpoint', kind: 'decoy' },
    // The touch source — a flow that reached into the negative space (cookie 0x118).
    // Tap emits this with the 'touch-src:0x<cookie>' id (NOT the identity scheme).
    { id: 'touch-src:0x118', label: '0x118', kind: 'unknown' },
  ],
  edges: [
    // Ingress: named callers reach the ingress gateway, which fans into the mesh.
    { src_id: 'id:caller:web-client', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 1980, bytes: 26_400_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:reporting-worker', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 320, bytes: 2_300_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:batch-client', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 960, bytes: 11_600_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:mobile-gateway', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 1240, bytes: 14_900_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:partner-api', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 540, bytes: 6_100_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:ci-runner', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 210, bytes: 1_300_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:etl-scheduler', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 430, bytes: 5_200_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:support-console', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 180, bytes: 920_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:ops-dashboard', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 260, bytes: 1_500_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:caller:prober', dst_id: 'id:external:ingress-gateway', port: 8080, proto: 'tcp', flow_count: 140, bytes: 480_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:external:ingress-gateway', dst_id: 'id:service:frontend', port: 8001, proto: 'tcp', flow_count: 3400, bytes: 41_000_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    // Edge tier: frontend -> {cdn-edge, api}; cdn-edge -> api.
    { src_id: 'id:service:frontend', dst_id: 'id:service:cdn-edge', port: 8008, proto: 'tcp', flow_count: 1700, bytes: 9_800_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:frontend', dst_id: 'id:service:api', port: 8002, proto: 'tcp', flow_count: 1620, bytes: 19_200_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:cdn-edge', dst_id: 'id:service:api', port: 8002, proto: 'tcp', flow_count: 1500, bytes: 8_400_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    // App tier: api -> {auth, db, cache, payments, search}.
    { src_id: 'id:service:api', dst_id: 'id:service:auth', port: 8003, proto: 'tcp', flow_count: 880, bytes: 3_100_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:api', dst_id: 'id:service:db', port: 8004, proto: 'tcp', flow_count: 1320, bytes: 16_800_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:api', dst_id: 'id:service:cache', port: 8005, proto: 'tcp', flow_count: 1510, bytes: 8_900_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:api', dst_id: 'id:service:payments', port: 8006, proto: 'tcp', flow_count: 640, bytes: 4_200_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:api', dst_id: 'id:service:search', port: 8007, proto: 'tcp', flow_count: 720, bytes: 5_600_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    // Service tier: auth -> session-store; payments -> ledger; search -> db-replica.
    { src_id: 'id:service:auth', dst_id: 'id:service:session-store', port: 8011, proto: 'tcp', flow_count: 700, bytes: 2_100_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:payments', dst_id: 'id:service:ledger', port: 8009, proto: 'tcp', flow_count: 600, bytes: 3_300_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:search', dst_id: 'id:service:db-replica', port: 8010, proto: 'tcp', flow_count: 680, bytes: 5_000_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    // Data tier: ledger -> db; db-replica -> cache.
    { src_id: 'id:service:ledger', dst_id: 'id:service:db', port: 8004, proto: 'tcp', flow_count: 560, bytes: 3_000_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    { src_id: 'id:service:db-replica', dst_id: 'id:service:cache', port: 8005, proto: 'tcp', flow_count: 620, bytes: 2_900_000, first_seen: TOPO_FIRST, last_seen: TOPO_LAST, class: 'learned' },
    // NOTE: no 'live'/deviant edge here. The slice-3 live /api/topology emits ONLY
    // 'learned' and 'decoy_touch' classes; the deviant overlay (a novel pivot from an
    // UNLABELED identity, which the clean-fabric filter drops anyway) lands with the
    // F2 deviants store + its own ⚠ simulated fence. Keeping the fixture to those two
    // classes makes it a faithful mirror of what the live page actually serves.
    // BRIGHT source->decoy touch edge — the only edge that ever crosses into the
    // ring. A real adapter-recognized canary touch (Tier>=1) by cookie 0x118.
    { src_id: 'touch-src:0x118', dst_id: 'decoy:planted_credential', port: 0, proto: 'decoy', flow_count: 1, bytes: 0, first_seen: TOPO_LAST, last_seen: TOPO_LAST, class: 'decoy_touch' },
  ],
};

// fixtureDeviants — the F2 deviant hunting log. Realistic fingerprints of flows
// that DEVIATED from the learned baseline but touched NO canary, so NOTHING was
// armed (Rule 8). Ranked HitCount desc, then peak_value desc, then last_seen desc:
//   #1 the careful-mover — a FRESH identity (10.20.1.104, never in the registry, so
//      it resolves UNKNOWN/raw-IP) probing the api service, with the highest +
//      GROWING hit-count so it stays pinned despite its per-hit novelty decaying as
//      it teaches the baseline. Peak: "new identity".
//   #2 a new-identity burst (10.20.1.207) hitting auth — high identity/adjacency,
//      lower hit-count.
//   #3 a volume-spike — a KNOWN caller (etl-scheduler) moving far more data than
//      baseline; peak "volume deviation", lowest hit-count.
// simulated:true — the demo posture (the deviant flows are real local observations;
// the synthetic-peer cross-customer context is what's simulated).
export const fixtureDeviants: DeviantsView = {
  scope: 'm7-window',
  staged_labels: true,
  simulated: true,
  caption:
    "These flows DEVIATED from the learned baseline — an unfamiliar identity, a new adjacency, a volume or cadence shift — but touched NO canary, so NO response was armed (Rule 8). They are logged for threat-hunting, never actioned, and are NOT confirmed adversaries. The list is ranked by UNFAMILIARITY: unregistered movers first (the prime hunting leads), then known callers, with mesh services that initiated a novel flow last; the platform's own management-plane traffic — loopback (127.0.0.0/8) and the box talking to itself — is demoted to the bottom, never dropped. Identities are resolved from the operator registry where named; the rest fall back to raw IP. Local to this deployment; addresses never cross a boundary (Rule 9).",
  simulated_note:
    'Demo posture: synthetic-peer cross-customer context is simulated. The deviant flows shown are real local observations.',
  rows: [
    {
      // The careful-mover: fresh, unregistered identity -> resolves UNKNOWN/raw-IP.
      src: { label: '10.20.1.104', kind: 'unknown', addr: '10.20.1.104', port: 0 },
      dst: { label: 'api', kind: 'service', addr: '127.0.1.2', port: 8002 },
      src_familiarity: 'unfamiliar',
      identity_novelty: 0.93,
      adjacency_novelty: 0.81,
      port_novelty: 0.12,
      volume_deviation: 0.22,
      cadence_deviation: 0.18,
      peak_dim: 'new identity',
      peak_value: 0.93,
      hit_count: 41,
      first_seen: '2026-06-09T11:02:30Z',
      last_seen: '2026-06-09T13:57:48Z',
      score: 0,
    },
    {
      // New-identity burst: another unregistered identity probing auth.
      src: { label: '10.20.1.207', kind: 'unknown', addr: '10.20.1.207', port: 0 },
      dst: { label: 'auth', kind: 'service', addr: '127.0.1.3', port: 8003 },
      src_familiarity: 'unfamiliar',
      identity_novelty: 0.88,
      adjacency_novelty: 0.74,
      port_novelty: 0.34,
      volume_deviation: 0.15,
      cadence_deviation: 0.41,
      peak_dim: 'new identity',
      peak_value: 0.88,
      hit_count: 6,
      first_seen: '2026-06-09T13:46:10Z',
      last_seen: '2026-06-09T13:55:02Z',
      score: 0,
    },
    {
      // Volume-spike: a KNOWN caller moving far more data than baseline.
      src: { label: 'etl-scheduler', kind: 'caller', addr: '10.20.1.108', port: 0 },
      dst: { label: 'db-replica', kind: 'service', addr: '127.0.1.10', port: 8010 },
      src_familiarity: 'known',
      identity_novelty: 0.08,
      adjacency_novelty: 0.12,
      port_novelty: 0.05,
      volume_deviation: 0.79,
      cadence_deviation: 0.33,
      peak_dim: 'volume deviation',
      peak_value: 0.79,
      hit_count: 2,
      first_seen: '2026-06-09T13:20:00Z',
      last_seen: '2026-06-09T13:51:36Z',
      score: 0,
    },
  ],
};

export const fixtureReconTimeline: ReconTimeline = {
  total_recon: 3,
  rows: [
    { flow_id_hex: '0x118', flow_id: 0x118, session_start: '2026-06-09T13:54:00Z', timestamp: '2026-06-09T13:54:00Z', offset_label: '−4:12', canary_type: '.env', severity: 'surfaced', description: 'cluster · 0x118 repeated probing', escalated: true, escalated_tier: 3 },
    { flow_id_hex: '0x2a', flow_id: 0x2a, session_start: '2026-06-09T13:40:00Z', timestamp: '2026-06-09T13:40:00Z', offset_label: '−18:00', canary_type: '.aws/credentials', severity: 'recon', description: 'quiet probe · .aws/credentials', escalated: true, escalated_tier: 2 },
    { flow_id_hex: '0x7c', flow_id: 0x7c, session_start: '2026-06-09T13:30:00Z', timestamp: '2026-06-09T13:30:00Z', offset_label: '−28:00', canary_type: '.env', severity: 'recon', description: 'quiet probe · .env', escalated: false, escalated_tier: 0 },
  ],
};
