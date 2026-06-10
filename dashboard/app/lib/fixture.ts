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
  calibration: { calibrated: true, evidence_seen: 50, evidence_floor: 50 },

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

export const fixtureCostBreakdown: CostBreakdown = {
  total: { time_held_sec: 24, bytes_served: 25726, requests: 3, token_cost: 6432 },
  by_flow: fixtureFlowsList.flows.filter((f) => f.total_cost.time_held_sec > 0),
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
};

export const fixtureReconTimeline: ReconTimeline = {
  total_recon: 3,
  rows: [
    { flow_id_hex: '0x118', flow_id: 0x118, session_start: '2026-06-09T13:54:00Z', timestamp: '2026-06-09T13:54:00Z', offset_label: '−4:12', canary_type: '.env', severity: 'surfaced', description: 'cluster · 0x118 repeated probing', escalated: true, escalated_tier: 3 },
    { flow_id_hex: '0x2a', flow_id: 0x2a, session_start: '2026-06-09T13:40:00Z', timestamp: '2026-06-09T13:40:00Z', offset_label: '−18:00', canary_type: '.aws/credentials', severity: 'recon', description: 'quiet probe · .aws/credentials', escalated: true, escalated_tier: 2 },
    { flow_id_hex: '0x7c', flow_id: 0x7c, session_start: '2026-06-09T13:30:00Z', timestamp: '2026-06-09T13:30:00Z', offset_label: '−28:00', canary_type: '.env', severity: 'recon', description: 'quiet probe · .env', escalated: false, escalated_tier: 0 },
  ],
};
