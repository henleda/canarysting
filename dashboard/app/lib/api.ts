// Data access for the dashboard. Everything goes through /api/* which Next.js
// rewrites to the dashboard-backend (see next.config.ts). No host is hardcoded
// in client JS — dev and prod are identical.

import type { Overview } from './types';

export const OVERVIEW_URL = '/api/overview';
export const STREAM_URL = '/api/stream';

// fetchOverview pulls the current snapshot (GET /api/overview). Used on mount,
// before the SSE stream delivers its first frame.
export async function fetchOverview(): Promise<Overview> {
  const res = await fetch(OVERVIEW_URL, {
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`overview: HTTP ${res.status}`);
  return res.json() as Promise<Overview>;
}

// ---- Interactive console drill-down endpoints ----
import type { FlowDetail, FlowsList, CostBreakdown, ReconTimeline, TopologyView } from './types';

// `since` is the Go-duration string the time pills produce ("1h","6h","24h").
// `session` (optional, Unix seconds of the session start) disambiguates a reused
// cookie's distinct sessions; omit to get the latest session.
export function flowDetailURL(cookie: string, since: string, session?: number): string {
  const s = session && session > 0 ? `&session=${session}` : '';
  return `/api/flow/${cookie}?since=${since}${s}`;
}
// flowsURL builds the /api/flows request. `minTier` (1..3, optional) selects the
// CUMULATIVE-reach cohort (rows that reached >= minTier) and, when set, takes
// precedence over the exact `tier` filter — matching the backend's two params.
export function flowsURL(tier: number, since: string, minTier?: number): string {
  if (minTier && minTier >= 1 && minTier <= 3) {
    return `/api/flows?since=${since}&min_tier=${minTier}`;
  }
  return `/api/flows?since=${since}${tier >= 0 ? `&tier=${tier}` : ''}`;
}
export function costURL(since: string): string {
  return `/api/cost?since=${since}`;
}
export function reconURL(since: string): string {
  return `/api/recon?since=${since}`;
}
// topologyURL is the learned east-west graph (F1). It is a CURRENT-state view (the
// aggregator's live in-memory topology map + canary decoy ring + recent touch
// edges), not windowed — so there is no `since`. The backend serves the tap's
// /raw/topology shape PLUS the pre-rendered honesty `caption`.
export function topologyURL(): string {
  return `/api/topology`;
}

async function fetchJSON<T>(url: string, label: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}
export const fetchFlowDetail = (cookie: string, since: string, session?: number) =>
  fetchJSON<FlowDetail>(flowDetailURL(cookie, since, session), 'flow');
export const fetchFlows = (tier: number, since: string, minTier?: number) =>
  fetchJSON<FlowsList>(flowsURL(tier, since, minTier), 'flows');
export const fetchCost = (since: string) => fetchJSON<CostBreakdown>(costURL(since), 'cost');
export const fetchRecon = (since: string) => fetchJSON<ReconTimeline>(reconURL(since), 'recon');
export const fetchTopology = () => fetchJSON<TopologyView>(topologyURL(), 'topology');
