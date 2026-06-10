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
import type { FlowDetail, FlowsList, CostBreakdown, ReconTimeline } from './types';

// `since` is the Go-duration string the time pills produce ("1h","6h","24h").
// `session` (optional, Unix seconds of the session start) disambiguates a reused
// cookie's distinct sessions; omit to get the latest session.
export function flowDetailURL(cookie: string, since: string, session?: number): string {
  const s = session && session > 0 ? `&session=${session}` : '';
  return `/api/flow/${cookie}?since=${since}${s}`;
}
export function flowsURL(tier: number, since: string): string {
  return `/api/flows?since=${since}${tier >= 0 ? `&tier=${tier}` : ''}`;
}
export function costURL(since: string): string {
  return `/api/cost?since=${since}`;
}
export function reconURL(since: string): string {
  return `/api/recon?since=${since}`;
}

async function fetchJSON<T>(url: string, label: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}
export const fetchFlowDetail = (cookie: string, since: string, session?: number) =>
  fetchJSON<FlowDetail>(flowDetailURL(cookie, since, session), 'flow');
export const fetchFlows = (tier: number, since: string) => fetchJSON<FlowsList>(flowsURL(tier, since), 'flows');
export const fetchCost = (since: string) => fetchJSON<CostBreakdown>(costURL(since), 'cost');
export const fetchRecon = (since: string) => fetchJSON<ReconTimeline>(reconURL(since), 'recon');
