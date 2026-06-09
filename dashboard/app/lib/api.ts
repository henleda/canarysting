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
