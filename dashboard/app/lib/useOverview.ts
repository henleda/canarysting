'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchOverview, STREAM_URL } from './api';
import { useEventSource } from './useEventSource';
import type { Overview } from './types';

export type DataStatus =
  | 'loading' // initial, no data yet
  | 'live' // SSE connected, fresh data flowing
  | 'stale' // SSE disconnected — showing last-known snapshot (or none)
  | 'empty'; // connected, but the backend reports no engine data yet

// isEmptyOverview is true when the backend is reachable but has no engine data
// to show — the tap is unreachable AND there is no flow, no folds, no
// interactions. This drives the honest "OBSERVING / WARMING UP" states.
function isEmptyOverview(ov: Overview): boolean {
  const hasFlow = !!ov.escalation?.flow;
  const folds = ov.escalation?.tier_ladder?.[0]?.count ?? 0;
  const interactions = ov.attacker_cost?.active_response_count ?? 0;
  const ladderDenom = ov.escalation?.ladder_denominator ?? 0;
  return !ov.tap_reachable && !hasFlow && folds === 0 && interactions === 0 && ladderDenom === 0;
}

// useOverview is the single data hook: an initial GET /api/overview, then a
// persistent SSE stream that replaces the snapshot on each push. Status reflects
// connection health honestly (loading -> live/empty; drop -> stale).
export function useOverview(): { snapshot: Overview | null; status: DataStatus } {
  const [snapshot, setSnapshot] = useState<Overview | null>(null);
  const [status, setStatus] = useState<DataStatus>('loading');
  const haveData = useRef(false);

  const apply = useCallback((ov: Overview) => {
    haveData.current = true;
    setSnapshot(ov);
    setStatus(isEmptyOverview(ov) ? 'empty' : 'live');
  }, []);

  // Initial snapshot — populate before the SSE stream delivers its first frame.
  useEffect(() => {
    let cancelled = false;
    fetchOverview()
      .then((ov) => {
        if (!cancelled) apply(ov);
      })
      .catch(() => {
        if (!cancelled && !haveData.current) setStatus('stale');
      });
    return () => {
      cancelled = true;
    };
  }, [apply]);

  const onMessage = useCallback(
    (data: string) => {
      try {
        apply(JSON.parse(data) as Overview);
      } catch {
        // ignore malformed frames
      }
    },
    [apply],
  );

  const onError = useCallback(() => {
    // Keep the last-known snapshot on screen, but flag the connection as stale.
    setStatus('stale');
  }, []);

  useEventSource(STREAM_URL, { onMessage, onError });

  return { snapshot, status };
}
