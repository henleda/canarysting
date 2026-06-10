'use client';

import { useEffect, useRef, useState } from 'react';

// usePolling fetches `url` immediately and then on an interval (adaptive to the
// window size unless overridden). It keeps the last-good data on error and
// surfaces an error string. Cancels on unmount / url change.
export function usePolling<T>(
  url: string,
  sinceSec: number,
  opts?: { intervalMs?: number },
): { data: T | null; loading: boolean; error: string | null; notice: string | null } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const dataRef = useRef<T | null>(null);

  useEffect(() => {
    let cancelled = false;
    const interval = opts?.intervalMs ?? (sinceSec <= 300 ? 10000 : 30000);

    async function tick() {
      try {
        const res = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as T;
        if (cancelled) return;
        dataRef.current = json;
        setData(json);
        setError(null);
        // The backend sets this when a tap outage forced a narrower (cache)
        // window than requested — surface it so the range label never overstates.
        const eff = res.headers.get('X-CS-Effective-Window-Sec');
        setNotice(eff ? `tap unreachable — showing cached ${Math.round(Number(eff) / 60)}m` : null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
        // keep last-good data
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    // On a window/url change, drop the prior window's data so the loading state
    // shows for the NEW window — never render old numbers under a new range label.
    dataRef.current = null;
    setData(null);
    setLoading(true);
    setNotice(null);
    tick();
    const id = setInterval(tick, interval);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [url, sinceSec, opts?.intervalMs]);

  return { data, loading, error, notice };
}
