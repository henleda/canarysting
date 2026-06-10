'use client';

import { createContext, useContext, useCallback } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

// `since` is a Go-duration string in the URL (?since=6h) passed straight to the
// backend. Default 1h. setSince rewrites the URL preserving other params.
type SinceCtx = { since: string; sinceSec: number; setSince: (s: string) => void };

const Ctx = createContext<SinceCtx>({ since: '1h', sinceSec: 3600, setSince: () => {} });

// parseDurationSec parses the Go-duration subset the pills produce ("1h","6h",
// "24h","30m","Ns"). Falls back to 3600 on anything unexpected.
function parseDurationSec(s: string): number {
  const m = /^(\d+)(s|m|h)$/.exec(s.trim());
  if (!m) {
    const n = Number(s);
    return Number.isFinite(n) && n > 0 ? n : 3600;
  }
  const n = Number(m[1]);
  const mult = m[2] === 'h' ? 3600 : m[2] === 'm' ? 60 : 1;
  return n * mult;
}

export function SinceProvider({ children }: { children: React.ReactNode }) {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const since = params.get('since') ?? '1h';

  const setSince = useCallback(
    (s: string) => {
      const next = new URLSearchParams(params.toString());
      next.set('since', s);
      router.push(`${pathname}?${next.toString()}`);
    },
    [params, router, pathname],
  );

  return <Ctx.Provider value={{ since, sinceSec: parseDurationSec(since), setSince }}>{children}</Ctx.Provider>;
}

export const useSince = () => useContext(Ctx);
