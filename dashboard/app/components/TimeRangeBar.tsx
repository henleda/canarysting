'use client';

import { useSince } from './SinceProvider';

// TimeRangeBar shows the window pills. 7d is intentionally absent: the cookie-
// reuse honesty cap (gap #1) keeps the max selectable window at 24h. Session-
// splitting (decision E) makes longer windows safe per-session, but the pills
// stay conservative for the aggregate views.
const RANGES = ['1h', '6h', '24h'] as const;

export default function TimeRangeBar() {
  const { since, setSince } = useSince();
  return (
    <div className="trange" role="group" aria-label="time range">
      {RANGES.map((r) => (
        <button
          key={r}
          className={`pill-btn${r === since ? ' active' : ''}`}
          onClick={() => setSince(r)}
          aria-pressed={r === since}
        >
          {r}
        </button>
      ))}
    </div>
  );
}
