'use client';

import { useEffect, useState } from 'react';
import { utcClock } from '@/lib/format';
import type { Overview } from '@/lib/types';
import type { DataStatus } from '@/lib/useOverview';

// Brand diamond, inlined verbatim from dashboard/design/prototype.html.
function Logo() {
  return (
    <svg width="28" height="28" viewBox="0 0 26 26" fill="none">
      <path d="M13 2 L23 13 L13 24 L3 13 Z" stroke="#ffce3a" strokeWidth="1.4" fill="rgba(255,206,58,0.06)" />
      <circle cx="13" cy="13" r="3.4" fill="#ffce3a" />
      <path d="M13 13 L20 6" stroke="#ff4d60" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export default function TopBar({ snapshot, status }: { snapshot: Overview | null; status: DataStatus }) {
  // Live UTC clock — local, independent of backend ticks (matches prototype).
  const [clock, setClock] = useState('--:--:-- UTC');
  useEffect(() => {
    const tick = () => setClock(utcClock(new Date()));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const scope = snapshot?.scope || '—';
  const env = snapshot?.env || '—';
  const calib = snapshot?.calibration;
  const baselineLive = snapshot?.baseline_live ?? false;

  // Calibration pill: calibrated -> green ".ok"; otherwise neutral "WARMING UP".
  const calibrated = calib?.calibrated ?? false;
  const seen = calib?.evidence_seen ?? 0;
  const floor = calib?.evidence_floor ?? 0;
  const calibClass = calibrated ? 'pill ok' : 'pill';
  const calibText = calib
    ? calibrated
      ? `CALIBRATED · ${seen}/${floor}`
      : `WARMING UP · ${seen}/${floor}`
    : 'CALIBRATED · —';

  // Baseline pill: live -> amber ".live" (pulsing); otherwise neutral.
  const baseClass = baselineLive ? 'pill live' : 'pill';
  const baseText = baselineLive ? 'BASELINE LIVE' : 'BASELINE WARMING';

  return (
    <header className="topbar">
      <div className="brand">
        <Logo />
        <span className="name">
          CANARY<b>STING</b>
        </span>
      </div>
      <span className="sep" />
      <div className="meta">
        <span className="k">scope</span>
        <span className="v">{scope}</span>
      </div>
      <div className="meta">
        <span className="k">env</span>
        <span className="v">{env}</span>
      </div>
      <span className="spacer" />
      <span className={calibClass}>
        <span className="dot" />
        {calibText}
      </span>
      <span className={baseClass}>
        <span className="dot" />
        {baseText}
      </span>
      {status === 'stale' && (
        <span className="pill" style={{ borderColor: 'rgba(255,206,58,0.45)', color: 'var(--canary)' }}>
          <span className="dot" style={{ background: 'var(--canary)' }} />
          RECONNECTING
        </span>
      )}
      <span className="sep" />
      <span className="clock">{clock}</span>
    </header>
  );
}
