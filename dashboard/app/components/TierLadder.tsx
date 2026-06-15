import Link from 'next/link';
import { fmtInt, fmtPct } from '@/lib/format';
import { WALL_LINK } from '@/lib/links';
import type { TierStep } from '@/lib/types';

interface TierLadderProps {
  ladder: readonly TierStep[]; // length 4 (T0..T3)
}

// The prototype's tier-number prefix ("T0 · Observe" …). We pair the backend's
// label with the tier index to render exactly that.
function tierName(step: TierStep): string {
  return `T${step.tier} · ${step.label}`;
}

// TierLadder is the horizontal climb (`.ladder-track` in the prototype). Each
// `.step` is one rung. Visual state derives from the real data:
//   - `active`  : step.is_active (the highest occupied tier)
//   - `done`    : an occupied/active tier below the active one (filled segment)
//   - `t0..t3`  : the per-tier color class
//   - `resp`    : step.has_response (T2/T3 carry an active-response tag)
// The bar fill width uses the backend's fraction; the percent label is fmtPct.
export default function TierLadder({ ladder }: TierLadderProps) {
  const activeTier = ladder.find((s) => s.is_active)?.tier ?? -1;

  return (
    <div className="ladder">
      <div className="phead" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 10 }}>Tier distribution · canary-interacting flows (5m)</h2>
        <span className="line" />
      </div>
      <div className="ladder-track">
        {ladder.map((step) => {
          const isActive = step.is_active;
          // "done" = a lit-up rung the attacker has already climbed past: any
          // tier strictly below the active tier (or, if no active tier, T0 when
          // there are folds). The prototype lights T0..(active-1) and the active.
          const isDone =
            !isActive && activeTier >= 0 && step.tier < activeTier;
          const cls = [
            'step',
            isDone ? 'done' : '',
            isActive ? 'active' : '',
            `t${step.tier}`,
            step.has_response ? 'resp' : '',
          ]
            .filter(Boolean)
            .join(' ');

          return (
            <Link key={step.tier} href={`/flows?tier=${step.tier}&since=1h`} className={cls} style={WALL_LINK}>
              <span className="seg" />
              <span className="knob" />
              <div className="tn">{tierName(step)}</div>
              <div className="cnt">{fmtInt(step.count)}</div>
              <div className="pct">
                <span className="pb">
                  <i style={{ width: `${Math.round(step.fraction * 100)}%` }} />
                </span>
                <span className="pn">{fmtPct(step.fraction)}</span>
              </div>
              {step.has_response && step.resp_label && (
                <span className="resp-tag">{step.resp_label}</span>
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
