import Link from 'next/link';
import PanelHead from './PanelHead';
import { WALL_LINK } from '@/lib/links';
import { fmtInt } from '@/lib/format';
import type { CredibilityView } from '@/lib/types';

// Credibility is the /credibility page panel: the "real learned state" panel. Three
// cred-items:
//   1. Guardrail — architectural invariant (guardrail_active, always true): a
//      flow off-baseline that never touches a canary triggers nothing.
//   2. Baseline multiplier — M badge + the feature bars. When the baseline is
//      not live, M is neutral (1.00) and we say so explicitly.
//   3. Scope / calibration — the calibration meter (seen/floor) + badge.
export default function Credibility({ credibility }: { credibility: CredibilityView | undefined }) {
  const cred = credibility;
  const baselineLive = cred?.baseline_gates?.live ?? false;
  const m = cred?.baseline_multiplier_m ?? 1.0;
  const featureBars = cred?.feature_bars ?? [];

  const calib = cred?.calibration;
  const calibrated = calib?.calibrated ?? false;
  const seen = calib?.evidence_seen ?? 0;
  const floor = calib?.evidence_floor ?? 0;
  const meterPct = floor > 0 ? Math.min(100, Math.round((seen / floor) * 100)) : 0;

  // M badge text: honest neutral when the baseline gate isn't live.
  const mBadge = baselineLive ? `M = ${m.toFixed(2)}` : 'M = 1.00 (neutral)';

  return (
    <section className="cell">
      <PanelHead title="Credibility — real learned state" />

      {/* 1. Guardrail — deep-links to /precision (the structural-zero proof). */}
      <Link href="/precision" className="cred-item" style={{ ...WALL_LINK, display: 'block' }}>
        <div className="cred-h">
          <span className="ic" style={{ background: 'var(--safe)', boxShadow: '0 0 8px var(--safe)' }} />
          <span className="t">Guardrail</span>
          <span className="badge green">no trigger</span>
        </div>
        <div className="cred-body">
          a flow wildly off-baseline that <span className="em">never touches a canary</span> → nothing happens.
          deviation is weight context, never a trigger.
        </div>
      </Link>

      {/* 2. Baseline multiplier */}
      <div className="cred-item">
        <div className="cred-h">
          <span className="ic" style={{ background: 'var(--canary)', boxShadow: '0 0 8px var(--canary)' }} />
          <span className="t">Baseline multiplier</span>
          <span className="badge amber">{mBadge}</span>
        </div>
        {featureBars.length > 0 ? (
          <div className="feats">
            {featureBars.map((fb, i) => {
              const pct = Math.max(0, Math.min(100, Math.round(fb.value * 100)));
              return (
                <div className="feat" key={`${fb.name}-${i}`}>
                  <span className="fn">{fb.name}</span>
                  <span className="fbar">
                    <i style={{ width: `${pct}%` }} />
                  </span>
                  <span className="fv">{fb.value.toFixed(2)}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="cred-body faint">no canary-interacting features in window — multiplier neutral.</div>
        )}
      </div>

      {/* 3. Scope / calibration */}
      <div className="cred-item">
        <div className="cred-h">
          <span className="ic" style={{ background: 'var(--canary)', boxShadow: '0 0 8px var(--canary)' }} />
          <span className="t">Scope / calibration</span>
          <span className={`badge ${calibrated ? 'green' : 'amber'}`}>{calibrated ? 'calibrated' : 'warming up'}</span>
        </div>
        <div className="calib">
          <div className="calmeter">
            <i style={{ width: `${meterPct}%` }} />
          </div>
          <div className="calnum">
            <b>{fmtInt(seen)}</b>
            <span className="dim"> / {fmtInt(floor)} labels · never cross-scope</span>
          </div>
        </div>
      </div>
    </section>
  );
}
