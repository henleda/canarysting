// RETIRED: no longer rendered on the wall (demoted to LiveSpotlight on Row4). Retained only for the shared WALL_LINK export below. TODO: relocate WALL_LINK to lib/format.ts and delete this file.
import Link from 'next/link';
import PanelHead from './PanelHead';
import Spark from './Spark';
import TierLadder from './TierLadder';
import { fmtInt } from '@/lib/format';
import type { EscalationView } from '@/lib/types';

const STING_TAG_STYLE = { color: 'var(--sting)', borderColor: 'rgba(255,77,96,0.4)' };
// Home-wall links inherit color and drop the underline so the signed-off look is
// unchanged — only a pointer cursor appears. Default since=1h on wall entry.
export const WALL_LINK = { color: 'inherit', textDecoration: 'none' } as const;

// LiveEscalation is the hero-left panel. It binds escalation.flow + the tier
// ladder. Identity is the socket-cookie hex (flow_id_hex) — the data has NO
// source IP/role, so we render the cookie as the headline identifier and the
// engine verdict as the status tag (the prototype's "attacker" role slot).
export default function LiveEscalation({ escalation }: { escalation: EscalationView | undefined }) {
  const flow = escalation?.flow ?? null;
  const ladder = escalation?.tier_ladder;

  const head = (
    <PanelHead
      title="Live escalation"
      preTags={[{ label: 'flow' }]}
      postTags={[{ label: 'async · kernel-enforced', style: STING_TAG_STYLE }]}
    />
  );

  // Honest empty state: no current attacker flow. The ladder still renders so
  // T0 (observed-normal folds) stays visible — we are observing, not idle.
  if (!flow) {
    return (
      <section className="hpanel">
        {head}
        <div
          style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: 120,
          }}
        >
          <span className="faint mono" style={{ fontSize: 11, letterSpacing: '0.12em' }}>
            NO ACTIVE ESCALATION — OBSERVING
          </span>
        </div>
        {ladder && <TierLadder ladder={ladder} />}
      </section>
    );
  }

  return (
    <section className="hpanel">
      {head}
      <div className="esc-top">
        <div>
          <div className="flow-id">
            <Link href={`/flow/${flow.flow_id_hex}?since=1h`} className="ip mono" style={WALL_LINK}>
              {flow.flow_id_hex}
            </Link>
            <span className="role">{flow.verdict || 'flagged'}</span>
          </div>
          <div className="flow-sub">
            cookie {flow.flow_id_hex} · {fmtInt(flow.touch_count)} distinct touches / 5m window
          </div>
          {flow.canary_touches.length > 0 && (
            <div className="chips">
              <span className="lbl">canary touches · negative space</span>
              {flow.canary_touches.map((ct, i) => (
                <span key={`${ct}-${i}`} className="chip">
                  {ct}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="scorebox">
          <div className="score">{flow.score.toFixed(2)}</div>
          <div className="score-meta">
            <span className="arrow">▲ escalating</span> · base × M <b>{flow.base_m.toFixed(2)}</b>
          </div>
        </div>
      </div>
      <Spark series={flow.spark_series} />
      {ladder && <TierLadder ladder={ladder} />}
    </section>
  );
}
