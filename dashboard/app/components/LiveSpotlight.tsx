import Link from 'next/link';
import Spark from './Spark';
import { WALL_LINK } from './LiveEscalation';
import { fmtInt } from '@/lib/format';
import type { EscalationView } from '@/lib/types';

// LiveSpotlight is the DEMOTED single-flow strip (Row 4): the old hero-left
// escalation panel, compressed to one compact row now that the fleet view owns
// the wall. It shows ONE flow at a time — "1 of N active" — so the wall no longer
// implies a single attacker is the whole story.
//
// "LIVE ATTACKER" is a UI eyebrow heading ONLY (MAY-NOT #3): the flow is a
// decoy-armed flow that crossed the response threshold, never asserted to be a
// "confirmed adversary". The score uses the NEW compact .score-strip class — the
// signed-off 104px .score is untouched.
export default function LiveSpotlight({
  escalation,
  armedCount,
}: {
  escalation: EscalationView | undefined;
  armedCount: number;
}) {
  const flow = escalation?.flow ?? null;

  // Honest non-idle empty state: no current spotlight flow, but we are tracking
  // armed flows this window — observing, not idle.
  if (!flow) {
    return (
      <section className="live-strip empty">
        <span className="faint mono ls-empty">
          NO ACTIVE SPOTLIGHT — {fmtInt(armedCount)} armed flow{armedCount === 1 ? '' : 's'} tracked this
          window, observing
        </span>
      </section>
    );
  }

  // Status indicator DERIVED from the flow's real tier/verdict — never a hardcoded
  // "escalating". Jail/T3 → jailed; T2 → contained; T1 → tagged; else escalating.
  const status =
    flow.verdict === 'jail' || flow.tier === 3
      ? 'jailed'
      : flow.tier === 2
        ? 'contained'
        : flow.tier === 1
          ? 'tagged'
          : '▲ escalating';

  return (
    <section className="live-strip">
      <div className="ls-lead">
        <div className="ls-eyebrow mono">
          LIVE ATTACKER · 1 of {fmtInt(armedCount)} armed this window
        </div>
        <div className="ls-id">
          <Link href={`/flow/${flow.flow_id_hex}?since=1h`} className="ip mono" style={WALL_LINK}>
            {flow.flow_id_hex}
          </Link>
          <span className="role">{flow.verdict || 'flagged'}</span>
        </div>
        <div className="flow-sub">
          cookie {flow.flow_id_hex} · {fmtInt(flow.touch_count)} distinct touches / 5m window
        </div>
      </div>
      <div className="ls-spark">
        <Spark series={flow.spark_series} />
      </div>
      <div className="ls-score">
        <div className="score-strip">{flow.score.toFixed(2)}</div>
        <div className="score-meta">
          <span className="arrow">{status}</span> · base × M <b>{flow.base_m.toFixed(2)}</b>
        </div>
      </div>
    </section>
  );
}
