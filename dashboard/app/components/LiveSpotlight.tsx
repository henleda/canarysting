import Link from 'next/link';
import Spark from './Spark';
import { WALL_LINK } from '@/lib/links';
import { fmtInt } from '@/lib/format';
import type { DataStatus } from '@/lib/useOverview';
import type { EscalationView, FlowRow } from '@/lib/types';

// LiveSpotlight is the Row-4 full-width live-attacker strip: a horizontally
// scrollable track of armed-flow cards. The featured current flow (if any) is the
// first card; the rest come from escalation.attacker_flows (the capped, ranked
// armed-flow list), deduped against the featured one.
//
// "LIVE ATTACKERS" / "LIVE ATTACKER" is a UI heading ONLY (MAY-NOT #3): each card
// represents a decoy-armed flow that crossed the response threshold — NEVER
// asserted to be a "confirmed adversary" or "real attacker". The featured card's
// score uses the compact .score-strip class; the signed-off 104px .score is
// untouched.
export default function LiveSpotlight({
  escalation,
  armedCount,
  status,
}: {
  escalation: EscalationView | undefined;
  armedCount: number;
  status?: DataStatus;
}) {
  const flow = escalation?.flow ?? null;
  // Dedup the featured flow out of the attacker_flows cards so it isn't shown twice.
  const rows = (escalation?.attacker_flows ?? []).filter(
    (r) => !flow || r.flow_id_hex !== flow.flow_id_hex,
  );

  // Don't assert "no attacker" before data has loaded: while loading with nothing
  // yet, show a neutral OBSERVING line instead of the definitive empty state.
  if (!flow && rows.length === 0 && status === 'loading') {
    return (
      <section className="live-strip empty">
        <span className="faint mono ls-empty" style={{ opacity: 0.5 }}>
          OBSERVING…
        </span>
      </section>
    );
  }

  // Honest empty state: no featured flow AND no armed-flow cards — observing, not idle.
  if (!flow && rows.length === 0) {
    return (
      <section className="live-strip empty">
        <span className="faint mono ls-empty">
          NO ACTIVE ATTACKER — {fmtInt(armedCount)} armed flow{armedCount === 1 ? '' : 's'} tracked this
          window, observing
        </span>
      </section>
    );
  }

  return (
    <section className="live-strip">
      <div className="ls-head">
        LIVE ATTACKERS · {fmtInt(armedCount)} armed this window ·{' '}
        <Link
          href="/flows?since=1h"
          style={{ color: 'var(--canary)', textDecoration: 'underline', fontWeight: 700 }}
        >
          browse all {fmtInt(armedCount)} →
        </Link>
      </div>
      <div className="ls-track">
        {flow && (
          <Link href={`/flow/${flow.flow_id_hex}?since=1h`} className="ls-card live" style={WALL_LINK} aria-label={`view flow ${flow.flow_id_hex}`}>
            <div className="meta">
              <span className="live-dot">● LIVE</span>
              <span className="role">{flow.verdict || 'flagged'}</span>
            </div>
            <div className="cookie mono">{flow.flow_id_hex}</div>
            <div className="score-strip">{(flow.score ?? 0).toFixed(2)}</div>
            <div className="meta">base × M <b>{(flow.base_m ?? 0).toFixed(2)}</b></div>
            <Spark series={flow.spark_series} />
          </Link>
        )}
        {rows.map((r) => (
          <AttackerCard key={r.flow_id_hex} row={r} />
        ))}
      </div>
    </section>
  );
}

// AttackerCard is one armed-flow card (no spark — attacker_flows rows carry no
// spark series). The tier badge colors by peak tier; the score renders "—" when 0.
function AttackerCard({ row }: { row: FlowRow }) {
  const peakTier = row.peak_tier ?? 0;
  const tierColor =
    peakTier >= 3 ? 'var(--sting)' : peakTier === 2 ? 'var(--contain)' : 'var(--tag)';
  return (
    <Link href={`/flow/${row.flow_id_hex}?since=1h`} className="ls-card" style={WALL_LINK} aria-label={`view flow ${row.flow_id_hex}`}>
      <div className="meta">
        <span
          className="tier-badge mono"
          style={{ color: tierColor, borderColor: tierColor }}
        >
          T{peakTier}
        </span>
        <span className="role">{row.verdict || '—'}</span>
      </div>
      <div className="cookie mono">{row.flow_id_hex}</div>
      <div className="score-strip">{(row.score ?? 0) > 0 ? row.score.toFixed(2) : '—'}</div>
      <div className="meta">{fmtInt(row.touch_count ?? 0)} touches</div>
    </Link>
  );
}
