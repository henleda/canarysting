import Link from 'next/link';
import Spark from './Spark';
import { WALL_LINK } from '@/lib/links';
import { fmtInt, fmtAgo } from '@/lib/format';
import type { DataStatus } from '@/lib/useOverview';
import type { EscalationView, FlowRow } from '@/lib/types';

// LiveSpotlight is the Row-4 full-width live-attacker strip: a horizontally
// scrollable track of armed-flow cards rendered as a RECENCY FEED over
// escalation.attacker_flows (the backend already sorts them LastSeen desc and
// gives EACH row its own spark_series). Every card is identical in structure —
// timestamp + cookie + tier + score + touches + its own spark — so the strip
// reads as a believable feed of the real Tag/Contain/Jail mix, not a wall of
// identical top-tier jails. The most-recent card carries a subtle ● LIVE dot but
// otherwise has the SAME layout as the rest (no special featured card).
//
// "LIVE ATTACKERS" is a UI heading ONLY (MAY-NOT #3): each card represents a
// decoy-armed flow that crossed the response threshold — NEVER asserted to be a
// "confirmed adversary" or "real attacker". escalation.flow is still in the
// payload (it gates the /flow deep-link), it is just no longer rendered here as a
// separate featured card.
export default function LiveSpotlight({
  escalation,
  armedCount,
  status,
  at,
}: {
  escalation: EscalationView | undefined;
  armedCount: number;
  status?: DataStatus;
  at?: string; // the snapshot's `at` — the "now" reference for the relative timestamps
}) {
  const rows = escalation?.attacker_flows ?? [];
  // "now" reference: the snapshot time if present (feed reads relative to the data),
  // else the wall clock.
  const nowMs = at ? Date.parse(at) : Date.now();

  // Don't assert "no attacker" before data has loaded: while loading with nothing
  // yet, show a neutral OBSERVING line instead of the definitive empty state.
  if (rows.length === 0 && status === 'loading') {
    return (
      <section className="live-strip empty">
        <span className="faint mono ls-empty" style={{ opacity: 0.5 }}>
          OBSERVING…
        </span>
      </section>
    );
  }

  // Honest empty state: no armed-flow cards — observing, not idle.
  if (rows.length === 0) {
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
        {rows.map((r, i) => (
          // The first (most-recent) card is flagged live; structure is identical.
          <AttackerCard key={`${r.flow_id_hex}-${r.last_seen}`} row={r} nowMs={nowMs} isLive={i === 0} />
        ))}
      </div>
    </section>
  );
}

// AttackerCard is one armed-flow card in the recency feed. EVERY card is the same:
// a relative timestamp, the cookie deep-link, a tier badge colored by peak tier,
// the score ("—" when 0), the touch count + verdict, and its OWN spark series. The
// most-recent card additionally shows a ● LIVE dot (no layout change otherwise).
function AttackerCard({ row, nowMs, isLive }: { row: FlowRow; nowMs: number; isLive: boolean }) {
  const peakTier = row.peak_tier ?? 0;
  const tierColor =
    peakTier >= 3 ? 'var(--sting)' : peakTier === 2 ? 'var(--contain)' : 'var(--tag)';
  const ago = fmtAgo(row.last_seen, nowMs);
  return (
    <Link
      href={`/flow/${row.flow_id_hex}?since=1h`}
      className={`ls-card${isLive ? ' live' : ''}`}
      style={WALL_LINK}
      aria-label={`view flow ${row.flow_id_hex}`}
    >
      <div className="meta">
        {isLive && <span className="ls-live">● LIVE</span>}
        {ago && <span className="ago">{ago}</span>}
      </div>
      <div className="meta">
        <span className="tier-badge mono" style={{ color: tierColor, borderColor: tierColor }}>
          T{peakTier}
        </span>
        <span className="role">{row.verdict || '—'}</span>
      </div>
      <div className="cookie mono">{row.flow_id_hex}</div>
      <div className="score-strip">{(row.score ?? 0) > 0 ? row.score.toFixed(2) : '—'}</div>
      <div className="meta">{fmtInt(row.touch_count ?? 0)} touches</div>
      <Spark series={row.spark_series ?? []} />
    </Link>
  );
}
