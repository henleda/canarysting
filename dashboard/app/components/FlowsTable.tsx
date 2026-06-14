'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { fmtK, fmtTime } from '@/lib/format';
import { useSince } from './SinceProvider';
import type { FlowsList } from '@/lib/types';

const TIERS = [
  { v: -1, l: 'all' },
  { v: 0, l: 'T0' },
  { v: 1, l: 'T1' },
  { v: 2, l: 'T2' },
  { v: 3, l: 'T3' },
];

// tierName maps a tier index to its short verdict label (used in the reached-cohort
// header, e.g. min_tier=2 → "reached ≥ Contain").
function tierName(t: number): string {
  return t === 1 ? 'Tag' : t === 2 ? 'Contain' : t === 3 ? 'Jail' : `T${t}`;
}

function localTime(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().slice(11, 19);
}

// FlowsTable lists SESSIONS (decision E): each row is a cookie-session. The
// cookie cell deep-links to that exact session via ?session=<start unix>.
//
// Two filter modes: `tierFilter` (exact peak, driven by the pill row) and
// `minTier` (cumulative reach, reached >= minTier — the funnel's "reached at
// least" drill-down). When minTier is set it takes precedence over tierFilter.
export default function FlowsTable({
  data,
  tierFilter,
  minTier = 0,
  loading,
}: {
  data: FlowsList | null;
  tierFilter: number;
  minTier?: number;
  loading: boolean;
}) {
  const router = useRouter();
  const { since } = useSince();

  const setTier = (v: number) => {
    const p = new URLSearchParams({ since });
    if (v >= 0) p.set('tier', String(v));
    router.replace(`/flows?${p.toString()}`);
  };

  return (
    <>
      {minTier > 0 ? (
        <h3 style={{ marginBottom: 16 }}>flows that reached ≥ {tierName(minTier)}</h3>
      ) : (
        <div className="trange" style={{ marginBottom: 16 }}>
          {TIERS.map((t) => (
            <button key={t.v} className={`pill-btn${t.v === tierFilter ? ' active' : ''}`} onClick={() => setTier(t.v)}>
              {t.l}
            </button>
          ))}
        </div>
      )}
      {!data ? (
        <div className="faint mono">{loading ? 'WARMING UP…' : 'no flows'}</div>
      ) : data.flows.length === 0 && tierFilter === 0 ? (
        // Tier 0 (Observe) has NO per-flow records BY DESIGN. Benign east-west is
        // folded into the eBPF baseline as an aggregate count, but never persisted
        // as an interaction event (the engine drops everything below Tier 1 —
        // boltevents CaptureVerdict returns nil for v.Tier < TierTag). The Tier-0
        // tile is therefore a counter, not a queryable list. Explain that posture
        // instead of rendering a misleading empty table.
        <div className="t0-empty">
          <div className="t0-empty-h">No per-flow records at Tier&nbsp;0 — by&nbsp;design</div>
          <p>
            CanarySting keeps <b>no per-flow log of benign east-west traffic.</b> The Tier-0
            count is an aggregate the eBPF baseline folds into “normal” — not a record of
            who-talked-to-whom. Per-flow detail begins at <b>Tier&nbsp;1: the first decoy touch.</b>
          </p>
          <p className="t0-empty-sub">
            This is the zero-surveillance posture — we don’t retain traffic until it interacts
            with a decoy. To see the observed-normal volume in aggregate, open{' '}
            <Link href="/precision?since=1h">Bystanders / the observed funnel →</Link>. To see
            anomalous-but-untouched flows we surface without acting, open{' '}
            <Link href="/recon?since=1h">Recon →</Link>.
          </p>
        </div>
      ) : data.flows.length === 0 ? (
        <div className="faint mono">no sessions in window{minTier > 0 ? ` that reached ≥ ${tierName(minTier)}` : tierFilter >= 0 ? ` at tier ${tierFilter}` : ''}</div>
      ) : (
        <table className="flows-table">
          <thead>
            <tr>
              <th>cookie</th><th>tier</th><th>score</th><th>touches</th><th>last seen</th><th>time imposed</th><th>tokens</th>
            </tr>
          </thead>
          <tbody>
            {data.flows.map((f, i) => {
              const tcls = f.peak_tier >= 3 ? 't3' : f.peak_tier === 2 ? 't2' : '';
              const start = Math.floor(new Date(f.session_start).getTime() / 1000);
              return (
                <tr key={`${f.flow_id_hex}-${f.session_index}`} className={tcls}>
                  <td className="cookie">
                    <Link href={`/flow/${f.flow_id_hex}?since=${since}&session=${start}`}>{f.flow_id_hex}</Link>
                    {f.session_count > 1 && <span className="session-badge">{f.session_index}/{f.session_count}</span>}
                  </td>
                  <td className="tiercell">T{f.peak_tier} {f.verdict}</td>
                  <td>{f.score > 0 ? f.score.toFixed(2) : '—'}</td>
                  <td>{f.touch_count}</td>
                  <td>{localTime(f.last_seen)}</td>
                  <td>{f.total_cost.time_held_sec > 0 ? fmtTime(f.total_cost.time_held_sec) : '—'}</td>
                  <td>{f.total_cost.token_cost > 0 ? fmtK(f.total_cost.token_cost) : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {data && data.flows.length > 200 && <div className="faint mono" style={{ marginTop: 10 }}>showing {data.flows.length} sessions</div>}
    </>
  );
}
