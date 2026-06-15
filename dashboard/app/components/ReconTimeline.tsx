'use client';

import Link from 'next/link';
import { useSince } from './SinceProvider';
import type { ReconTimeline as ReconTimelineT } from '@/lib/types';

// ReconTimeline: every T1 (recon) touch, oldest-first (decision H). Recon is
// early-warning ("surfaced"/"recon"), never "detected". Escalation badges link
// to the flow's session.
export default function ReconTimeline({ data, loading }: { data: ReconTimelineT | null; loading: boolean }) {
  const { since } = useSince();
  if (!data) return <div className="faint mono">{loading ? 'WARMING UP…' : 'no recon data'}</div>;
  const rows = data.rows ?? []; // Go nil slice → JSON null; guard the map/length.
  if (rows.length === 0) return <div className="faint mono">no recon (T1) touches in window</div>;

  return (
    <>
      <div className="flow-sub" style={{ marginBottom: 14 }}>{data.total_recon} recon touches · oldest first</div>
      <table className="flows-table">
        <thead><tr><th>offset</th><th>cookie</th><th>canary</th><th>signal</th><th>severity</th><th>escalation</th></tr></thead>
        <tbody>
          {rows.map((r, i) => {
            // Deep-link to the EXACT session this T1 belongs to (a reused cookie has
            // several sessions; without &session= the detail lands on the latest one).
            const t = new Date(r.session_start).getTime();
            const start = Number.isFinite(t) ? Math.floor(t / 1000) : 0;
            const href =
              start > 0
                ? `/flow/${r.flow_id_hex}?since=${since}&session=${start}`
                : `/flow/${r.flow_id_hex}?since=${since}`;
            return (
              <tr key={i}>
                <td>{r.offset_label}</td>
                <td className="cookie"><Link href={href}>{r.flow_id_hex}</Link></td>
                <td>{r.canary_type || '—'}</td>
                <td>{r.description}</td>
                <td className={r.severity === 'surfaced' ? 't-mech' : 'faint'}>{r.severity}</td>
                <td>
                  {r.escalated ? (
                    <Link className={`esc-badge t${r.escalated_tier}`} href={href}>T{r.escalated_tier}</Link>
                  ) : (
                    <span className="faint">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}
