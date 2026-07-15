import Link from 'next/link';
import PanelHead from './PanelHead';
import { fmtBytes, fmtK, fmtTime } from '@/lib/format';
import type { FlowRow } from '@/lib/types';

// AttackerCostFlows: per-flow "attacker cost / context wasted" panel for the
// /intel page. Each row is one armed attacker flow (escalation.attacker_flows)
// showing what the sting layer imposed on it — time held, decoy bytes served,
// token cost, maze depth, and the last mechanism attributed. Deterred flows
// show a real mechanism (poison_field, fake_tree, token_bait, …); flows that
// escalated straight to kernel containment show "kernel-enforced" — the sting
// layer never got attribution, which is the honest "" sentinel from the
// backend (docs/INTELLIGENCE.md §5.3), not a missing value.
export default function AttackerCostFlows({ flows }: { flows: FlowRow[] | undefined }) {
  const rows = flows ?? [];
  return (
    <section className="detail-section">
      <PanelHead title="Attacker cost / context wasted" preTags={[{ label: 'per-flow' }]} />
      <p className="faint" style={{ fontSize: 11, marginBottom: 14 }}>
        context wasted per attacker flow — deterred flows bleed time/tokens then disengage; jailed flows
        escalate to kernel containment.
      </p>
      {rows.length === 0 ? (
        <div className="faint mono">no armed attacker flows in window</div>
      ) : (
        <table className="flows-table">
          <thead>
            <tr>
              <th>cookie</th>
              <th>tier</th>
              <th>time held</th>
              <th>decoy bytes</th>
              <th>tokens</th>
              <th>depth</th>
              <th>mechanism</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f, i) => {
              const tcls = f.peak_tier >= 3 ? 't3' : f.peak_tier === 2 ? 't2' : '';
              return (
                <tr key={`${f.flow_id_hex}-${f.session_index}-${i}`} className={tcls}>
                  <td className="cookie">
                    <Link href={`/flow/${f.flow_id_hex}?since=1h`}>{f.flow_id_hex}</Link>
                  </td>
                  <td className="tiercell">T{f.peak_tier} {f.verdict}</td>
                  <td>{fmtTime(f.total_cost.time_held_sec)}</td>
                  <td>{fmtBytes(f.total_cost.bytes_served)}</td>
                  <td>{fmtK(f.total_cost.token_cost)}</td>
                  <td>{f.max_depth > 0 ? f.max_depth : '—'}</td>
                  <td>{f.last_mechanism || 'kernel-enforced'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
