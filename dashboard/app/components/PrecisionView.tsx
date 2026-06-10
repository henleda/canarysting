'use client';

import Link from 'next/link';
import { fmtInt } from '@/lib/format';
import type { Overview } from '@/lib/types';

// PrecisionView is the BYSTANDER / FALSE-POSITIVE PROOF — the answer to the #1
// CISO objection ("will it false-positive my legitimate traffic?").
//
// The claim is STRUCTURAL, not statistical: a flow is only ever actioned when it
// touches a planted decoy (CLAUDE.md rule 8 — deviation from baseline NEVER
// triggers a response). So legitimate traffic cannot be false-positived by
// construction. The live numbers are illustration, not the guarantee:
//   - observed  = baseline observe-folds (every completed east-west flow the eBPF
//                 baseline saw — overwhelmingly legitimate traffic)
//   - flagged   = T1 (tagged, watched; no punitive effect)
//   - actioned  = T2 contain + T3 jail (the only punitive tiers)
// Every actioned flow is in the funnel BECAUSE it touched a decoy. There is no
// per-flow benign list by design (we never persist benign identities — rules 8/9);
// the contrast (huge observed vs tiny actioned, all decoy-touchers) IS the proof.
export default function PrecisionView({ snapshot, loading }: { snapshot: Overview | null; loading: boolean }) {
  if (!snapshot) {
    return <div className="faint mono">{loading ? 'WARMING UP…' : 'no data'}</div>;
  }
  const ladder = snapshot.escalation?.tier_ladder;
  const observed = ladder?.[0]?.count ?? 0;
  const flagged = ladder?.[1]?.count ?? 0;
  const contained = ladder?.[2]?.count ?? 0;
  const jailed = ladder?.[3]?.count ?? 0;
  const actioned = contained + jailed;
  const jailedFlows = snapshot.kernel_containment?.jailed_flows ?? [];

  return (
    <>
      <section className="detail-section precision-hero">
        <div className="precision-zero">
          <div className="pz-num">0</div>
          <div className="pz-cap">
            <div className="pz-k">legitimate flows actioned</div>
            <div className="pz-sub">
              false positives are <b>structurally impossible</b>: only a planted-decoy touch
              can trigger a response — never deviation from the learned baseline.
            </div>
          </div>
        </div>
      </section>

      <section className="detail-section">
        <h3>observed → actioned</h3>
        <div className="funnel">
          <FunnelStep cls="t0" n={observed} label="observed" note="cumulative · since start" />
          <span className="funnel-arrow">›</span>
          <FunnelStep cls="t1" n={flagged} label="flagged" note="T1 · window · tagged" />
          <span className="funnel-arrow">›</span>
          <FunnelStep cls="t2" n={contained} label="contained" note="T2 · window · rate-limit/tarpit" />
          <span className="funnel-arrow">›</span>
          <FunnelStep cls="t3" n={jailed} label="jailed" note="T3 · window · kernel drop" />
        </div>
        <div className="flow-sub" style={{ marginTop: 12 }}>
          {fmtInt(observed)} flows observed (cumulative, since engine start) · {fmtInt(actioned)}{' '}
          actioned in this window (contain + jail) — and every actioned flow reached the response
          pipeline by touching a decoy. Observation alone never acts.
        </div>
        {snapshot.escalation?.ladder_caption && (
          <div className="fs-note" style={{ marginTop: 6 }}>{snapshot.escalation.ladder_caption}</div>
        )}
      </section>

      <section className="detail-section">
        <h3>what was actioned · cookie-precise containment</h3>
        {jailedFlows.length === 0 ? (
          <div className="faint mono">no sockets jailed in window — kernel enforcement idle, observing.</div>
        ) : (
          <table className="flows-table">
            <thead><tr><th>cookie</th><th>tier</th><th>verdict</th></tr></thead>
            <tbody>
              {jailedFlows.map((f) => (
                <tr key={f.flow_id_hex} className="t3">
                  <td className="cookie"><Link href={`/flow/${f.flow_id_hex}?since=1h`}>{f.flow_id_hex}</Link></td>
                  <td className="tiercell">T{f.tier}</td>
                  <td>{f.verdict || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="precis-note" style={{ marginTop: 12 }}>
          the offending socket&apos;s egress is dropped in-kernel by its socket cookie.{' '}
          <b>bystanders on the same host keep working</b> — we contain the flow, not the host,
          not the IP, not the service.
        </div>
      </section>
    </>
  );
}

function FunnelStep({ cls, n, label, note }: { cls: string; n: number; label: string; note: string }) {
  return (
    <div className={`funnel-step ${cls}`}>
      <div className="fs-num">{fmtInt(n)}</div>
      <div className="fs-label">{label}</div>
      <div className="fs-note">{note}</div>
    </div>
  );
}
