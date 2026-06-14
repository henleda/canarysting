'use client';

import Link from 'next/link';
import { fmtInt } from '@/lib/format';
import type { FlowFunnelView, Overview } from '@/lib/types';

// PrecisionView is the BYSTANDER / FALSE-POSITIVE PROOF — the answer to the #1
// CISO objection ("will it false-positive my traffic?").
//
// The claim is STRUCTURAL, not statistical: a flow is only ever actioned when it
// touches a planted decoy (CLAUDE.md rule 8 — deviation from baseline NEVER
// triggers a response). So traffic cannot be false-positived by construction. The
// live numbers are illustration, not the guarantee:
//   - observed  = baseline observe-folds (every completed east-west flow the eBPF
//                 baseline saw — non-armed, observed-normal traffic)
//   - decoy-touched / contained / jailed = the DISTINCT-flow funnel (sessions, not
//                 events; each flow once at its highest tier)
// Every actioned flow is in the funnel BECAUSE it touched a decoy. There is no
// per-flow benign list by design (we never persist benign identities — rules 8/9);
// the contrast (huge observed vs tiny actioned, all decoy-touchers) IS the proof.

// PrecisionFunnel is the SHARED structural-zero block: the giant 0 + the
// by-construction caption + the Rule-7 placement caveat. It is the single source
// of truth for the zero claim — BOTH /precision (via PrecisionView) and the home
// wall (via FleetSafety) render it, so the copy can never drift between them.
export function PrecisionFunnel() {
  return (
    <div className="precision-zero">
      <div className="pz-num">0</div>
      <div className="pz-cap">
        <div className="pz-k">actioned by anything other than a decoy touch</div>
        <div className="pz-sub">
          false positives are <b>structurally impossible</b>: only a planted-decoy touch can
          arm a response — never deviation from the learned baseline.{' '}
          <span className="pz-caveat">
            (Placement is careful, not infallible: a benign service that brushes a decoy can
            still be surfaced — see <Link href="/precision">/precision</Link>.)
          </span>
        </div>
      </div>
    </div>
  );
}

export default function PrecisionView({ snapshot, loading }: { snapshot: Overview | null; loading: boolean }) {
  if (!snapshot) {
    return <div className="faint mono">{loading ? 'WARMING UP…' : 'no data'}</div>;
  }
  const ladder = snapshot.escalation?.tier_ladder;
  const observed = ladder?.[0]?.count ?? 0;
  const funnel = snapshot.escalation?.flow_funnel;
  const jailedFlows = snapshot.kernel_containment?.jailed_flows ?? [];

  return (
    <>
      <section className="detail-section precision-hero">
        <PrecisionFunnel />
      </section>

      <section className="detail-section">
        <h3>observed → actioned · distinct flows</h3>
        <DistinctFunnel observed={observed} funnel={funnel} />
        <div className="flow-sub" style={{ marginTop: 12 }}>
          {fmtInt(observed)} flows observed (cumulative, since engine start) · {fmtInt(funnel?.jailed ?? 0)}{' '}
          jailed and {fmtInt(funnel?.contained ?? 0)} contained in this window — and every actioned flow
          reached the response pipeline by touching a decoy. Observation alone never acts.
        </div>
        {snapshot.escalation?.funnel_caption && (
          <div className="fs-note" style={{ marginTop: 6 }}>{snapshot.escalation.funnel_caption}</div>
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

// DistinctFunnel renders the four DISTINCT-flow stages by CUMULATIVE REACH:
// observed (cumulative, its own rail) › decoy-touched › contained › jailed
// (windowed, each flow counted in EVERY stage it reached — never per-event). The
// › arrows mean "reached at least", so flows that escalate through containment to
// the jail are counted in BOTH contained and jailed. Each step deep-links to the
// matching /flows view (contained uses the cumulative min_tier=2 cohort).
export function DistinctFunnel({ observed, funnel }: { observed: number; funnel: FlowFunnelView | undefined }) {
  const decoyTouched = funnel?.decoy_touched ?? 0;
  const contained = funnel?.contained ?? 0;
  const jailed = funnel?.jailed ?? 0;
  return (
    <div className="funnel">
      <FunnelStep cls="t0" n={observed} label="observed" note="cumulative · since start" href="/flows?tier=0&since=1h" title="cumulative observed-normal traffic since engine start (its own rail, never summed)" />
      <span className="funnel-arrow">›</span>
      <FunnelStep cls="t1" n={decoyTouched} label="decoy-touched" note="distinct · this window" href="/flows?since=1h" title="reached at least a decoy touch (Tier 1) this window" />
      <span className="funnel-arrow">›</span>
      <FunnelStep cls="t2" n={contained} label="contained" note="distinct · reached T2+" href="/flows?min_tier=2&since=1h" title="reached at least containment (Tier 2) this window" />
      <span className="funnel-arrow">›</span>
      <FunnelStep cls="t3" n={jailed} label="jailed" note="distinct · reached T3" href="/flows?tier=3&since=1h" title="reached the kernel jail (Tier 3) this window" />
    </div>
  );
}

function FunnelStep({ cls, n, label, note, href, title }: { cls: string; n: number; label: string; note: string; href: string; title?: string }) {
  return (
    <Link className={`funnel-step ${cls}`} href={href} title={title} style={{ color: 'inherit', textDecoration: 'none' }}>
      <div className="fs-num">{fmtInt(n)}</div>
      <div className="fs-label">{label}</div>
      <div className="fs-note">{note}</div>
    </Link>
  );
}
