import Link from 'next/link';
import { PrecisionFunnel, DistinctFunnel } from './PrecisionView';
import { WALL_LINK } from './LiveEscalation';
import { fmtInt } from '@/lib/format';
import type { Overview } from '@/lib/types';

// FleetSafety is the NEW Row-2 hero: the wall-level "is the FLEET safe?" answer,
// reframed from the old single-flow spotlight. It has two strips.
//
// TOP STRIP — the structural-zero claim (the shared <PrecisionFunnel>, single
// source of truth) + a three-number fleet band, each headline on its OWN rail
// with its own basis chip (never one mixed denominator — MAY-NOT #5):
//   OBSERVED       = tier_ladder[0].count        cumulative since engine start
//   DISTINCT ARMED = armed_flows.distinct_count  distinct sessions, this window
//   JAILED         = jailed_flows.length         distinct sockets, this window
// A data-gated ⚠ sim-badge (snapshot.simulated — MAY-NOT #6) and a blast-radius
// line ("contain the flow, not the host") round out the top.
//
// BOTTOM STRIP — the DISTINCT-flow funnel (observed › decoy-touched › contained
// › jailed) + the verbatim two-rails caption + a subordinate per-EVENT fraction
// line (the only place attacker_cost_fraction is allowed; never "of armed flows").
export default function FleetSafety({ snapshot }: { snapshot: Overview | null }) {
  if (!snapshot) {
    return (
      <section className="fleet-safety">
        <div className="faint mono">NO ENGINE DATA — OBSERVING</div>
      </section>
    );
  }

  const observed = snapshot.escalation?.tier_ladder?.[0]?.count ?? 0;
  const armed = snapshot.armed_flows?.distinct_count ?? 0;
  // JAILED uses the per-session distinct-jailed funnel count (consistent with the
  // funnel strip and the /flows?tier=3 drill-down) — NOT the per-socket
  // kernel_containment.jailed_flows list (that stays the source for the WOW panel).
  const jailed = snapshot.escalation?.flow_funnel?.jailed ?? 0;
  const neighbors = snapshot.bystanders?.count ?? snapshot.bystanders?.flows?.length ?? 0;
  const funnel = snapshot.escalation?.flow_funnel;
  const funnelCaption = snapshot.escalation?.funnel_caption;
  const fraction = snapshot.attacker_cost?.attacker_cost_fraction ?? 0;
  // fmtPctLocal: 0.0019 -> "0.19%" with one significant place for tiny fractions.
  const fractionLabel = (fraction * 100).toFixed(fraction < 0.01 ? 2 : 1) + '%';

  return (
    <section className="fleet-safety">
      {/* ---- TOP STRIP: structural zero + fleet band ---- */}
      <div className="fs-top">
        <PrecisionFunnel />

        {snapshot.simulated && (
          <div className="sim-badge">
            ⚠ simulated traffic — this demo is driven by the simdriver, not a live customer fleet
          </div>
        )}

        <div className="fs-band">
          <Link href="/flows?tier=0&since=1h" className="fs-stat" style={WALL_LINK}>
            <div className="fs-scale-num t0">{fmtInt(observed)}</div>
            <div className="fs-stat-k">observed</div>
            <div className="fs-basis">cumulative, since engine start</div>
          </Link>
          <Link
            href="/flows?since=1h"
            className="fs-stat"
            style={WALL_LINK}
            title="cookies recycle → split per session at 10-min idle; these are sessions, not unique attackers"
          >
            <div className="fs-scale-num">{fmtInt(armed)}</div>
            <div className="fs-stat-k">decoy-armed flows</div>
            <div className="fs-basis">distinct armed sessions, this window</div>
          </Link>
          <Link href="/flows?tier=3&since=1h" className="fs-stat" style={WALL_LINK}>
            <div className="fs-scale-num t3">{fmtInt(jailed)}</div>
            <div className="fs-stat-k">jailed</div>
            <div className="fs-basis">distinct sockets dropped in-kernel, this window</div>
          </Link>
        </div>

        <div className="fs-blast">
          {neighbors > 0
            ? 'jail drops ' +
              fmtInt(jailed) +
              ' socket' +
              (jailed === 1 ? '' : 's') +
              ' — ' +
              fmtInt(neighbors) +
              ' same-host neighbor' +
              (neighbors === 1 ? '' : 's') +
              ' still serving 200 (below)'
            : 'jail drops one socket cookie — same-host neighbors keep serving (below)'}
        </div>
      </div>

      {/* ---- BOTTOM STRIP: the distinct-flow funnel ---- */}
      <div className="fs-bottom">
        <DistinctFunnel observed={observed} funnel={funnel} />
        {funnelCaption && <div className="fs-note">{funnelCaption}</div>}
        <Link href="/cost?since=1h" className="fs-fraction" style={WALL_LINK}>
          <b>{fractionLabel}</b> of canary-interaction events met with active response, this window →
        </Link>
      </div>
    </section>
  );
}
