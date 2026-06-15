import Link from 'next/link';
import { PrecisionFunnel, DistinctFunnel } from './PrecisionView';
import { WALL_LINK } from '@/lib/links';
import { fmtInt } from '@/lib/format';
import type { Overview } from '@/lib/types';

// FleetSafety is the NEW Row-2 hero: the wall-level "is the FLEET safe?" answer,
// reframed from the old single-flow spotlight.
//
// It leads with the structural-zero claim (the shared <PrecisionFunnel>, single
// source of truth) + a data-gated ⚠ sim-badge (snapshot.simulated — MAY-NOT #6),
// then the DISTINCT-flow funnel (observed › decoy-touched › contained › jailed) as
// the fleet-scale headline — each stage on its own basis and drilling to its exact
// cohort. (This replaced a redundant 3-stat band that duplicated the funnel's
// observed/armed/jailed numbers and made the hero too tall.) A blast-radius line
// ("contain the flow, not the host"), the verbatim two-rails caption, and a
// subordinate per-EVENT fraction line (the only place attacker_cost_fraction is
// allowed; never "of armed flows") close the hero.
export default function FleetSafety({ snapshot }: { snapshot: Overview | null }) {
  if (!snapshot) {
    return (
      <section className="fleet-safety">
        <div className="faint mono">NO ENGINE DATA — OBSERVING</div>
      </section>
    );
  }

  const observed = snapshot.escalation?.tier_ladder?.[0]?.count ?? 0;
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
      {/* ---- structural-zero safety claim + simulated disclosure ---- */}
      <div className="fs-top">
        <PrecisionFunnel />
        {snapshot.simulated && (
          <div className="sim-badge">
            ⚠ simulated traffic — this demo is driven by the simdriver, not a live customer fleet
          </div>
        )}
      </div>

      {/* ---- the fleet-scale read: the DISTINCT-flow funnel IS the headline
           (observed › decoy-touched › contained › jailed). Each stage carries its
           own basis and drills to its exact cohort — this replaced a redundant
           3-stat band that duplicated these same numbers. ---- */}
      <DistinctFunnel observed={observed} funnel={funnel} />

      {/* ---- blast-radius + verbatim two-rails caption + subordinate per-event fraction ---- */}
      <div className="fs-bottom">
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
        {funnelCaption && <div className="fs-note">{funnelCaption}</div>}
        <Link href="/cost?since=1h" className="fs-fraction" style={WALL_LINK}>
          <b>{fractionLabel}</b> of canary-interaction events met with active response, this window →
        </Link>
      </div>
    </section>
  );
}
