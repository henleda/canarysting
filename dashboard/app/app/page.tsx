'use client';

import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';
import TopBar from '@/components/TopBar';
import FleetSafety from '@/components/FleetSafety';
import KernelContainment from '@/components/KernelContainment';
import BystanderHealth from '@/components/BystanderHealth';
import LiveSpotlight from '@/components/LiveSpotlight';
import Credibility from '@/components/Credibility';

export default function OperationsPage() {
  // PRODUCTION render path: live snapshot + status from the dashboard-backend.
  const { snapshot: liveSnapshot, status } = useOverview();

  // DEV / VISUAL-VERIFICATION ONLY escape hatch. When NEXT_PUBLIC_FIXTURE === '1'
  // we render the static prototype fixture for pixel-fidelity checks. This is
  // NEVER the default/production path — when the env flag is unset, the app
  // always renders the live snapshot from useOverview() above.
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const snapshot = useFixture ? fixtureOverview : liveSnapshot;
  const effectiveStatus = useFixture ? 'live' : status;
  const armedCount = snapshot?.armed_flows?.distinct_count ?? 0;

  return (
    <div className="app">
      <TopBar snapshot={snapshot} status={effectiveStatus} />
      {/* Row 2 — THE FLEET WALL: "is the fleet safe?" answered full-width. The
          structural-zero claim + the three-rail fleet band (observed / armed /
          jailed, each on its own basis) + the distinct-flow funnel. */}
      <FleetSafety snapshot={snapshot} />
      {/* Row 3 — THE WOW: flow-precise containment in ONE eye-span: the attacker
          socket jailed in-kernel (left) right next to non-actioned same-host
          workloads still serving 200 (right). The dashboard-native bystander
          proof. KernelContainment links to /precision from its note. */}
      <div className="hero">
        <KernelContainment containment={snapshot?.kernel_containment} />
        <BystanderHealth bystanders={snapshot?.bystanders} />
      </div>
      {/* Row 4 — the demoted single-flow spotlight (1 of N active) beside the
          credibility proof (live M / baseline novelty / calibration). */}
      <div className="hero">
        <LiveSpotlight escalation={snapshot?.escalation} armedCount={armedCount} />
        <Credibility credibility={snapshot?.credibility} />
      </div>
    </div>
  );
}
