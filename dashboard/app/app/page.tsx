'use client';

import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';
import TopBar from '@/components/TopBar';
import LiveEscalation from '@/components/LiveEscalation';
import AttackerCost from '@/components/AttackerCost';
import KernelContainment from '@/components/KernelContainment';
import Credibility from '@/components/Credibility';
import AdversaryIntelligence from '@/components/AdversaryIntelligence';

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

  return (
    <div className="app">
      <TopBar snapshot={snapshot} status={effectiveStatus} />
      <div className="hero">
        <LiveEscalation escalation={snapshot?.escalation} />
        <AttackerCost cost={snapshot?.attacker_cost} real={snapshot?.real_attack_cost} />
      </div>
      <div className="band">
        <KernelContainment containment={snapshot?.kernel_containment} />
        <Credibility credibility={snapshot?.credibility} />
        <AdversaryIntelligence intel={snapshot?.adversary_intel} />
      </div>
    </div>
  );
}
