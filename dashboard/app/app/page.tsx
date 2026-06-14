'use client';

import Link from 'next/link';
import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';
import TopBar from '@/components/TopBar';
import LiveEscalation from '@/components/LiveEscalation';
import AttackerCost from '@/components/AttackerCost';
import KernelContainment from '@/components/KernelContainment';
import Credibility from '@/components/Credibility';
import AdversaryIntelligence from '@/components/AdversaryIntelligence';
import Journey from '@/components/Journey';
import ReconLive from '@/components/ReconLive';
import BystanderHealth from '@/components/BystanderHealth';

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
        {/* The whole attacker-cost panel deep-links to the /cost breakdown.
            display:contents keeps the grid layout identical (the <a> box vanishes). */}
        <Link href="/cost?since=1h" style={{ display: 'contents', color: 'inherit', textDecoration: 'none' }}>
          <AttackerCost cost={snapshot?.attacker_cost} real={snapshot?.real_attack_cost} />
        </Link>
      </div>
      {/* THE WOW — flow-precise containment in ONE eye-span: the attacker socket
          jailed in-kernel (left) right next to legitimate same-host workloads
          still serving 200 (right). This is the dashboard-native bystander proof
          that replaces the old terminal-curl. KernelContainment links to
          /precision from its note (inner cookie links, so not one anchor). */}
      <div className="hero">
        <KernelContainment containment={snapshot?.kernel_containment} />
        <BystanderHealth bystanders={snapshot?.bystanders} />
      </div>
      <div className="journey-row">
        <Journey journey={snapshot?.journey} />
      </div>
      <div className="journey-row">
        <ReconLive recon={snapshot?.recon_live} />
      </div>
      <div className="band">
        <Credibility credibility={snapshot?.credibility} />
        <AdversaryIntelligence intel={snapshot?.adversary_intel} />
      </div>
    </div>
  );
}
