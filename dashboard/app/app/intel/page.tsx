'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import AdversaryIntelligence from '@/components/AdversaryIntelligence';
import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';

// Adversary Intelligence as its own page (moved off the Operations wall to
// declutter). The compounding moat: the attacker-cost KPI, recon early-warning,
// the adversary fingerprint, and the cross-customer network signal (with its
// "simulated peer data" disclosure). Bound to adversary_intel from the overview.
export default function IntelPage() {
  const { snapshot, status } = useOverview();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const snap = useFixture ? fixtureOverview : snapshot;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Adversary Intelligence' }]} />
          <TimeRangeBar />
        </div>
        {/* AdversaryIntelligence renders the band cell + .intel-grid (height:100%);
            .intel-standalone gives it a defined height off the fixed-height wall. */}
        <div className="detail-section intel-standalone" style={{ padding: 0, overflow: 'hidden' }}>
          <AdversaryIntelligence intel={snap?.adversary_intel} />
        </div>
      </main>
    </div>
  );
}
