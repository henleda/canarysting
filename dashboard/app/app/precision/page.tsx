'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import PrecisionView from '@/components/PrecisionView';
import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';

// /precision — the bystander / false-positive proof. Live (SSE via useOverview),
// same data the home wall shows, reframed to answer "will it FP my traffic?".
export default function PrecisionPage() {
  const { snapshot: liveSnapshot, status } = useOverview();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const snapshot = useFixture ? fixtureOverview : liveSnapshot;

  return (
    <div className="app-console">
      <TopBar snapshot={snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Containment Precision' }]} />
        </div>
        <PrecisionView snapshot={snapshot} loading={!useFixture && status === 'loading'} />
      </main>
    </div>
  );
}
