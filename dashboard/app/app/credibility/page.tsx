'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import Credibility from '@/components/Credibility';
import { useOverview } from '@/lib/useOverview';
import { fixtureOverview } from '@/lib/fixture';

// /credibility — the "real learned state" proof. Moved off the Operations wall
// (where its baseline-multiplier feature bars got clipped in the short Row 4)
// onto its own full-height page. Live (SSE via useOverview), same data the wall
// shows: live M / baseline novelty / calibration.
export default function CredibilityPage() {
  const { snapshot: liveSnapshot, status } = useOverview();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const snapshot = useFixture ? fixtureOverview : liveSnapshot;

  return (
    <div className="app-console">
      <TopBar snapshot={snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Credibility' }]} />
        </div>
        <Credibility credibility={snapshot?.credibility} />
      </main>
    </div>
  );
}
