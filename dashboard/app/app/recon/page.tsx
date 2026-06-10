'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import ReconTimeline from '@/components/ReconTimeline';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { reconURL } from '@/lib/api';
import { fixtureReconTimeline } from '@/lib/fixture';
import type { ReconTimeline as ReconTimelineT } from '@/lib/types';

export default function ReconPage() {
  const { snapshot, status } = useOverview();
  const { since, sinceSec } = useSince();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<ReconTimelineT>(reconURL(since), sinceSec);
  const data = useFixture ? fixtureReconTimeline : live.data;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Recon' }]} />
          <TimeRangeBar />
        </div>
        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}
        <section className="detail-section">
          <ReconTimeline data={data} loading={useFixture ? false : live.loading} />
        </section>
      </main>
    </div>
  );
}
