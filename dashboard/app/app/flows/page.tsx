'use client';

import { useSearchParams } from 'next/navigation';
import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import FlowsTable from '@/components/FlowsTable';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { flowsURL } from '@/lib/api';
import { fixtureFlowsList } from '@/lib/fixture';
import type { FlowsList } from '@/lib/types';

export default function FlowsPage() {
  const { snapshot, status } = useOverview();
  const { since, sinceSec } = useSince();
  const tier = Number(useSearchParams().get('tier') ?? -1);

  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<FlowsList>(flowsURL(tier, since), sinceSec);
  const data = useFixture ? fixtureFlowsList : live.data;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Flows' }]} />
          <TimeRangeBar />
        </div>
        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}
        <section className="detail-section">
          <FlowsTable data={data} tierFilter={tier} loading={useFixture ? false : live.loading} />
        </section>
      </main>
    </div>
  );
}
