'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import CostView from '@/components/CostView';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { costURL } from '@/lib/api';
import { fixtureCostBreakdown } from '@/lib/fixture';
import type { CostBreakdown } from '@/lib/types';

export default function CostPage() {
  const { snapshot, status } = useOverview();
  const { since, sinceSec } = useSince();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<CostBreakdown>(costURL(since), sinceSec);
  const data = useFixture ? fixtureCostBreakdown : live.data;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Attacker Cost' }]} />
          <TimeRangeBar />
        </div>
        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}
        <CostView data={data} loading={useFixture ? false : live.loading} />
      </main>
    </div>
  );
}
