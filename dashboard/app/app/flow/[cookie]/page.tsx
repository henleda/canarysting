'use client';

import { useParams, useSearchParams } from 'next/navigation';
import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import FlowDetail from '@/components/FlowDetail';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { flowDetailURL } from '@/lib/api';
import { fixtureFlowDetail } from '@/lib/fixture';
import type { FlowDetail as FlowDetailT } from '@/lib/types';

export default function FlowPage() {
  const { snapshot, status } = useOverview();
  const params = useParams<{ cookie: string }>();
  const cookie = params.cookie;
  const { since, sinceSec } = useSince();
  const sessionParam = Number(useSearchParams().get('session') ?? 0);

  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<FlowDetailT>(flowDetailURL(cookie, since, sessionParam || undefined), sinceSec);
  const detail = useFixture ? fixtureFlowDetail : live.data;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Flow' }, { label: cookie }]} />
          <TimeRangeBar />
        </div>
        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}
        <FlowDetail detail={detail} loading={useFixture ? false : live.loading} cookie={cookie} />
      </main>
    </div>
  );
}
