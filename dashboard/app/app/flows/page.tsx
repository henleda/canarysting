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
  const params = useSearchParams();
  const tier = Number(params.get('tier') ?? -1);
  // min_tier (1..3) selects the cumulative-reach cohort (reached >= minTier); when
  // set it takes precedence over the exact tier filter (matches the backend).
  const minTierRaw = Number(params.get('min_tier') ?? 0);
  const minTier = minTierRaw >= 1 && minTierRaw <= 3 ? minTierRaw : 0;

  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<FlowsList>(flowsURL(tier, since, minTier), sinceSec);
  // FIXTURE path: filter the static list to the reached-cohort when min_tier is set.
  const fixtureData =
    minTier > 0
      ? { ...fixtureFlowsList, flows: (fixtureFlowsList.flows ?? []).filter((f) => f.peak_tier >= minTier) }
      : fixtureFlowsList;
  const data = useFixture ? fixtureData : live.data;

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
          <FlowsTable data={data} tierFilter={tier} minTier={minTier} loading={useFixture ? false : live.loading} />
        </section>
      </main>
    </div>
  );
}
