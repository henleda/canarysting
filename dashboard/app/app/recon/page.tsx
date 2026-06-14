'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import ReconTimeline from '@/components/ReconTimeline';
import ReconLive from '@/components/ReconLive';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { reconURL } from '@/lib/api';
import { fixtureOverview, fixtureReconTimeline } from '@/lib/fixture';
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
        {/* The live negative-space surface: anomalous-from-baseline flows that
            touched NO decoy. We see them; we take no action (Rule 8). This is the
            "we watch the recon, we don't act on it" proof — the restraint that IS
            the zero-FP guarantee. */}
        <div className="detail-section" style={{ padding: 0, overflow: 'hidden' }}>
          <ReconLive recon={useFixture ? fixtureOverview.recon_live : snapshot?.recon_live} />
        </div>
        {/* The recon EVENT history: canary near-touches surfaced over the window. */}
        <section className="detail-section">
          <h3>Recon timeline · canary near-touches</h3>
          <ReconTimeline data={data} loading={useFixture ? false : live.loading} />
        </section>
      </main>
    </div>
  );
}
