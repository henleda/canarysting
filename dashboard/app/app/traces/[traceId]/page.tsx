'use client';

import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'next/navigation';
import Breadcrumbs from '@/components/Breadcrumbs';
import TopBar from '@/components/TopBar';
import TraceWorkspace from '@/components/TraceWorkspace';
import { fetchTraceWorkspace } from '@/lib/api';
import { fixtureTraceWorkspace } from '@/lib/fixture';
import type { Overview, TraceWorkspace as TraceWorkspaceView } from '@/lib/types';
import { useOverview, type DataStatus } from '@/lib/useOverview';

export default function TracePage() {
  const params = useParams<{ traceId: string | string[] }>();
  const traceID = useMemo(() => {
    const value = Array.isArray(params.traceId) ? params.traceId[0] : params.traceId;
    return decodeURIComponent(value ?? '');
  }, [params.traceId]);
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';

  if (useFixture) {
    const view = traceID === fixtureTraceWorkspace.trace_id ? fixtureTraceWorkspace : null;
    return <TracePageFrame view={view} error="" snapshot={null} status="live" fixture />;
  }

  return <LiveTracePage traceID={traceID} />;
}

function LiveTracePage({ traceID }: { traceID: string }) {
  const { snapshot, status } = useOverview();
  const [live, setLive] = useState<TraceWorkspaceView | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!traceID) return;
    const controller = new AbortController();
    setError('');
    fetchTraceWorkspace(traceID, controller.signal)
      .then((value) => setLive(value))
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'trace request failed');
      });
    return () => controller.abort();
  }, [traceID]);

  return <TracePageFrame view={live} error={error} snapshot={snapshot} status={status} fixture={false} />;
}

function TracePageFrame({
  view,
  error,
  snapshot,
  status,
  fixture,
}: {
  view: TraceWorkspaceView | null;
  error: string;
  snapshot: Overview | null;
  status: DataStatus;
  fixture: boolean;
}) {
  return (
    <div className="app-console">
      <TopBar snapshot={snapshot} status={status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Flows', href: '/flows?since=1h' }, { label: 'Security trace' }]} />
        </div>
        {error && <div className="errstrip">trace unavailable — {error}</div>}
        {view ? (
          <TraceWorkspace view={view} />
        ) : (
          <section className="detail-section" aria-live="polite">
            <h1>{fixture ? 'Fixture trace not found' : 'Loading security trace…'}</h1>
            <p className="faint">{fixture ? 'This fixture route does not match the bounded M2B.5 trace.' : 'Waiting for the scoped read-only trace query.'}</p>
          </section>
        )}
      </main>
    </div>
  );
}
