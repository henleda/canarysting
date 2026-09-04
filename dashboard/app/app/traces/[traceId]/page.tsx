'use client';

import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'next/navigation';
import Breadcrumbs from '@/components/Breadcrumbs';
import TopBar from '@/components/TopBar';
import TraceWorkspace from '@/components/TraceWorkspace';
import { APIRequestError, MalformedResponseError, fetchTraceWorkspace } from '@/lib/api';
import type { Overview, TraceWorkspace as TraceWorkspaceView } from '@/lib/types';
import { useOverview, type DataStatus } from '@/lib/useOverview';

export default function TracePage() {
  const params = useParams<{ traceId: string | string[] }>();
  const traceID = useMemo(() => {
    const value = Array.isArray(params.traceId) ? params.traceId[0] : params.traceId;
    return decodeURIComponent(value ?? '');
  }, [params.traceId]);
  return <LiveTracePage traceID={traceID} />;
}

type TraceLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ready'; view: TraceWorkspaceView }
  | { kind: 'not-found' }
  | { kind: 'unavailable'; detail: string }
  | { kind: 'malformed' };

function LiveTracePage({ traceID }: { traceID: string }) {
  const { snapshot, status } = useOverview();
  const [traceState, setTraceState] = useState<TraceLoadState>({ kind: 'idle' });

  useEffect(() => {
    if (!traceID) {
      setTraceState({ kind: 'not-found' });
      return;
    }
    const controller = new AbortController();
    setTraceState({ kind: 'loading' });
    fetchTraceWorkspace(traceID, controller.signal)
      .then((value) => setTraceState({ kind: 'ready', view: value }))
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        if (cause instanceof APIRequestError && cause.status === 404) {
          setTraceState({ kind: 'not-found' });
        } else if (cause instanceof MalformedResponseError) {
          setTraceState({ kind: 'malformed' });
        } else {
          setTraceState({ kind: 'unavailable', detail: cause instanceof Error ? cause.message : 'trace request failed' });
        }
      });
    return () => controller.abort();
  }, [traceID]);

  return <TracePageFrame traceState={traceState} snapshot={snapshot} status={status} />;
}

function TracePageFrame({
  traceState,
  snapshot,
  status,
}: {
  traceState: TraceLoadState;
  snapshot: Overview | null;
  status: DataStatus;
}) {
  return (
    <div className="app-console">
      <TopBar snapshot={snapshot} status={status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Flows', href: '/flows?since=1h' }, { label: 'Security trace' }]} />
        </div>
        <p className="trace-load-announcer" role="status" aria-live="polite" aria-atomic="true">
          {traceState.kind === 'loading'
            ? 'Loading security trace'
            : traceState.kind === 'ready'
              ? `Security trace loaded: ${traceState.view.title}`
              : ''}
        </p>
        {traceState.kind === 'ready' ? (
          <TraceWorkspace view={traceState.view} />
        ) : traceState.kind === 'idle' || traceState.kind === 'loading' ? (
          <section className="detail-section">
            <h1>Loading security trace…</h1>
            <p className="dim">Waiting for the scoped read-only trace query.</p>
          </section>
        ) : traceState.kind === 'not-found' ? (
          <TraceLoadFailure
            heading="Security trace not found"
            impact="No trace is available for this immutable identifier in the authorized scope."
            nextStep="Verify the trace link and scope, then return to Flows to select an available trace."
          />
        ) : traceState.kind === 'malformed' ? (
          <TraceLoadFailure
            heading="Security trace could not be read"
            impact="The trace service returned a malformed response, so CanaryView did not render partial or inferred content."
            nextStep="Retry the request. If it persists, check the dashboard-backend trace route and projection logs."
          />
        ) : (
          <TraceLoadFailure
            heading="Security trace unavailable"
            impact={`The scoped trace service could not complete this read-only request (${traceState.detail}).`}
            nextStep="Retry after the trace query service recovers; no response action was changed."
          />
        )}
      </main>
    </div>
  );
}

function TraceLoadFailure({ heading, impact, nextStep }: { heading: string; impact: string; nextStep: string }) {
  return (
    <section className="detail-section trace-load-failure" role="alert" aria-live="assertive">
      <h1>{heading}</h1>
      <p>{impact}</p>
      <p><strong>Next step:</strong> {nextStep}</p>
    </section>
  );
}
