'use client';

import { useParams, useSearchParams } from 'next/navigation';
import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TimeRangeBar from '@/components/TimeRangeBar';
import FlowDetail from '@/components/FlowDetail';
import Journey from '@/components/Journey';
import TierLadder from '@/components/TierLadder';
import { useOverview } from '@/lib/useOverview';
import { useSince } from '@/components/SinceProvider';
import { usePolling } from '@/lib/usePolling';
import { flowDetailURL } from '@/lib/api';
import { fixtureFlowDetail, fixtureOverview } from '@/lib/fixture';
import type { FlowDetail as FlowDetailT } from '@/lib/types';

// Compare two socket-cookie hexes ("0x118") tolerant of casing.
function sameCookie(a: string | undefined, b: string | undefined): boolean {
  return !!a && !!b && a.toLowerCase() === b.toLowerCase();
}

export default function FlowPage() {
  const { snapshot, status } = useOverview();
  const params = useParams<{ cookie: string }>();
  const cookie = params.cookie;
  const { since, sinceSec } = useSince();
  const sessionParam = Number(useSearchParams().get('session') ?? 0);

  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  const live = usePolling<FlowDetailT>(flowDetailURL(cookie, since, sessionParam || undefined), sinceSec);
  const detail = useFixture ? fixtureFlowDetail : live.data;
  const ov = useFixture ? fixtureOverview : snapshot;

  // selectCurrentFlow constraint: the wall's "current flow" elements (the
  // attacker-journey ribbon + the tier ladder) are only meaningful for the flow
  // the engine is currently tracking. Render them here ONLY when the cookie being
  // viewed IS that current flow — otherwise the timeline + M-breakdown in this
  // flow's own payload are the truth. This is where the wall-demoted journey +
  // ladder are preserved.
  const isCurrentFlow = sameCookie(cookie, ov?.escalation?.flow?.flow_id_hex);
  const journey = ov?.journey;
  const showJourney = isCurrentFlow && !!journey?.present && sameCookie(cookie, journey.flow_id_hex);
  const ladder = ov?.escalation?.tier_ladder;

  // A 404 from /api/flow/{cookie} means there is no per-flow record: bystanders
  // are non-armed Tier-0 flows and the events store only persists Tier>=1, so
  // there is nothing to show. Render an HONEST empty-state instead of an error —
  // a bystander having no dossier is the proof it was never actioned.
  const noRecord = !useFixture && !!live.error && live.error.includes('404') && !detail;

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Flow' }, { label: cookie }]} />
          <TimeRangeBar />
        </div>
        {!useFixture && live.error && !live.error.includes('404') && (
          <div className="errstrip">stale — {live.error}</div>
        )}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}

        {noRecord ? (
          <section className="detail-section">
            <div className="t0-empty">
              <div className="t0-empty-h">No per-flow record for {cookie}</div>
              <p>CanarySting keeps per-flow detail only for flows that <b>touched a decoy and armed a response</b> (Tier&nbsp;1+). This cookie has no record in this window.</p>
              <p className="t0-empty-sub">Non-armed flows — including the same-host <b>bystanders still serving</b> on the wall — are observed but never logged per flow: a <b>zero-surveillance posture</b> (Rules 8/9). A bystander having no dossier here is the proof it was never actioned. <a href="/">← back to Operations</a></p>
            </div>
          </section>
        ) : (
          <>
            {/* The attacker-journey ribbon — current flow only (selectCurrentFlow).
                Journey renders its own panel section. */}
            {showJourney && <Journey journey={journey} />}

            {/* The full per-flow detail: timeline + M-breakdown + fingerprint + cost. */}
            <FlowDetail detail={detail} loading={useFixture ? false : live.loading} cookie={cookie} />

            {/* The tier ladder — current flow only. Demoted from the wall; preserved
                here so the fleet-wide tier climb stays reachable for this flow. */}
            {isCurrentFlow && ladder && (
              <section className="detail-section">
                <h3>tier distribution · canary-interacting flows</h3>
                <TierLadder ladder={ladder} />
              </section>
            )}
          </>
        )}
      </main>
    </div>
  );
}
