'use client';

import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import TopologyGraph from '@/components/TopologyGraph';
import { useOverview } from '@/lib/useOverview';
import { usePolling } from '@/lib/usePolling';
import { topologyURL } from '@/lib/api';
import { fixtureTopology } from '@/lib/fixture';
import type { TopologyView } from '@/lib/types';

// /topology — F1 learned east-west attack surface. The CURRENT-state graph (the
// aggregator's live in-memory topology map + the canary decoy ring + recent
// source->decoy touch edges), not a windowed view, so there is no time range.
//
// READ-SIDE ONLY (Rule 8): nothing on this page arms a response — it draws what
// was observed. The decoy ring is negative space the legit mesh never serves; the
// only edge that ever crosses into it is a REAL adapter-recognized canary touch.
//
// HONESTY (staged_labels): the graph SHAPE, edges, and volumes are real observed
// traffic; only the human-readable NAMES come from the operator registry. The
// persistent caption (backend pre-rendered into `caption`) says so verbatim.

// Fallback captions if the backend ever omits the pre-rendered one (it should
// not). Picked by staged_labels so the badge and the copy never contradict each
// other: with an operator registry loaded the NAMES are staged; without one the
// nodes fall back to raw IPs and we say exactly that.
const STAGED_CAPTION =
  'Staged-range view: node NAMES come from the operator registry; the engine baseline is hashed. The graph SHAPE/edges are real observed traffic. In production this is drawn from your own service registry, not ours.';
const UNLABELED_CAPTION =
  'No node-name registry loaded: nodes are labeled by raw IP. The graph SHAPE/edges are real observed traffic — load an operator registry to attach service names.';

export default function TopologyPage() {
  const { snapshot, status } = useOverview();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  // 30s poll: the topology evolves slowly (folded learned edges), so it does not
  // need the live SSE cadence. sinceSec is unused by the endpoint but the hook
  // signature wants it — pass a large value so the poll interval is the slow one.
  const live = usePolling<TopologyView>(topologyURL(), 99999, { intervalMs: 30000 });
  const view: TopologyView | null = useFixture ? fixtureTopology : live.data;

  // Degraded path (no operator registry): staged_labels=false. Drive both the
  // badge and the fallback caption off it so a yellow 'staged-range' badge never
  // sits beside copy that says nodes are raw IPs.
  const staged = view?.staged_labels ?? true;
  const caption = view?.caption || (staged ? STAGED_CAPTION : UNLABELED_CAPTION);

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Attack Surface' }]} />
        </div>

        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}

        <section className="detail-section">
          <h3>Learned east-west topology · legit services vs decoys</h3>

          {/* The persistent HONESTY fence. Render verbatim, always — never imply the
              engine natively knows service names, and never imply the map auto-acts. */}
          <div className="topo-caption" role="note">
            <span className="topo-caption-badge">{staged ? 'staged-range' : 'topology'}</span>
            {caption}
          </div>

          {view && view.nodes.length > 0 ? (
            <TopologyGraph view={view} />
          ) : (
            <div className="topo-empty faint">
              {!useFixture && live.loading
                ? 'loading topology…'
                : 'no learned topology yet — the engine has not folded any east-west edges in this scope.'}
            </div>
          )}

          {/* Rule 8 restatement under the graph: this is a view, not a trigger. */}
          <div className="topo-rule8">
            Read-side only. Observation never arms a response (Rule 8) — only a canary touch does. This graph is local
            to the deployment; raw addresses never cross a boundary (Rule 9).
          </div>
        </section>
      </main>
    </div>
  );
}
