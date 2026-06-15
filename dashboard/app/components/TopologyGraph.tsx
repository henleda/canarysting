'use client';

import { useMemo } from 'react';
import type { TopologyView, TopologyNode, TopologyEdge } from '@/lib/types';
import { fmtBytes, fmtInt } from '@/lib/format';

// TopologyGraph renders the learned east-west attack surface (F1) as a
// hand-rolled SVG — no graph library, matching the dashboard's house style.
//
// Layout is DETERMINISTIC by node kind (left-to-right columns), so the same data
// always lays out the same way and reads cleanly at the wall size:
//   - col 0 (left):     CALLERS (+ unknown / touch-src) — the initiators
//   - col 1 (entry):    INGRESS gateway (kind external) — the front door
//   - col 2 (middle):   SERVICES — the learned mesh, node radius ~ flow volume
//   - col 3 (right):    CANARY DECOYS in a DASHED negative-space ring the legit
//                       graph never touches (zero learned in-edges by design)
// Callers -> ingress -> services reads left-to-right; an arrowhead on each edge
// carries the direction explicitly.
//
// Edge classes carry the meaning:
//   - learned    -> solid, thickness scaled by flow_count (the real observed mesh)
//   - live       -> faint dashed (a deviant/novel pivot — observe-only, never arms)
//   - decoy_touch-> BRIGHT red, the only edge that crosses into the ring (the money
//                   shot: "an attacker reached into the negative space")
//
// HONESTY (Rule 8 / staged_labels): nothing here arms a response; the SHAPE/edges
// are real observed traffic, only the NAMES are operator-registry metadata.

// LEFT_PAD is dead negative space to the LEFT of the caller column so caller
// labels (anchored 'end', e.g. "reporting-worker") get room to breathe inside the
// viewBox instead of clipping off the left edge. It shifts the viewBox origin only
// — every column X below is unchanged, so the columns-by-kind layout is identical.
const LEFT_PAD = 160;
// RIGHT_PAD mirrors LEFT_PAD on the right so the decoy labels (anchored 'start' to
// the right of the ring, e.g. "planted_credential") get room inside the viewBox
// instead of clipping off the right edge. Like LEFT_PAD it only extends the viewBox,
// not any column X.
const RIGHT_PAD = 150;
const W = 1040;
const COL_CALLER_X = 120;
const COL_INGRESS_X = 320;
const COL_SERVICE_X = 600;
const COL_DECOY_X = 910;
const TOP = 70;
const ROW = 96; // vertical spacing between nodes in a column
const SERVICE_R_MIN = 16;
const SERVICE_R_MAX = 34;
const NODE_R = 18; // caller / ingress / decoy base radius

// X of the decoy-ring negative-space boundary (midway between services and decoys).
const NEGSPACE_X = (COL_SERVICE_X + COL_DECOY_X) / 2;
// The decoy ring sits in its own band to the right of the boundary; the faint band
// fill makes the "negative space the legit mesh never serves" read as a region, not
// just a dashed line. Right edge tracks the viewBox so the band runs to the margin.
const RING_BAND_X1 = NEGSPACE_X + 26;

type Placed = TopologyNode & { x: number; y: number; r: number; volume: number };

// Columns by kind: callers (+ unknown/touch-src) on the left as initiators; the
// ingress gateway (kind external) in its own entry column so caller->ingress and
// ingress->service edges run inter-column (and bow + arrow correctly); services in
// the middle; decoys in the ring.
function isCaller(n: TopologyNode): boolean {
  return n.kind !== 'service' && n.kind !== 'decoy' && n.kind !== 'external';
}
function isIngress(n: TopologyNode): boolean {
  return n.kind === 'external';
}

export default function TopologyGraph({ view }: { view: TopologyView }) {
  const { placed, byId, height } = useMemo(() => layout(view), [view]);
  const hasIngress = placed.some((p) => p.kind === 'external');

  // Edge thickness scales with flow_count, normalized to the busiest learned edge.
  const maxFlow = useMemo(
    () => Math.max(1, ...view.edges.filter((e) => e.class === 'learned').map((e) => e.flow_count)),
    [view.edges],
  );

  const touchCount = view.edges.filter((e) => e.class === 'decoy_touch').length;
  const liveCount = view.edges.filter((e) => e.class === 'live').length;
  // Count learned edges directly (not by subtraction) so a future edge class is
  // surfaced as uncounted rather than silently folded into the 'learned' tally.
  const learnedCount = view.edges.filter((e) => e.class === 'learned').length;

  return (
    <div className="topo-wrap">
      <svg
        className="topo-svg"
        viewBox={`${-LEFT_PAD} 0 ${W + LEFT_PAD + RIGHT_PAD} ${height}`}
        role="img"
        aria-label="Learned east-west topology: callers, services, and canary decoys"
        preserveAspectRatio="xMidYMin meet"
      >
        {/* Directed-edge arrowhead. context-stroke makes it inherit each edge's
            class color (learned/live/touch) so direction reads per edge. A slightly
            slimmer head with refX at the tip keeps it crisp where it meets the rim. */}
        <defs>
          <marker
            id="topo-arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto"
          >
            <path d="M0,1.5 L9,5 L0,8.5 z" fill="context-stroke" opacity="0.95" />
          </marker>
        </defs>

        {/* The decoy ring's negative-space BAND — a faint canary wash to the right of
            the dashed boundary so the ring reads as a separate region the legit mesh
            never serves, not just a column. Drawn first, behind everything. */}
        <rect
          x={RING_BAND_X1}
          y={42}
          width={W + RIGHT_PAD - RING_BAND_X1}
          height={height - 42 - 12}
          className="topo-ring-band"
          rx={8}
        />

        {/* Column headers, with a hairline baseline that anchors them as a row. */}
        <line x1={-LEFT_PAD + 12} y1={40} x2={W + RIGHT_PAD} y2={40} className="topo-header-rule" />
        <text x={COL_CALLER_X} y={26} className="topo-col-h" textAnchor="middle">
          CALLERS
        </text>
        {hasIngress && (
          <text x={COL_INGRESS_X} y={26} className="topo-col-h" textAnchor="middle">
            INGRESS
          </text>
        )}
        <text x={COL_SERVICE_X} y={26} className="topo-col-h" textAnchor="middle">
          SERVICES · learned mesh
        </text>
        <text x={COL_DECOY_X} y={26} className="topo-col-h topo-col-h-decoy" textAnchor="middle">
          DECOY RING
        </text>
        <text x={COL_DECOY_X} y={37} className="topo-col-sub topo-col-sub-decoy" textAnchor="middle">
          negative space · zero learned in-edges
        </text>

        {/* The dashed negative-space boundary the legit graph never crosses. */}
        <line
          x1={NEGSPACE_X}
          y1={42}
          x2={NEGSPACE_X}
          y2={height - 16}
          className="topo-negspace-line"
        />

        {/* Edges first (under the nodes). */}
        <g className="topo-edges">
          {view.edges.map((e, i) => {
            const a = byId.get(e.src_id);
            const b = byId.get(e.dst_id);
            if (!a || !b) return null; // an edge to a node we did not place — skip
            return <EdgeLine key={`e-${i}`} a={a} b={b} edge={e} maxFlow={maxFlow} />;
          })}
        </g>

        {/* Nodes on top. */}
        <g className="topo-nodes">
          {placed.map((n) => (
            <NodeMark key={n.id} n={n} />
          ))}
        </g>
      </svg>

      <Legend touchCount={touchCount} liveCount={liveCount} learnedCount={learnedCount} />
    </div>
  );
}

// layout assigns each node a deterministic (x,y,r). Columns are sorted by id so the
// arrangement is stable across polls; service radius scales with total volume
// (in + out flow_count) through it.
function layout(view: TopologyView): { placed: Placed[]; byId: Map<string, Placed>; height: number } {
  // Per-node total flow volume (for service sizing).
  const vol = new Map<string, number>();
  for (const e of view.edges) {
    if (e.class !== 'learned') continue;
    vol.set(e.src_id, (vol.get(e.src_id) ?? 0) + e.flow_count);
    vol.set(e.dst_id, (vol.get(e.dst_id) ?? 0) + e.flow_count);
  }
  const maxVol = Math.max(1, ...Array.from(vol.values()));

  const callers = view.nodes.filter(isCaller).sort((a, b) => a.id.localeCompare(b.id));
  const ingress = view.nodes.filter(isIngress).sort((a, b) => a.id.localeCompare(b.id));
  const services = view.nodes
    .filter((n) => n.kind === 'service')
    .sort((a, b) => (vol.get(b.id) ?? 0) - (vol.get(a.id) ?? 0) || a.id.localeCompare(b.id));
  const decoys = view.nodes.filter((n) => n.kind === 'decoy').sort((a, b) => a.id.localeCompare(b.id));

  const placed: Placed[] = [];
  const place = (n: TopologyNode, x: number, y: number, r: number) => {
    const p: Placed = { ...n, x, y, r, volume: vol.get(n.id) ?? 0 };
    placed.push(p);
  };

  // Center each column vertically against the tallest column for a balanced look.
  const rows = Math.max(callers.length, ingress.length, services.length, decoys.length, 1);
  const colHeight = (rows - 1) * ROW;
  const yFor = (idx: number, count: number) =>
    TOP + colHeight / 2 - ((count - 1) * ROW) / 2 + idx * ROW;

  callers.forEach((n, i) => place(n, COL_CALLER_X, yFor(i, callers.length), NODE_R));
  ingress.forEach((n, i) => place(n, COL_INGRESS_X, yFor(i, ingress.length), NODE_R));
  services.forEach((n, i) => {
    const v = vol.get(n.id) ?? 0;
    const r = SERVICE_R_MIN + (SERVICE_R_MAX - SERVICE_R_MIN) * Math.sqrt(v / maxVol);
    place(n, COL_SERVICE_X, yFor(i, services.length), r);
  });
  decoys.forEach((n, i) => place(n, COL_DECOY_X, yFor(i, decoys.length), NODE_R));

  const byId = new Map(placed.map((p) => [p.id, p]));
  const height = TOP + colHeight + TOP;
  return { placed, byId, height };
}

// EdgeLine draws one directed adjacency as a curved path with an arrowhead, styled
// by class. Learned edges scale stroke width with flow_count; live is faint dashed;
// decoy_touch is the bright red money-shot edge.
function EdgeLine({ a, b, edge, maxFlow }: { a: Placed; b: Placed; edge: TopologyEdge; maxFlow: number }) {
  // Cubic curve, bowed horizontally between columns for legibility. End the curve at
  // the destination node's EDGE (not its center) so the arrowhead sits at the rim,
  // visible rather than hidden under the circle. The curve LEAVES the source and
  // ARRIVES at the destination horizontally (control points share a.y then b.y), so
  // edges depart/land flat against the rim — this untangles the caller->ingress fan
  // and the ingress->service funnel where many edges share one endpoint. The control
  // handles are pushed out (0.55 of the span) for a softer, more deliberate bow.
  const dirX = b.x >= a.x ? 1 : -1;
  const endX = b.x - dirX * (b.r + 3);
  const startX = a.x + dirX * (a.r + 1);
  const handle = (endX - startX) * 0.55;
  const c1x = startX + handle;
  const c2x = endX - handle;
  const d = `M ${startX} ${a.y} C ${c1x} ${a.y}, ${c2x} ${b.y}, ${endX} ${b.y}`;

  let cls = 'topo-edge topo-edge-learned';
  let width = 1;
  if (edge.class === 'learned') {
    width = 1 + 4.5 * Math.sqrt(edge.flow_count / maxFlow);
  } else if (edge.class === 'live') {
    cls = 'topo-edge topo-edge-live';
    width = 1.6;
  } else if (edge.class === 'decoy_touch') {
    cls = 'topo-edge topo-edge-touch';
    width = 2.6;
  }

  const title =
    edge.class === 'decoy_touch'
      ? `DECOY TOUCH · ${shortId(edge.src_id)} → ${shortId(edge.dst_id)}`
      : `${shortId(edge.src_id)} → ${shortId(edge.dst_id)} :${edge.port} · ${fmtInt(edge.flow_count)} flows · ${fmtBytes(edge.bytes)}`;

  return (
    <path d={d} className={cls} style={{ strokeWidth: width }} fill="none" markerEnd="url(#topo-arrow)">
      <title>{title}</title>
    </path>
  );
}

// NodeMark draws a node circle + label, colored by kind. Decoys are dashed rings.
// Labels carry a stroke-painted halo (paint-order: stroke) so they stay legible when
// an edge runs underneath — this is the lever for the dense service column where
// edges fan into the next tier right past the labels.
function NodeMark({ n }: { n: Placed }) {
  const kindClass = `topo-node topo-node-${n.kind}`;
  const labelLeft = n.kind === 'caller' || n.kind === 'unknown' || n.kind === 'external';
  const labelDx = labelLeft ? -(n.r + 9) : n.r + 9;
  const anchor = labelLeft ? 'end' : 'start';
  const sub =
    n.kind === 'service'
      ? `${fmtInt(n.volume)} flows`
      : n.kind === 'decoy'
        ? 'no learned in-edges'
        : '';
  // With a sub-label, raise the name and drop the sub so the pair centers on the node.
  const labelY = sub ? n.y - 5 : n.y;
  const subY = n.y + 8;

  return (
    <g className={kindClass}>
      <circle cx={n.x} cy={n.y} r={n.r} className={`topo-node-c topo-node-c-${n.kind}`}>
        <title>{`${n.label} · ${n.kind}`}</title>
      </circle>
      <text x={n.x + labelDx} y={labelY} textAnchor={anchor} className="topo-node-label">
        {n.label}
      </text>
      {sub && (
        <text x={n.x + labelDx} y={subY} textAnchor={anchor} className="topo-node-sub">
          {sub}
        </text>
      )}
    </g>
  );
}

function Legend({ learnedCount, liveCount, touchCount }: { learnedCount: number; liveCount: number; touchCount: number }) {
  return (
    <div className="topo-legend">
      <span className="topo-legend-item">
        <span className="topo-swatch topo-swatch-learned" />
        <span className="topo-legend-label">learned</span>
        <span className="topo-legend-count">{learnedCount} edges</span>
      </span>
      <span className="topo-legend-item">
        <span className="topo-swatch topo-swatch-live" />
        <span className="topo-legend-label">live / deviant</span>
        <span className="topo-legend-count">{liveCount} · observe-only, never arms</span>
      </span>
      <span className="topo-legend-item">
        <span className="topo-swatch topo-swatch-touch" />
        <span className="topo-legend-label">decoy touch</span>
        <span className="topo-legend-count">{touchCount} · the only edge into the ring</span>
      </span>
      <span className="topo-legend-item">
        <span className="topo-swatch topo-swatch-decoy" />
        <span className="topo-legend-label">canary decoy</span>
        <span className="topo-legend-count">negative space</span>
      </span>
    </div>
  );
}

// shortId trims the id prefix for tooltips. For the IDENTITY-keyed named-node scheme
// "id:<kind>:<label>" it returns just the label ("id:service:frontend" -> "frontend");
// for the decoy/touch/ip schemes it strips the first prefix segment
// ("decoy:fake_secret" -> "fake_secret", "ip:127.0.0.9:50051" -> "127.0.0.9:50051").
function shortId(id: string): string {
  if (id.startsWith('id:')) {
    const i = id.indexOf(':', 3);
    return i >= 0 ? id.slice(i + 1) : id.slice(3);
  }
  const i = id.indexOf(':');
  return i >= 0 ? id.slice(i + 1) : id;
}
