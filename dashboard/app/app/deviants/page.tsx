'use client';

import { useState } from 'react';
import TopBar from '@/components/TopBar';
import Breadcrumbs from '@/components/Breadcrumbs';
import { useOverview } from '@/lib/useOverview';
import { usePolling } from '@/lib/usePolling';
import { deviantsURL } from '@/lib/api';
import { fixtureDeviants } from '@/lib/fixture';
import { fmtAgo, fmtPct } from '@/lib/format';
import type { DeviantsView, DeviantRow, DeviantEndpoint } from '@/lib/types';

// /deviants — the F2 deviant hunting log. A ranked list of flows that DEVIATED from
// the learned baseline (an unfamiliar identity, a new adjacency, a volume/cadence
// shift) but touched NO canary — so NOTHING was armed (Rule 8). It is the
// "skilled-mover" surface: the careful operator who never trips a tripwire still
// leaves a baseline-deviation fingerprint we LOG (never action) for hunting.
//
// READ-SIDE ONLY (Rule 8): every row is, by construction, a flow that touched no
// canary; surfacing it on a page takes no action. These are NOT "confirmed
// adversaries" — they are anomalies logged for a human to hunt.
//
// CURRENT-state (non-windowed) view like /topology: 30s poll, no TimeRangeBar.
// HONESTY: the persistent caption (backend pre-rendered into `caption`) states the
// never-armed posture verbatim; the ⚠ simulated badge reflects the demo posture.

// Byte-identical fallback if the backend ever omits the pre-rendered caption (it
// should not) — kept in lockstep with views/deviants.go deviantsCaption.
const FALLBACK_CAPTION =
  "These flows DEVIATED from the learned baseline — an unfamiliar identity, a new adjacency, a volume or cadence shift — but touched NO canary, so NO response was armed (Rule 8). They are logged for threat-hunting, never actioned, and are NOT confirmed adversaries. The list is ranked by UNFAMILIARITY: unregistered movers first (the prime hunting leads), then known callers, with mesh services that initiated a novel flow last; the platform's own management-plane traffic — loopback (127.0.0.0/8) and the box talking to itself — is demoted to the bottom, never dropped. Identities are resolved from the operator registry where named; the rest fall back to raw IP. Local to this deployment; addresses never cross a boundary (Rule 9).";

export default function DeviantsPage() {
  const { snapshot, status } = useOverview();
  const useFixture = process.env.NEXT_PUBLIC_FIXTURE === '1';
  // 30s poll: the deviant log evolves on the engine's fold cadence, not the live
  // SSE tick. sinceSec is unused by the endpoint; pass a large value so the slow
  // interval is what governs.
  const live = usePolling<DeviantsView>(deviantsURL(), 99999, { intervalMs: 30000 });
  const view: DeviantsView | null = useFixture ? fixtureDeviants : live.data;

  const caption = view?.caption || FALLBACK_CAPTION;
  const simulated = view?.simulated ?? false;
  const rows = view?.rows ?? [];

  return (
    <div className="app-console">
      <TopBar snapshot={useFixture ? null : snapshot} status={useFixture ? 'live' : status} />
      <main className="detail-page">
        <div className="detail-head">
          <Breadcrumbs crumbs={[{ label: 'Operations', href: '/' }, { label: 'Deviants' }]} />
        </div>

        {!useFixture && live.error && <div className="errstrip">stale — {live.error}</div>}
        {!useFixture && live.notice && <div className="errstrip">{live.notice}</div>}

        <section className="detail-section">
          <h3>
            Deviant hunting log · skilled movers
            <span className="pill-observe" style={{ marginLeft: 10 }}>
              OBSERVE-ONLY · never armed (Rule 8)
            </span>
            {simulated && (
              <span className="pill-sim" style={{ marginLeft: 8 }}>
                ⚠ simulated
              </span>
            )}
          </h3>

          {/* The persistent HONESTY fence. Render verbatim, always — these are logged
              for hunting, never actioned, and never "confirmed adversaries". */}
          <div className="topo-caption" role="note">
            <span className="topo-caption-badge">hunting</span>
            {caption}
          </div>

          {simulated && view?.simulated_note && (
            <div className="topo-caption" role="note" style={{ marginTop: 6 }}>
              <span className="topo-caption-badge">⚠ demo</span>
              {view.simulated_note}
            </div>
          )}

          {rows.length > 0 ? (
            <div className="deviant-list">
              {rows.map((r, i) => (
                <DeviantRowCard key={`${r.src.addr}-${r.dst.addr}-${r.dst.port}-${i}`} r={r} />
              ))}
            </div>
          ) : (
            <div className="topo-empty faint">
              {!useFixture && live.loading
                ? 'loading deviants…'
                : 'no baseline deviants in this scope yet — every observed flow looks normal, or none has crossed the deviation floor.'}
            </div>
          )}

          {/* Rule 8 restatement under the list: this is a view, not a trigger. */}
          <div className="topo-rule8">
            Read-side only. A deviation never arms a response (Rule 8) — only a canary touch does. These flows touched
            no canary; they are logged for hunting, not actioned. Local to this deployment; raw addresses never cross a
            boundary (Rule 9).
          </div>
        </section>
      </main>
    </div>
  );
}

// DeviantRowCard renders one ranked deviant: the fingerprint (src -> dst with
// identity), the headline PEAK dim ("why it looked anomalous"), the compact 5-dim
// mini-bar set, the recurrence count, and last-seen. Vocabulary is "anomalous" /
// "logged" — never "detected" / "blocked" (we are not acting on it).
//
// The card is EXPANDABLE: clicking (or keyboard-toggling) the fingerprint header
// reveals the full L4 east-west fingerprint detail panel. No new fetch — the row
// already carries everything (resolved identities, all 5 dims, peak, recurrence,
// score). The panel is honest that the L7 request PATH/payload is NOT captured here.
function DeviantRowCard({ r }: { r: DeviantRow }) {
  // The hunting headline: an UNFAMILIAR source (an identity the operator never
  // registered — the careful-mover / recon lead) is ranked first and flagged. A
  // KNOWN source that deviates is a lower-priority, honest lead.
  const unfamiliar = r.src_familiarity === 'unfamiliar';
  const [open, setOpen] = useState(false);
  return (
    <div className={`deviant-card${unfamiliar ? ' deviant-card-unfamiliar' : ''}`}>
      <div className="deviant-head">
        {/* The fingerprint is the expand control: a real <button> so it is keyboard-
            toggleable (Enter/Space) and screen-reader-announced via aria-expanded. */}
        <button
          type="button"
          className="deviant-fp deviant-fp-toggle"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          title={open ? 'collapse flow detail' : 'expand the full L4 fingerprint'}
        >
          <span className="deviant-caret" aria-hidden="true">
            {open ? '▾' : '▸'}
          </span>
          <span
            className={`deviant-fam ${unfamiliar ? 'deviant-fam-unfamiliar' : 'deviant-fam-known'}`}
            title={unfamiliar ? 'unfamiliar source — unregistered identity (hunting lead)' : 'known source — declared identity'}
          >
            {unfamiliar ? 'unfamiliar' : 'known'}
          </span>
          <Endpoint e={r.src} role="from" />
          <span className="deviant-arrow">→</span>
          <Endpoint e={r.dst} role="to" />
        </button>
        <span className="deviant-peak" title={`peak dim ${r.peak_dim} = ${fmtPct(r.peak_value)}`}>
          {r.peak_dim} · {fmtPct(r.peak_value)}
        </span>
      </div>

      <Dims r={r} />

      {open && <DeviantDetail r={r} />}

      <div className="deviant-foot faint">
        <span className="pill-observe">OBSERVE-ONLY · never armed</span>
        <span>seen ~{r.hit_count.toLocaleString('en-US')} times</span>
        {r.last_seen && <span>last {fmtAgo(r.last_seen)}</span>}
      </div>
    </div>
  );
}

// DeviantDetail is the expanded drill-down for one flow. It is built ENTIRELY from
// the row (no new fetch) and is honest about what L4 east-west capture does and does
// NOT carry: the dst :port is the real reached service port (L4) — NOT an L7 request
// path; the L7 path/payload is genuinely absent here and joins in a later L7/SIEM
// fusion slice. We never invent a path. The score=0 fold-seam note is expected
// (no canary touch ⇒ no base suspicion score). OBSERVE-ONLY framing throughout.
function DeviantDetail({ r }: { r: DeviantRow }) {
  const dims: Array<{ label: string; meaning: string; v: number }> = [
    { label: 'identity', meaning: 'unfamiliar source — an identity not in the registry', v: r.identity_novelty },
    { label: 'adjacency', meaning: 'a new src → dst pair the baseline had not seen', v: r.adjacency_novelty },
    { label: 'port', meaning: 'an unusual destination port for this source', v: r.port_novelty },
    { label: 'volume', meaning: 'more bytes/flows than the learned baseline', v: r.volume_deviation },
    { label: 'cadence', meaning: 'off-rhythm timing vs the learned cadence', v: r.cadence_deviation },
  ];
  return (
    <section className="deviant-detail">
      {/* (1) Resolved SRC and DST identity: label + kind + RAW addr + port (L4). */}
      <div className="deviant-detail-ends">
        <EndpointDetail e={r.src} role="from" />
        <span className="deviant-detail-arrow" aria-hidden="true">→</span>
        <EndpointDetail e={r.dst} role="to" />
      </div>

      {/* (2) Full 5-dim novelty breakdown, each labeled in plain English. */}
      <div className="deviant-detail-block">
        <div className="deviant-detail-h">baseline novelty — all 5 dimensions</div>
        <div className="deviant-detail-dims">
          {dims.map((d) => {
            const pct = Math.max(0, Math.min(1, Number.isFinite(d.v) ? d.v : 0)) * 100;
            const peak = d.label === peakDimKey(r.peak_dim);
            return (
              <div className={`deviant-detail-dim${peak ? ' deviant-detail-dim-peak' : ''}`} key={d.label}>
                <div className="deviant-detail-dim-top">
                  <span className="deviant-detail-dim-label">{d.label}</span>
                  <span className="deviant-detail-dim-val">{fmtPct(d.v)}</span>
                </div>
                <span className="deviant-detail-dim-track">
                  <span className="deviant-detail-dim-fill" style={{ width: `${pct}%` }} />
                </span>
                <span className="deviant-detail-dim-meaning">{d.meaning}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* (3) PEAK + (4) recurrence + (5) score, with the fold-seam note. */}
      <div className="deviant-detail-meta">
        <div className="deviant-detail-kv">
          <span className="deviant-detail-k">peak signal</span>
          <span className="deviant-detail-v">
            {r.peak_dim} · {fmtPct(r.peak_value)}
          </span>
        </div>
        <div className="deviant-detail-kv">
          <span className="deviant-detail-k">recurrence</span>
          <span className="deviant-detail-v">
            seen ~{r.hit_count.toLocaleString('en-US')} times
            {r.first_seen && r.last_seen ? ` · ${r.first_seen} → ${r.last_seen}` : ''}
          </span>
        </div>
        <div className="deviant-detail-kv">
          <span className="deviant-detail-k">score</span>
          <span className="deviant-detail-v">
            {r.score}
            {r.score === 0 && (
              <span className="deviant-detail-note">
                {' '}
                — score 0 is expected at the fold seam: no canary touch, no base suspicion score.
              </span>
            )}
          </span>
        </div>
      </div>

      {/* (6) HONESTY: this is the L4 east-west fingerprint; no L7 path is captured. */}
      <div className="deviant-detail-honesty" role="note">
        <span className="pill-observe">L4 east-west fingerprint</span> This is the network-layer (L4)
        fingerprint of the flow — endpoints, the reached <code>:port</code>, and the baseline-novelty dims. The
        L7 request <strong>path / payload is NOT captured here</strong>; it joins later in an L7/SIEM fusion
        slice. We never show or invent a path we do not have. Observe-only — no response was armed (Rule 8).
      </div>
    </section>
  );
}

// peakDimKey maps the row's human peak_dim string ("new identity", "volume
// deviation", …) onto the matching 5-dim key so the peak dim can be highlighted in
// the detail breakdown. Best-effort: an unmatched peak_dim simply highlights nothing.
function peakDimKey(peakDim: string): string {
  const p = (peakDim || '').toLowerCase();
  if (p.includes('identity')) return 'identity';
  if (p.includes('adjacen')) return 'adjacency';
  if (p.includes('port')) return 'port';
  if (p.includes('volume')) return 'volume';
  if (p.includes('cadence')) return 'cadence';
  return '';
}

// EndpointDetail renders one fully-resolved end for the drill-down: kind + label +
// the RAW addr + the L4 port. The port is the L4 reached service port — explicitly
// NOT an L7 path. An UNKNOWN/raw-IP kind is the unfamiliar-identity signal.
function EndpointDetail({ e, role }: { e: DeviantEndpoint; role: 'from' | 'to' }) {
  const unknown = e.kind === 'unknown';
  const label = e.label || e.addr || 'unknown';
  return (
    <div className={`deviant-detail-ep${unknown ? ' deviant-detail-ep-unknown' : ''}`}>
      <div className="deviant-detail-ep-role">{role === 'from' ? 'source' : 'destination'}</div>
      <div className="deviant-detail-ep-id">
        <span className="deviant-ep-kind">{e.kind}</span>
        <span className="deviant-detail-ep-label">{label}</span>
      </div>
      <div className="deviant-detail-ep-addr">
        {e.addr || '—'}
        {role === 'to' && e.port > 0 && (
          <span className="deviant-detail-ep-port" title="L4 reached service port (not an L7 path)">
            :{e.port}
          </span>
        )}
      </div>
    </div>
  );
}

// Endpoint renders one resolved identity. An UNKNOWN/raw-IP kind is the
// unfamiliar-identity signal — flagged, not hidden.
function Endpoint({ e, role }: { e: DeviantEndpoint; role: 'from' | 'to' }) {
  const unknown = e.kind === 'unknown';
  const label = e.label || e.addr || 'unknown';
  const portSuffix = role === 'to' && e.port > 0 ? `:${e.port}` : '';
  return (
    <span className={`deviant-ep${unknown ? ' deviant-ep-unknown' : ''}`} title={`${e.kind} · ${e.addr}${portSuffix}`}>
      <span className="deviant-ep-kind">{e.kind}</span>
      <span className="deviant-ep-label">
        {label}
        {portSuffix}
      </span>
    </span>
  );
}

// Dims renders the compact 5-dim novelty mini-bar set. ALL FIVE dims (identity,
// adjacency, port, volume, cadence) come straight from the record.
function Dims({ r }: { r: DeviantRow }) {
  const dims: Array<{ label: string; v: number }> = [
    { label: 'identity', v: r.identity_novelty },
    { label: 'adjacency', v: r.adjacency_novelty },
    { label: 'port', v: r.port_novelty },
    { label: 'volume', v: r.volume_deviation },
    { label: 'cadence', v: r.cadence_deviation },
  ];
  return (
    <div className="deviant-dims">
      {dims.map((d) => {
        const pct = Math.max(0, Math.min(1, Number.isFinite(d.v) ? d.v : 0)) * 100;
        return (
          <div className="deviant-dim" key={d.label} title={`${d.label} ${fmtPct(d.v)}`}>
            <span className="deviant-dim-label">{d.label}</span>
            <span className="deviant-dim-track">
              <span className="deviant-dim-fill" style={{ width: `${pct}%` }} />
            </span>
          </div>
        );
      })}
    </div>
  );
}
