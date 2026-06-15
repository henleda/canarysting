import Spark from './Spark';
import EventTimeline from './EventTimeline';
import { fmtBytes, fmtInt, fmtK, fmtTime } from '@/lib/format';
import type { FlowDetail as FlowDetailT } from '@/lib/types';

const TIER_LABEL = ['Observe', 'Tag', 'Contain', 'Jail'];

// FlowDetail is one SESSION's full record. session_index/count expose cookie
// reuse honestly. Score 0 renders "—". M breakdown shows all 5 features.
export default function FlowDetail({ detail, loading, cookie }: { detail: FlowDetailT | null; loading: boolean; cookie: string }) {
  if (!detail) {
    return <div className="faint mono">{loading ? 'WARMING UP…' : `no flow ${cookie} in window`}</div>;
  }
  const peakLabel = TIER_LABEL[detail.peak_tier] ?? `T${detail.peak_tier}`;
  // cost strip from the timeline
  const cost = detail.timeline.reduce(
    (a, e) => ({
      held: a.held + e.time_held_sec,
      bytes: a.bytes + e.bytes_served,
      reqs: a.reqs + e.requests,
      tok: a.tok + e.token_cost,
    }),
    { held: 0, bytes: 0, reqs: 0, tok: 0 },
  );

  return (
    <>
      <section className="detail-section">
        <div className="flow-id" style={{ marginBottom: 8 }}>
          <span className="ip">{detail.flow_id_hex}</span>
          <span className="role">{detail.verdict || peakLabel}</span>
          {detail.session_count > 1 && (
            <span className="session-badge mono">session {detail.session_index} of {detail.session_count}</span>
          )}
        </div>
        <div className="flow-sub">
          peak {peakLabel} · score {detail.score > 0 ? detail.score.toFixed(2) : '—'} · {detail.touch_count} touches
        </div>
        <Spark series={detail.spark_series} />
      </section>

      {detail.fingerprint && (
        <section className="detail-section">
          <h3>adversary fingerprint</h3>
          <div className="fp">
            <div className="r"><span className="k">sequence</span><span className="v">{(detail.fingerprint.ordered_types ?? []).join(' → ') || '—'}</span></div>
            <div className="r"><span className="k">cadence</span><span className="v">{detail.fingerprint.cadence_sec.toFixed(0)}s ± {detail.fingerprint.cadence_jitter.toFixed(1)}s</span></div>
            <div className="r"><span className="k">adjacency</span><span className="v">{detail.fingerprint.adjacency_nov.toFixed(2)}</span></div>
            <div className="r"><span className="k">identity</span><span className="v">{detail.fingerprint.identity_nov.toFixed(2)}</span></div>
            <div className="r"><span className="k">tarpit</span><span className="v">{detail.fingerprint.persists_tarpit ? 'persisted' : 'no'}</span></div>
            <div className="fp-hash">{detail.fingerprint.hash}</div>
          </div>
        </section>
      )}

      <section className="detail-section">
        <h3>touch timeline · M shown per touch</h3>
        <EventTimeline events={detail.timeline} />
      </section>

      <section className="detail-section">
        <h3>baseline multiplier{detail.m_breakdown ? ` · M = ${detail.m_breakdown.m.toFixed(2)} (peak event)` : ''}</h3>
        {detail.m_breakdown ? (
          <>
            <div className="mbars">
              {detail.m_breakdown.contributions.map((c) => (
                <div className="mbar" key={c.feature}>
                  <span>{c.label}</span>
                  <span className="track"><span className="fill" style={{ width: `${Math.round(c.capped * 100)}%` }} /></span>
                  <span className="val">{c.raw_value.toFixed(2)}</span>
                </div>
              ))}
            </div>
            <div className="flow-sub" style={{ marginTop: 10 }}>{detail.m_breakdown.gate_note}</div>
          </>
        ) : (
          // Never silently hide the section: a flow whose events carry no baseline
          // features (e.g. recorded before observe re-tracked it) gets M=1.0 neutral.
          <div className="flow-sub">
            No per-touch baseline features recorded for this flow in the window — M defaults to 1.0 (neutral).
            The Credibility page’s baseline multiplier reflects the current live calibrated state.
          </div>
        )}
      </section>

      <section className="detail-section">
        <h3>imposed cost (this session)</h3>
        <div className="cost-metrics">
          <div className="cm"><div className="v">{fmtTime(cost.held)}</div><div className="k">time imposed</div></div>
          <div className="cm"><div className="v">{fmtK(cost.tok)}</div><div className="k">tokens (proxy)</div></div>
          <div className="cm"><div className="v">{fmtInt(cost.reqs)}</div><div className="k">reqs absorbed</div></div>
          <div className="cm"><div className="v">{fmtBytes(cost.bytes)}</div><div className="k">bytes served</div></div>
        </div>
      </section>
    </>
  );
}
