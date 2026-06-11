'use client';

import Link from 'next/link';
import { fmtBytes, fmtInt, fmtK, fmtPct, fmtTime } from '@/lib/format';
import { useSince } from './SinceProvider';
import type { CostBreakdown } from '@/lib/types';

// CostView: total hero + by-mechanism + by-flow (session rows) + zero-filled
// time series. Real attacker cost; defender cost is structurally flat.
export default function CostView({ data, loading }: { data: CostBreakdown | null; loading: boolean }) {
  const { since } = useSince();
  if (!data) return <div className="faint mono">{loading ? 'WARMING UP…' : 'no cost data'}</div>;

  // Go nil slices marshal to JSON null, not []; guard so the maps never crash.
  const timeSeries = data.time_series ?? [];
  const byMechanism = data.by_mechanism ?? [];
  const byFlow = data.by_flow ?? [];
  const peakHeld = Math.max(1, ...timeSeries.map((b) => b.time_held_sec));

  return (
    <>
      <section className="detail-section">
        <h3>imposed cost · total (window)</h3>
        <div className="cost-metrics">
          <div className="cm"><div className="v">{fmtTime(data.total.time_held_sec)}</div><div className="k">time imposed</div></div>
          <div className="cm"><div className="v">{fmtK(data.total.token_cost)}</div><div className="k">tokens (proxy)</div></div>
          <div className="cm"><div className="v">{fmtInt(data.total.requests)}</div><div className="k">reqs absorbed</div></div>
          <div className="cm"><div className="v">{fmtBytes(data.total.bytes_served)}</div><div className="k">bytes served</div></div>
        </div>
      </section>

      <section className="detail-section">
        <h3>cost over time</h3>
        {timeSeries.length === 0 ? (
          <div className="faint mono">no events in window</div>
        ) : (
          <div className="tseries">
            {timeSeries.map((b, i) => (
              <span
                key={i}
                className={`bar${b.time_held_sec === 0 ? ' zero' : ''}`}
                style={{ height: `${Math.round((b.time_held_sec / peakHeld) * 100)}%` }}
                title={`${b.bucket_start}: ${fmtTime(b.time_held_sec)}, ${fmtK(b.token_cost)} tok`}
              />
            ))}
          </div>
        )}
      </section>

      <section className="detail-section">
        <h3>by mechanism</h3>
        {byMechanism.length === 0 ? (
          <div className="faint mono">no attrition mechanisms recorded (kernel-enforced cost not attributed)</div>
        ) : (
          <table className="flows-table">
            <thead><tr><th>mechanism</th><th>events</th><th>time imposed</th><th>tokens</th><th>bytes</th></tr></thead>
            <tbody>
              {byMechanism.map((m) => (
                <tr key={m.mechanism}>
                  <td className="t-mech">{m.mechanism}</td>
                  <td>{m.event_count}</td>
                  <td>{fmtTime(m.time_held_sec)}</td>
                  <td>{fmtK(m.token_cost)}</td>
                  <td>{fmtBytes(m.bytes_served)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="detail-section">
        <h3>engagement contest</h3>
        <div className="cost-metrics">
          <div className="cm"><div className="v">{fmtTime(data.engagement.median_sec)}</div><div className="k">median held</div></div>
          <div className="cm"><div className="v">{fmtTime(data.engagement.p90_sec)}</div><div className="k">p90 held</div></div>
          <div className="cm"><div className="v">{fmtTime(data.engagement.longest_sec)}</div><div className="k">longest held</div></div>
        </div>
        <div className="faint" style={{ marginTop: 8, fontSize: 12 }}>
          <span style={{ color: 'var(--sting)' }}>{fmtPct(data.engagement.disengaged_early_fraction)} disengaged early</span>
          {' '}— {data.engagement.disengaged_early} gave up · {data.engagement.defender_capped} capped · {data.engagement.generator_exhausted} exhausted
        </div>
      </section>

      <section className="detail-section">
        <h3>deception reactions</h3>
        <div className="cost-metrics">
          <div className="cm">
            <div className="v" style={data.reactions.poison_reached > 0 ? { color: 'var(--sting)' } : undefined}>
              {data.reactions.poison_reached > 0 ? data.reactions.poison_class || `stage ${data.reactions.poison_reached}` : '—'}
            </div>
            <div className="k">poison reached</div>
          </div>
          <div className="cm"><div className="v">{fmtInt(data.reactions.exploits_observed)}</div><div className="k">exploits fired</div></div>
          <div className="cm"><div className="v">{fmtInt(data.reactions.exposure_signals)}</div><div className="k">tooling exposed</div></div>
        </div>
      </section>

      <section className="detail-section">
        <h3>by flow (session)</h3>
        {byFlow.length === 0 ? (
          <div className="faint mono">no cost-bearing flows</div>
        ) : (
          <table className="flows-table">
            <thead><tr><th>cookie</th><th>tier</th><th>time imposed</th><th>tokens</th></tr></thead>
            <tbody>
              {byFlow.map((f, i) => {
                const start = Math.floor(new Date(f.session_start).getTime() / 1000);
                return (
                  <tr key={`${f.flow_id_hex}-${f.session_index}`} className={f.peak_tier >= 3 ? 't3' : f.peak_tier === 2 ? 't2' : ''}>
                    <td className="cookie">
                      <Link href={`/flow/${f.flow_id_hex}?since=${since}&session=${start}`}>{f.flow_id_hex}</Link>
                      {f.session_count > 1 && <span className="session-badge">{f.session_index}/{f.session_count}</span>}
                    </td>
                    <td className="tiercell">T{f.peak_tier}</td>
                    <td>{fmtTime(f.total_cost.time_held_sec)}</td>
                    <td>{fmtK(f.total_cost.token_cost)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
