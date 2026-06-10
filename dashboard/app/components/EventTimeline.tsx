import { fmtK, fmtTime } from '@/lib/format';
import type { TouchEvent } from '@/lib/types';

function localTime(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().slice(11, 19);
}

// EventTimeline renders one session's ordered canary touches. Score 0 → "—"
// (honesty rule). A zero-cost T2/T3 row (kernel-enforced, no inline Sting) is
// labeled honestly rather than shown as "0s held".
export default function EventTimeline({ events }: { events: TouchEvent[] }) {
  if (!events || events.length === 0) {
    return <div className="faint mono">no touches in window</div>;
  }
  return (
    <div className="timeline">
      {events.map((e, i) => {
        const tcls = e.tier >= 3 ? 't3' : e.tier === 2 ? 't2' : 't1';
        const enforced = e.tier >= 2 && e.mechanism === '' && e.time_held_sec === 0;
        return (
          <div className="trow" key={i}>
            <span className="t-offset">{localTime(e.timestamp)}</span>
            <span className="t-type">{e.canary_type || '—'}</span>
            <span className={`t-tier ${tcls}`}>T{e.tier}</span>
            <span className="t-score">{e.score > 0 ? e.score.toFixed(2) : '—'}</span>
            <span className="t-m" title="baseline multiplier for this touch">{e.m > 1 ? `×${e.m.toFixed(2)}` : '—'}</span>
            {enforced ? (
              <span className="t-mech none">kernel-enforced · cost not attributed</span>
            ) : (
              <span className="t-mech">{e.mechanism || '—'}</span>
            )}
            <span className="t-cost">
              {e.time_held_sec > 0 ? `${fmtTime(e.time_held_sec)} held` : '—'}
              {e.token_cost > 0 ? ` · ${fmtK(e.token_cost)} tok` : ''}
            </span>
          </div>
        );
      })}
    </div>
  );
}
