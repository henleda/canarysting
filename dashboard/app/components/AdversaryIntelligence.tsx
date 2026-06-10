import Link from 'next/link';
import PanelHead from './PanelHead';
import { fmtBytes, fmtInt, fmtK, fmtOffsetLabel, fmtTimeLong } from '@/lib/format';
import { WALL_LINK } from './LiveEscalation';
import type { AdversaryIntelView, FlowFingerprint, ReconEvent } from '@/lib/types';

// AdversaryIntelligence is the band-right cell (widest). Three facets in the
// intel-grid: the attacker-cost KPI (board-level), the recon early-warning feed,
// and the adversary fingerprint. All bound to adversary_intel. Recon is labeled
// "recon"/"surfaced" — never "detected" (early-warning, not enforcement).
export default function AdversaryIntelligence({ intel }: { intel: AdversaryIntelView | undefined }) {
  const kpi = intel?.kpi;
  const feed = intel?.recon_feed ?? [];
  const fp = intel?.fingerprint ?? null;

  return (
    <section className="cell">
      <PanelHead title="Adversary intelligence" preTags={[{ label: 'compounding' }]} />
      <div className="intel-grid">
        {/* attacker-cost KPI */}
        <div className="intel-kpi">
          <div className="big">
            {fmtK(kpi?.tokens_burned ?? 0)}
            <span className="u">tok</span>
          </div>
          <div className="cap">attacker-cost KPI · board-level</div>
          <div className="legend">
            <div className="lr">
              <span className="lk">time imposed</span>
              <span className="lv">{fmtTimeLong(kpi?.time_imposed_sec ?? 0)}</span>
            </div>
            <div className="lr">
              <span className="lk">reqs absorbed</span>
              <span className="lv">{fmtInt(kpi?.requests_absorbed ?? 0)}</span>
            </div>
            <div className="lr">
              <span className="lk">fake bytes</span>
              <span className="lv">{fmtBytes(kpi?.bytes_served ?? 0)}</span>
            </div>
            <div className="lr">
              <span className="lk">defender</span>
              <span className="lv" style={{ color: 'var(--safe)' }}>
                {kpi?.defender_cost_label || 'flat'}
              </span>
            </div>
          </div>
        </div>

        {/* recon early-warning */}
        <div className="intel-sub">
          <h3>
            <Link href="/recon?since=1h" style={WALL_LINK}>Recon early-warning →</Link>
          </h3>
          {feed.length > 0 ? (
            <div className="feed">
              {feed.slice(0, 3).map((ev, i) => (
                <ReconRow key={`${ev.flow_id_hex}-${i}`} ev={ev} />
              ))}
            </div>
          ) : (
            <span className="faint" style={{ fontSize: 10 }}>
              building… no recon in window
            </span>
          )}
        </div>

        {/* adversary fingerprint */}
        <div className="intel-sub">
          <h3>Adversary fingerprint</h3>
          {fp ? (
            <Fingerprint fp={fp} />
          ) : (
            <span className="faint" style={{ fontSize: 10 }}>
              fingerprint building…
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

function ReconRow({ ev }: { ev: ReconEvent }) {
  // severity: "surfaced" -> warn (amber), "recon" (or anything else) -> quiet.
  const sevClass = ev.severity === 'surfaced' ? 'warn' : 'quiet';
  const label = ev.offset_label || fmtOffsetLabel(ev.offset_sec);
  return (
    <div className="ev">
      <span className="ts">{label}</span>
      <span className="what">{ev.description}</span>
      <span className={`sev ${sevClass}`}>{ev.severity}</span>
    </div>
  );
}

function Fingerprint({ fp }: { fp: FlowFingerprint }) {
  const order = fp.ordered_types && fp.ordered_types.length > 0 ? fp.ordered_types.join('→') : '—';
  const reaction = fp.persists_tarpit ? 'persisted thru tarpit' : 'released early';
  // cadence: median inter-arrival + a jitter qualifier from the MAD.
  const cadence =
    fp.cadence_sec > 0
      ? `~${fp.cadence_sec.toFixed(0)}s · ${fp.cadence_jitter <= 2 ? 'low-jitter' : 'high-jitter'}`
      : '—';
  return (
    <div className="fp">
      <div className="r">
        <span className="k">order</span>
        <span className="v">{order}</span>
      </div>
      <div className="r">
        <span className="k">reaction</span>
        <span className="v">{reaction}</span>
      </div>
      <div className="r">
        <span className="k">cadence</span>
        <span className="v">{cadence}</span>
      </div>
      <Link className="fp-hash" href={`/flow/${fp.flow_id_hex}?since=1h`} style={WALL_LINK}>
        {fp.hash}
      </Link>
    </div>
  );
}
