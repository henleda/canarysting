import PanelHead from './PanelHead';
import { fmtBytes } from '@/lib/format';
import type { ReconLiveView, ReconLiveFlow } from '@/lib/types';

// ReconLive is the OBSERVE-ONLY recon surface — the visible proof of RESTRAINT.
// It lists currently-live flows that look anomalous from the learned baseline but
// touched NO canary, under a fixed "surfaced, not actioned" note. Nothing here can
// arm a response (Rule 8: only a canary touch does); it is early-warning only,
// never enforcement — the discipline that IS the zero-false-positive guarantee.
export default function ReconLive({ recon }: { recon: ReconLiveView | undefined }) {
  const flows = recon?.flows ?? [];
  const active = recon?.active ?? false;
  const note =
    recon?.note ||
    'Surfaced, not actioned — anomalous from the learned baseline; none has armed a response (only a decoy touch that crosses the threshold can — Rule 8).';

  return (
    <section className="cell">
      <PanelHead title="Recon — watching, not acting" preTags={[{ label: 'observe-only' }]} />
      {active ? (
        <div className="feed">
          {flows.slice(0, 6).map((f, i) => (
            <ReconLiveRow key={`${f.flow_id_hex}-${i}`} f={f} />
          ))}
        </div>
      ) : (
        <span className="faint" style={{ fontSize: 10 }}>
          no anomalous non-canary flows in view
        </span>
      )}
      <div
        className="faint"
        style={{ fontSize: 9, color: 'var(--ink-dim)', marginTop: 8, lineHeight: 1.45 }}
      >
        {note}
      </div>
    </section>
  );
}

// ReconLiveRow renders one anomalous non-touching flow: its cookie, the baseline
// signal that flagged it, coarse traffic, and the severity tier. Vocabulary is
// "recon"/"surfaced" — never "detected"/"blocked" (we are not acting on it).
function ReconLiveRow({ f }: { f: ReconLiveFlow }) {
  const sevClass = f.severity === 'surfaced' ? 'warn' : 'quiet';
  return (
    <div className="ev">
      <span className="ts">{f.flow_id_hex}</span>
      <span className="what">
        {f.top_signal} · {fmtBytes(f.bytes)}
      </span>
      <span className={`sev ${sevClass}`}>{f.severity}</span>
    </div>
  );
}
