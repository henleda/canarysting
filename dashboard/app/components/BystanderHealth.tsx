import Link from 'next/link';
import PanelHead from './PanelHead';
import { WALL_LINK } from './LiveEscalation';
import { fmtBytes, fmtTimeLong } from '@/lib/format';
import type { BystanderView, BystanderFlow } from '@/lib/types';

// BystanderHealth is the dashboard-native "contain the flow, not the host" proof:
// flows on the SAME host still serving traffic, untouched by the response, while
// an attacker socket is kernel-jailed. It replaces the old terminal-curl proof
// with first-party eBPF live-flow data. Observe-only — it takes no action; it just
// shows that flow-precise containment dropped only the attacker's socket. (The
// claim is "not actioned / still serving", not a categorical "legitimate".)
export default function BystanderHealth({ bystanders }: { bystanders: BystanderView | undefined }) {
  const flows = bystanders?.flows ?? [];
  const active = bystanders?.active ?? false;
  const note =
    bystanders?.note ||
    "Same host, still serving — the kernel jail dropped only the attacker's socket; every other flow here is untouched by the response and keeps returning traffic. We contain the flow, not the host.";

  return (
    <section className="cell">
      <PanelHead title="Bystanders — still serving" preTags={[{ label: 'same host' }]} />
      {active ? (
        <div className="cell-scroll">
          <div className="feed">
            {flows.map((f, i) => (
              <BystanderRow key={`${f.flow_id_hex}-${i}`} f={f} />
            ))}
          </div>
        </div>
      ) : (
        <span className="faint" style={{ fontSize: 10 }}>
          no other live flows serving in view
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

// BystanderRow shows one serving workload: its cookie, coarse traffic served, and
// a green "200 · serving" status — the visceral contrast to the jailed socket.
function BystanderRow({ f }: { f: BystanderFlow }) {
  return (
    <div className="ev">
      <span className="ts">
        <Link href={`/flow/${f.flow_id_hex}?since=1h`} style={WALL_LINK}>{f.flow_id_hex}</Link>
      </span>
      <span className="what">
        {fmtBytes(f.bytes)} served · {fmtTimeLong(f.duration_sec)}
      </span>
      <span className="sev" style={{ color: 'var(--safe)' }}>
        200 · serving
      </span>
    </div>
  );
}
