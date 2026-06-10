import Link from 'next/link';
import PanelHead from './PanelHead';
import { WALL_LINK } from './LiveEscalation';
import type { ContainedFlow, KernelContainmentView } from '@/lib/types';

// KernelContainment is the band-left cell. It lists jailed (T3) flows and a
// sample of non-jailed (T1/T2) "OK" flows. The data carries ONLY the socket
// cookie hex + tier + verdict — there are no source IPs/roles — so the `.src`
// slot shows the engine verdict (cookie-based identity, not a fabricated host).
export default function KernelContainment({ containment }: { containment: KernelContainmentView | undefined }) {
  const jailed = containment?.jailed_flows ?? [];
  const ok = containment?.ok_flows ?? [];
  const hasAny = jailed.length > 0 || ok.length > 0;

  return (
    <section className="cell">
      <PanelHead title="Kernel containment" preTags={[{ label: 'eBPF' }]} />
      {hasAny ? (
        <div className="sockets">
          {jailed.map((f) => (
            <Sock key={`jail-${f.flow_id_hex}`} flow={f} jailed />
          ))}
          {ok.map((f) => (
            <Sock key={`ok-${f.flow_id_hex}`} flow={f} jailed={false} />
          ))}
        </div>
      ) : (
        <div className="precis-note faint">no contained sockets in window — kernel enforcement idle, observing.</div>
      )}
      <div className="precis-note">
        the offending socket&apos;s egress is dropped in-kernel by its cookie.{' '}
        <b>bystanders on the same host keep working</b> — we contain the flow, not the host.
      </div>
    </section>
  );
}

function Sock({ flow, jailed }: { flow: ContainedFlow; jailed: boolean }) {
  return (
    <div className={`sock ${jailed ? 'jail' : 'ok'}`}>
      <div className="st">
        <span className="d" />
        {jailed ? 'Jailed' : 'OK'}
      </div>
      <div className="cookie">
        cookie <Link href={`/flow/${flow.flow_id_hex}?since=1h`} style={WALL_LINK}>{flow.flow_id_hex}</Link>
      </div>
      <div className="src">
        T{flow.tier}
        <br />
        {flow.verdict || '—'}
      </div>
    </div>
  );
}
