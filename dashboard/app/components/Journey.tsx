import PanelHead from './PanelHead';
import type { JourneyView } from '@/lib/types';

// tier → the CSS color class shared with the tier ladder / recon badges.
const tierClass = (t: number) => (t >= 3 ? 't3' : t === 2 ? 't2' : 't1');

// Journey is the current attacker flow's legible ARC — recon → escalation (with the
// OVERLAPPING attrition axes that fired at each crossing) → disengage — as one ordered
// ribbon, so a CISO follows the cascade as a story rather than reading a tier-count
// snapshot. Every milestone traces to a real engine event (honest; nothing fabricated).
// The axes are overlapping, never a partition.
export default function Journey({ journey }: { journey?: JourneyView }) {
  const head = (
    <PanelHead
      title="Attacker journey"
      preTags={journey?.present ? [{ label: journey.flow_id_hex }] : []}
    />
  );

  if (!journey || !journey.present) {
    return (
      <section className="hpanel">
        {head}
        <div className="faint mono">no active attacker flow — observing</div>
      </section>
    );
  }

  const ms = journey.milestones ?? [];
  return (
    <section className="hpanel">
      {head}
      <ol className="journey">
        {ms.map((m, i) => (
          <li key={i} className="journey-step">
            <span className="journey-offset mono faint">{m.offset_label}</span>
            <span className={`journey-tier ${tierClass(m.tier)}`}>T{m.tier}</span>
            <span className="journey-body">
              <span className="journey-title">{m.title}</span>
              {m.axes_firing && m.axes_firing.length > 0 ? (
                <span className="journey-axes">
                  {m.axes_firing.map((a) => (
                    <span key={a} className="axis-chip mono">
                      {a}
                    </span>
                  ))}
                </span>
              ) : m.detail ? (
                <span className="journey-detail faint mono">{m.detail}</span>
              ) : null}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}
