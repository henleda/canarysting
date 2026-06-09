import PanelHead from './PanelHead';
import { fmtInt, fmtK, fmtPct, fmtTime } from '@/lib/format';
import type { AttackerCostView } from '@/lib/types';

const STING_TAG_STYLE = { color: 'var(--sting)', borderColor: 'rgba(255,77,96,0.4)' };

// AttackerCost is the hero-right panel: the economic inversion. Binds the whole
// attacker_cost slice. When no flow is in active response (T2+T3 == 0) it shows
// an HONEST empty state — no fabricated token/time numbers, just the readiness
// note. The attacker/defender inversion bars are CSS-animated (verbatim from the
// prototype); the defender bar is structurally bounded at 6%.
export default function AttackerCost({ cost }: { cost: AttackerCostView | undefined }) {
  const head = (
    <PanelHead title="Attacker cost" preTags={[{ label: 'attrition · economics', style: STING_TAG_STYLE }]} />
  );

  const active = cost?.active_response_count ?? 0;

  if (!cost || active === 0) {
    return (
      <section className="hpanel">
        {head}
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            textAlign: 'center',
          }}
        >
          <span
            className="mono"
            style={{
              fontSize: 11,
              letterSpacing: '0.16em',
              textTransform: 'uppercase',
              color: 'var(--sting)',
            }}
          >
            ATTRITION READY
          </span>
          <span style={{ fontFamily: 'var(--sans)', fontSize: 12, color: 'var(--ink-dim)', maxWidth: 280, lineHeight: 1.5 }}>
            engages when active response runs — no flows in attrition right now
          </span>
        </div>
      </section>
    );
  }

  return (
    <section className="hpanel">
      {head}
      <div className="aresp">
        <div className="lead">
          {fmtInt(active)}
          <small>flows in active response</small>
        </div>
        <div className="split2">
          <div className="rs jail">
            <span className="d" />
            <span className="n">{fmtInt(cost.jailed)}</span>
            <span className="l">
              jailed
              <br />
              kernel
            </span>
          </div>
          <div className="rs ca">
            <span className="d" />
            <span className="n">{fmtInt(cost.counter_attacked)}</span>
            <span className="l">
              counter-
              <br />
              attacked
            </span>
          </div>
        </div>
        <div className="arrow2">
          <b>{fmtPct(cost.attacker_cost_fraction)}</b> of flagged
          <br />
          traffic — driving ↓
        </div>
      </div>
      <div className="cost-metrics">
        <div className="cm">
          <div className="v">{fmtTime(cost.time_imposed_sec)}</div>
          <div className="k">time imposed</div>
        </div>
        <div className="cm">
          <div className="v">{fmtK(cost.tokens_burned)}</div>
          <div className="k">tokens burned</div>
        </div>
        <div className="cm">
          <div className="v">{fmtInt(cost.requests_absorbed)}</div>
          <div className="k">reqs absorbed</div>
        </div>
      </div>
      <div className="inversion">
        <div className="inv-row att">
          <div className="inv-head">
            <span className="who">ATTACKER</span>
            <span className="amt">climbing ▲</span>
          </div>
          <div className="bigtrack">
            <div className="fill" />
          </div>
        </div>
        <div className="inv-row def">
          <div className="inv-head">
            <span className="who">DEFENDER</span>
            <span className="amt">{cost.defender_cost_flat ? 'flat · bounded' : 'unbounded'}</span>
          </div>
          <div className="bigtrack">
            <div className="fill" />
          </div>
        </div>
        <div className="cost-note">
          every fake-resource generator is ceiling-bounded — attrition burns the attacker&apos;s time, tokens and
          compute, <b>never the defender&apos;s</b>.
        </div>
      </div>
    </section>
  );
}
