import PanelHead from './PanelHead';
import { fmtInt, fmtK, fmtPct, fmtTime } from '@/lib/format';
import type { AttackerCostView, AxisCostView, EngagementView, RealAttackCostView } from '@/lib/types';

const STING_TAG_STYLE = { color: 'var(--sting)', borderColor: 'rgba(255,77,96,0.4)' };

// ByAxis renders the OVERLAPPING per-axis cost breakdown: one bar per axis, scaled
// to the largest axis's imposed time. The bars OVERLAP (a flow counts toward every
// axis its mechanism imposes), so they are deliberately NOT a 100%-stacked partition.
function ByAxis({ axes }: { axes: AxisCostView[] | null | undefined }) {
  if (!axes || axes.length === 0) return null;
  const maxT = Math.max(...axes.map((a) => a.time_sec), 1);
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--ink-dim)', marginBottom: 6 }}>
        cost by axis · overlapping
      </div>
      {axes.map((a) => (
        <div key={a.axis} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className="mono" style={{ width: 92, fontSize: 11, color: 'var(--ink-dim)' }}>{a.axis}</span>
          <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3 }}>
            <div style={{ width: `${Math.round((a.time_sec / maxT) * 100)}%`, height: '100%', background: 'var(--sting)', borderRadius: 3 }} />
          </div>
          <span className="mono" style={{ width: 56, fontSize: 11, textAlign: 'right' }}>{fmtTime(a.time_sec)}</span>
        </div>
      ))}
      <div style={{ fontSize: 10, color: 'var(--ink-dim)', marginTop: 4, fontStyle: 'italic' }}>
        a flow counts toward every axis it triggers — overlapping, not a partition
      </div>
    </div>
  );
}

// fmtUSD: 0.4612 -> "$0.46", 2 -> "$2.00".
function fmtUSD(n: number): string {
  return '$' + n.toFixed(2);
}

// RealMeter is the M9 live cost meter: the attacker's GROUND-TRUTH Anthropic
// token/$ burn (real_attack_cost), shown SEPARATELY from the defender's proxy
// estimate. It only renders when an attack run has posted a ledger. The dollar
// figure climbs toward the hard cap; the bar fills with cap_fraction.
function RealMeter({ real }: { real: RealAttackCostView | undefined }) {
  if (!real || !real.present) return null;
  const pct = Math.round(Math.min(1, Math.max(0, real.cap_fraction)) * 100);
  return (
    <div className="rmeter">
      <div className="rmeter-head">
        <span className={`rmeter-dot${real.active ? ' live' : ''}`} />
        <span className="rmeter-label">
          {real.active ? 'REAL TOKENS BURNING' : 'LAST ATTACK — REAL SPEND'}
        </span>
        <span className="rmeter-model mono">{real.model || 'llm-attacker'}</span>
      </div>
      <div className="rmeter-usd">
        {fmtUSD(real.usd)}
        <small> / {fmtUSD(real.hard_cap_usd)} cap</small>
      </div>
      <div className="rmeter-track">
        <div className="rmeter-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="rmeter-toks mono">
        {fmtInt(real.total_tokens)} real tokens · in {fmtK(real.input_tokens)} · out {fmtK(real.output_tokens)} ·
        cache {fmtK(real.cache_read_tokens)}
      </div>
      <div className="rmeter-note">
        the attacker&apos;s <b>own</b> Anthropic spend, measured from <span className="mono">resp.usage</span> — distinct
        from the defender-side proxy estimate above.
      </div>
    </div>
  );
}

// Engagement surfaces the engagement-contest story (design §8): median/p90 imposed
// hold, and the disengage split — how many attackers GAVE UP before we capped them
// (the engagement signal) vs were defender-capped vs exhausted the generator. Honest
// empty: renders nothing until there is held time or a classified session.
function Engagement({ e }: { e: EngagementView | undefined }) {
  if (!e) return null;
  const total = e.disengaged_early + e.generator_exhausted + e.defender_capped;
  if (total === 0 && e.median_sec === 0) return null;
  return (
    <div style={{ marginTop: 10, fontFamily: 'var(--sans)', fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.6 }}>
      <span style={{ color: 'var(--ink)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>engagement</span>
      {' · '}median {fmtTime(e.median_sec)} · p90 {fmtTime(e.p90_sec)}
      {total > 0 && (
        <>
          <br />
          <span style={{ color: 'var(--sting)' }}>{fmtPct(e.disengaged_early_fraction)} disengaged early</span>
          {' '}— {e.disengaged_early} gave up · {e.defender_capped} capped · {e.generator_exhausted} exhausted
        </>
      )}
    </div>
  );
}

// AttackerCost is the hero-right panel: the economic inversion. Binds the whole
// attacker_cost slice plus the M9 real_attack_cost meter. When no flow is in
// active response (T2+T3 == 0) AND no real attack ledger is present it shows an
// HONEST empty state — no fabricated numbers. If a real attack is burning tokens
// (even before the engine tiers it to T2+) the live meter renders regardless.
// The attacker/defender inversion bars are CSS-animated (verbatim from the
// prototype); the defender bar is structurally bounded at 6%.
export default function AttackerCost({
  cost,
  real,
}: {
  cost: AttackerCostView | undefined;
  real?: RealAttackCostView | undefined;
}) {
  const head = (
    <PanelHead title="Attacker cost" preTags={[{ label: 'attrition · opportunity cost', style: STING_TAG_STYLE }]} />
  );

  const active = cost?.active_response_count ?? 0;
  const realPresent = !!real?.present;

  if ((!cost || active === 0) && !realPresent) {
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

  // If only the real meter is present (no active engine response yet), show the
  // meter alone over a brief readiness note rather than the inversion bars.
  if (!cost || active === 0) {
    return (
      <section className="hpanel">
        {head}
        <RealMeter real={real} />
        <div style={{ marginTop: 12, fontFamily: 'var(--sans)', fontSize: 12, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
          attacker is spending real tokens; engine has not escalated this flow to active response yet.
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
          <div className="v">{fmtTime(cost.engagement?.longest_sec ?? 0)}</div>
          <div className="k">longest held</div>
        </div>
        <div className="cm">
          <div className="v">{fmtK(cost.tokens_burned)}</div>
          <div className="k">tokens (proxy)</div>
        </div>
      </div>
      <ByAxis axes={cost.per_axis} />
      <Engagement e={cost.engagement} />
      <RealMeter real={real} />
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
          every fake-resource generator is ceiling-bounded — attrition imposes <b>opportunity cost</b> on a
          velocity-dependent adversary (its time, capacity and intelligence), <b>never the defender&apos;s</b>. tokens
          are a qualified proxy, not a dollar bill.
        </div>
      </div>
    </section>
  );
}
