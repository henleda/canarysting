import type { Overview } from '@/lib/types';
import { fmtUtc, isZeroTime } from '@/lib/format';

// KillSwitchBanner — the PRIMARY, high-visibility surface for the deployment-wide
// enforcement kill-switch. A kill-switch DISARMS containment/sting fleet-wide, so an
// IR/CISO viewer must not miss it: this is a full-width red banner mounted between
// <TopBar/> and <FleetSafety/> (page.tsx). It SELF-HIDES (returns null) when the
// switch is disengaged, so the wall is quiet in the normal armed posture and the
// halted state stands out by contrast.
//
// READ-ONLY: it renders snapshot.kill_switch verbatim and offers NO engage/revive
// control (that path is canaryctl + the token-gated admin endpoint).
//
// All states handled without crashing:
//   - loading (snapshot null)            -> null (nothing to show yet)
//   - disengaged (engaged false/missing) -> null (quiet default)
//   - engaged-timed                      -> shows absolute + relative expiry
//   - engaged-indefinite (zero expiry)   -> "no auto-expiry (INDEFINITE …)"
//   - already-expired                    -> the tap reports engaged=false on the
//                                           next poll, so this just self-hides; no
//                                           client-side timer is needed.
//
// AUTHORITATIVE BIT: we gate ONLY on `engaged`. operator/reason/expires_at may still
// echo a stale snapshot after expiry, so they are never used to infer the posture.
//
// HONESTY (load-bearing): the copy states enforcement is HALTED/DISARMED, by whom, and
// the expiry. On in-flight jails it is PRECISE (not a blanket claim either way): while
// halted, a flow that touches a canary again is de-escalated — its floored verdict
// drives the adapter's RELEASE branch — but a cookie already jailed that sends no
// further traffic lingers until its socket closes (no active kernel-map flush; that is
// a documented B2 residual). Detection/scoring/labeling continue.
export default function KillSwitchBanner({ snapshot }: { snapshot: Overview | null }) {
  // Safe access throughout — kill_switch may be absent on a partial/legacy payload
  // (recall the Go nil-field null-deref): optional-chain and default to disengaged.
  const ks = snapshot?.kill_switch;
  if (!ks?.engaged) return null; // self-hides when loading or disengaged

  const operator = ks.operator || 'an operator';
  const reason = ks.reason || 'no reason given';

  // Expiry: the zero-value sentinel ('0001-01-01T00:00:00Z') means INDEFINITE.
  const indefinite = isZeroTime(ks.expires_at);
  const expiresUtc = indefinite ? '' : fmtUtc(ks.expires_at);
  const countdown = indefinite ? '' : fmtCountdown(ks.expires_at);

  return (
    <section className="killswitch-banner" role="alert">
      <div className="ksb-line">
        <span className="ksb-mark" aria-hidden="true">
          ⚠
        </span>
        <span className="ksb-headline">
          ENFORCEMENT HALTED — kernel sting/containment is DISARMED deployment-wide.
        </span>
        <span className="ksb-meta">
          Disarmed by <b>{operator}</b>
          {reason ? <> · {reason}</> : null}
          {indefinite ? (
            <> · no auto-expiry (INDEFINITE — halted until an operator revives).</>
          ) : (
            <>
              {' '}
              · expires <b>{expiresUtc || ks.expires_at}</b>
              {countdown ? <> ({countdown})</> : null}.
            </>
          )}
        </span>
      </div>
      <div className="ksb-sub">
        Observe-only: detection, scoring, and labeling continue; no new flow will be
        contained, tarpitted, or jailed while halted. A jailed flow that touches a canary
        again is de-escalated (its kernel jail released); a flow already jailed that
        sends no further traffic stays jailed until its socket closes — it is not
        actively flushed (a full active-jail flush is a B2 follow-on). This dashboard is
        read-only; resume enforcement via <code>canaryctl killswitch revive</code>.
      </div>
    </section>
  );
}

// fmtCountdown: a COSMETIC relative time-to-expiry ("in 42m" / "in 1h 5m" /
// "expiring"). Computed browser-side, so it can disagree with the tap's `engaged`
// bit near the boundary (clock skew) — never used to gate; the server `engaged`
// bit is authoritative. Returns "" for the zero sentinel / unparseable.
function fmtCountdown(iso?: string | null): string {
  if (isZeroTime(iso)) return '';
  const t = Date.parse(iso as string);
  if (!Number.isFinite(t)) return '';
  const sec = Math.floor((t - Date.now()) / 1000);
  if (sec <= 0) return 'expiring';
  if (sec < 60) return `in ${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `in ${min}m`;
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return remMin > 0 ? `in ${hr}h ${remMin}m` : `in ${hr}h`;
}
