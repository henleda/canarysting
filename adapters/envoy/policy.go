package envoy

import "github.com/canarysting/canarysting/internal/contract"

// FailPolicy is the per-tier INLINE fail behavior, expressed purely in contract
// terms so the adapter never imports internal/engine (the import-graph guard
// forbids it). It is injected at the composition root from operator config
// (fail_closed.tier1 / fail_closed.tier3). It mirrors the engine's documented
// rule — fail-OPEN at Tier 1, fail-CLOSED at Tier 3 (docs/ENGINE.md) — but as a
// duplicated two-line map, not an import, to keep rule 1 (thin proxy) absolute.
//
// Allow answers: when the engine is UNAVAILABLE for an inline decision at a given
// tier, should the request be let through? Tiers at or below TierTag are
// async/non-blocking by design and always allow; a tier marked fail-closed denies.
// On a Submit error the tier is usually unknown (the verdict is what failed), so
// the adapter asks Allow(TierJail) — the most-conservative inline posture — which
// is fail-closed by default: a canary-touched (almost-certainly hostile) flow is
// denied, not waved through, when the engine is down.
type FailPolicy struct {
	FailClosed map[contract.Tier]bool
}

// DefaultFailPolicy returns the documented rule: fail-closed at TierJail, fail-open
// elsewhere (matches config fail_closed.tier3=true, fail_closed.tier1=false).
func DefaultFailPolicy() FailPolicy {
	return FailPolicy{FailClosed: map[contract.Tier]bool{contract.TierJail: true}}
}

// Allow reports whether to let a request through when the engine is unavailable
// for an inline decision at tier. Tiers <= TierTag always allow (non-blocking by
// design); otherwise allow unless the tier is configured fail-closed.
func (p FailPolicy) Allow(tier contract.Tier) bool {
	if tier <= contract.TierTag {
		return true
	}
	return !p.FailClosed[tier]
}
