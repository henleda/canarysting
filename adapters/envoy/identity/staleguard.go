package identity

// staleguard.go implements the userspace attribution-freshness guard for
// socket-cookie resolution (docs/IDENTITY.md, CLAUDE.md rule 4 + "a jailed
// bystander is a critical failure").
//
// What actually protects a bystander, in two layers:
//
//  1. Enforcement keys on the LIVE socket cookie. The enforce path
//     (bpf/enforce, enforce_egress) reads the offending socket's cookie directly
//     via bpf_get_socket_cookie and Linux socket cookies are monotonic and NEVER
//     reused. So a STALE cookie left in the verdict map is inert: no live socket
//     carries it, and it cannot jail a bystander. This is the primary guarantee,
//     and it holds regardless of anything in this file.
//
//  2. This guard protects the ATTRIBUTION itself. The sockops bridge resolves a
//     connection 4-tuple to a socket cookie via an LRU map whose only freshness
//     signal is best-effort delete-on-close. A MISSED TCP_CLOSE plus a reused
//     ephemeral port means a NEW connection's 4-tuple still resolves to the OLD
//     connection's cookie until the new PASSIVE_ESTABLISHED capture overwrites
//     it. Attribution drives scoring, evidence, the operator's view, and any
//     future ingress-hold enforcement that does NOT read the cookie live — so a
//     stale resolution there would charge the wrong flow. The guard re-reads the
//     tuple and refuses any resolution it cannot confirm is stable.
//
// The freshness signal is the socket cookie. Because cookies are never reused, a
// fresh capture for a reused tuple necessarily carries a DIFFERENT cookie than the
// stale entry it replaces. So a re-read that returns a different cookie (or no
// entry at all) is proof the entry churned under us. There is no reliance on the
// kernel flow_val.generation field: the committed sockops object does not stamp a
// real monotonic generation (it is a layout-only vestige), so the cookie-change
// comparison — which works regardless of generation — is the actual guard.

// StaleGuardResolver decorates a CookieResolver and only returns a resolution it
// can confirm is stable (the same socket cookie across a confirmation re-read).
// Any instability — the entry vanished, or the cookie changed (a newer connection
// captured on the same 4-tuple, the reused-ephemeral-port churn) — is reported as
// a MISS. The caller then treats the flow as unattributable and never enforces,
// which is the fail-safe direction (CLAUDE.md "fail safe on uncertainty"; a
// refuse-to-jail is always preferable to a possibly-misattributed jail). It is a
// pure decorator: zero kernel dependencies, unit-testable on any OS via a
// FakeResolver/scriptedResolver.
type StaleGuardResolver struct {
	inner CookieResolver
}

var _ CookieResolver = (*StaleGuardResolver)(nil)

// NewStaleGuard wraps inner with the staleness guard. A nil inner is a programming
// error the caller must avoid; the composition root always passes the real
// resolver.
func NewStaleGuard(inner CookieResolver) *StaleGuardResolver {
	return &StaleGuardResolver{inner: inner}
}

// Resolve returns a confirmed-stable resolution, or a MISS. It reads the tuple
// twice: the entry must be present both times, with the SAME socket cookie. A
// second read that misses or returns a different cookie means the LRU entry was
// evicted/closed or replaced by a newer connection on the same 4-tuple (the
// missed-close + reused-ephemeral-port race). In that case the first read's cookie
// may not belong to the live flow, so we refuse it rather than risk a
// misattribution. Cookies are never reused, so a changed cookie is unambiguous
// proof of churn.
func (g *StaleGuardResolver) Resolve(t FourTuple) (Resolution, bool) {
	first, ok := g.inner.Resolve(t)
	if !ok {
		return Resolution{}, false
	}
	second, ok := g.inner.Resolve(t)
	if !ok {
		// Entry vanished between reads (eviction / close) -> unstable -> refuse.
		return Resolution{}, false
	}
	if second.Cookie != first.Cookie {
		// The entry was replaced by a newer connection on this 4-tuple (the reused
		// ephemeral port the guard exists to catch — a fresh capture always carries a
		// new, never-reused cookie). The first read's cookie cannot be trusted to be
		// the live flow's -> refuse rather than risk a misattribution.
		return Resolution{}, false
	}
	return first, true
}

// Close closes the wrapped resolver.
func (g *StaleGuardResolver) Close() error { return g.inner.Close() }
