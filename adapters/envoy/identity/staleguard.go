package identity

// staleguard.go implements the real staleness guard for socket-cookie attribution
// (docs/IDENTITY.md, CLAUDE.md rule 4 + "a jailed bystander is a critical
// failure"). It is the userspace half of the guard; the kernel half is the real
// monotonic flow_val.generation the sockops program now writes (was a hardcoded 1).
//
// The hole it closes: the sockops bridge resolves a connection 4-tuple to a socket
// cookie via an LRU map whose only freshness signal was best-effort delete-on-close.
// A MISSED TCP_CLOSE plus a reused ephemeral port means a NEW (possibly legitimate)
// connection's 4-tuple still resolves to the OLD connection's cookie until the new
// PASSIVE_ESTABLISHED capture overwrites it. Acting on that stale resolution
// attributes a verdict to the wrong flow.
//
// Why a generation, not just the cookie: the enforce path reads the live socket's
// cookie directly (bpf_get_socket_cookie on egress), and Linux socket cookies are
// monotonic and never reused, so a STALE cookie programmed into the verdict map is
// usually inert (no live socket carries it). But attribution still drives scoring,
// evidence, the operator's view, and any future ingress-hold enforcement that does
// NOT read the cookie live. So we refuse to hand a resolution to enforcement unless
// we can confirm the entry is the CURRENT capture for that tuple, not a stale one
// being replaced. The generation is that confirmation: a fresh capture for a reused
// tuple has a strictly higher generation, so a re-read that returns a different
// cookie or a higher generation proves the entry churned under us.

// StaleGuardResolver decorates a CookieResolver and only returns a resolution that
// it can confirm is stable (the same cookie+generation across a confirmation
// re-read) and non-stale (a non-zero generation). Any instability or a zero
// generation is reported as a MISS — the caller then treats the flow as
// unattributable and never enforces, which is the fail-safe direction (CLAUDE.md
// "fail safe on uncertainty"; a refuse-to-jail is always preferable to a
// possibly-misattributed jail). It is a pure decorator: zero kernel dependencies,
// unit-testable on any OS via a FakeResolver.
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
// twice: the entry must be present both times, with the SAME cookie and a
// generation that did not advance. A second read that misses, returns a different
// cookie, or shows a higher generation means the LRU entry was evicted or replaced
// by a newer connection on the same 4-tuple between the reads (the missed-close +
// port-reuse race) — so the first read's cookie may not belong to the live flow and
// we refuse it. A zero generation (an entry never stamped by a real capture, or the
// pre-guard map layout) is also refused: without a freshness ordinal we cannot
// prove the entry is current.
func (g *StaleGuardResolver) Resolve(t FourTuple) (Resolution, bool) {
	first, ok := g.inner.Resolve(t)
	if !ok {
		return Resolution{}, false
	}
	if first.Generation == 0 {
		// No freshness ordinal -> cannot confirm the entry is the current capture.
		return Resolution{}, false
	}
	second, ok := g.inner.Resolve(t)
	if !ok {
		// Entry vanished between reads (eviction / close) -> unstable -> refuse.
		return Resolution{}, false
	}
	if second.Cookie != first.Cookie || second.Generation != first.Generation {
		// The entry was replaced by a newer connection on this 4-tuple (the reused
		// ephemeral port the guard exists to catch). The first read's cookie cannot be
		// trusted to be the live flow's -> refuse rather than risk a misattribution.
		return Resolution{}, false
	}
	return first, true
}

// Close closes the wrapped resolver.
func (g *StaleGuardResolver) Close() error { return g.inner.Close() }
