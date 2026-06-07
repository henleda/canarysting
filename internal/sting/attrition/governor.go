package attrition

import "sync/atomic"

// Governor is the host-wide accountant + kill switch shared by ALL flows. It is
// the universal backstop that a per-flow Budget cannot provide: a flood of
// suspicious flows, each within its own per-flow budget, must still not be able
// to collectively exhaust the host. The Governor caps aggregate bytes and the
// number of concurrent streams, and carries the single kill switch the operator
// (canaryctl) and the engine (host-pressure) both trip.
//
// It is concurrency-safe via atomics (the canonical shared-counter case), so the
// hot path never takes a lock. Every fail direction is the SAFE one: at the
// ceiling, killed, or at the stream cap, admission is refused and attrition
// degrades to a no-op.
type Governor struct {
	ceilingBytes  int64 // immutable after construction
	maxStreams    int64 // immutable after construction
	usedBytes     atomic.Int64
	activeStreams atomic.Int64
	killed        atomic.Bool
}

// NewGovernor builds a shared accountant. Zero/negative arguments fall back to
// the documented defaults — a missing ceiling is the conservative cap, never
// "unbounded".
func NewGovernor(ceilingBytes int64, maxStreams int) *Governor {
	if ceilingBytes <= 0 {
		ceilingBytes = DefaultGlobalCeiling
	}
	if maxStreams <= 0 {
		maxStreams = DefaultMaxConcurrentFlows
	}
	return &Governor{ceilingBytes: ceilingBytes, maxStreams: int64(maxStreams)}
}

// Reserve atomically admits n host-wide bytes against the ceiling. It returns
// false (the caller must stop, fail-closed) if the switch is killed or the
// ceiling would be exceeded. The compare-and-swap loop guarantees concurrent
// flows can never collectively overshoot the ceiling.
func (g *Governor) Reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	if g.killed.Load() {
		return false
	}
	for {
		cur := g.usedBytes.Load()
		if cur+n > g.ceilingBytes {
			return false
		}
		if g.usedBytes.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// Release returns n previously reserved bytes (called once at stream Close), so a
// flood recovers as flows finish and the ceiling does not erode over time.
func (g *Governor) Release(n int64) {
	if n > 0 {
		g.usedBytes.Add(-n)
	}
}

// OpenStream reserves a concurrent-stream slot (the fd/goroutine-exhaustion guard
// that bytes alone do not bound). Returns false if killed or at the cap; a
// successful OpenStream must be paired with exactly one CloseStream.
func (g *Governor) OpenStream() bool {
	if g.killed.Load() {
		return false
	}
	if g.activeStreams.Add(1) > g.maxStreams {
		g.activeStreams.Add(-1)
		return false
	}
	return true
}

// CloseStream releases a stream slot. Called once per successful OpenStream.
func (g *Governor) CloseStream() { g.activeStreams.Add(-1) }

// Kill trips the switch. Both the operator (canaryctl) and the engine
// (host-pressure hook) converge on this single atomic flag; there is no second
// kill mechanism. After Kill, every in-flight stream stops within one chunk and
// every new Open is a no-op.
func (g *Governor) Kill() { g.killed.Store(true) }

// Revive clears the switch (operator only).
func (g *Governor) Revive() { g.killed.Store(false) }

// Killed reports whether the switch is tripped.
func (g *Governor) Killed() bool { return g.killed.Load() }

// Snapshot returns live host-wide counters for the operator CLI / dashboard.
// OpenStream admits optimistically (Add then roll back on overshoot), so the raw
// activeStreams counter can transiently exceed maxStreams under concurrent Opens;
// the reported value is clamped so the operator dashboard never reads over-cap.
func (g *Governor) Snapshot() (usedBytes, activeStreams int64, killed bool) {
	a := g.activeStreams.Load()
	if a > g.maxStreams {
		a = g.maxStreams
	}
	return g.usedBytes.Load(), a, g.killed.Load()
}
