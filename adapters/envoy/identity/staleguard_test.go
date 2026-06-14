package identity

import "testing"

// scriptedResolver returns a scripted sequence of resolutions for one tuple, so a
// test can model the entry CHANGING between the guard's two reads (the missed-close
// + reused-ephemeral-port race the guard exists to catch). After the script is
// exhausted it repeats the last element.
type scriptedResolver struct {
	seq    []resolveResult
	calls  int
	closed bool
}

type resolveResult struct {
	res Resolution
	ok  bool
}

func (s *scriptedResolver) Resolve(FourTuple) (Resolution, bool) {
	i := s.calls
	s.calls++
	if i >= len(s.seq) {
		i = len(s.seq) - 1
	}
	r := s.seq[i]
	return r.res, r.ok
}
func (s *scriptedResolver) Close() error { s.closed = true; return nil }

var guardTuple, _ = TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)

// TestStaleGuardPassesStableResolution: a stable entry (same socket cookie on both
// reads) resolves through unchanged. Generation is irrelevant to the guard — the
// freshness signal is the never-reused socket cookie.
func TestStaleGuardPassesStableResolution(t *testing.T) {
	want := Resolution{Cookie: 0xC0FFEE, PID: 42}
	g := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{want, true}, {want, true}}})
	got, ok := g.Resolve(guardTuple)
	if !ok {
		t.Fatal("stable, current resolution must pass the guard")
	}
	if got != want {
		t.Fatalf("guard altered the resolution: got %+v want %+v", got, want)
	}
}

// TestStaleGuardRefusesReplacedEntry is the core B2 case: a stale entry (missed
// TCP_CLOSE) is REPLACED by a newer connection on the same 4-tuple between the two
// reads — a DIFFERENT socket cookie (cookies are never reused, so a fresh capture
// always carries a new one). The guard must MISS so the adapter never attributes
// against a cookie that may not be the live flow's. This is the "stale/reused-port
// scenario does NOT attribute to the wrong flow" assertion at the resolver seam.
func TestStaleGuardRefusesReplacedEntry(t *testing.T) {
	stale := Resolution{Cookie: 0xAAAA} // old connection's entry
	fresh := Resolution{Cookie: 0xBBBB} // new connection captured between reads
	g := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{stale, true}, {fresh, true}}})
	if r, ok := g.Resolve(guardTuple); ok {
		t.Fatalf("guard must refuse a churned (reused-port) entry, but returned %+v", r)
	}
}

// TestStaleGuardVanishedEntry: the entry is evicted/closed between the two reads
// (first hit, second miss) -> unstable -> refuse.
func TestStaleGuardRefusesVanishedEntry(t *testing.T) {
	hit := Resolution{Cookie: 0xAAAA}
	g := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{hit, true}, {Resolution{}, false}}})
	if _, ok := g.Resolve(guardTuple); ok {
		t.Fatal("an entry that vanished between reads must be refused")
	}
}

// TestStaleGuardIgnoresGeneration: the kernel flow_val.generation is a layout-only
// vestige (the committed sockops object does not stamp a real monotonic value), so
// the guard must NOT key on it. A stable cookie with a zero (or any) generation
// passes; only a cookie change/vanish refuses. This pins that the guard does not
// regress to a generation check that the kernel can no longer satisfy.
func TestStaleGuardIgnoresGeneration(t *testing.T) {
	// Zero generation, stable cookie -> passes (generation is not a signal).
	z := Resolution{Cookie: 0xAAAA, Generation: 0}
	if _, ok := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{z, true}, {z, true}}}).Resolve(guardTuple); !ok {
		t.Fatal("a stable cookie must pass regardless of a zero generation")
	}
	// Generation differs but the cookie is stable -> still passes (same live flow).
	a := Resolution{Cookie: 0xAAAA, Generation: 5}
	b := Resolution{Cookie: 0xAAAA, Generation: 6}
	if _, ok := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{a, true}, {b, true}}}).Resolve(guardTuple); !ok {
		t.Fatal("a generation difference with a stable cookie must pass (cookie is the signal)")
	}
}

// TestStaleGuardMissStaysMiss: a plain miss from the inner resolver stays a miss
// (the guard never invents an attribution).
func TestStaleGuardMissStaysMiss(t *testing.T) {
	g := NewStaleGuard(&scriptedResolver{seq: []resolveResult{{Resolution{}, false}}})
	if _, ok := g.Resolve(guardTuple); ok {
		t.Fatal("a miss must stay a miss")
	}
}

// TestStaleGuardClosePropagates: Close reaches the wrapped resolver.
func TestStaleGuardClosePropagates(t *testing.T) {
	inner := &scriptedResolver{seq: []resolveResult{{Resolution{}, false}}}
	g := NewStaleGuard(inner)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if !inner.closed {
		t.Fatal("Close did not propagate to the wrapped resolver")
	}
}
