package containment

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/bpf/loader"
	"github.com/canarysting/canarysting/internal/contract"
)

type progRec struct {
	action      uint32
	rate, burst uint64
	n           int
}

type fakeLoader struct {
	programmed map[uint64]progRec
	released   map[uint64]int
}

func newFakeLoader() *fakeLoader {
	return &fakeLoader{programmed: map[uint64]progRec{}, released: map[uint64]int{}}
}

var _ loader.Loader = (*fakeLoader)(nil)

func (f *fakeLoader) Load() error { return nil }
func (f *fakeLoader) Program(c uint64, a uint32, rate, burst uint64) error {
	r := f.programmed[c]
	r.action, r.rate, r.burst, r.n = a, rate, burst, r.n+1
	f.programmed[c] = r
	return nil
}
func (f *fakeLoader) Release(c uint64) error                  { f.released[c]++; delete(f.programmed, c); return nil }
func (f *fakeLoader) Counters(uint64) (loader.Counters, bool) { return loader.Counters{}, false }
func (f *fakeLoader) Close() error                            { return nil }

func mustContainer(t *testing.T, f loader.Loader) *KernelContainer {
	t.Helper()
	c, err := New(Config{Loader: f})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verdict(tier contract.Tier, cookie uint64) contract.Verdict {
	return contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: cookie}, Tier: tier}
}

func TestApplyRefusesZeroCookie(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	if err := c.Apply(verdict(contract.TierJail, 0), Jail); !errors.Is(err, ErrUnattributable) {
		t.Fatalf("expected ErrUnattributable, got %v", err)
	}
	if len(f.programmed) != 0 {
		t.Fatal("a cookie-0 (unattributable) flow was programmed — precision violated")
	}
}

func TestApplyProgramsJailForTier3(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	if err := c.Apply(verdict(contract.TierJail, 0xABC), Jail); err != nil {
		t.Fatal(err)
	}
	r, ok := f.programmed[0xABC]
	if !ok || r.action != loader.ActionJail || r.n != 1 {
		t.Fatalf("jail not programmed exactly once: %+v ok=%v", r, ok)
	}
}

func TestApplyRateLimitSetsBucket(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	if err := c.Apply(verdict(contract.TierContain, 0x1), RateLimit); err != nil {
		t.Fatal(err)
	}
	r := f.programmed[0x1]
	if r.action != loader.ActionRateLimit || r.rate != DefaultRateBytesPerSec || r.burst != DefaultBurstBytes {
		t.Fatalf("rate-limit token bucket not sized: %+v", r)
	}
}

func TestBystanderNeverProgrammed(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	if err := c.Apply(verdict(contract.TierJail, 0xA77), Jail); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.programmed[0xBEEF]; ok {
		t.Fatal("a bystander cookie was programmed")
	}
	if len(f.programmed) != 1 {
		t.Fatalf("expected only the attacker programmed, got %d entries", len(f.programmed))
	}
}

func TestActionForTier(t *testing.T) {
	if _, ok := ActionForTier(contract.TierObserve); ok {
		t.Fatal("Tier 0 must not contain")
	}
	if _, ok := ActionForTier(contract.TierTag); ok {
		t.Fatal("Tier 1 must not contain")
	}
	if a, ok := ActionForTier(contract.TierContain); !ok || a != RateLimit {
		t.Fatalf("Tier 2 -> RateLimit, got %v %v", a, ok)
	}
	if a, ok := ActionForTier(contract.TierJail); !ok || a != Jail {
		t.Fatalf("Tier 3 -> Jail, got %v %v", a, ok)
	}
}

func TestReleaseIsIdempotentAndCookieZeroNoop(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	_ = c.Apply(verdict(contract.TierJail, 0x9), Jail)
	if err := c.Release(verdict(contract.TierJail, 0x9)); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(verdict(contract.TierJail, 0x9)); err != nil {
		t.Fatal("double release errored")
	}
	if err := c.Release(verdict(contract.TierJail, 0)); err != nil {
		t.Fatal("cookie-0 release should be a no-op nil")
	}
	if f.released[0x9] < 1 {
		t.Fatal("release was not forwarded to the loader")
	}
}

func TestNewRejectsNilLoader(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New should reject a nil loader")
	}
}

// TestEscalateThenReleaseRemovesEntry is the B3 de-escalation invariant at the
// containment layer: a flow jailed at Tier 3 and then Released must leave NO entry
// in the verdict map (the fakeLoader deletes on Release, mirroring the kernel's
// bpf_map_delete_elem). Proves a de-escalation actually frees the kernel state
// rather than leaving a stale jail behind.
func TestEscalateThenReleaseRemovesEntry(t *testing.T) {
	f := newFakeLoader()
	c := mustContainer(t, f)
	const cookie = 0xD06
	if err := c.Apply(verdict(contract.TierJail, cookie), Jail); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.programmed[cookie]; !ok {
		t.Fatal("escalate did not program the jail")
	}
	if err := c.Release(verdict(contract.TierJail, cookie)); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.programmed[cookie]; ok {
		t.Fatal("de-escalation left the verdict-map entry in place (stale jail)")
	}
	if f.released[cookie] != 1 {
		t.Fatalf("Release was not forwarded exactly once: %d", f.released[cookie])
	}
}
