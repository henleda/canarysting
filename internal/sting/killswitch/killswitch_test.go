package killswitch

import (
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

// A fresh switch is disengaged (the safe, normal posture — never starts halted).
func TestNewStartsDisengaged(t *testing.T) {
	k := New(func() time.Time { return t0 })
	if k.Active(t0) {
		t.Fatal("a fresh kill-switch must start disengaged")
	}
	if st := k.Status(t0); st.Engaged {
		t.Fatalf("fresh status must be disengaged: %+v", st)
	}
}

// A timed engagement is active up to the expiry and auto-expires lazily after it,
// with no background goroutine — evaluated purely by comparison against `now`.
func TestTimedEngageAutoExpires(t *testing.T) {
	k := New(nil)
	k.Engage(t0, time.Minute, "alice", "incident-42")
	if !k.Active(t0) {
		t.Fatal("just-engaged switch must be active")
	}
	if !k.Active(t0.Add(59 * time.Second)) {
		t.Fatal("must still be active before expiry")
	}
	if k.Active(t0.Add(time.Minute)) {
		t.Fatal("must auto-expire AT the expiry instant (now.Before(expiry) is false)")
	}
	if k.Active(t0.Add(2 * time.Minute)) {
		t.Fatal("must stay expired past the expiry")
	}
	// Status reflects the same lazy expiry.
	if st := k.Status(t0.Add(2 * time.Minute)); st.Engaged {
		t.Fatalf("status must report disengaged after auto-expiry: %+v", st)
	}
}

// A non-positive duration means INDEFINITE: active until an explicit Revive, never
// auto-expiring.
func TestIndefiniteEngageNeedsRevive(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		k := New(nil)
		st := k.Engage(t0, d, "bob", "halt")
		if !st.ExpiresAt.IsZero() {
			t.Fatalf("d=%v: indefinite engage must have a zero ExpiresAt, got %v", d, st.ExpiresAt)
		}
		if !k.Active(t0.Add(1000 * time.Hour)) {
			t.Fatalf("d=%v: indefinite engage must not auto-expire", d)
		}
		k.Revive(t0.Add(1000*time.Hour), "bob", "all clear")
		if k.Active(t0.Add(1001 * time.Hour)) {
			t.Fatalf("d=%v: revive must clear an indefinite engage", d)
		}
	}
}

// Status carries who/why/when for the IR surface, and a revive clears them.
func TestStatusFieldsAndRevive(t *testing.T) {
	k := New(nil)
	st := k.Engage(t0, time.Hour, "carol", "suspected FP storm")
	if !st.Engaged || st.Operator != "carol" || st.Reason != "suspected FP storm" {
		t.Fatalf("engage status wrong: %+v", st)
	}
	if !st.EngagedAt.Equal(t0) || !st.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("engage timestamps wrong: %+v", st)
	}
	rs := k.Revive(t0.Add(time.Minute), "carol", "resolved")
	if rs.Engaged || rs.Operator != "" || rs.Reason != "" {
		t.Fatalf("revive must clear the live status: %+v", rs)
	}
}

// Re-engaging extends/replaces the window (e.g. to lengthen a halt).
func TestReEngageReplacesWindow(t *testing.T) {
	k := New(nil)
	k.Engage(t0, time.Minute, "a", "first")
	st := k.Engage(t0.Add(30*time.Second), 10*time.Minute, "b", "extend")
	if st.Operator != "b" || st.Reason != "extend" {
		t.Fatalf("re-engage must replace operator/reason: %+v", st)
	}
	if !k.Active(t0.Add(5 * time.Minute)) {
		t.Fatal("re-engage must extend the active window")
	}
}

// A nil *KillSwitch is safe: never active, zero status (the seam guard relies on this).
func TestNilReceiverSafe(t *testing.T) {
	var k *KillSwitch
	if k.Active(t0) {
		t.Fatal("nil switch must never be active")
	}
	if st := k.Status(t0); st.Engaged {
		t.Fatalf("nil switch status must be disengaged: %+v", st)
	}
}

// Concurrent engages/revives/reads must not race (run under -race).
func TestConcurrentAccessNoRace(t *testing.T) {
	k := New(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); k.Engage(t0, time.Minute, "op", "r") }()
		go func() { defer wg.Done(); _ = k.Active(t0.Add(time.Second)) }()
		go func() { defer wg.Done(); k.Revive(t0.Add(time.Second), "op", "r") }()
	}
	wg.Wait()
}
