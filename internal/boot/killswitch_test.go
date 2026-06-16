package boot_test

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
)

// buildAggressive returns an engine where a single canary touch escalates to Jail
// (the -aggressive single-touch band), backed by a durable DB so the capture/audit
// siblings are real — they are the "spy" that proves the seam captured the REAL
// verdict even when the kill-switch floors the RETURNED one.
func buildAggressive(t *testing.T) *boot.Built {
	t.Helper()
	return buildAggressiveClock(t, nil)
}

// buildAggressiveClock is buildAggressive with an injectable TRUSTED engine clock
// (Options.Now) so a test can drive the kill-switch's auto-expire deterministically —
// and prove the floor consults THIS clock, never the per-event timestamp. A nil clock
// defaults to time.Now (the production behavior).
func buildAggressiveClock(t *testing.T, clock func() time.Time) *boot.Built {
	t.Helper()
	db := filepath.Join(t.TempDir(), "baseline.db")
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute, BaselineDBPath: db, Aggressive: true, Now: clock}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = built.Close() })
	return built
}

// jailCanaries are 4 DISTINCT canary types: under -aggressive (MinConfidence) the
// Jail threshold is minTouches(3)+0.01*span(3)=3.03, so 4 distinct touches (score
// 4.0) on one cookie escalate to Jail. (A single touch only reaches Tag.)
var jailCanaries = []string{"aws.key", "ssh.key", "db.dump", "api.token"}

// escalateToJail submits the 4 distinct touches that drive cookie to Jail and
// returns the FINAL verdict the engine emitted (post-kill-switch floor, if any).
func escalateToJail(t *testing.T, built *boot.Built, cookie uint64, now time.Time) contract.Verdict {
	t.Helper()
	var v contract.Verdict
	for _, c := range jailCanaries {
		var err error
		v, err = built.Engine.Submit(contract.SignalEvent{
			Flow:      contract.FlowIdentity{SocketCookie: cookie},
			Scope:     "scopeA",
			Canary:    contract.CanaryType(c),
			Timestamp: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return v
}

// auditTierFor returns the tier recorded in the latest audit-chain decision record
// for scopeA — the proof of what the capture seam REALLY saw.
func latestDecisionTier(t *testing.T, built *boot.Built) int {
	t.Helper()
	blob, err := built.Audit.Export("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	var report audit.CaseReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Verify.Intact {
		t.Fatalf("audit chain not intact: %+v", report.Verify)
	}
	last := -1
	for _, r := range report.Records {
		if r.Kind == audit.KindDecision {
			last = r.Tier
		}
	}
	if last < 0 {
		t.Fatal("no decision record found in the audit chain")
	}
	return last
}

// (a) When engaged, Submit returns a TIER-FLOORED (Observe) verdict to the caller —
// while the capture/audit siblings still recorded the REAL (Jail) tier. The floor is
// a COPY: history is not rewritten.
func TestKillSwitchEngagedFloorsReturnedTierButCapturesReal(t *testing.T) {
	built := buildAggressive(t)
	now := time.Now()
	built.KillSwitch.Engage(now, time.Hour, "ir", "halt enforcement")

	v := escalateToJail(t, built, 0xBEEF, now)
	if v.Tier != contract.TierObserve {
		t.Fatalf("engaged kill-switch must floor the RETURNED tier to Observe, got %d", v.Tier)
	}
	// Identity + non-enforcement fields preserved so the adapter's Release targets the
	// right socket and the dashboard still sees the real score.
	if v.Flow.SocketCookie != 0xBEEF {
		t.Fatalf("floored verdict lost the socket cookie: %#x", v.Flow.SocketCookie)
	}
	if v.Score < 1.0 {
		t.Fatalf("floored verdict must preserve the real score, got %v", v.Score)
	}
	// The audit chain (the capture seam's record) saw the REAL Jail tier.
	if got := latestDecisionTier(t, built); got != int(contract.TierJail) {
		t.Fatalf("audit chain recorded tier %d, want the REAL Jail (%d) — the floor must not rewrite history", got, contract.TierJail)
	}
}

// (b) A timed engagement auto-expires against the TRUSTED ENGINE CLOCK — NOT the
// per-event timestamp. Regression test for the clock-source bug: a touch dated far
// past the expiry must NOT bypass an active halt, and once the trusted clock passes
// the expiry the real tier returns regardless of the event's timestamp.
func TestKillSwitchAutoExpireUsesTrustedClockNotEventTimestamp(t *testing.T) {
	var mu sync.Mutex
	cur := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return cur }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); cur = cur.Add(d) }
	built := buildAggressiveClock(t, clock)

	// Engage a 1-minute halt as of the trusted clock.
	built.KillSwitch.Engage(clock(), time.Minute, "ir", "brief halt")

	// A touch whose EVENT timestamp is 10 minutes in the FUTURE (a skewed/hostile
	// adapter clock far past the expiry). The floor must IGNORE it and consult the
	// trusted engine clock (still inside the window) — so the verdict is STILL floored.
	future := cur.Add(10 * time.Minute)
	if v := escalateToJail(t, built, 0x1, future); v.Tier != contract.TierObserve {
		t.Fatalf("a future-dated event must NOT bypass an active halt — the floor must use the trusted engine clock, not the event timestamp (got tier %d, want Observe)", v.Tier)
	}

	// Advance the TRUSTED clock past the expiry. Now the halt auto-expires and the real
	// tier returns — even for an event timestamped back INSIDE the original window,
	// proving expiry tracks the trusted clock, not the event ts.
	advance(2 * time.Minute)
	past := time.Date(2026, 6, 15, 12, 0, 30, 0, time.UTC) // inside the original 1-min window
	if v := escalateToJail(t, built, 0x2, past); v.Tier != contract.TierJail {
		t.Fatalf("after the trusted clock passes expiry the real tier must return regardless of event ts (got %d, want Jail %d)", v.Tier, contract.TierJail)
	}
}

// (c) When NOT engaged, the verdict passes through byte-identical to the un-killed
// engine (the kill-switch is byte-neutral until engaged).
func TestKillSwitchDisengagedPassesThrough(t *testing.T) {
	built := buildAggressive(t)
	now := time.Now()
	// Never engaged.
	v := escalateToJail(t, built, 0xCAFE, now)
	if v.Tier != contract.TierJail {
		t.Fatalf("disengaged kill-switch must pass the verdict through unchanged; tier=%d want Jail %d", v.Tier, contract.TierJail)
	}
	// Re-run the SAME engine path with the switch engaged-then-revived: still passes through.
	built.KillSwitch.Engage(now, time.Hour, "ir", "x")
	built.KillSwitch.Revive(now, "ir", "clear")
	if v := escalateToJail(t, built, 0xF00D, now); v.Tier != contract.TierJail {
		t.Fatalf("after revive the verdict must pass through; tier=%d want Jail %d", v.Tier, contract.TierJail)
	}
}

// (d) EngageKillSwitch/ReviveKillSwitch append operator-action records into the same
// per-scope chain as decisions, and the mixed chain Verifies Intact.
func TestKillSwitchTogglesAuditIntoChain(t *testing.T) {
	built := buildAggressive(t)
	now := time.Now()

	// A real decision first (Jail), then engage + revive (both audited).
	escalateToJail(t, built, 0xABCD, now)
	idIR := boot.OperatorIdentity{Name: "ir", Role: "operator", AuthVia: "single-token"}
	if _, err := built.EngageKillSwitch(now.Add(time.Second), time.Hour, idIR, "incident"); err != nil {
		t.Fatalf("EngageKillSwitch audit: %v", err)
	}
	if _, err := built.ReviveKillSwitch(now.Add(2*time.Second), idIR, "resolved"); err != nil {
		t.Fatalf("ReviveKillSwitch audit: %v", err)
	}

	blob, err := built.Audit.Export("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	var report audit.CaseReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Verify.Intact {
		t.Fatalf("mixed decision+operator chain must verify intact: %+v", report.Verify)
	}
	var decisions, engages, revives int
	for _, r := range report.Records {
		switch {
		case r.Kind == audit.KindDecision:
			decisions++
		case r.Kind == audit.KindOperator && r.Action == "kill_switch_engage":
			engages++
			if r.Posture["operator"] != "ir" || r.Posture["reason"] != "incident" {
				t.Fatalf("engage operator-action posture wrong: %+v", r.Posture)
			}
			// Additive RBAC posture keys: role + auth_via are threaded from the identity.
			if r.Posture["role"] != "operator" || r.Posture["auth_via"] != "single-token" {
				t.Fatalf("engage posture missing role/auth_via: %+v", r.Posture)
			}
		case r.Kind == audit.KindOperator && r.Action == "kill_switch_revive":
			revives++
		}
	}
	if decisions < 1 || engages != 1 || revives != 1 {
		t.Fatalf("chain composition wrong: decisions=%d (want >=1) engages=%d revives=%d", decisions, engages, revives)
	}
}
