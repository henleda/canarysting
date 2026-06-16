package boot_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
)

// A fake canonical deviant key (the bytes are opaque to the overlay — only the
// identity-as-bytes matters). Shaped like deviantKey: [0x01][fam][src][dst][port][dim].
var fakeDeviantKey = []byte{0x01, 0x00, 0x02, 10, 20, 1, 104, 10, 20, 1, 9, 0x1f, 0x42, 0x01}

// Suppress -> Unsuppress round-trips through the overlay AND both audit into the SAME
// per-scope tamper-evident chain as decisions; the mixed chain Verifies Intact. The
// deviant key rides Posture["deviant_key"] (hex), NOT the SocketCookie field.
func TestDeviantSuppressUnsuppressAuditsIntoChain(t *testing.T) {
	built := buildAggressive(t)
	now := time.Now()

	// A real decision first (Jail), then suppress + ack + unsuppress (all audited).
	escalateToJail(t, built, 0xBEEF, now)
	id := boot.OperatorIdentity{Name: "alice", Role: "operator", AuthVia: "principal"}

	state, err := built.SuppressDeviant(now.Add(time.Second), fakeDeviantKey, id, "known benign scanner", "10.20.1.104")
	if err != nil {
		t.Fatalf("SuppressDeviant: %v", err)
	}
	if state != "suppressed" {
		t.Fatalf("suppress state = %q, want suppressed", state)
	}
	if state, err := built.AckDeviant(now.Add(2*time.Second), fakeDeviantKey, id, "seen", ""); err != nil || state != "acked" {
		t.Fatalf("AckDeviant = %q, %v; want acked, nil", state, err)
	}
	if state, err := built.UnsuppressDeviant(now.Add(3*time.Second), fakeDeviantKey, id, "cleared"); err != nil || state != "normal" {
		t.Fatalf("UnsuppressDeviant = %q, %v; want normal, nil", state, err)
	}

	// The overlay is cleared after unsuppress (round-trip back to absent/normal).
	if _, ok, err := built.Persist.GetDeviantTriage(built.BoundaryScope, fakeDeviantKey); err != nil || ok {
		t.Fatalf("overlay row still present after unsuppress: ok=%v err=%v", ok, err)
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
		t.Fatalf("mixed decision+deviant-triage chain must verify intact: %+v", report.Verify)
	}
	wantKeyHex := hex.EncodeToString(fakeDeviantKey)
	var suppress, ack, unsuppress int
	for _, r := range report.Records {
		if r.Kind != audit.KindOperator {
			continue
		}
		switch r.Action {
		case "deviant_suppress":
			suppress++
			if r.Posture["operator"] != "alice" || r.Posture["reason"] != "known benign scanner" {
				t.Fatalf("suppress posture wrong: %+v", r.Posture)
			}
			if r.Posture["deviant_key"] != wantKeyHex {
				t.Fatalf("suppress deviant_key = %q, want %q", r.Posture["deviant_key"], wantKeyHex)
			}
			if r.Posture["role"] != "operator" || r.Posture["auth_via"] != "principal" {
				t.Fatalf("suppress posture missing role/auth_via: %+v", r.Posture)
			}
			// The deviant key must NOT be jammed into the per-connection cookie field.
			if r.SocketCookie != 0 {
				t.Fatalf("deviant action recorded a SocketCookie %d; a deviant is keyed by deviant_key, not a cookie", r.SocketCookie)
			}
		case "deviant_ack":
			ack++
		case "deviant_unsuppress":
			unsuppress++
		}
	}
	if suppress != 1 || ack != 1 || unsuppress != 1 {
		t.Fatalf("triage chain composition wrong: suppress=%d ack=%d unsuppress=%d", suppress, ack, unsuppress)
	}
}

// RULE 8 BEHAVIORAL INVARIANT (load-bearing): suppressing a deviant identity does NOT
// remove it from detection — a mover whose pattern an operator SUPPRESSED that LATER
// touches a canary STILL ARMS. The overlay is display-only; it is not a
// BenignExcluder and not on the Submit verdict path, so a canary touch still scores
// base>0, still base×M, still Decides a tier, and still escalates. We suppress the
// identity's deviant key, THEN drive that same cookie's flow to a canary-touch
// escalation, and assert the emitted verdict still reaches the Jail tier.
func TestSuppressedDeviantStillArms(t *testing.T) {
	built := buildAggressive(t)
	now := time.Now()

	id := boot.OperatorIdentity{Name: "alice", Role: "operator", AuthVia: "principal"}
	if _, err := built.SuppressDeviant(now, fakeDeviantKey, id, "known benign", "10.20.1.104"); err != nil {
		t.Fatalf("SuppressDeviant: %v", err)
	}
	// Confirm the suppression is actually recorded (so the test is not vacuous).
	if rec, ok, _ := built.Persist.GetDeviantTriage(built.BoundaryScope, fakeDeviantKey); !ok || rec.State != "suppressed" {
		t.Fatalf("suppression not recorded: ok=%v rec=%+v", ok, rec)
	}

	// The SAME identity now touches canaries (enters the response pipeline). Despite
	// the suppression, the engine still escalates to Jail.
	v := escalateToJail(t, built, 0xCAFE, now.Add(time.Minute))
	if v.Tier < contract.TierContain {
		t.Fatalf("suppressed identity did NOT arm on a canary touch: emitted tier %v (< Contain) — the overlay must NOT be on the verdict path (Rule 8)", v.Tier)
	}
	// The audit chain's REAL decision tier is the highest (Jail) — the touch armed.
	if got := latestDecisionTier(t, built); got < int(contract.TierJail) {
		t.Fatalf("real decision tier = %d, want >= Jail (%d): a suppressed mover that touches a canary must still arm", got, int(contract.TierJail))
	}
}

// With no durable store, the deviant-triage seams refuse (they cannot persist the
// intent, so they must not silently report success).
func TestDeviantTriageRefusesWithoutStore(t *testing.T) {
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = built.Close() })
	if built.Persist != nil {
		t.Fatal("expected no durable store (Persist nil) for the no-DB build")
	}
	id := boot.OperatorIdentity{Name: "alice", Role: "operator", AuthVia: "single-token"}
	if _, err := built.SuppressDeviant(time.Now(), fakeDeviantKey, id, "x", ""); err == nil {
		t.Fatal("SuppressDeviant must refuse with no durable store")
	}
	if _, err := built.UnsuppressDeviant(time.Now(), fakeDeviantKey, id, "x"); err == nil {
		t.Fatal("UnsuppressDeviant must refuse with no durable store")
	}
}
