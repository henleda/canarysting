package main

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

type fakeEnforcer struct {
	applied  []containment.Action
	cookies  []uint64
	released []uint64
	err      error
}

func (f *fakeEnforcer) Apply(v contract.Verdict, a containment.Action) error {
	f.applied = append(f.applied, a)
	f.cookies = append(f.cookies, v.Flow.SocketCookie)
	return f.err
}
func (f *fakeEnforcer) Release(v contract.Verdict) error {
	f.released = append(f.released, v.Flow.SocketCookie)
	return f.err
}
func (f *fakeEnforcer) Close() error { return nil }

func verdict(mode contract.EnforcementMode, tier contract.Tier, cookie uint64) contract.Verdict {
	return contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: cookie}, Mode: mode, Tier: tier}
}

func TestEnforceVerdict(t *testing.T) {
	cases := []struct {
		name         string
		v            contract.Verdict
		wantApplied  bool
		wantReleased bool
		wantAct      containment.Action
	}{
		{"inline T3 not kernel-enforced (proxy actioned it)", verdict(contract.ModeInline, contract.TierJail, 1), false, false, 0},
		{"async T0 releases (de-escalation)", verdict(contract.ModeAsync, contract.TierObserve, 1), false, true, 0},
		{"async T1 releases (de-escalation)", verdict(contract.ModeAsync, contract.TierTag, 1), false, true, 0},
		{"async T2 -> rate-limit", verdict(contract.ModeAsync, contract.TierContain, 1), true, false, containment.RateLimit},
		{"async T3 -> jail", verdict(contract.ModeAsync, contract.TierJail, 1), true, false, containment.Jail},
		{"async T3 cookie-0 unattributable -> none", verdict(contract.ModeAsync, contract.TierJail, 0), false, false, 0},
		{"inline T0 cookie-0 -> nothing", verdict(contract.ModeInline, contract.TierObserve, 0), false, false, 0},
	}
	for _, tc := range cases {
		f := &fakeEnforcer{}
		act, applied, released, err := enforceVerdict(f, tc.v)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if applied != tc.wantApplied {
			t.Fatalf("%s: applied=%v want %v", tc.name, applied, tc.wantApplied)
		}
		if released != tc.wantReleased {
			t.Fatalf("%s: released=%v want %v", tc.name, released, tc.wantReleased)
		}
		if tc.wantApplied {
			if act != tc.wantAct || len(f.applied) != 1 || f.applied[0] != tc.wantAct {
				t.Fatalf("%s: act=%v applied=%v want %v", tc.name, act, f.applied, tc.wantAct)
			}
			if len(f.released) != 0 {
				t.Fatalf("%s: released the loader while applying: %+v", tc.name, f.released)
			}
		} else if len(f.applied) != 0 {
			t.Fatalf("%s: enforcer Apply called when it must not be: %+v", tc.name, f.applied)
		}
		if tc.wantReleased {
			if len(f.released) != 1 || f.released[0] != tc.v.Flow.SocketCookie {
				t.Fatalf("%s: Release not called for the flow: %+v", tc.name, f.released)
			}
		} else if len(f.released) != 0 {
			t.Fatalf("%s: Release called when it must not be: %+v", tc.name, f.released)
		}
	}
}

func TestEnforceVerdictErrorPropagates(t *testing.T) {
	f := &fakeEnforcer{err: errors.New("program failed")}
	if _, applied, _, err := enforceVerdict(f, verdict(contract.ModeAsync, contract.TierJail, 7)); err == nil || !applied {
		t.Fatalf("expected an applied-with-error result, got applied=%v err=%v", applied, err)
	}
}

// TestEnforceVerdictReleaseErrorPropagates: a de-escalation Release that fails must
// surface released=true AND the error (so the composition root logs a release miss,
// not an apply miss).
func TestEnforceVerdictReleaseErrorPropagates(t *testing.T) {
	f := &fakeEnforcer{err: errors.New("release failed")}
	_, applied, released, err := enforceVerdict(f, verdict(contract.ModeAsync, contract.TierObserve, 7))
	if err == nil || applied || !released {
		t.Fatalf("expected released-with-error, got applied=%v released=%v err=%v", applied, released, err)
	}
}

// TestEscalateThenDeEscalateReleases is the B3 escalate -> de-escalate sequence:
// a flow jailed at Tier 3 whose next async verdict drops to Tier 0 must end with
// the containment entry RELEASED.
func TestEscalateThenDeEscalateReleases(t *testing.T) {
	f := &fakeEnforcer{}
	// Escalate: Tier 3 jail.
	if _, applied, _, err := enforceVerdict(f, verdict(contract.ModeAsync, contract.TierJail, 0x42)); err != nil || !applied {
		t.Fatalf("escalate: applied=%v err=%v", applied, err)
	}
	if len(f.applied) != 1 || f.applied[0] != containment.Jail {
		t.Fatalf("escalate did not jail: %+v", f.applied)
	}
	// De-escalate: a later verdict for the SAME flow drops to Tier 0.
	if _, applied, released, err := enforceVerdict(f, verdict(contract.ModeAsync, contract.TierObserve, 0x42)); err != nil || applied || !released {
		t.Fatalf("de-escalate: applied=%v released=%v err=%v", applied, released, err)
	}
	if len(f.released) != 1 || f.released[0] != 0x42 {
		t.Fatalf("de-escalate did not release the jailed flow: %+v", f.released)
	}
}

// TestReleaseVerdictForLabel: a false-positive label releases; a confirmed-malicious
// label does not; a cookie-0 label is a no-op.
func TestReleaseVerdictForLabel(t *testing.T) {
	cases := []struct {
		name         string
		label        contract.FeedbackLabel
		wantReleased bool
	}{
		{"false positive releases", contract.FeedbackLabel{Flow: contract.FlowIdentity{SocketCookie: 0x9}, WasMalicious: false}, true},
		{"confirmed malicious keeps containment", contract.FeedbackLabel{Flow: contract.FlowIdentity{SocketCookie: 0x9}, WasMalicious: true}, false},
		{"cookie-0 label is a no-op", contract.FeedbackLabel{Flow: contract.FlowIdentity{SocketCookie: 0}, WasMalicious: false}, false},
	}
	for _, tc := range cases {
		f := &fakeEnforcer{}
		released, err := releaseVerdictForLabel(f, tc.label)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if released != tc.wantReleased {
			t.Fatalf("%s: released=%v want %v", tc.name, released, tc.wantReleased)
		}
		if tc.wantReleased {
			if len(f.released) != 1 || f.released[0] != tc.label.Flow.SocketCookie {
				t.Fatalf("%s: Release not called for the labeled flow: %+v", tc.name, f.released)
			}
		} else if len(f.released) != 0 {
			t.Fatalf("%s: Release called when it must not be: %+v", tc.name, f.released)
		}
	}
}

// TestOperatorClear: the operator clear seam releases an attributed flow and
// refuses a cookie-0 request.
func TestOperatorClear(t *testing.T) {
	f := &fakeEnforcer{}
	if err := operatorClear(f, 0xABCD); err != nil {
		t.Fatalf("operator clear of an attributed flow errored: %v", err)
	}
	if len(f.released) != 1 || f.released[0] != 0xABCD {
		t.Fatalf("operator clear did not release the flow: %+v", f.released)
	}
	if err := operatorClear(f, 0); !errors.Is(err, errClearUnattributable) {
		t.Fatalf("operator clear of cookie 0 must be refused, got %v", err)
	}
	if len(f.released) != 1 {
		t.Fatalf("operator clear of cookie 0 must not release anything: %+v", f.released)
	}
}
