package main

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

type fakeEnforcer struct {
	applied []containment.Action
	cookies []uint64
	err     error
}

func (f *fakeEnforcer) Apply(v contract.Verdict, a containment.Action) error {
	f.applied = append(f.applied, a)
	f.cookies = append(f.cookies, v.Flow.SocketCookie)
	return f.err
}
func (f *fakeEnforcer) Close() error { return nil }

func verdict(mode contract.EnforcementMode, tier contract.Tier, cookie uint64) contract.Verdict {
	return contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: cookie}, Mode: mode, Tier: tier}
}

func TestEnforceVerdict(t *testing.T) {
	cases := []struct {
		name        string
		v           contract.Verdict
		wantApplied bool
		wantAct     containment.Action
	}{
		{"inline T3 not kernel-enforced (proxy actioned it)", verdict(contract.ModeInline, contract.TierJail, 1), false, 0},
		{"async T0 never contains", verdict(contract.ModeAsync, contract.TierObserve, 1), false, 0},
		{"async T1 never contains", verdict(contract.ModeAsync, contract.TierTag, 1), false, 0},
		{"async T2 -> rate-limit", verdict(contract.ModeAsync, contract.TierContain, 1), true, containment.RateLimit},
		{"async T3 -> jail", verdict(contract.ModeAsync, contract.TierJail, 1), true, containment.Jail},
		{"async T3 cookie-0 unattributable -> none", verdict(contract.ModeAsync, contract.TierJail, 0), false, 0},
	}
	for _, tc := range cases {
		f := &fakeEnforcer{}
		act, applied, err := enforceVerdict(f, tc.v)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if applied != tc.wantApplied {
			t.Fatalf("%s: applied=%v want %v", tc.name, applied, tc.wantApplied)
		}
		if tc.wantApplied {
			if act != tc.wantAct || len(f.applied) != 1 || f.applied[0] != tc.wantAct {
				t.Fatalf("%s: act=%v applied=%v want %v", tc.name, act, f.applied, tc.wantAct)
			}
		} else if len(f.applied) != 0 {
			t.Fatalf("%s: enforcer called when it must not be: %+v", tc.name, f.applied)
		}
	}
}

func TestEnforceVerdictErrorPropagates(t *testing.T) {
	f := &fakeEnforcer{err: errors.New("program failed")}
	if _, applied, err := enforceVerdict(f, verdict(contract.ModeAsync, contract.TierJail, 7)); err == nil || !applied {
		t.Fatalf("expected an applied-with-error result, got applied=%v err=%v", applied, err)
	}
}
