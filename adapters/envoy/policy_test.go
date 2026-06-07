package envoy

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
)

func TestFailPolicyDefault(t *testing.T) {
	p := DefaultFailPolicy()
	if !p.Allow(contract.TierObserve) || !p.Allow(contract.TierTag) {
		t.Fatal("Tiers 0/1 must fail-open (non-blocking by design)")
	}
	if !p.Allow(contract.TierContain) {
		t.Fatal("Tier 2 is fail-open by default (only Tier 3 is fail-closed)")
	}
	if p.Allow(contract.TierJail) {
		t.Fatal("Tier 3 must fail-closed by default (the conservative inline posture)")
	}
}

func TestFailPolicyConfigurable(t *testing.T) {
	open := FailPolicy{FailClosed: map[contract.Tier]bool{}}
	if !open.Allow(contract.TierJail) {
		t.Fatal("an operator may configure Tier 3 fail-open")
	}
	closedT2 := FailPolicy{FailClosed: map[contract.Tier]bool{contract.TierContain: true}}
	if closedT2.Allow(contract.TierContain) {
		t.Fatal("Tier 2 should fail-closed when configured")
	}
}
