package main

import (
	"testing"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// TestNewEnforcerNoEBPFReturnsNoop verifies the -no-ebpf selection path: on a
// BTF-less Linux host (kina node) the no-op enforcer must load without error.
// A real eBPF load attempt would error on such a host, so the selection
// function must short-circuit to noopEnforcer before ever touching cilium/ebpf.
func TestNewEnforcerNoEBPFReturnsNoop(t *testing.T) {
	enf, err := newEnforcer(true)
	if err != nil {
		t.Fatalf("newEnforcer(true) returned error: %v", err)
	}
	if enf == nil {
		t.Fatal("newEnforcer(true) returned nil enforcer")
	}
	if _, ok := enf.(noopEnforcer); !ok {
		t.Fatalf("newEnforcer(true) returned %T, want noopEnforcer", enf)
	}
}

// TestNoopEnforcerContract guards that the no-op enforcer honestly reports "no
// kernel containment available" rather than silently acking a jail/rate-limit
// it never applied — a false ack here would look like containment succeeded
// on a host with no kernel enforcement at all.
func TestNoopEnforcerContract(t *testing.T) {
	enf := noopEnforcer{}

	if err := enf.Apply(contract.Verdict{}, containment.RateLimit); err == nil {
		t.Error("noopEnforcer.Apply returned nil error, want non-nil")
	}
	if err := enf.Release(contract.Verdict{}); err == nil {
		t.Error("noopEnforcer.Release returned nil error, want non-nil")
	}
	if err := enf.Close(); err != nil {
		t.Errorf("noopEnforcer.Close returned %v, want nil", err)
	}
}

// TestNewResolverNoEBPFReturnsNoop verifies the resolver-side -no-ebpf
// selection: it must succeed with a resolver that reports every lookup as a
// MISS (unattributable), never error and never fabricate a cookie.
func TestNewResolverNoEBPFReturnsNoop(t *testing.T) {
	r, err := newResolver(true)
	if err != nil {
		t.Fatalf("newResolver(true) returned error: %v", err)
	}
	if r == nil {
		t.Fatal("newResolver(true) returned nil resolver")
	}
	if _, ok := r.(*identity.FakeResolver); !ok {
		t.Fatalf("newResolver(true) returned %T, want *identity.FakeResolver", r)
	}
}
