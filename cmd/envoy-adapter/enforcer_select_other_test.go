//go:build !linux

package main

import "testing"

// TestNewEnforcerDefaultAttemptsKernel guards the dev-build (non-Linux)
// false-path: newEnforcer(false) must still delegate to the build-tagged
// newKernelEnforcer() indirection and, on this platform, that stub succeeds
// (returns noopEnforcer) exactly as the pre-existing enforcer_other.go stub
// does today. The Linux false-path (attempts real eBPF, errors without BTF)
// is out of unit scope for this seam test — it requires a Linux kernel.
func TestNewEnforcerDefaultAttemptsKernel(t *testing.T) {
	enf, err := newEnforcer(false)
	if err != nil {
		t.Fatalf("newEnforcer(false) returned error: %v", err)
	}
	if enf == nil {
		t.Fatal("newEnforcer(false) returned nil enforcer")
	}
}
