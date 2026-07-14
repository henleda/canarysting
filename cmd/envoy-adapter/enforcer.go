package main

import (
	"errors"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// noopEnforcer is the no-op containment implementation: it honestly reports
// "no kernel containment available" rather than silently acking a
// jail/rate-limit it never applied. Used on non-Linux builds (enforcer_other.go's
// newKernelEnforcer) and, on any platform, when the operator passes -no-ebpf to
// run the adapter on a BTF-less Linux host (kina) without attempting a real
// eBPF load.
type noopEnforcer struct{}

func (noopEnforcer) Apply(contract.Verdict, containment.Action) error {
	return errors.New("enforcer: kernel containment requires Linux")
}
func (noopEnforcer) Release(contract.Verdict) error {
	return errors.New("enforcer: kernel containment requires Linux")
}
func (noopEnforcer) Close() error { return nil }

// newEnforcer selects the containment implementation. noEBPF=true short-
// circuits to noopEnforcer before ever touching cilium/ebpf or attempting a
// kernel load — the escape hatch for a BTF-less Linux host (kina) where a real
// eBPF load would fail. noEBPF=false delegates to the build-tagged
// newKernelEnforcer (real eBPF on Linux, no-op stub elsewhere).
func newEnforcer(noEBPF bool) (enforcer, error) {
	if noEBPF {
		return noopEnforcer{}, nil
	}
	return newKernelEnforcer()
}
