//go:build !linux

package main

import (
	"errors"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// newEnforcer on non-Linux: kernel containment (eBPF) runs only on the Linux box.
// The local pure-Go containment logic is covered by internal/sting/containment
// unit tests; this stub keeps the composition root compiling on macOS.
func newEnforcer() (enforcer, error) { return noopEnforcer{}, nil }

type noopEnforcer struct{}

func (noopEnforcer) Apply(contract.Verdict, containment.Action) error {
	return errors.New("enforcer: kernel containment requires Linux")
}
func (noopEnforcer) Release(contract.Verdict) error {
	return errors.New("enforcer: kernel containment requires Linux")
}
func (noopEnforcer) Close() error { return nil }
