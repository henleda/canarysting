//go:build !linux

package main

// newKernelEnforcer on non-Linux: kernel containment (eBPF) runs only on the
// Linux box. The local pure-Go containment logic is covered by
// internal/sting/containment unit tests; this stub keeps the composition root
// compiling on macOS. noopEnforcer is defined in enforcer.go (untagged) so it
// is available on every platform.
func newKernelEnforcer() (enforcer, error) { return noopEnforcer{}, nil }
