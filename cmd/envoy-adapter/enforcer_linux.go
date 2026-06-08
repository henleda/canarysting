//go:build linux

package main

import (
	"github.com/canarysting/canarysting/bpf/enforce"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// kernelEnforcer wires the cgroup eBPF loader to the containment logic: Apply
// programs the kernel verdict map for an attributed flow; Close detaches.
type kernelEnforcer struct {
	l *enforce.KernelLoader
	c *containment.KernelContainer
}

func (e *kernelEnforcer) Apply(v contract.Verdict, a containment.Action) error {
	return e.c.Apply(v, a)
}
func (e *kernelEnforcer) Close() error { return e.l.Close() }

// newEnforcer loads + attaches the enforce programs at the cgroup-v2 root (the
// same root the sockops bridge uses) and returns a containment-backed enforcer.
// Requires CAP_BPF + CAP_NET_ADMIN.
func newEnforcer() (enforcer, error) {
	l := enforce.NewKernelLoader(cgroupV2Root)
	if err := l.Load(); err != nil {
		return nil, err
	}
	c, err := containment.New(containment.Config{Loader: l})
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	return &kernelEnforcer{l: l, c: c}, nil
}
