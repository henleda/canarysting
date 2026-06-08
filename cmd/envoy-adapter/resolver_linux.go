//go:build linux

package main

import (
	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/bpf/sockops"
)

// cgroupV2Root is the unified cgroup-v2 hierarchy the sockops program attaches to;
// attaching at the root captures every connection on the host (host-networked
// Envoy + services share it). Override per deployment if cgroups are namespaced.
const cgroupV2Root = "/sys/fs/cgroup"

// newResolver returns the real kernel-backed CookieResolver: the sockops
// MapResolver that captures each accepted connection's socket cookie and resolves
// the adapter's 4-tuple lookups against the pinned-in-memory flow_cookies map.
// Requires CAP_BPF + CAP_NET_ADMIN.
func newResolver() (identity.CookieResolver, error) {
	return sockops.NewMapResolver(cgroupV2Root)
}
