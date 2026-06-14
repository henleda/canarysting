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
// the adapter's 4-tuple lookups against the pinned-in-memory flow_cookies map,
// WRAPPED in the staleness guard so a stale entry (missed TCP_CLOSE + reused
// ephemeral port) can never hand a misattributed cookie to attribution — a jailed
// bystander is a critical failure (docs/IDENTITY.md, CLAUDE.md rule 4). The guard
// confirms the resolved entry is the current capture (stable socket cookie across a
// re-read; the cookie is never reused, so a changed cookie is unambiguous churn)
// before the adapter ever stamps it onto a flow. Requires CAP_BPF + CAP_NET_ADMIN.
func newResolver() (identity.CookieResolver, error) {
	mr, err := sockops.NewMapResolver(cgroupV2Root)
	if err != nil {
		return nil, err
	}
	return identity.NewStaleGuard(mr), nil
}
