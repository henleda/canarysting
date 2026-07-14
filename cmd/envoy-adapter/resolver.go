package main

import "github.com/canarysting/canarysting/adapters/envoy/identity"

// newResolver selects the CookieResolver implementation. noEBPF=true
// short-circuits to identity.NewFakeResolver (every lookup MISSes; never
// fabricates a cookie) before ever touching the kernel sockops map — the
// escape hatch for a BTF-less Linux host (kina) where a real eBPF load would
// fail. noEBPF=false delegates to the build-tagged newKernelResolver (real
// kernel-backed resolver on Linux, an error stub elsewhere).
func newResolver(noEBPF bool) (identity.CookieResolver, error) {
	if noEBPF {
		return identity.NewFakeResolver(), nil
	}
	return newKernelResolver()
}
