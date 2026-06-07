//go:build linux

package main

import (
	"errors"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

// newResolver on Linux will return the real kernel-backed CookieResolver — the
// MapResolver in bpf/loader that reads the pinned sockops flow_cookies map. That
// loader (sockops.bpf.c + cilium/ebpf) is the M4 ON-BOX deliverable; until it
// lands, this fails fast with a clear message rather than silently mis-resolving.
func newResolver() (identity.CookieResolver, error) {
	return nil, errors.New("envoy-adapter: the sockops cookie resolver (bpf/loader MapResolver) lands in the M4 on-box phase")
}
