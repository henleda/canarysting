//go:build !linux

package main

import (
	"errors"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

// newResolver on non-Linux: the socket-cookie join is kernel-backed (eBPF), so the
// adapter binary only runs on the Linux demo host. The local pure-Go path is
// exercised by cmd/envoy-selfcheck with a FakeResolver.
func newResolver() (identity.CookieResolver, error) {
	return nil, errors.New("the kernel socket-cookie resolver requires Linux; run envoy-adapter on the dev box (use cmd/envoy-selfcheck locally)")
}
