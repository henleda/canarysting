//go:build !linux

package kernel

// AssertSocketCookie is a no-op off Linux: there is no Linux kernel to interrogate, and
// the kernel-backed loaders are Linux-only and already fail loud on other platforms
// (bpf/loader.NoopLoader). The cross-platform release-version policy (checkRelease) is
// still exercised by the tests everywhere. Defined here so any cross-platform caller of
// AssertSocketCookie compiles on all targets.
func AssertSocketCookie() error { return nil }
