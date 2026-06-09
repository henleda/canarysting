//go:build linux

package observe

// PlatformObserver returns the observer for Linux.
//
// TODO(M7 on-box): return NewKernelObserver() once bpf/observe/loader_linux.go
// (the cilium/ebpf-backed KernelObserver over the cgroup_skb observe programs) is
// built and proven on the box. Until then this is the NoopObserver placeholder so
// the linux build is green before the on-box phase; with observe disabled (no
// -observe-cgroup) the engine runs touch-only either way.
func PlatformObserver() Observer { return NoopObserver{} }
