//go:build linux

package observe

// PlatformObserver returns the kernel-backed observer on Linux: the
// cilium/ebpf-loaded KernelObserver over the cgroup_skb observe programs. With
// observe disabled (no -observe-cgroup) the engine never calls Load, so this is
// inert until wired; on a host without CAP_BPF/cgroup-v2, Load fails loudly.
func PlatformObserver() Observer { return NewKernelObserver() }
