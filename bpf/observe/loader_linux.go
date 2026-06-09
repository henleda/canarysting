//go:build linux

package observe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// KernelObserver implements Observer over the OBSERVE-ONLY eBPF programs: it
// loads + attaches cgroup_skb/ingress, cgroup_skb/egress, and cgroup/sock_release
// at a cgroup-v2 path and reads the per-cookie flow_stats map. It exposes ONLY
// reads — there is no method that writes/updates/deletes the map, so userspace is
// structurally incapable of mutating the baseline (the observe-never-enforces
// guarantee, paired with the kernel programs that only ever PASS). Requires
// CAP_BPF + CAP_PERFMON on a cgroup-v2 unified hierarchy.
type KernelObserver struct {
	objs  observeObjects
	links []link.Link
}

var _ Observer = (*KernelObserver)(nil)

// NewKernelObserver returns an observer; it does no kernel work until Load.
func NewKernelObserver() *KernelObserver { return &KernelObserver{} }

// Load loads the objects and attaches the three observe programs to cgroupPath.
func (o *KernelObserver) Load(cgroupPath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("observe: remove memlock: %w", err)
	}
	if err := loadObserveObjects(&o.objs, nil); err != nil {
		return fmt.Errorf("observe: load objects: %w", err)
	}
	type attach struct {
		name    string
		typ     ebpf.AttachType
		program *ebpf.Program
	}
	for _, a := range []attach{
		{"cgroup_skb/ingress", ebpf.AttachCGroupInetIngress, o.objs.ObserveIngress},
		{"cgroup_skb/egress", ebpf.AttachCGroupInetEgress, o.objs.ObserveEgress},
		{"cgroup/sock_release", ebpf.AttachCgroupInetSockRelease, o.objs.ObserveRelease},
	} {
		lk, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: a.typ, Program: a.program})
		if err != nil {
			o.closeLinks()
			o.objs.Close()
			return fmt.Errorf("observe: attach %s at %q: %w", a.name, cgroupPath, err)
		}
		o.links = append(o.links, lk)
	}
	return nil
}

// ReadStats returns the current stats for a cookie; ok=false on a map miss. It
// only Lookups — never writes.
func (o *KernelObserver) ReadStats(cookie uint64) (FlowStats, bool, error) {
	var raw observeCsFlowStats
	if err := o.objs.ObserveStats.Lookup(&cookie, &raw); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return FlowStats{}, false, nil
		}
		return FlowStats{}, false, err
	}
	return fromRaw(raw), true, nil
}

// IterStats calls fn for every live (cookie, stats) entry. It only iterates —
// never writes.
func (o *KernelObserver) IterStats(fn func(cookie uint64, stats FlowStats) error) error {
	var cookie uint64
	var raw observeCsFlowStats
	it := o.objs.ObserveStats.Iterate()
	for it.Next(&cookie, &raw) {
		if err := fn(cookie, fromRaw(raw)); err != nil {
			return err
		}
	}
	return it.Err()
}

// Close detaches the programs and releases the objects.
func (o *KernelObserver) Close() error {
	o.closeLinks()
	return o.objs.Close()
}

func (o *KernelObserver) closeLinks() {
	for _, lk := range o.links {
		if lk != nil {
			_ = lk.Close()
		}
	}
	o.links = nil
}
