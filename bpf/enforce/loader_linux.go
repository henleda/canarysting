//go:build linux

package enforce

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/canarysting/canarysting/bpf/loader"
)

// KernelLoader implements loader.Loader: it loads + attaches the enforce programs
// (cgroup_skb/egress drop+throttle, cgroup/sock_release close-delete) and programs
// per-cookie verdicts in the shared verdict_map. One process owns both programs.
// Requires CAP_BPF + CAP_NET_ADMIN and a cgroup-v2 unified hierarchy.
type KernelLoader struct {
	cgroupPath string
	objs       enforceObjects
	links      []link.Link
}

var _ loader.Loader = (*KernelLoader)(nil)

// NewKernelLoader returns a loader that attaches at cgroupPath (e.g.
// "/sys/fs/cgroup"). It does no kernel work until Load.
func NewKernelLoader(cgroupPath string) *KernelLoader { return &KernelLoader{cgroupPath: cgroupPath} }

// Load loads the objects and attaches both programs to the cgroup.
func (l *KernelLoader) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("enforce: remove memlock: %w", err)
	}
	if err := loadEnforceObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("enforce: load objects: %w", err)
	}
	egress, err := link.AttachCgroup(link.CgroupOptions{
		Path: l.cgroupPath, Attach: ebpf.AttachCGroupInetEgress, Program: l.objs.EnforceEgress,
	})
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("enforce: attach cgroup_skb/egress at %q: %w", l.cgroupPath, err)
	}
	release, err := link.AttachCgroup(link.CgroupOptions{
		Path: l.cgroupPath, Attach: ebpf.AttachCgroupInetSockRelease, Program: l.objs.EnforceRelease,
	})
	if err != nil {
		egress.Close()
		l.objs.Close()
		return fmt.Errorf("enforce: attach cgroup/sock_release at %q: %w", l.cgroupPath, err)
	}
	l.links = []link.Link{egress, release}
	return nil
}

// Program writes the verdict for a cookie. For rate-limit, rate/burst size the
// token bucket; for deny/jail they are zero. Refuses cookie 0.
func (l *KernelLoader) Program(cookie uint64, action uint32, rate, burst uint64) error {
	if cookie == 0 {
		return errors.New("enforce: refusing to program cookie 0 (unattributable)")
	}
	v := enforceVerdictVal{Action: action, Rate: rate, Burst: burst}
	return l.objs.VerdictMap.Update(&cookie, &v, ebpf.UpdateAny)
}

// Release deletes a cookie's verdict (idempotent).
func (l *KernelLoader) Release(cookie uint64) error {
	if cookie == 0 {
		return nil
	}
	if err := l.objs.VerdictMap.Delete(&cookie); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// Counters reads the kernel drop counters for a cookie.
func (l *KernelLoader) Counters(cookie uint64) (loader.Counters, bool) {
	var v enforceVerdictVal
	if err := l.objs.VerdictMap.Lookup(&cookie, &v); err != nil {
		return loader.Counters{}, false
	}
	return loader.Counters{DroppedPkts: v.DroppedPkts, DroppedBytes: v.DroppedBytes}, true
}

// Close detaches the programs and releases the objects.
func (l *KernelLoader) Close() error {
	for _, lk := range l.links {
		if lk != nil {
			_ = lk.Close()
		}
	}
	return l.objs.Close()
}
