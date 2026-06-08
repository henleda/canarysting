//go:build linux

package sockops

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

// MapResolver is the kernel-backed identity.CookieResolver. It loads the sockops
// program, attaches it to the cgroup-v2 hierarchy, holds the flow_cookies map, and
// resolves a connection 4-tuple to the socket cookie the program captured. One
// process loads, attaches, and reads — no pinning needed for the single-host demo.
// Requires CAP_BPF + CAP_NET_ADMIN and a cgroup-v2 unified hierarchy.
type MapResolver struct {
	objs sockopsObjects
	lnk  link.Link
}

var _ identity.CookieResolver = (*MapResolver)(nil)

// NewMapResolver loads the sockops program, attaches it at cgroupPath (e.g.
// "/sys/fs/cgroup"), and returns a resolver over the flow_cookies map. The
// attached program captures the cookie for every connection accepted by a process
// under that cgroup.
func NewMapResolver(cgroupPath string) (*MapResolver, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("sockops: remove memlock: %w", err)
	}
	var objs sockopsObjects
	if err := loadSockopsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("sockops: load objects: %w", err)
	}
	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.CanarySockops,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("sockops: attach to cgroup %q: %w", cgroupPath, err)
	}
	return &MapResolver{objs: objs, lnk: lnk}, nil
}

// Resolve looks up the socket cookie for a connection 4-tuple. ok=false is a MISS:
// the flow is unattributable and the caller must not enforce against it. The key
// is built from the generated flow_key struct (whose layout the kernel program
// wrote), so the Go lookup and the kernel map agree byte-for-byte.
func (r *MapResolver) Resolve(t identity.FourTuple) (identity.Resolution, bool) {
	key := sockopsFlowKey{
		Family:  t.Family,
		SrcPort: t.SrcPort,
		DstPort: t.DstPort,
		SrcIp:   t.SrcIP,
		DstIp:   t.DstIP,
	}
	var v sockopsFlowVal
	if err := r.objs.FlowCookies.Lookup(&key, &v); err != nil {
		return identity.Resolution{}, false
	}
	return identity.Resolution{
		Cookie:     v.Cookie,
		CgroupID:   v.CgroupId,
		PID:        v.Pid,
		Generation: v.Generation,
	}, true
}

// Close detaches the program and releases the objects.
func (r *MapResolver) Close() error {
	var err error
	if r.lnk != nil {
		err = r.lnk.Close()
	}
	if cerr := r.objs.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}
