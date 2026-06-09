// Package observe is the Go userspace side of the M7 OBSERVE-ONLY baseline path.
// It defines the read-only contract over the kernel flow-stats map: load the
// observation programs, read per-socket-cookie flow statistics, iterate them,
// and close. The kernel-backed KernelObserver (loader_linux.go, build-tag linux)
// implements it by attaching cgroup_skb/ingress + cgroup_skb/egress (per-packet
// byte/packet accounting) plus cgroup/sock_release (delete-on-close) over an
// LRU_HASH keyed by bpf_get_socket_cookie(); a NoopObserver implements it
// elsewhere so the tree builds on macOS.
//
// THIS PATH NEVER ENFORCES (CLAUDE.md rules 4 & 8, docs/BASELINE_MULTIPLIER.md
// §10). It is structurally distinct from the M5 enforcement path (bpf/enforce):
// a SEPARATE program, map, loader, and cgroup link. Two structural guarantees
// make "observe never enforces" impossible to violate:
//   - The kernel programs return PASS on every path (there is no DROP; a layout
//     test greps for the absence of `return 0` in observe.bpf.c).
//   - This interface has NO write method — no Program/Update/Delete. Userspace is
//     incapable of mutating the kernel map; it can only read. The baseline is an
//     observation, and observation cannot act.
//
// The socket cookie is the SAME join key the M4 sockops bridge and the M5
// enforce map use (rule 4) — one cookie, now four touchpoints, no second join.
package observe

import "errors"

// Address family values (Linux) carried in FlowStats.Family.
const (
	AFInet  = 2  // AF_INET (IPv4; address in SrcIP/DstIP[0:4])
	AFInet6 = 10 // AF_INET6 (IPv6; full 16 bytes)
)

// FlowStats is the userspace view of one flow's kernel-accumulated statistics,
// keyed in the map by socket cookie. It mirrors the generated observeFlowStats
// struct field-for-field (the on-box layout_test pins their parity); this clean
// type is what the loader hands to the aggregator so observebaseline never
// imports the cilium/ebpf-generated bindings.
//
// All counters are cumulative since the flow's first observed packet. The
// aggregator tracks each cookie across ticks and folds the flow exactly ONCE,
// with its FINAL cumulative totals, when the cookie disappears (sock_release
// delete = flow ended) — never inter-read deltas — so a long-lived flow read on
// many ticks is never double-counted (see internal/engine/observebaseline,
// aggregate.foldFlow). These counters must therefore be monotonic non-decreasing
// for a live cookie; a backwards step is read as a new socket reusing the cookie.
type FlowStats struct {
	IngressPackets uint64 // packets observed cgroup-ingress (toward the workload)
	IngressBytes   uint64 // bytes observed cgroup-ingress
	EgressPackets  uint64 // packets observed cgroup-egress (from the workload)
	EgressBytes    uint64 // bytes observed cgroup-egress
	FirstSeenNs    uint64 // bpf_ktime_get_ns at first packet (4-tuple captured here)
	LastSeenNs     uint64 // bpf_ktime_get_ns at most recent packet

	Family  uint16 // AFInet or AFInet6
	SrcPort uint16 // remote/initiator port, host order (the caller)
	DstPort uint16 // local/service port, host order (the workload being reached)
	Closed  uint16 // 0 = open; 1 = the flow has ended (sock_release). A closed flow is folded once.

	// SrcIP/DstIP hold the captured addresses. For AFInet the address is in the
	// first 4 bytes. These are consumed by the aggregator to derive adjacency and
	// identity novelty and are NEVER persisted raw — only their FNV hash and
	// derived novelty cross into the durable baseline (rule 9).
	SrcIP [16]byte // remote/initiator address (the caller's identity)
	DstIP [16]byte // local/service address (the reached workload)
}

// TotalBytes is ingress+egress bytes — the volume envelope for VolumeDeviation.
func (f FlowStats) TotalBytes() uint64 { return f.IngressBytes + f.EgressBytes }

// TotalPackets is ingress+egress packets.
func (f FlowStats) TotalPackets() uint64 { return f.IngressPackets + f.EgressPackets }

// DurationNs is the observed lifetime of the flow (>= 0). Used for CadenceDeviation.
func (f FlowStats) DurationNs() uint64 {
	if f.LastSeenNs >= f.FirstSeenNs {
		return f.LastSeenNs - f.FirstSeenNs
	}
	return 0
}

// Reader is the minimal read surface the aggregator depends on. Keeping it
// separate from the lifecycle (Load/Close) lets tests supply a fake without a
// kernel, and makes explicit that the consumer can only READ.
type Reader interface {
	// ReadStats returns the current stats for a cookie; ok=false on a map miss
	// (the flow is gone or was never observed). Never mutates the map.
	ReadStats(cookie uint64) (stats FlowStats, ok bool, err error)
	// IterStats calls fn for every live (cookie, stats) entry. fn must not retain
	// stats by reference across calls. Never mutates the map.
	IterStats(fn func(cookie uint64, stats FlowStats) error) error
}

// Observer is the full lifecycle contract: a Reader plus load/close. It has no
// write method by construction (see the package doc) — there is no way to
// program the map from userspace.
type Observer interface {
	Reader
	// Load loads and attaches the observe programs at cgroupPath (cgroup v2 mount,
	// e.g. /sys/fs/cgroup). Must be called before reads.
	Load(cgroupPath string) error
	// Close detaches the programs and releases resources. Idempotent.
	Close() error
}

// errNotLinux reports that kernel observation is unavailable (off Linux, or
// before the on-box kernel observer is built). Load and IterStats fail LOUD
// (never a silent empty baseline that would look like "calibrated on no data");
// ReadStats reports a clean miss so the per-flow scoring path degrades to neutral
// M=1 rather than erroring on every request.
var errNotLinux = errors.New("observe: kernel observation unavailable on this platform; run on the box")

// NoopObserver satisfies Observer where no kernel observer is available, so the
// tree builds everywhere and the engine runs with no baseline data — every scope
// stays not-live, so M is a forced 1.0 (touch-only), the safe cold-start
// behavior. It is the macOS/CI observer and the pre-on-box linux placeholder.
type NoopObserver struct{}

var _ Observer = (*NoopObserver)(nil)

func (NoopObserver) Load(string) error { return errNotLinux }

func (NoopObserver) ReadStats(uint64) (FlowStats, bool, error) { return FlowStats{}, false, nil }

func (NoopObserver) IterStats(func(uint64, FlowStats) error) error { return errNotLinux }

func (NoopObserver) Close() error { return nil }
