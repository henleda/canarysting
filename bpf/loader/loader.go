// Package loader is the Go (cilium/ebpf) userspace side of kernel enforcement.
// It defines the Loader contract — load the eBPF enforcement programs, program a
// per-flow verdict keyed by the socket cookie, release it, and read counters —
// implemented by the kernel-backed KernelLoader in bpf/enforce (build-tag linux)
// and by a NoopLoader elsewhere. The map schema (keyed by socket cookie) is the
// loader<->kernel contract. See docs/IDENTITY.md and docs/STING.md.
//
// The verdict map's write-ownership is split and deliberate: the loader writes the
// action (and the rate-limit rate/burst); the KERNEL writes the counters and the
// token-bucket state. The map is keyed by the SAME socket cookie the M4 sockops
// bridge resolves — one cookie, three touchpoints, no second join.
//
// This enforcement path is kept DISTINCT from the M4 sockops BASELINE observation
// path (separate program, map, loader, and cgroup link): observation never
// enforces, and a verdict (from a canary touch) is the only thing that programs
// the enforcement map.
package loader

// Action codes mirror internal/sting/containment.Action and the enforce.bpf.c
// #defines: 0 = rate-limit (token-bucket throttle), 1 = hard-deny, 2 = jail.
const (
	ActionRateLimit uint32 = 0
	ActionHardDeny  uint32 = 1
	ActionJail      uint32 = 2
)

// Counters are the kernel-written drop counters for one programmed cookie.
type Counters struct {
	DroppedPkts  uint64
	DroppedBytes uint64
}

// Loader manages the lifecycle of the eBPF enforcement programs and the verdict
// map. Implementations must NEVER program cookie 0 (an unattributable flow).
type Loader interface {
	// Load loads and attaches the enforcement programs.
	Load() error
	// Program sets per-flow enforcement state keyed by socket cookie. For
	// rate-limit (ActionRateLimit), rate (bytes/sec) and burst (bytes) size the
	// token bucket; they are ignored for deny/jail. Programming cookie 0 is refused.
	Program(socketCookie uint64, action uint32, rate, burst uint64) error
	// Release removes a flow's enforcement entry (de-escalation / operator clear).
	// Idempotent.
	Release(socketCookie uint64) error
	// Counters reads the kernel drop counters for a cookie; ok=false if not present.
	Counters(socketCookie uint64) (Counters, bool)
	// Close detaches the programs and releases resources.
	Close() error
}
