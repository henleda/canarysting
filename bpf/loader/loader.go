// Package loader is the Go (cilium/ebpf) userspace side of kernel enforcement.
// It loads the eBPF programs in bpf/enforce/, manages maps keyed by the socket
// cookie, pushes per-flow verdict state, and reads counters back. The map
// schema (keyed by socket cookie) is the loader<->kernel contract. See
// docs/IDENTITY.md and docs/STING.md.
//
// The same eBPF substrate also powers BASELINE observation (see
// docs/TECHNICAL_ARCHITECTURE.md): low-overhead, in-kernel summarized flow
// records (adjacency, ports, cadence, volume, lifecycle) feed the per-scope
// baseline used as scoring weight context and to auto-derive benign exclusion.
// Baseline observation NEVER enforces on its own — only a verdict (from a
// canary touch) programs the enforcement map. Keep observation and enforcement
// paths distinct.
package loader

// Loader manages the lifecycle of the eBPF enforcement programs.
type Loader interface {
	Load() error
	// Program sets per-flow enforcement state keyed by socket cookie.
	Program(socketCookie uint64, action uint32) error
	Close() error
}

// TODO: cilium/ebpf load + map management; schema keyed by socket cookie.
