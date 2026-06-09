// Package identity bridges the L7 (Envoy ext_proc) view of a connection to the
// kernel socket cookie — the single L7<->kernel join key (docs/IDENTITY.md). The
// adapter builds a host-canonical FourTuple from ext_proc connection attributes
// and asks a CookieResolver for the cookie that the sockops eBPF program captured
// for that connection. A MISS means the flow is unattributable: the adapter emits
// observe-only and MUST NOT enforce against it. There is no second join mechanism.
//
// The real resolver is kernel-backed (cilium/ebpf, reading the pinned sockops
// map) and lives behind a //go:build linux file in bpf/loader; this package
// defines only the seam plus a FakeResolver, so the ENTIRE adapter is unit-
// testable on any OS without a kernel or a running Envoy.
package identity

import (
	"io"
	"net/netip"
	"sync"
)

// Address families, matching the C/eBPF side (AF_INET / AF_INET6). Defined here
// rather than via syscall so the package builds identically on every OS.
const (
	AFInet  uint16 = 2
	AFInet6 uint16 = 10
)

// FourTuple is the host-canonical connection key. Its byte layout is mirrored,
// field-for-field, by the bpf2go-generated C struct so the Go lookup key and the
// kernel map key can never drift; a //go:build linux test asserts Sizeof and
// field offsets against the generated struct on the box.
//
// Src is the connection's REMOTE end (the attacker; ext_proc source.*); Dst is
// the LOCAL end (Envoy; ext_proc destination.*). IPv4 occupies the first 4 bytes
// of the 16-byte address fields with the rest zero (uniform with IPv6, so v4 and
// v6 share one map layout). Ports are host byte order; the adapter canonicalizes
// before lookup, and the sockops program normalizes the kernel's network-order
// fields to match.
type FourTuple struct {
	Family  uint16
	SrcPort uint16
	DstPort uint16
	_       uint16 // explicit pad to 8-byte-align the address fields (matches C)
	SrcIP   [16]byte
	DstIP   [16]byte
}

// SourceAddr reconstructs the caller's IP from the tuple's family + bytes. It is
// the (real, kernel-observed) source identity an adapter may stamp into
// contract.AttrSourceAddress for the M7 staged labeler. ok=false if the family
// is unset (a zero tuple).
func (t FourTuple) SourceAddr() (netip.Addr, bool) {
	switch t.Family {
	case AFInet:
		return netip.AddrFrom4([4]byte{t.SrcIP[0], t.SrcIP[1], t.SrcIP[2], t.SrcIP[3]}), true
	case AFInet6:
		return netip.AddrFrom16(t.SrcIP), true
	default:
		return netip.Addr{}, false
	}
}

// Resolution is the kernel-side value for a FourTuple: the socket cookie plus the
// coarse identifiers (cgroup/pid) and a generation that lets the resolver treat a
// stale or ambiguous entry as a MISS rather than risk a misattributed verdict.
type Resolution struct {
	Cookie     uint64
	CgroupID   uint64
	PID        uint32
	Generation uint32
}

// CookieResolver maps a connection 4-tuple to its kernel socket cookie. ok=false
// is a MISS — the flow is unattributable and MUST NOT be enforced against. The
// real implementation reads the pinned sockops map (bpf/loader, linux-only); the
// FakeResolver drives tests and the local selfcheck everywhere.
type CookieResolver interface {
	Resolve(t FourTuple) (Resolution, bool)
	io.Closer
}

// TupleFromAddrs builds a host-canonical FourTuple from the connection's remote
// (source) and local (destination) IP:port as Envoy ext_proc reports them. It
// accepts IPv4 or IPv6 (including v4-mapped v6, which it folds to canonical v4).
// An unparseable address yields ok=false so the caller treats the flow as
// unattributable rather than guessing.
func TupleFromAddrs(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (FourTuple, bool) {
	s, errS := netip.ParseAddr(srcIP)
	d, errD := netip.ParseAddr(dstIP)
	if errS != nil || errD != nil {
		return FourTuple{}, false
	}
	s, d = s.Unmap(), d.Unmap()
	// Both ends of one connection share an address family.
	if s.Is4() != d.Is4() {
		return FourTuple{}, false
	}
	ft := FourTuple{SrcPort: srcPort, DstPort: dstPort}
	if s.Is4() {
		ft.Family = AFInet
		sa, da := s.As4(), d.As4()
		copy(ft.SrcIP[:4], sa[:])
		copy(ft.DstIP[:4], da[:])
	} else {
		ft.Family = AFInet6
		a, b := s.As16(), d.As16()
		copy(ft.SrcIP[:], a[:])
		copy(ft.DstIP[:], b[:])
	}
	return ft, true
}

// FakeResolver is an in-memory CookieResolver for tests and the local selfcheck.
// It supports forced misses and a "miss N times then hit" mode to exercise the
// establish-vs-first-byte race the adapter absorbs with a bounded re-lookup. It is
// concurrency-safe so the adapter's per-request lookups can run under -race.
type FakeResolver struct {
	mu         sync.Mutex
	entries    map[FourTuple]Resolution
	missesLeft map[FourTuple]int
	forceMiss  bool
}

// NewFakeResolver returns an empty FakeResolver (every lookup misses until Set).
func NewFakeResolver() *FakeResolver {
	return &FakeResolver{entries: map[FourTuple]Resolution{}, missesLeft: map[FourTuple]int{}}
}

// Set registers a cookie for a tuple (subsequent Resolve hits, unless forced miss
// or pending miss-count).
func (f *FakeResolver) Set(t FourTuple, r Resolution) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[t] = r
}

// SetForceMiss makes every Resolve return a MISS (models a flow with no cookie).
func (f *FakeResolver) SetForceMiss(b bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forceMiss = b
}

// MissThenHit registers a cookie that MISSES the first n Resolve calls for the
// tuple, then hits — exercising the adapter's bounded re-lookup over the
// establish-vs-first-byte race.
func (f *FakeResolver) MissThenHit(t FourTuple, r Resolution, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[t] = r
	f.missesLeft[t] = n
}

// Resolve implements CookieResolver.
func (f *FakeResolver) Resolve(t FourTuple) (Resolution, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forceMiss {
		return Resolution{}, false
	}
	if n := f.missesLeft[t]; n > 0 {
		f.missesLeft[t] = n - 1
		return Resolution{}, false
	}
	r, ok := f.entries[t]
	return r, ok
}

// Close implements CookieResolver (nothing to release).
func (f *FakeResolver) Close() error { return nil }
