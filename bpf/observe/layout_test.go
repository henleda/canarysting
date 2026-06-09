package observe

import (
	"testing"
	"unsafe"
)

// TestFlowStatsLayout pins the bpf2go-generated observeCsFlowStats against
// observe.bpf.c's struct flow_stats: the counters start at offset 0 (where the
// kernel's __sync_fetch_and_add lands), the struct is the expected 88 bytes, and
// the field widths are right. It guards against a stale/mis-generated binding
// (e.g. a missing -type flag) shipping out of sync with the C. Runs on every
// platform (the generated struct is not OS-tagged).
func TestFlowStatsLayout(t *testing.T) {
	var r observeCsFlowStats
	if off := unsafe.Offsetof(r.IngressPackets); off != 0 {
		t.Fatalf("IngressPackets must be at offset 0 (the kernel accumulates there first), got %d", off)
	}
	if got := unsafe.Sizeof(r); got != 88 {
		t.Fatalf("flow_stats size = %d, want 88", got)
	}
	// Field-width accesses fail to COMPILE if -type didn't generate them — the real
	// guard that the kernel's counters/timestamps/tuple are mirrored in Go.
	if unsafe.Sizeof(r.IngressPackets) != 8 || unsafe.Sizeof(r.IngressBytes) != 8 ||
		unsafe.Sizeof(r.EgressPackets) != 8 || unsafe.Sizeof(r.EgressBytes) != 8 ||
		unsafe.Sizeof(r.FirstSeenNs) != 8 || unsafe.Sizeof(r.LastSeenNs) != 8 {
		t.Fatal("expected 8-byte counter/timestamp fields")
	}
	if unsafe.Sizeof(r.Family) != 2 || unsafe.Sizeof(r.SrcPort) != 2 || unsafe.Sizeof(r.DstPort) != 2 {
		t.Fatal("expected 2-byte family/port fields")
	}
	if unsafe.Sizeof(r.SrcIp) != 16 || unsafe.Sizeof(r.DstIp) != 16 {
		t.Fatal("expected 16-byte IP fields")
	}
}

// TestFromRawParity asserts the loader's generated-struct -> clean-FlowStats
// conversion preserves every field (no drift between the kernel value and the
// view the aggregator derives features from).
func TestFromRawParity(t *testing.T) {
	raw := observeCsFlowStats{
		IngressPackets: 11, IngressBytes: 22, EgressPackets: 33, EgressBytes: 44,
		FirstSeenNs: 55, LastSeenNs: 66, Family: AFInet, SrcPort: 40000, DstPort: 8080,
		SrcIp: [16]byte{10, 0, 1, 5}, DstIp: [16]byte{10, 0, 2, 1},
	}
	fs := fromRaw(raw)
	if fs.IngressPackets != 11 || fs.IngressBytes != 22 || fs.EgressPackets != 33 || fs.EgressBytes != 44 {
		t.Fatalf("counter parity broken: %+v", fs)
	}
	if fs.FirstSeenNs != 55 || fs.LastSeenNs != 66 {
		t.Fatalf("timestamp parity broken: %+v", fs)
	}
	if fs.Family != AFInet || fs.SrcPort != 40000 || fs.DstPort != 8080 {
		t.Fatalf("tuple scalar parity broken: %+v", fs)
	}
	if fs.SrcIP != raw.SrcIp || fs.DstIP != raw.DstIp {
		t.Fatalf("ip parity broken: src=%v dst=%v", fs.SrcIP, fs.DstIP)
	}
}
