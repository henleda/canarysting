package sockops

import (
	"testing"
	"unsafe"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

// TestLayoutMatchesBpf2go pins identity.FourTuple / identity.Resolution to the
// bpf2go-generated structs (which mirror the C map key/value the kernel program
// writes), so the Go lookup key and the kernel map can never silently drift — the
// #1 cause of a 100%-miss socket-cookie bridge. Runs on every platform (the
// generated structs are not OS-tagged).
func TestLayoutMatchesBpf2go(t *testing.T) {
	if got, want := unsafe.Sizeof(identity.FourTuple{}), unsafe.Sizeof(sockopsFlowKey{}); got != want {
		t.Fatalf("FourTuple size %d != generated flow_key size %d", got, want)
	}
	if got, want := unsafe.Sizeof(identity.Resolution{}), unsafe.Sizeof(sockopsFlowVal{}); got != want {
		t.Fatalf("Resolution size %d != generated flow_val size %d", got, want)
	}

	var ft identity.FourTuple
	var k sockopsFlowKey
	for _, c := range []struct {
		name string
		a, b uintptr
	}{
		{"Family", unsafe.Offsetof(ft.Family), unsafe.Offsetof(k.Family)},
		{"SrcPort", unsafe.Offsetof(ft.SrcPort), unsafe.Offsetof(k.SrcPort)},
		{"DstPort", unsafe.Offsetof(ft.DstPort), unsafe.Offsetof(k.DstPort)},
		{"SrcIP", unsafe.Offsetof(ft.SrcIP), unsafe.Offsetof(k.SrcIp)},
		{"DstIP", unsafe.Offsetof(ft.DstIP), unsafe.Offsetof(k.DstIp)},
	} {
		if c.a != c.b {
			t.Errorf("FourTuple.%s offset %d != flow_key offset %d", c.name, c.a, c.b)
		}
	}

	var res identity.Resolution
	var v sockopsFlowVal
	for _, c := range []struct {
		name string
		a, b uintptr
	}{
		{"Cookie", unsafe.Offsetof(res.Cookie), unsafe.Offsetof(v.Cookie)},
		{"CgroupID", unsafe.Offsetof(res.CgroupID), unsafe.Offsetof(v.CgroupId)},
		{"PID", unsafe.Offsetof(res.PID), unsafe.Offsetof(v.Pid)},
		{"Generation", unsafe.Offsetof(res.Generation), unsafe.Offsetof(v.Generation)},
	} {
		if c.a != c.b {
			t.Errorf("Resolution.%s offset %d != flow_val offset %d", c.name, c.a, c.b)
		}
	}
}
