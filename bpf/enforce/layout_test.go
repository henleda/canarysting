package enforce

import (
	"testing"
	"unsafe"
)

// TestVerdictValLayout sanity-checks the bpf2go-generated verdict value: Action is
// the first field (the kernel reads v->action), the kernel-written drop counters
// and the token-bucket fields are present and 8-byte, and the struct is the
// expected 56 bytes. It guards against a stale/mis-generated binding (e.g. a
// missing -type field) shipping out of sync with enforce.bpf.c. Runs on every
// platform (the generated struct is not OS-tagged).
func TestVerdictValLayout(t *testing.T) {
	var v enforceVerdictVal
	if off := unsafe.Offsetof(v.Action); off != 0 {
		t.Fatalf("Action must be at offset 0 (the kernel reads v->action first), got %d", off)
	}
	if got := unsafe.Sizeof(v); got != 56 {
		t.Fatalf("verdict value size = %d, want 56 (action+pad + 2 counters + 4 token-bucket fields)", got)
	}
	// These field accesses fail to compile if -type didn't generate them — the real
	// guard that the kernel's counters and rate-limit state are mirrored in Go.
	if unsafe.Sizeof(v.DroppedPkts) != 8 || unsafe.Sizeof(v.DroppedBytes) != 8 ||
		unsafe.Sizeof(v.Tokens) != 8 || unsafe.Sizeof(v.Rate) != 8 || unsafe.Sizeof(v.Burst) != 8 {
		t.Fatal("expected 8-byte counter/token-bucket fields")
	}
}
