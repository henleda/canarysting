package observe

import (
	"reflect"
	"strings"
	"testing"
)

// OBSERVE NEVER ENFORCES (structural): the Observer contract exposes no write-
// shaped method, so userspace is incapable of mutating the kernel map. Combined
// with the kernel programs returning PASS on every path (asserted on-box by a
// grep for the absence of `return 0` in observe.bpf.c), observation cannot act.
func TestObserverInterfaceIsReadOnly(t *testing.T) {
	typ := reflect.TypeOf((*Observer)(nil)).Elem()
	writeShaped := []string{"Program", "Update", "Delete", "Put", "Write", "Set", "Mark", "Apply", "Enforce", "Drop"}
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		for _, w := range writeShaped {
			if strings.Contains(name, w) {
				t.Errorf("Observer exposes write-shaped method %q — the observe path must be read-only", name)
			}
		}
	}
	for _, want := range []string{"ReadStats", "IterStats", "Load", "Close"} {
		if _, ok := typ.MethodByName(want); !ok {
			t.Errorf("Observer missing expected read/lifecycle method %q", want)
		}
	}
}
