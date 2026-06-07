package envoy

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAdapterImportsAreThin is the executable form of CLAUDE.md rule 1: the Envoy
// adapter is a thin proxy. Its TRANSITIVE dependency closure must not reach the
// engine (no scoring/tiering/decision logic) nor cilium/ebpf (kernel coupling
// lives behind the CookieResolver seam, build-tagged linux in bpf/loader).
//
// `go list -deps` returns the full transitive closure for the current platform,
// so a leak through ANY seam package is caught — not just a direct import (which a
// parser-only check would miss). The adapter legitimately reaches the contract,
// the canary signal/seeder seams, and the sting attrition interface.
func TestAdapterImportsAreThin(t *testing.T) {
	forbidden := []string{
		"canarysting/internal/engine",
		"github.com/cilium/ebpf",
		"canarysting/internal/intelligence",
	}
	out, err := exec.Command("go", "list", "-deps", ".", "./identity").Output()
	if err != nil {
		t.Fatalf("go list -deps failed: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.Contains(dep, f) {
				t.Errorf("adapter transitively imports forbidden package %q (rule 1)", dep)
			}
		}
	}
}
