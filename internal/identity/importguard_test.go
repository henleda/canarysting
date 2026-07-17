package identity_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestIdentitySpineHasNoEngineOrAdapterDeps asserts, via `go list -deps`, that the
// core identity spine (identity, mesh, labels, workload) depends on NO engine,
// adapter, or proxy/eBPF SDK. It stays production-importable and keeps attribution
// from entangling with the decision engine or a specific proxy.
//
// scopemap is deliberately EXCLUDED: it is the glue leaf and legitimately imports
// the engine's scope package to produce scope.ClusterIdentity/scope.Zone values.
func TestIdentitySpineHasNoEngineOrAdapterDeps(t *testing.T) {
	const mod = "github.com/canarysting/canarysting"
	spine := []string{
		mod + "/internal/identity",
		mod + "/internal/identity/mesh",
		mod + "/internal/identity/labels",
		mod + "/internal/identity/workload",
	}
	forbidden := []string{
		mod + "/internal/engine",
		mod + "/adapters",
		mod + "/internal/sting",
		"github.com/envoyproxy/go-control-plane",
		"github.com/cilium/ebpf",
	}
	for _, pkg := range spine {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) == 0 {
			t.Fatalf("go list -deps %s returned no deps (guard would be vacuous)", pkg)
		}
		for _, d := range deps {
			for _, f := range forbidden {
				if d == f || strings.HasPrefix(d, f+"/") {
					t.Errorf("identity spine leak: %s must not depend on %s (found %s)", pkg, f, d)
				}
			}
		}
	}
}
