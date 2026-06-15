package network_test

import (
	"os/exec"
	"strings"
	"testing"
)

// RULE 9 / "local-rich, export-coarse" (see docs/TOPOLOGY_AND_DEVIANTS.md): the
// cross-customer egress filter is the ONLY place data is coarsened before it
// leaves a deployment. The LOCAL rich stores — the observe baseline and its bbolt
// persistence — now hold RAW east-west edges/identities (the learned-topology
// edge store reverses the old hash-and-discard). Those raw addresses must be
// STRUCTURALLY unreachable from the egress path, not merely kept apart by
// convention: if anyone ever wires a reader of the rich store into the egress
// filter's dependency closure, raw environment-identifying data could cross a
// customer boundary — a critical Rule-9 leak.
//
// This guard makes the separation enforced by the dependency graph: the egress
// filter's transitive imports must NOT include the rich local stores. Wiring one
// in breaks this test (and thus the build gate), before any byte can leak.
func TestEgressFilterCannotReachRichLocalStores(t *testing.T) {
	const networkPkg = "github.com/canarysting/canarysting/internal/intelligence/network"
	forbidden := []string{
		"github.com/canarysting/canarysting/internal/engine/observebaseline",
		"github.com/canarysting/canarysting/internal/engine/persist",
	}
	deps := egressDeps(t, networkPkg)
	for _, f := range forbidden {
		if deps[f] {
			t.Fatalf("egress filter %s transitively imports %s — raw local data (e.g. east-west IPs/edges) could cross a deployment boundary (Rule 9). The rich local stores MUST stay unreachable from the egress path; coarsen at the boundary, never expose the raw store.", networkPkg, f)
		}
	}

	// Sanity: the forbidden packages are REAL and reachable from SOMEWHERE, so the
	// guard above is not vacuous (e.g. a typo'd import path that matches nothing).
	// cmd/staged-range legitimately reaches both rich stores.
	staged := egressDeps(t, "github.com/canarysting/canarysting/cmd/staged-range")
	for _, f := range forbidden {
		if !staged[f] {
			t.Fatalf("sanity: cmd/staged-range does not reach %s — the forbidden import path may be wrong, making the egress guard vacuous", f)
		}
	}
}

func egressDeps(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	set := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		set[p] = true
	}
	return set
}
