package identity_test

import (
	"os/exec"
	"strings"
	"testing"
)

const (
	identityPkg    = "github.com/canarysting/canarysting/internal/topology/identity"
	stagedlabelPkg = "github.com/canarysting/canarysting/internal/intelligence/stagedlabel"
	networkPkg     = "github.com/canarysting/canarysting/internal/intelligence/network"
)

// TestResolverIsProductionImportable asserts the resolver's transitive dependency
// closure stays clean of:
//
//   - internal/intelligence/stagedlabel — the STAGING-ONLY calibration labeler the
//     production cmd/engine cannot import. The resolver must be importable by the
//     production engine AND the dashboard backend, so it must not reach the
//     labeler. (The demo's node names come from this resolver's operator map, NOT
//     from the labeler — they are separate concerns.)
//   - internal/engine and adapters internals — the resolver operates on plain
//     IP/port/SPIFFE values + its own config; it must not pull in engine/adapter
//     implementation packages.
//
// Modeled on stagedlabel/importguard_test.go's TestProductionEngineCannotImportLabeler.
func TestResolverIsProductionImportable(t *testing.T) {
	deps := goListDeps(t, identityPkg)

	for _, forbidden := range []string{stagedlabelPkg, networkPkg} {
		if deps[forbidden] {
			t.Errorf("%s transitively imports %s — the resolver must stay self-contained and production-importable", identityPkg, forbidden)
		}
	}

	for dep := range deps {
		if dep == identityPkg {
			continue
		}
		if strings.HasPrefix(dep, "github.com/canarysting/canarysting/internal/engine") {
			t.Errorf("%s transitively imports engine internal %s — the resolver must not depend on engine internals", identityPkg, dep)
		}
		if strings.HasPrefix(dep, "github.com/canarysting/canarysting/adapters") {
			t.Errorf("%s transitively imports adapter %s — the resolver must not depend on adapter internals", identityPkg, dep)
		}
	}
}

func goListDeps(t *testing.T, pkg string) map[string]bool {
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
