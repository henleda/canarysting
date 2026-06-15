package siem_test

import (
	"os/exec"
	"strings"
	"testing"
)

// RULE 9 (docs/INTELLIGENCE.md) — TWO-EGRESS SEPARATION. There are two distinct
// outbound paths and they must NEVER be confused:
//
//  1. The CROSS-CUSTOMER feed: anonymized, addressless adversary patterns that may
//     cross a DEPLOYMENT boundary, only through the single default-deny egress filter
//     in internal/intelligence/network.
//  2. This LOCAL SIEM/SOAR emitter (internal/intelligence/siem): the deployment's OWN
//     "a decoy was touched" alert stream. It is LOCAL-RICH — it carries the RAW source
//     address, :method/:path (query included), and SPIFFE id straight off the
//     l7events.EnrichedTouchRecord. It goes to the operator's OWN SIEM, NOT across a
//     customer boundary.
//
// If the siem package ever transitively imported internal/intelligence/network, an
// author could be tempted to route these local-rich alerts through the cross-customer
// egress path (or blur the two product lines) — a critical Rule-9 leak of un-anonymized,
// environment-identifying data across a deployment boundary. This guard makes the
// separation enforced by the dependency graph, not by convention: wiring network into
// siem's closure breaks this test (and the build gate) before any byte can leak.
//
// This is the INVERSE edge of network/egress_importguard_test.go (which asserts the
// egress filter cannot reach l7events). Both directions are needed and complementary:
//   - egress filter MUST NOT import l7events  (asserted in network's test)
//   - siem        MUST NOT import network     (asserted HERE)
func TestSIEMEmitterDoesNotImportNetwork(t *testing.T) {
	const siemPkg = "github.com/canarysting/canarysting/internal/intelligence/siem"
	const networkPkg = "github.com/canarysting/canarysting/internal/intelligence/network"

	deps := deepDeps(t, siemPkg)
	if deps[networkPkg] {
		t.Fatalf("siem %s transitively imports the cross-customer egress package %s — the LOCAL-RICH SIEM alert (raw src/path/SPIFFE) could be routed through the cross-customer egress path, a critical Rule-9 leak. The local SIEM emitter and the cross-customer feed are SEPARATE product lines; coarsen at the network boundary, never push the local-rich event through it.", siemPkg, networkPkg)
	}

	// Sanity: the forbidden package is REAL and reachable from SOMEWHERE, so the guard
	// is not vacuous (e.g. a typo'd import path that matches nothing). cmd/staged-range
	// legitimately reaches the network package (it wires the D6 ledger/egress path).
	staged := deepDeps(t, "github.com/canarysting/canarysting/cmd/staged-range")
	if !staged[networkPkg] {
		t.Fatalf("sanity: cmd/staged-range does not reach %s — the forbidden import path may be wrong, making the siem import guard vacuous", networkPkg)
	}
}

func deepDeps(t *testing.T, pkg string) map[string]bool {
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
