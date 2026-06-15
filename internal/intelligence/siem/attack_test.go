package siem

import (
	"testing"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
)

func TestAttackMap_AllFiveCatalogTypesMapped(t *testing.T) {
	// Every shipped catalog type must have a defensible primary technique. Match on
	// the catalog CONSTANTS so a renamed type is caught here, not silently dropped.
	cases := map[contract.CanaryType]string{
		catalog.TypePlantedCredential: "T1552.001",
		catalog.TypeFakeSecret:        "T1552",
		catalog.TypeDecoyFile:         "T1005",
		catalog.TypeFakeBucket:        "T1530",
		catalog.TypeFakeEndpoint:      "T1046",
	}
	for ct, wantPrimary := range cases {
		got := techniquesFor(ct)
		if len(got) == 0 {
			t.Errorf("canary type %q has no ATT&CK technique", ct)
			continue
		}
		if got[0] != wantPrimary {
			t.Errorf("canary type %q primary technique = %q, want %q", ct, got[0], wantPrimary)
		}
	}
}

func TestAttackMap_UnknownTypeOmitted(t *testing.T) {
	if got := techniquesFor(contract.CanaryType("not_a_real_type")); got != nil {
		t.Fatalf("unknown canary type must map to nil (omit, never guess), got %v", got)
	}
	if got := techniquesFor(contract.CanaryType("")); got != nil {
		t.Fatalf("empty canary type must map to nil, got %v", got)
	}
}

func TestAttackMap_ReturnsCopyNotSharedSlice(t *testing.T) {
	a := techniquesFor(catalog.TypeFakeBucket)
	if len(a) == 0 {
		t.Fatal("expected techniques")
	}
	a[0] = "MUTATED"
	b := techniquesFor(catalog.TypeFakeBucket)
	if b[0] == "MUTATED" {
		t.Fatal("techniquesFor returned a slice aliasing the shared table — a caller could corrupt the map")
	}
}
