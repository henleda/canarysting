package siem

import (
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
)

// attackTechniques is the static, reviewed CanaryType -> MITRE ATT&CK technique-id
// map for the "a decoy of this kind was touched" event. It is keyed on the catalog
// CONSTANTS (not string literals), so renaming a canary type is a compile error
// rather than a silently-dropped tag. Each entry is the technique(s) an operator's
// SOC would correlate a touch of that decoy against — the most defensible PRIMARY
// id first.
//
// HONESTY (spec: "unknown type -> no tag (omit, never guess)"): a CanaryType that
// is not in this table returns no techniques and the emitter OMITS the att_ck field
// entirely rather than inventing one. So a NEW catalog type ships with no ATT&CK tag
// until this table is reviewed and extended — visible as a missing field, never a
// wrong one.
//
// STABLE: ids are append-only. Do not repurpose an existing mapping; a SOC
// detection rule keyed on a technique id must keep meaning the same touch.
var attackTechniques = map[contract.CanaryType][]string{
	// A planted credential is unsecured creds in a file; using it is valid-account
	// abuse.
	catalog.TypePlantedCredential: {"T1552.001", "T1078"},
	// A fake secret is unsecured credentials / a credential store target.
	catalog.TypeFakeSecret: {"T1552", "T1555"},
	// A decoy file read is local-system data collection / discovery.
	catalog.TypeDecoyFile: {"T1005", "T1083"},
	// A fake bucket is cloud-storage data access / object discovery.
	catalog.TypeFakeBucket: {"T1530", "T1619"},
	// A fake API endpoint is network-service / info-repository discovery.
	catalog.TypeFakeEndpoint: {"T1046", "T1213"},
}

// techniquesFor returns the ATT&CK technique ids for a canary type, or nil for an
// unmapped/empty type. nil => the emitter omits the att_ck field (never guesses).
// The returned slice is a copy so a caller cannot mutate the shared table.
func techniquesFor(t contract.CanaryType) []string {
	src, ok := attackTechniques[t]
	if !ok || len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
