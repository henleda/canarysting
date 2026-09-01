package testgate

import "testing"

func TestRepositoryBuildChecksShareWorkspaceIsolation(t *testing.T) {
	manifest, _, err := LoadManifests("../../test/gates/checks.json", "../../test/gates/adversarial-scenarios.json")
	if err != nil {
		t.Fatal(err)
	}

	checks := make(map[string]Check, len(manifest.Checks))
	for _, check := range manifest.Checks {
		checks[check.ID] = check
	}
	const isolationKey = "workspace-build"
	for _, id := range []string{"dgx-harness:build", "bpf-compile", "bpf-object-assert"} {
		check, ok := checks[id]
		if !ok {
			t.Fatalf("repository manifest is missing %q", id)
		}
		if check.IsolationKey != isolationKey {
			t.Fatalf("%s isolation_key = %q, want %q", id, check.IsolationKey, isolationKey)
		}
	}
}
