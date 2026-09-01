package testgate

import (
	"os"
	"strings"
	"testing"
)

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

func TestSelfHostedDGXJobsDoNotUploadControllerGoCache(t *testing.T) {
	workflowBytes, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)

	for _, bounds := range [][2]string{
		{"pr-dgx", "pr-gate"},
		{"integration-dgx", "campaign"},
	} {
		startMarker := "\n  " + bounds[0] + ":\n"
		endMarker := "\n  " + bounds[1] + ":\n"
		start := strings.Index(workflow, startMarker)
		if start < 0 {
			t.Fatalf("workflow is missing %q job", bounds[0])
		}
		end := strings.Index(workflow[start+len(startMarker):], endMarker)
		if end < 0 {
			t.Fatalf("workflow is missing boundary after %q job", bounds[0])
		}
		job := workflow[start : start+len(startMarker)+end]
		if !strings.Contains(job, "runs-on: [self-hosted, canarysting-dgx-controller]") {
			t.Fatalf("%s must use the bounded DGX controller", bounds[0])
		}
		if !strings.Contains(job, "uses: actions/setup-go@v5") {
			t.Fatalf("%s must configure the repository Go toolchain", bounds[0])
		}
		if !strings.Contains(job, "cache: false") || strings.Contains(job, "cache: true") {
			t.Fatalf("%s must not upload the persistent controller's global Go cache", bounds[0])
		}
	}
}
