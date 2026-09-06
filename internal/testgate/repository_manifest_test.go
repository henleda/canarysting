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

func TestPRDGXRunsEveryMappedProfile(t *testing.T) {
	workflowBytes, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	start := strings.Index(workflow, "\n  pr-dgx:\n")
	end := strings.Index(workflow, "\n  pr-gate:\n")
	if start < 0 || end <= start {
		t.Fatal("workflow PR DGX job boundaries are missing")
	}
	job := workflow[start:end]
	if !strings.Contains(job, "timeout-minutes: 20") {
		t.Fatal("PR DGX job does not have a bounded overall timeout")
	}
	if !strings.Contains(job, "dgx-trace) selected='trace' ;;") {
		t.Fatal("PR DGX job does not route dgx-trace to the trace coordinator profile")
	}
	if !strings.Contains(job, "dgx-attacker-check) selected='attacker-check' ;;") {
		t.Fatal("PR DGX job does not route readiness checks to the read-only attacker-check coordinator profile")
	}
	for _, required := range []string{
		`IFS=',' read -ra required_profiles`,
		`for required in "${required_profiles[@]}"`,
		`for selected in ${SELECTED_PROFILES}`,
		`RUN_ID="pr-${{ github.event.pull_request.number || github.run_id }}-${short_sha}-${index}"`,
	} {
		if !strings.Contains(job, required) {
			t.Fatalf("PR DGX job does not preserve and run every required profile; missing %q", required)
		}
	}
}
