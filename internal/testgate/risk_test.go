package testgate

import (
	"strings"
	"testing"
)

func TestRiskClassificationRepresentativePaths(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		want    RiskLevel
		profile string
	}{
		{name: "low", files: []string{"docs/README.md"}, want: RiskLow},
		{name: "standard", files: []string{"internal/dashboard/views.go"}, want: RiskStandard},
		{name: "high", files: []string{"internal/engine/engine.go"}, want: RiskHigh},
		{name: "critical", files: []string{"bpf/enforce/enforce.bpf.c"}, want: RiskCritical, profile: "dgx-kernel"},
		{name: "unknown", files: []string{"unmapped/new-format.xyz"}, want: RiskHigh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := ClassifyRisk(test.files, "")
			if err != nil {
				t.Fatal(err)
			}
			if report.Effective != test.want {
				t.Fatalf("risk=%s want=%s reasons=%+v", report.Effective, test.want, report.Reasons)
			}
			if test.profile != "" && !contains(report.RemoteProfiles, test.profile) {
				t.Fatalf("missing remote profile %s: %+v", test.profile, report)
			}
		})
	}
}

func TestManualRiskCanIncreaseButNeverReduce(t *testing.T) {
	increased, err := ClassifyRisk([]string{"docs/README.md"}, "CRITICAL")
	if err != nil {
		t.Fatal(err)
	}
	if increased.Effective != RiskCritical || !increased.RequiresDGX || !strings.Contains(increased.OverrideDisposition, "increased") {
		t.Fatalf("manual increase was not applied safely: %+v", increased)
	}
	reduced, err := ClassifyRisk([]string{"bpf/enforce/enforce.bpf.c"}, "LOW")
	if err != nil {
		t.Fatal(err)
	}
	if reduced.Effective != RiskCritical || !strings.Contains(reduced.OverrideDisposition, "ignored") {
		t.Fatalf("manual reduction changed automatic coverage: %+v", reduced)
	}
}

func TestTraceProofChangesSelectOnlyTraceDGXProfile(t *testing.T) {
	for _, path := range []string{"cmd/tracespike/main.go", "scripts/dgx/tracespike.sh", "scripts/dgx/tracespike_test.sh"} {
		report, err := ClassifyRisk([]string{path}, "")
		if err != nil {
			t.Fatal(err)
		}
		if report.Effective != RiskCritical || !report.RequiresDGX || len(report.RemoteProfiles) != 1 || report.RemoteProfiles[0] != "dgx-trace" {
			t.Fatalf("%s classification = %+v", path, report)
		}
	}
}

func TestAttackerReadinessChangesSelectOnlyReadOnlyDGXProfile(t *testing.T) {
	for _, path := range []string{"scripts/dgx/attackercheck.sh", "scripts/dgx/attackercheck_test.sh"} {
		report, err := ClassifyRisk([]string{path}, "")
		if err != nil {
			t.Fatal(err)
		}
		if report.Effective != RiskCritical || !report.RequiresDGX || report.RequiresLiveQwen || len(report.RemoteProfiles) != 1 || report.RemoteProfiles[0] != "dgx-attacker-check" {
			t.Fatalf("%s classification = %+v", path, report)
		}
	}
}

func TestCombinedCriticalChangesRetainEveryDGXProfile(t *testing.T) {
	report, err := ClassifyRisk([]string{"bpf/enforce/enforce.bpf.c", "cmd/tracespike/main.go"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(report.RemoteProfiles, ","); got != "dgx-kernel,dgx-trace" {
		t.Fatalf("remote profiles = %q, want both kernel and trace", got)
	}
}

func TestGoBackedTracePathsSelectFrontendValidation(t *testing.T) {
	for _, path := range []string{
		"test/fixtures/tracebackend/main.go",
		"internal/dashboard/backend/views/trace.go",
		"internal/canaryview/tracefixture/operator.go",
	} {
		report, err := ClassifyRisk([]string{path}, "")
		if err != nil {
			t.Fatal(err)
		}
		if !report.FrontendAffected {
			t.Fatalf("%s did not mark the frontend affected: %+v", path, report)
		}
	}
}

func TestTimingBudgetsDependOnLevelAndRisk(t *testing.T) {
	if got := timingBudget("check-fast", RiskCritical); got != 180 {
		t.Fatalf("check-fast budget=%v", got)
	}
	if got := timingBudget("check-pr-local", RiskLow); got != 600 {
		t.Fatalf("check-pr-local budget=%v", got)
	}
	if got := timingBudget("check-pr", RiskStandard); got != 900 {
		t.Fatalf("standard PR budget=%v", got)
	}
	if got := timingBudget("check-pr", RiskHigh); got != 1800 {
		t.Fatalf("high PR budget=%v", got)
	}
}

func TestPRSelectionByRiskAndPath(t *testing.T) {
	ids := []string{
		"manifest-schema", "safety-policy", "repo-config", "format", "generated-proto", "generated-operator",
		"go-discovery", "go-vet", "go-build", "go-test", "go-test-race", "affected-go-race", "affected-go-integration", "security-invariants",
		"gate-selftests", "gate-synthetic-collect-all", "frontend-lint", "frontend-build", "frontend-playwright", "bpf-compile", "bpf-object-assert",
		"adversarial:fixture", "dgx-harness:syntax", "dgx-harness:enforce",
	}
	manifest := Manifest{Version: 1}
	for _, id := range ids {
		manifest.Checks = append(manifest.Checks, Check{ID: id, Label: id, Command: []string{id}, Gates: []string{"fixture"}, Timeout: "1s", Privilege: "local", IsolationKey: id, ConcurrencyGroup: id, FailureClass: "test defect", Replay: "make check-one CHECK=" + id})
	}
	low, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"docs/README.md"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, low, "go-test")
	assertNotSelected(t, low, "go-test-race", "security-invariants", "frontend-build", "bpf-compile")

	standard, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"internal/dashboard/views.go"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, standard, "affected-go-race", "affected-go-integration")

	frontend, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"dashboard/app/app/page.tsx"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, frontend, "frontend-lint", "frontend-build", "frontend-playwright")

	goBackedFrontend, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"test/fixtures/tracebackend/main.go"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, goBackedFrontend, "frontend-lint", "frontend-build", "frontend-playwright", "go-test")

	high, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"internal/engine/engine.go"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, high, "security-invariants", "go-test-race", "adversarial:fixture")

	critical, err := SelectChecks(manifest, RunOptions{Gate: "check-pr"}, []string{"bpf/enforce/enforce.bpf.c"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, critical, "bpf-compile", "bpf-object-assert", "security-invariants", "go-test-race")
}

func TestFastGateOrchestrationChangeRunsSelfTestsWithoutFullMatrix(t *testing.T) {
	manifest := Manifest{Version: 1}
	for _, id := range []string{"manifest-schema", "safety-policy", "repo-config", "format", "go-discovery", "affected-go-build", "affected-go-test", "security-invariants", "gate-selftests", "gate-synthetic-collect-all", "go-test-race", "frontend-build"} {
		manifest.Checks = append(manifest.Checks, Check{ID: id, Label: id, Command: []string{id}, Gates: []string{"fixture"}, Timeout: "1s", Privilege: "local", IsolationKey: id, ConcurrencyGroup: id, FailureClass: "test defect", Replay: "replay"})
	}
	checks, err := SelectChecks(manifest, RunOptions{Gate: "check-fast"}, []string{"internal/testgate/risk.go"})
	if err != nil {
		t.Fatal(err)
	}
	assertSelected(t, checks, "gate-selftests", "gate-synthetic-collect-all", "affected-go-build", "affected-go-test")
	assertNotSelected(t, checks, "go-test-race", "frontend-build")
}

func assertSelected(t *testing.T, checks []Check, ids ...string) {
	t.Helper()
	selected := make(map[string]bool)
	for _, check := range checks {
		selected[check.ID] = true
	}
	for _, id := range ids {
		if !selected[id] {
			t.Errorf("expected %s in selection: %v", id, selected)
		}
	}
}

func assertNotSelected(t *testing.T, checks []Check, ids ...string) {
	t.Helper()
	selected := make(map[string]bool)
	for _, check := range checks {
		selected[check.ID] = true
	}
	for _, id := range ids {
		if selected[id] {
			t.Errorf("did not expect %s in selection: %v", id, selected)
		}
	}
}
