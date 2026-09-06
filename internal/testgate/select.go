package testgate

import (
	"fmt"
	"sort"
	"strings"
)

func SelectChecks(manifest Manifest, options RunOptions, changedFiles []string) ([]Check, error) {
	all := make(map[string]Check, len(manifest.Checks))
	for _, check := range manifest.Checks {
		all[check.ID] = check
	}
	selected := make(map[string]bool)
	if len(options.OnlyChecks) > 0 {
		for _, id := range options.OnlyChecks {
			if _, ok := all[id]; !ok {
				return nil, fmt.Errorf("unknown check %q", id)
			}
			selected[id] = true
		}
	} else if options.Gate == "check-fast" {
		report, err := ClassifyRisk(changedFiles, options.RiskOverride)
		if err != nil {
			return nil, err
		}
		selected = selectAffected(all, changedFiles, report)
	} else if options.Gate == "check-pr-local" || options.Gate == "check-pr" {
		report, err := ClassifyRisk(changedFiles, options.RiskOverride)
		if err != nil {
			return nil, err
		}
		selected = selectPR(all, changedFiles, report)
	} else if options.Gate == "check-integration-full" || options.Gate == "check-campaign" {
		selected = selectByGate(all, "check-merge-local")
	} else {
		selected = selectByGate(all, options.Gate)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("gate %q selected no checks", options.Gate)
	}
	var addDeps func(string)
	addDeps = func(id string) {
		for _, dep := range all[id].Dependencies {
			if !selected[dep] {
				selected[dep] = true
				addDeps(dep)
			}
		}
	}
	for id := range selected {
		addDeps(id)
	}
	checks := make([]Check, 0, len(selected))
	for id := range selected {
		checks = append(checks, all[id])
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	return checks, nil
}

func selectByGate(all map[string]Check, gate string) map[string]bool {
	selected := make(map[string]bool)
	for id, check := range all {
		if contains(check.Gates, gate) {
			selected[id] = true
		}
	}
	return selected
}

func selectAffected(all map[string]Check, files []string, risk RiskReport) map[string]bool {
	selected := make(map[string]bool)
	addAvailable(selected, all, "manifest-schema", "safety-policy", "repo-config", "format")
	if len(files) == 0 {
		addAvailable(selected, all, "security-invariants", "affected-go-build", "affected-go-test")
		return selected
	}
	unknown := false
	for _, file := range files {
		switch {
		case strings.HasPrefix(file, "internal/testgate/"), strings.HasPrefix(file, "cmd/testgate/"), strings.HasPrefix(file, "test/gates/"), file == "Makefile", strings.HasPrefix(file, ".github/workflows/"):
			addAvailable(selected, all, "gate-selftests", "gate-synthetic-collect-all", "affected-go-build", "affected-go-test", "security-invariants")
		case isFrontendPath(file):
			addAvailable(selected, all, "frontend-lint", "frontend-playwright")
			if strings.HasSuffix(file, ".go") {
				addAvailable(selected, all, "affected-go-build", "affected-go-test", "go-vet", "security-invariants")
			}
		case strings.HasSuffix(file, ".go"), file == "go.mod", file == "go.sum":
			addAvailable(selected, all, "affected-go-build", "affected-go-test", "go-vet", "security-invariants")
			if isSecurityPath(file) {
				addAvailable(selected, all, "selfcheck-sting", "selfcheck-envoy")
				selectAdversarial(selected, all, files)
			}
		case strings.HasPrefix(file, "bpf/"):
			addAvailable(selected, all, "bpf-compile", "bpf-object-assert", "affected-go-build", "affected-go-test", "security-invariants")
			selectAdversarial(selected, all, files)
		case strings.HasPrefix(file, "scripts/dgx/"):
			selectDGXHarnessForPath(selected, all, file)
		case strings.HasPrefix(file, "api/proto/"), strings.HasPrefix(file, "internal/operator/api/"):
			addAvailable(selected, all, "generated-proto", "generated-operator", "affected-go-build", "affected-go-test", "security-invariants")
		case strings.HasPrefix(file, "docs/"), file == ".gitignore", file == "AGENTS.md", strings.HasPrefix(file, ".agents/skills/"):
			// Structural checks are already selected.
		default:
			unknown = true
		}
	}
	if unknown {
		selected = selectPR(all, files, RiskReport{Effective: RiskHigh, Executable: true, GateAffected: risk.GateAffected})
	}
	return selected
}

func selectPR(all map[string]Check, files []string, risk RiskReport) map[string]bool {
	selected := make(map[string]bool)
	addAvailable(selected, all, "manifest-schema", "safety-policy", "repo-config", "format", "generated-proto", "generated-operator", "go-vet", "go-build", "go-test")
	if risk.Executable {
		addAvailable(selected, all, "security-invariants")
	}
	if risk.Effective == RiskHigh || risk.Effective == RiskCritical {
		addAvailable(selected, all, "go-test-race", "selfcheck-sting", "selfcheck-envoy")
	} else if hasGoImpact(files) {
		addAvailable(selected, all, "affected-go-race", "affected-go-integration")
	}
	if risk.GateAffected {
		addAvailable(selected, all, "gate-selftests", "gate-synthetic-collect-all")
		selectAdversarial(selected, all, files)
	}
	for _, file := range files {
		switch {
		case isFrontendPath(file):
			addAvailable(selected, all, "frontend-lint", "frontend-build", "frontend-playwright")
		case strings.HasPrefix(file, "bpf/"):
			addAvailable(selected, all, "bpf-compile", "bpf-object-assert")
			selectAdversarial(selected, all, files)
		case strings.HasPrefix(file, "scripts/dgx/"):
			selectDGXHarnessForPath(selected, all, file)
		case isSecurityPath(file):
			selectAdversarial(selected, all, files)
		}
	}
	return selected
}

// isFrontendPath includes the Go-backed trace path used by Playwright. A
// fixture, projection, or handler-only change must not bypass the browser gate
// merely because no TypeScript file changed.
func isFrontendPath(path string) bool {
	for _, prefix := range []string{
		"dashboard/app/",
		"test/fixtures/tracebackend/",
		"internal/dashboard/backend/",
		"internal/canaryview/tracefixture/",
		"internal/canaryview/trace/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func addAvailable(selected map[string]bool, all map[string]Check, ids ...string) {
	for _, id := range ids {
		if _, ok := all[id]; ok {
			selected[id] = true
		}
	}
}

func hasGoImpact(files []string) bool {
	for _, file := range files {
		if strings.HasSuffix(file, ".go") || file == "go.mod" || file == "go.sum" {
			return true
		}
	}
	return false
}

func selectDGXHarnessForPath(selected map[string]bool, all map[string]Check, file string) {
	addAvailable(selected, all, "dgx-harness:syntax")
	name := strings.TrimSuffix(strings.TrimPrefix(file, "scripts/dgx/"), "_test.sh")
	name = strings.TrimSuffix(name, ".sh")
	id := "dgx-harness:" + name
	if _, ok := all[id]; ok {
		selected[id] = true
		return
	}
	for candidate := range all {
		if strings.HasPrefix(candidate, "dgx-harness:") {
			selected[candidate] = true
		}
	}
}

func selectAdversarial(selected map[string]bool, all map[string]Check, files []string) {
	matched := false
	for id, check := range all {
		if !strings.HasPrefix(id, "adversarial:") {
			continue
		}
		for _, tag := range check.Tags {
			if !strings.HasPrefix(tag, "affected:") {
				continue
			}
			prefix := strings.TrimPrefix(tag, "affected:")
			for _, file := range files {
				if strings.HasPrefix(file, prefix) {
					selected[id] = true
					matched = true
				}
			}
		}
	}
	if matched {
		return
	}
	// An unmapped security or gate impact expands to the complete deterministic
	// replay corpus; affected selection is never a coverage exemption.
	for id := range all {
		if strings.HasPrefix(id, "adversarial:") {
			selected[id] = true
		}
	}
}

func isSecurityPath(file string) bool {
	for _, prefix := range []string{"internal/contract/", "internal/engine/", "internal/sting/", "internal/identity/", "internal/operator/", "internal/canaryattacker/", "adapters/", "deploy/", "cmd/llm-attacker/", "internal/llm/attacker/", "bpf/"} {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
