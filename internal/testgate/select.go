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
		selected = selectAffected(all, changedFiles)
	} else {
		for _, check := range manifest.Checks {
			if contains(check.Gates, options.Gate) {
				selected[check.ID] = true
			}
		}
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

func selectAffected(all map[string]Check, files []string) map[string]bool {
	selected := map[string]bool{"manifest-schema": true, "safety-policy": true, "format": true}
	if len(files) == 0 {
		selected["go-test-race"] = true
		return selected
	}
	unknown := false
	for _, file := range files {
		switch {
		case strings.HasPrefix(file, "internal/testgate/"), strings.HasPrefix(file, "cmd/testgate/"), strings.HasPrefix(file, "test/gates/"), file == "Makefile", strings.HasPrefix(file, ".github/workflows/"):
			for id, check := range all {
				if contains(check.Gates, "check-local") {
					selected[id] = true
				}
			}
		case strings.HasSuffix(file, ".go"), file == "go.mod", file == "go.sum":
			selected["go-vet"] = true
			selected["go-build"] = true
			selected["go-test-race"] = true
			if isSecurityPath(file) {
				selected["selfcheck-sting"] = true
				selected["selfcheck-envoy"] = true
				selectAdversarial(selected, all)
			}
		case strings.HasPrefix(file, "dashboard/app/"):
			selected["frontend-lint"] = true
			selected["frontend-build"] = true
		case strings.HasPrefix(file, "bpf/"):
			selected["bpf-compile"] = true
			selected["go-test-race"] = true
			selectAdversarial(selected, all)
		case strings.HasPrefix(file, "scripts/dgx/"):
			for id := range all {
				if strings.HasPrefix(id, "dgx-harness:") {
					selected[id] = true
				}
			}
		case strings.HasPrefix(file, "api/proto/"), strings.HasPrefix(file, "internal/operator/api/"):
			selected["generated-proto"] = true
			selected["generated-operator"] = true
			selected["go-test-race"] = true
		case strings.HasPrefix(file, "docs/"), file == ".gitignore", file == "AGENTS.md", strings.HasPrefix(file, ".agents/skills/"):
			// Structural checks are already selected.
		default:
			unknown = true
		}
	}
	if unknown {
		for id, check := range all {
			if contains(check.Gates, "check-local") {
				selected[id] = true
			}
		}
	}
	return selected
}

func selectAdversarial(selected map[string]bool, all map[string]Check) {
	for id := range all {
		if strings.HasPrefix(id, "adversarial:") {
			selected[id] = true
		}
	}
}

func isSecurityPath(file string) bool {
	for _, prefix := range []string{"internal/contract/", "internal/engine/", "internal/sting/", "internal/identity/", "internal/operator/", "adapters/", "deploy/", "cmd/llm-attacker/"} {
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
