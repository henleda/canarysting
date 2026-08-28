package testgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var failureClasses = map[string]bool{
	"product defect": true, "test defect": true, "build defect": true,
	"environment defect": true, "missing prerequisite": true,
	"cleanup defect": true, "nondeterministic or flaky behavior": true,
	"safety invariant violation": true, "timeout": true, "unknown": true,
}

func LoadManifests(checkPath, scenarioPath string) (Manifest, ScenarioManifest, error) {
	var manifest Manifest
	var scenarios ScenarioManifest
	if err := decodeStrict(checkPath, &manifest); err != nil {
		return manifest, scenarios, err
	}
	if err := decodeStrict(scenarioPath, &scenarios); err != nil {
		return manifest, scenarios, err
	}
	for i := range manifest.Checks {
		if manifest.Checks[i].ResultParser == "" {
			manifest.Checks[i].ResultParser = "exit-code"
		}
		if manifest.Checks[i].ManualRecovery == "" {
			manifest.Checks[i].ManualRecovery = "Inspect the bounded node log, restore the named prerequisite, and rerun the direct reproduction command."
		}
	}
	if err := Validate(&manifest, &scenarios); err != nil {
		return manifest, scenarios, err
	}
	for _, scenario := range scenarios.Scenarios {
		manifest.Checks = append(manifest.Checks, scenarioCheck(scenarios.Version, scenario))
	}
	return manifest, scenarios, nil
}

func decodeStrict(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing JSON data", path)
	}
	return nil
}

func Validate(manifest *Manifest, scenarios *ScenarioManifest) error {
	var problems []string
	if manifest.Version < 1 {
		problems = append(problems, "check manifest version must be positive")
	}
	if scenarios.Version < 1 {
		problems = append(problems, "scenario manifest version must be positive")
	}
	seen := make(map[string]bool)
	scenarioTests := make(map[string]string)
	for i := range manifest.Checks {
		check := &manifest.Checks[i]
		validateCheck(check, seen, &problems)
		seen[check.ID] = true
	}
	for i := range scenarios.Scenarios {
		s := &scenarios.Scenarios[i]
		if seen["adversarial:"+s.ID] {
			problems = append(problems, "duplicate scenario id: "+s.ID)
		}
		seen["adversarial:"+s.ID] = true
		if s.ID == "" || s.Title == "" || s.Objective == "" || s.TargetScope == "" || s.DeterministicSeed == 0 || len(s.Command) == 0 || s.Timeout == "" || s.IsolationKey == "" || s.Replay == "" || s.AttackerIntent == "" || s.AttackerAction == "" {
			problems = append(problems, fmt.Sprintf("scenario %q is missing a required declaration", s.ID))
		}
		if len(s.ExpectedObservations) == 0 || len(s.ExpectedCanarySting) == 0 || len(s.ProhibitedOutcomes) == 0 || len(s.AfterStateAssertions) == 0 || len(s.GroundTruth) == 0 || len(s.RequiredTestPasses) == 0 {
			problems = append(problems, fmt.Sprintf("scenario %q has incomplete safety or ground-truth declarations", s.ID))
		}
		if !contains(s.ValidationForms, "deterministic-replay") || !contains(s.ValidationForms, "campaign") || len(s.AffectedPaths) == 0 {
			problems = append(problems, fmt.Sprintf("scenario %q must declare deterministic-replay, campaign, and affected paths", s.ID))
		}
		for _, testName := range s.RequiredTestPasses {
			if prior := scenarioTests[testName]; prior != "" {
				problems = append(problems, fmt.Sprintf("scenario test %q is owned by both %q and %q", testName, prior, s.ID))
			}
			scenarioTests[testName] = s.ID
		}
		validateScenarioCommand(s, &problems)
		for _, host := range s.AllowedHosts {
			if host != "127.0.0.1" && host != "localhost" && host != "::1" {
				problems = append(problems, fmt.Sprintf("scenario %q host %q is outside the local allowlist", s.ID, host))
			}
		}
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			problems = append(problems, fmt.Sprintf("scenario %q timeout: %v", s.ID, err))
		}
	}
	all := make(map[string]Check, len(manifest.Checks)+len(scenarios.Scenarios))
	for _, check := range manifest.Checks {
		all[check.ID] = check
	}
	for _, scenario := range scenarios.Scenarios {
		all["adversarial:"+scenario.ID] = scenarioCheck(scenarios.Version, scenario)
	}
	for id, check := range all {
		for _, dep := range check.Dependencies {
			if _, ok := all[dep]; !ok {
				problems = append(problems, fmt.Sprintf("check %q has unknown dependency %q", id, dep))
			}
		}
	}
	if cycle := findCycle(all); len(cycle) > 0 {
		problems = append(problems, "dependency cycle: "+strings.Join(cycle, " -> "))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validateScenarioCommand(s *Scenario, problems *[]string) {
	// Local adversarial manifests are data, not a shell escape hatch. They may
	// invoke only an exact, uncached JSON Go-test selection rooted at the fixture
	// directory declared by the scenario.
	if len(s.Command) != 8 || s.Command[0] != "go" || s.Command[1] != "test" ||
		s.Command[2] != "-json" || s.Command[3] != "-count=1" || s.Command[4] != "-race" || s.Command[6] != "-run" {
		*problems = append(*problems, fmt.Sprintf("scenario %q command must be exactly go test -json -count=1 -race <fixture-package> -run <anchored-tests>", s.ID))
		return
	}
	fixtureDirs := make(map[string]bool)
	for _, fixture := range s.Fixtures {
		fixtureDirs["./"+filepath.ToSlash(filepath.Dir(fixture))] = true
	}
	if !fixtureDirs[s.Command[5]] {
		*problems = append(*problems, fmt.Sprintf("scenario %q command package %q is not a declared fixture directory", s.ID, s.Command[5]))
	}
	pattern, err := regexp.Compile(s.Command[7])
	if err != nil || !strings.HasPrefix(s.Command[7], "^(") || !strings.HasSuffix(s.Command[7], ")$") {
		*problems = append(*problems, fmt.Sprintf("scenario %q test selection must be a valid anchored group", s.ID))
		return
	}
	quoted := make([]string, 0, len(s.RequiredTestPasses))
	for _, name := range s.RequiredTestPasses {
		quoted = append(quoted, regexp.QuoteMeta(name))
		if !strings.HasPrefix(name, "Test") || !pattern.MatchString(name) {
			*problems = append(*problems, fmt.Sprintf("scenario %q required test %q is outside its -run selection", s.ID, name))
		}
	}
	if exact := "^(" + strings.Join(quoted, "|") + ")$"; s.Command[7] != exact {
		*problems = append(*problems, fmt.Sprintf("scenario %q -run selection must exactly match required_test_passes in order", s.ID))
	}
}

func validateCheck(check *Check, seen map[string]bool, problems *[]string) {
	if check.ID == "" || check.Label == "" || len(check.Command) == 0 || len(check.Gates) == 0 || check.Timeout == "" || check.Privilege == "" || check.IsolationKey == "" || check.ConcurrencyGroup == "" || check.FailureClass == "" || check.Replay == "" {
		*problems = append(*problems, fmt.Sprintf("check %q is missing a required declaration", check.ID))
	}
	if seen[check.ID] {
		*problems = append(*problems, "duplicate check id: "+check.ID)
	}
	if !failureClasses[check.FailureClass] {
		*problems = append(*problems, fmt.Sprintf("check %q has unknown failure class %q", check.ID, check.FailureClass))
	}
	if check.Privilege != "local" && check.Privilege != "privileged" && check.Privilege != "dgx-read-only" && check.Privilege != "dgx-mutation" {
		*problems = append(*problems, fmt.Sprintf("check %q has invalid privilege %q", check.ID, check.Privilege))
	}
	if _, err := time.ParseDuration(check.Timeout); err != nil {
		*problems = append(*problems, fmt.Sprintf("check %q timeout: %v", check.ID, err))
	}
	if check.ResultParser == "go-test-json-required-passes" && len(check.RequiredTestPasses) == 0 {
		*problems = append(*problems, fmt.Sprintf("check %q result parser requires required_test_passes", check.ID))
	}
	for _, platform := range check.Platforms {
		if platform != "darwin" && platform != "linux" {
			*problems = append(*problems, fmt.Sprintf("check %q has unsupported platform %q", check.ID, platform))
		}
	}
}

func scenarioCheck(version int, s Scenario) Check {
	expected := append([]string(nil), s.ExpectedObservations...)
	expected = append(expected, s.ExpectedCanaryView...)
	expected = append(expected, s.ExpectedCanarySting...)
	tags := []string{"adversarial", "deterministic-replay"}
	for _, path := range s.AffectedPaths {
		tags = append(tags, "affected:"+path)
	}
	for _, form := range s.ValidationForms {
		tags = append(tags, "form:"+form)
	}
	return Check{
		ID: "adversarial:" + s.ID, Label: s.Title, Command: s.Command,
		Dependencies: s.Dependencies, Gates: []string{"check-local", "check-adversarial", "check-merge-local", "ci-adversarial"},
		Timeout: s.Timeout, Privilege: s.RequiredPrivileges, IsolationKey: s.IsolationKey,
		ConcurrencyGroup: "adversarial", FailureClass: s.FailureClass,
		ResultParser:       "go-test-json-required-passes",
		RequiredTestPasses: append([]string(nil), s.RequiredTestPasses...),
		Cleanup:            s.Cleanup, CleanupSafetyCritical: true, SafetyCritical: s.SafetyCritical,
		Replay: s.Replay, ManualRecovery: "Verify the scenario after-state, inspect its bounded log, then rerun only this scenario.", Tags: tags,
		Scenario: &ScenarioMetadata{ManifestVersion: version, DeterministicSeed: s.DeterministicSeed,
			AttackerIntent: s.AttackerIntent, AttackerAction: s.AttackerAction,
			ExpectedEvidence: expected, RequiredAssertions: append([]string(nil), s.RequiredTestPasses...),
			IdentityResult:    "not directly measured by this local fixture",
			CorrelationResult: "not directly measured by this local fixture", ResponseResult: "pending parsed assertions",
			CleanupResult: "pending execution", GroundTruth: s.GroundTruth},
	}
}

func findCycle(checks map[string]Check) []string {
	state := make(map[string]int)
	stack := make([]string, 0)
	var visit func(string) []string
	visit = func(id string) []string {
		if state[id] == 1 {
			for i, candidate := range stack {
				if candidate == id {
					return append(append([]string(nil), stack[i:]...), id)
				}
			}
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		stack = append(stack, id)
		for _, dep := range checks[id].Dependencies {
			if cycle := visit(dep); len(cycle) > 0 {
				return cycle
			}
		}
		stack = stack[:len(stack)-1]
		state[id] = 2
		return nil
	}
	ids := make([]string, 0, len(checks))
	for id := range checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if cycle := visit(id); len(cycle) > 0 {
			return cycle
		}
	}
	return nil
}

func platformAllowed(check Check) bool {
	if len(check.Platforms) == 0 {
		return true
	}
	for _, platform := range check.Platforms {
		if platform == runtime.GOOS {
			return true
		}
	}
	return false
}

func ManifestDigest(paths ...string) (string, error) {
	h := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return "", err
		}
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
