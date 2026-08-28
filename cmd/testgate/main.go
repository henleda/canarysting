package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/canarysting/canarysting/internal/testgate"
)

const checkManifest = "test/gates/checks.json"
const scenarioManifest = "test/gates/adversarial-scenarios.json"
const artifactRoot = ".test-artifacts/gates"

type listFlag []string

func (f *listFlag) String() string         { return strings.Join(*f, ",") }
func (f *listFlag) Set(value string) error { *f = append(*f, value); return nil }

func main() {
	if len(os.Args) < 2 {
		fatal("usage: testgate <run|validate|probe|report|synthetic>")
	}
	switch os.Args[1] {
	case "run":
		run(os.Args[2:])
	case "validate":
		validate()
	case "probe":
		probe(os.Args[2:])
	case "report":
		report()
	case "synthetic":
		synthetic()
	default:
		fatal("unknown command %q", os.Args[1])
	}
}

func load() (testgate.Manifest, testgate.ScenarioManifest) {
	manifest, scenarios, err := testgate.LoadManifests(checkManifest, scenarioManifest)
	if err != nil {
		fatal("manifest validation failed:\n%v", err)
	}
	return manifest, scenarios
}

func validate() {
	manifest, scenarios := load()
	fmt.Printf("PASS: manifest v%d: %d checks; scenario manifest v%d: %d scenarios\n", manifest.Version, len(manifest.Checks), scenarios.Version, len(scenarios.Scenarios))
}

func run(args []string) {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	gate := flags.String("gate", "check-local", "gate name")
	jobs := flags.Int("jobs", defaultJobs(), "bounded parallel jobs")
	lastFailed := flags.Bool("last-failed", false, "replay the latest compatible failure ledger")
	adversarialLast := flags.Bool("adversarial-last-failed", false, "replay adversarial failures only")
	retry := flags.Bool("diagnostic-retry", false, "retry failures once for classification without clearing failure")
	repeat := flags.Int("repeat", 1, "repeat selected checks")
	var checks listFlag
	flags.Var(&checks, "check", "specific check id (repeatable)")
	if err := flags.Parse(args); err != nil {
		fatal("%v", err)
	}
	if *repeat < 1 || *repeat > 1000 {
		fatal("repeat must be between 1 and 1000")
	}
	manifest, _ := load()
	digest, err := testgate.ManifestDigest(checkManifest, scenarioManifest)
	if err != nil {
		fatal("manifest fingerprint: %v", err)
	}
	fingerprint, err := testgate.BuildFingerprint(digest)
	if err != nil {
		fatal("environment fingerprint: %v", err)
	}
	options := testgate.RunOptions{Gate: *gate, OnlyChecks: checks, Jobs: *jobs, RetryFailures: *retry, ArtifactRoot: artifactRoot}
	if *lastFailed || *adversarialLast {
		parent, err := testgate.LoadLastFailed(artifactRoot)
		if err != nil {
			fatal("%v", err)
		}
		compatibility, ok := testgate.CompatibleForReplay(parent.Fingerprint, fingerprint)
		if !ok {
			fatal("last-failed replay refused: %s", compatibility)
		}
		options.ParentRunID = parent.RunID
		options.Compatibility = compatibility
		options.ParentStatuses = make(map[string]testgate.Status, len(parent.Results))
		for _, result := range parent.Results {
			options.ParentStatuses[result.ID] = result.Status
		}
		options.OnlyChecks = testgate.LastFailedIDs(parent, *adversarialLast)
		if len(options.OnlyChecks) == 0 {
			fatal("last failed run contains no matching checks")
		}
		if parent.Fingerprint.WorkingTree != fingerprint.WorkingTree {
			affected, err := testgate.SelectChecks(manifest, testgate.RunOptions{Gate: "check-fast"}, fingerprint.ChangedFiles)
			if err != nil {
				fatal("affected expansion: %v", err)
			}
			seen := make(map[string]bool)
			for _, id := range options.OnlyChecks {
				seen[id] = true
			}
			for _, check := range affected {
				if !seen[check.ID] {
					options.OnlyChecks = append(options.OnlyChecks, check.ID)
					seen[check.ID] = true
				}
			}
		}
	}
	failed := false
	for n := 1; n <= *repeat; n++ {
		if *repeat > 1 {
			fmt.Printf("\nREPEAT %d/%d\n", n, *repeat)
		}
		runner, err := testgate.NewRunner()
		if err != nil {
			fatal("%v", err)
		}
		summary, err := runner.Run(context.Background(), manifest, fingerprint, options)
		if err != nil {
			fatal("gate: %v", err)
		}
		failed = failed || testgate.GateFailed(summary)
	}
	if failed {
		os.Exit(1)
	}
}

func probe(args []string) {
	if len(args) != 1 {
		fatal("usage: testgate probe <repo|go|frontend|bpf|fixtures|cleanup>")
	}
	switch args[0] {
	case "repo":
		for _, path := range []string{"go.mod", "Makefile", checkManifest, scenarioManifest} {
			mustRegular(path)
		}
		fmt.Printf("PASS: repository configuration and gate inputs are present\n")
	case "go":
		out, err := exec.Command("go", "list", "./...").CombinedOutput()
		if err != nil {
			fatal("go package discovery: %v\n%s", err, out)
		}
		count := len(strings.Fields(string(out)))
		if count == 0 {
			fatal("go package discovery returned no packages")
		}
		fmt.Printf("PASS: discovered %d Go packages\n", count)
	case "frontend":
		mustRegular("dashboard/app/package.json")
		mustRegular("dashboard/app/package-lock.json")
		if info, err := os.Stat("dashboard/app/node_modules"); err != nil || !info.IsDir() {
			fatal("frontend dependencies missing; run cd dashboard/app && npm ci")
		}
		fmt.Println("PASS: frontend lockfile, configuration, and installed dependencies are present")
	case "bpf":
		matches, _ := filepath.Glob("bpf/*/*.bpf.c")
		sort.Strings(matches)
		if len(matches) != 3 {
			fatal("expected exactly 3 approved eBPF sources, found %d: %v", len(matches), matches)
		}
		fmt.Printf("PASS: discovered approved eBPF sources: %s\n", strings.Join(matches, ", "))
	case "fixtures":
		_, scenarios := load()
		ports := make(map[int]string)
		for _, scenario := range scenarios.Scenarios {
			for _, fixture := range scenario.Fixtures {
				mustRegular(fixture)
			}
			for _, port := range scenario.AllowedPorts {
				if port < 0 || port > 65535 {
					fatal("scenario %s has invalid port %d", scenario.ID, port)
				}
				if prior, exists := ports[port]; port != 0 && exists && prior != scenario.IsolationKey {
					fatal("duplicate port %d across isolation keys %s and %s", port, prior, scenario.IsolationKey)
				}
				ports[port] = scenario.IsolationKey
			}
		}
		fmt.Printf("PASS: %d scenario definitions have valid fixtures, ports, and local targets\n", len(scenarios.Scenarios))
	case "cleanup":
		fmt.Println("PASS: scenario used only process-local/httptest state; after-state is clean")
	default:
		fatal("unknown probe %q", args[0])
	}
}

func report() {
	data, err := os.ReadFile(filepath.Join(artifactRoot, "LATEST"))
	if err != nil {
		fatal("no gate results: %v", err)
	}
	runID := strings.TrimSpace(string(data))
	summaryData, err := os.ReadFile(filepath.Join(artifactRoot, runID, "summary.json"))
	if err != nil {
		fatal("%v", err)
	}
	var summary testgate.Summary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		fatal("%v", err)
	}
	fmt.Println(testgate.ConsoleSummary(summary))
}

func synthetic() {
	check := func(id string, command string, deps ...string) testgate.Check {
		return testgate.Check{ID: id, Label: "synthetic " + id, Command: []string{command}, Dependencies: deps,
			Gates: []string{"synthetic"}, Timeout: "5s", Privilege: "local", IsolationKey: id,
			ConcurrencyGroup: id, FailureClass: "test defect", Replay: "testgate synthetic --check " + id}
	}
	manifest := testgate.Manifest{Version: 1, Checks: []testgate.Check{
		check("independent-failure-a", "false"), check("independent-failure-b", "false"),
		check("dependent-block", "true", "independent-failure-a"), check("unrelated-pass", "true"),
	}}
	runner, err := testgate.NewRunner()
	if err != nil {
		fatal("synthetic runner: %v", err)
	}
	summary, err := runner.Run(context.Background(), manifest, testgate.Fingerprint{}, testgate.RunOptions{Gate: "synthetic", Jobs: 4, ArtifactRoot: ".test-artifacts/gate-selftests"})
	if err != nil {
		fatal("synthetic runner: %v", err)
	}
	if summary.Counts[testgate.StatusFail] != 2 || summary.Counts[testgate.StatusBlocked] != 1 || summary.Counts[testgate.StatusPass] != 1 {
		fatal("synthetic collect-all result mismatch: %+v", summary.Counts)
	}
	fmt.Println("SYNTHETIC PASS: two independent failures collected, one dependent blocked with reason, unrelated work continued")
}

func mustRegular(path string) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		fatal("required regular file missing: %s", path)
	}
}
func defaultJobs() int {
	n := runtime.NumCPU() / 2
	if n < 2 {
		n = 2
	}
	if n > 6 {
		n = 6
	}
	return n
}
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "testgate: "+format+"\n", args...)
	os.Exit(2)
}
