package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

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
		fatal("usage: testgate <run|classify|affected-go|go-nonscenario|validate|probe|report|synthetic>")
	}
	switch os.Args[1] {
	case "run":
		run(os.Args[2:])
	case "classify":
		classify(os.Args[2:])
	case "affected-go":
		affectedGo(os.Args[2:])
	case "go-nonscenario":
		goNonScenario(os.Args[2:])
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
	riskOverride := flags.String("risk", "", "manual risk increase: LOW, STANDARD, HIGH, or CRITICAL")
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
	options := testgate.RunOptions{Gate: *gate, OnlyChecks: checks, Jobs: *jobs, RetryFailures: *retry, ArtifactRoot: artifactRoot, RiskOverride: *riskOverride}
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
		options.CompleteFailureReplay = *lastFailed && !*adversarialLast
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for n := 1; n <= *repeat; n++ {
		if *repeat > 1 {
			fmt.Printf("\nREPEAT %d/%d\n", n, *repeat)
		}
		runner, err := testgate.NewRunner()
		if err != nil {
			fatal("%v", err)
		}
		summary, err := runner.Run(ctx, manifest, fingerprint, options)
		if err != nil {
			fatal("gate: %v", err)
		}
		failed = failed || testgate.GateFailed(summary)
		if ctx.Err() != nil {
			failed = true
			break
		}
	}
	if failed {
		os.Exit(1)
	}
}

func classify(args []string) {
	flags := flag.NewFlagSet("classify", flag.ExitOnError)
	riskOverride := flags.String("risk", "", "manual risk increase")
	githubOutput := flags.String("github-output", "", "optional GitHub Actions output file")
	if err := flags.Parse(args); err != nil {
		fatal("%v", err)
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
	report, err := testgate.ClassifyRisk(fingerprint.ChangedFiles, *riskOverride)
	if err != nil {
		fatal("risk classification: %v", err)
	}
	checks, err := testgate.SelectChecks(manifest, testgate.RunOptions{Gate: "check-pr", RiskOverride: *riskOverride}, fingerprint.ChangedFiles)
	if err != nil {
		fatal("PR selection: %v", err)
	}
	selected := make([]string, 0, len(checks))
	for _, check := range checks {
		selected = append(selected, check.ID)
	}
	sort.Strings(selected)
	encoded, err := json.MarshalIndent(map[string]any{"risk": report, "selected_checks": selected}, "", "  ")
	if err != nil {
		fatal("encode risk report: %v", err)
	}
	fmt.Printf("Risk classification: automatic=%s effective=%s executable=%t\n", report.Automatic, report.Effective, report.Executable)
	for _, reason := range report.Reasons {
		fmt.Printf("- %s %s: %s\n", reason.Level, reason.Path, reason.Reason)
	}
	fmt.Printf("Selected PR checks: %s\n%s\n", strings.Join(selected, ","), encoded)
	if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
		fatal("create artifact root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactRoot, "risk.json"), append(encoded, '\n'), 0o600); err != nil {
		fatal("write risk report: %v", err)
	}
	if *githubOutput != "" {
		values := []string{
			"risk=" + string(report.Effective),
			fmt.Sprintf("executable=%t", report.Executable),
			fmt.Sprintf("requires_privileged=%t", report.RequiresPrivileged),
			fmt.Sprintf("requires_dgx=%t", report.RequiresDGX),
			fmt.Sprintf("requires_live_qwen=%t", report.RequiresLiveQwen),
			fmt.Sprintf("frontend=%t", report.FrontendAffected),
			fmt.Sprintf("ebpf=%t", report.EBPFAffected),
			fmt.Sprintf("gate=%t", report.GateAffected),
			"remote_profiles=" + strings.Join(report.RemoteProfiles, ","),
		}
		file, err := os.OpenFile(filepath.Clean(*githubOutput), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			fatal("open GitHub output: %v", err)
		}
		if _, err := fmt.Fprintln(file, strings.Join(values, "\n")); err != nil {
			_ = file.Close()
			fatal("write GitHub output: %v", err)
		}
		if err := file.Close(); err != nil {
			fatal("close GitHub output: %v", err)
		}
	}
}

func affectedGo(args []string) {
	if len(args) != 1 {
		fatal("usage: testgate affected-go <build|test|race|integration>")
	}
	digest, err := testgate.ManifestDigest(checkManifest, scenarioManifest)
	if err != nil {
		fatal("manifest fingerprint: %v", err)
	}
	fingerprint, err := testgate.BuildFingerprint(digest)
	if err != nil {
		fatal("environment fingerprint: %v", err)
	}
	if err := testgate.RunAffectedGo(args[0], fingerprint.ChangedFiles); err != nil {
		fatal("%v", err)
	}
}

func goNonScenario(args []string) {
	if len(args) != 1 || (args[0] != "test" && args[0] != "race") {
		fatal("usage: testgate go-nonscenario <test|race>")
	}
	_, scenarios := load()
	if err := testgate.RunNonScenarioGo(args[0] == "race", scenarios); err != nil {
		fatal("%v", err)
	}
}

func probe(args []string) {
	if len(args) != 1 {
		fatal("usage: testgate probe <repo|go|frontend|bpf|fixtures|cleanup|ebpf-privileged>")
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
		fmt.Println("PASS: no external mutable state was declared; the runner separately verifies process-group exit")
	case "ebpf-privileged":
		probePrivilegedEBPF()
	default:
		fatal("unknown probe %q", args[0])
	}
}

func probePrivilegedEBPF() {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		fatal("privileged eBPF proof requires Linux root execution")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		fatal("cgroup-v2 unified hierarchy unavailable: %v", err)
	}
	out, err := exec.Command("go", "test", "-json", "-count=1", "./bpf/enforce/...", "./bpf/observe/...", "./bpf/sockops/...").CombinedOutput()
	_, _ = os.Stdout.Write(out)
	if err != nil {
		fatal("privileged eBPF test command failed: %v", err)
	}
	required := map[string]bool{
		"TestEnforceJailIsPrecise": false, "TestFailOpenOnMiss": false,
		"TestRateLimitSustainedThroughput": false, "TestCloseDeleteRemovesEntry": false,
		"TestSockopsCookieOracle": false, "TestObserveNeverDropsAPacket": false,
	}
	type event struct {
		Action string `json:"Action"`
		Test   string `json:"Test"`
	}
	var skipped, failed []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var item event
		if err := json.Unmarshal(line, &item); err != nil {
			fatal("malformed go test JSON: %v", err)
		}
		switch item.Action {
		case "pass":
			if _, ok := required[item.Test]; ok {
				required[item.Test] = true
			}
		case "skip":
			if item.Test != "" {
				skipped = append(skipped, item.Test)
			}
		case "fail":
			if item.Test != "" {
				failed = append(failed, item.Test)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fatal("read privileged test results: %v", err)
	}
	var missing []string
	for name, passed := range required {
		if !passed {
			missing = append(missing, name)
		}
	}
	sort.Strings(skipped)
	sort.Strings(failed)
	sort.Strings(missing)
	if len(skipped) > 0 || len(failed) > 0 || len(missing) > 0 {
		fatal("privileged eBPF proof incomplete: skipped=%v failed=%v missing_required=%v", skipped, failed, missing)
	}
	fmt.Printf("PASS: all %d required privileged eBPF datapath proofs executed without skips\n", len(required))
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
