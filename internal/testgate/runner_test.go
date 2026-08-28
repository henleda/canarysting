package testgate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCollectAllBlocksOnlyDependentsAndKeepsRepros(t *testing.T) {
	manifest := Manifest{Version: 1, Checks: []Check{
		fakeCheck("fail-a", nil), fakeCheck("fail-b", nil), fakeCheck("blocked", []string{"fail-a"}), fakeCheck("pass", nil),
	}}
	exec := newFakeExecutor(map[string][]commandResult{
		"fail-a": {{exitCode: 1, output: []byte("a")}}, "fail-b": {{exitCode: 2, output: []byte("b")}},
		"pass": {{exitCode: 0, output: []byte("pass")}},
	})
	summary := runFixture(t, manifest, exec, RunOptions{Gate: "fixture", Jobs: 4})
	assertStatus(t, summary, "fail-a", StatusFail)
	assertStatus(t, summary, "fail-b", StatusFail)
	assertStatus(t, summary, "blocked", StatusBlocked)
	assertStatus(t, summary, "pass", StatusPass)
	for _, id := range []string{"fail-a", "fail-b", "blocked"} {
		result := findResult(t, summary, id)
		if result.Replay == "" {
			t.Fatalf("%s has no direct replay", id)
		}
	}
	if !strings.Contains(findResult(t, summary, "blocked").Reason, "fail-a=FAIL") {
		t.Fatal("blocked reason does not name failed prerequisite")
	}
}

func TestCleanupRunsAfterFailureAndSafetyStopHaltsAdversarialWork(t *testing.T) {
	a := fakeCheck("unsafe", nil)
	a.SafetyCritical = true
	a.Cleanup = []string{"cleanup-unsafe"}
	a.CleanupSafetyCritical = true
	b := fakeCheck("adversarial:later", nil)
	b.Tags = []string{"adversarial"}
	b.Privilege = "privileged"
	b.Dependencies = []string{"unsafe"}
	c := fakeCheck("ordinary", nil)
	manifest := Manifest{Version: 1, Checks: []Check{a, b, c}}
	exec := newFakeExecutor(map[string][]commandResult{
		"unsafe": {{exitCode: 1}}, "cleanup-unsafe": {{exitCode: 0, output: []byte("clean")}}, "ordinary": {{exitCode: 0}},
	})
	summary := runFixture(t, manifest, exec, RunOptions{Gate: "fixture", Jobs: 1})
	assertStatus(t, summary, "unsafe", StatusSafetyStop)
	assertStatus(t, summary, "adversarial:later", StatusSafetyStop)
	assertStatus(t, summary, "ordinary", StatusPass)
	if !exec.called("cleanup-unsafe") {
		t.Fatal("cleanup did not run after ordinary failure")
	}
}

func TestCleanupFailureRaisesSafetyStop(t *testing.T) {
	check := fakeCheck("scenario", nil)
	check.Cleanup = []string{"cleanup"}
	check.CleanupSafetyCritical = true
	exec := newFakeExecutor(map[string][]commandResult{"scenario": {{exitCode: 0}}, "cleanup": {{exitCode: 1}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1})
	assertStatus(t, summary, "scenario", StatusSafetyStop)
	if !summary.SafetyStop {
		t.Fatal("summary omitted safety stop")
	}
}

func TestDiagnosticRetryNeverErasesOriginalFailure(t *testing.T) {
	check := fakeCheck("flaky", nil)
	check.Cleanup = []string{"cleanup"}
	exec := newFakeExecutor(map[string][]commandResult{"flaky": {{exitCode: 1}, {exitCode: 0}}, "cleanup": {{exitCode: 0}, {exitCode: 0}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1, RetryFailures: true})
	result := findResult(t, summary, "flaky")
	if result.Status != StatusFail || result.FailureClass != "nondeterministic or flaky behavior" || result.Retry == nil || result.Retry.Status != StatusPass || result.Retry.CleanupStatus != "PASS" {
		t.Fatalf("retry incorrectly cleared failure: %+v", result)
	}
	if got := exec.callCount("cleanup"); got != 2 {
		t.Fatalf("cleanup must run after the original and retry executions, got %d", got)
	}
}

func TestSafetyStopIsNeverRetried(t *testing.T) {
	check := fakeCheck("credential", nil)
	check.Cleanup = []string{"cleanup"}
	exec := newFakeExecutor(map[string][]commandResult{
		"credential": {{exitCode: 0, secretFound: true}, {exitCode: 0}},
		"cleanup":    {{exitCode: 0}},
	})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1, RetryFailures: true})
	assertStatus(t, summary, "credential", StatusSafetyStop)
	if got := exec.callCount("credential"); got != 1 {
		t.Fatalf("safety stop was retried %d times", got)
	}
}

func TestLastFailedAndCompatibility(t *testing.T) {
	summary := Summary{Results: []Result{{ID: "a", Status: StatusFail}, {ID: "b", Status: StatusBlocked}, {ID: "adversarial:c", Status: StatusSafetyStop}, {ID: "d", Status: StatusPass}}}
	if got := strings.Join(LastFailedIDs(summary, false), ","); got != "a,adversarial:c,b" {
		t.Fatalf("wrong replay subset: %s", got)
	}
	if got := strings.Join(LastFailedIDs(summary, true), ","); got != "adversarial:c" {
		t.Fatalf("wrong adversarial subset: %s", got)
	}
	base := Fingerprint{SourceRevision: "r", Toolchain: "t", Manifest: "m", Environment: "e", WorkingTree: "w"}
	changed := base
	changed.WorkingTree = "w2"
	message, ok := CompatibleForReplay(base, changed)
	if !ok || !strings.Contains(message, "expanded") {
		t.Fatalf("changed tree should expand safely: %s", message)
	}
	changed.SourceRevision = "r2"
	if _, ok := CompatibleForReplay(base, changed); ok {
		t.Fatal("revision mismatch must refuse replay")
	}
}

func TestTimeoutTerminatesProcessGroup(t *testing.T) {
	started := time.Now()
	result := executeCommand(context.Background(), []string{"sh", "-c", "sleep 10 & wait"}, 100*time.Millisecond, "")
	if !result.timedOut {
		t.Fatal("timeout was not classified")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("process group was not terminated promptly: %s", elapsed)
	}
}

func TestReplayDeltaReportsFixedStillAndNew(t *testing.T) {
	current := map[string]nodeExecution{
		"fixed":   {result: Result{ID: "fixed", Status: StatusPass}},
		"still":   {result: Result{ID: "still", Status: StatusFail}},
		"blocked": {result: Result{ID: "blocked", Status: StatusBlocked}},
		"new":     {result: Result{ID: "new", Status: StatusFail}},
	}
	changes := replayChanges(map[string]Status{"fixed": StatusFail, "still": StatusFail, "blocked": StatusPass}, current)
	if strings.Join(changes["fixed"], ",") != "fixed" || strings.Join(changes["still_failing"], ",") != "still" || strings.Join(changes["newly_blocked"], ",") != "blocked" || strings.Join(changes["newly_failing"], ",") != "new" {
		t.Fatalf("unexpected replay delta: %+v", changes)
	}
}

func TestArtifactsAndConsoleAgreeAndPathsAreSanitized(t *testing.T) {
	check := fakeCheck("check/with:punctuation", nil)
	exec := newFakeExecutor(map[string][]commandResult{check.ID: {{exitCode: 1, output: []byte("failure")}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1})
	data, err := os.ReadFile(filepath.Join(summary.ArtifactDirectory, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Counts[StatusFail] != 1 || !strings.Contains(ConsoleSummary(decoded), "FAIL=1") {
		t.Fatal("JSON and console summary disagree")
	}
	junit, err := os.ReadFile(filepath.Join(summary.ArtifactDirectory, "junit.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), `failures="1"`) {
		t.Fatal("JUnit and JSON summary disagree")
	}
	if strings.Contains(findResult(t, summary, check.ID).LogPath, ":") || strings.Contains(filepath.Base(findResult(t, summary, check.ID).LogPath), "/") {
		t.Fatal("unsafe result path")
	}
	for _, name := range []string{"summary.txt", "summary.json", "junit.xml", "environment.json", "dependency-graph.json", "failed-checks.json", "blocked-checks.json", "skipped-checks.json", "timing.json", "repro.sh"} {
		if _, err := os.Stat(filepath.Join(summary.ArtifactDirectory, name)); err != nil {
			t.Fatalf("missing artifact %s", name)
		}
	}
}

func TestCredentialOutputIsRedactedAndStops(t *testing.T) {
	result := executeCommand(context.Background(), []string{"sh", "-c", "printf 'Authorization: Bearer abcdefghijklmnop\\n'"}, time.Second, "")
	if !result.secretFound || strings.Contains(string(result.output), "abcdefghijklmnop") {
		t.Fatal("credential output was not redacted")
	}
}

func TestCredentialDetectionContinuesBeyondRetainedLogLimit(t *testing.T) {
	var output limitedBuffer
	if _, err := output.Write(bytes.Repeat([]byte("x"), maxLogBytes+1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("\nAuthorization: Bearer abcdefghijklmnop\n")); err != nil {
		t.Fatal(err)
	}
	if !output.truncated || !output.secretFound {
		t.Fatalf("full-stream scan failed: truncated=%v secret=%v", output.truncated, output.secretFound)
	}
}

func TestScenarioEvidenceComesFromParsedTestEvents(t *testing.T) {
	check := fakeCheck("adversarial:fixture", nil)
	check.ResultParser = "go-test-json-required-passes"
	check.Cleanup = []string{"cleanup"}
	check.Scenario = &ScenarioMetadata{
		ExpectedEvidence:   []string{"prose expectation must not be copied"},
		RequiredAssertions: []string{"TestOne", "TestTwo"},
	}
	output := []byte("{\"Action\":\"pass\",\"Test\":\"TestOne\"}\n{\"Action\":\"pass\",\"Test\":\"TestTwo\"}\n")
	exec := newFakeExecutor(map[string][]commandResult{check.ID: {{exitCode: 0, output: output}}, "cleanup": {{exitCode: 0}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1})
	result := findResult(t, summary, check.ID)
	assertStatus(t, summary, check.ID, StatusPass)
	if strings.Join(result.Scenario.ObservedEvidence, ",") != "test-pass:TestOne,test-pass:TestTwo" {
		t.Fatalf("observed evidence was fabricated or incomplete: %+v", result.Scenario)
	}
	if result.Scenario.IdentityResult == "PASS" || result.Scenario.CorrelationResult == "PASS" {
		t.Fatalf("unmeasured identity/correlation was fabricated: %+v", result.Scenario)
	}
}

func TestScenarioMissingRequiredPassFails(t *testing.T) {
	check := fakeCheck("adversarial:fixture", nil)
	check.ResultParser = "go-test-json-required-passes"
	check.Scenario = &ScenarioMetadata{RequiredAssertions: []string{"TestOne", "TestTwo"}}
	exec := newFakeExecutor(map[string][]commandResult{check.ID: {{exitCode: 0, output: []byte("{\"Action\":\"pass\",\"Test\":\"TestOne\"}\n")}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{check}}, exec, RunOptions{Gate: "fixture", Jobs: 1})
	assertStatus(t, summary, check.ID, StatusFail)
	if got := strings.Join(findResult(t, summary, check.ID).Scenario.MissingEvidence, ","); got != "test-pass:TestTwo" {
		t.Fatalf("wrong missing evidence: %s", got)
	}
}

func TestSubsetReplayPreservesUnresolvedParentLedger(t *testing.T) {
	root := t.TempDir()
	parent := Summary{RunID: "parent", Gate: "fixture", Counts: map[Status]int{StatusFail: 2}}
	if err := updatePointers(root, parent, false); err != nil {
		t.Fatal(err)
	}
	subset := Summary{RunID: "subset", ParentRunID: "parent", Gate: "fixture", Counts: map[Status]int{StatusPass: 1}}
	if err := updatePointers(root, subset, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "LAST_FAILED"))
	if err != nil || strings.TrimSpace(string(data)) != "parent" {
		t.Fatalf("subset replay erased parent ledger: %q %v", data, err)
	}
	if err := updatePointers(root, subset, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "LAST_FAILED")); !os.IsNotExist(err) {
		t.Fatalf("complete successful replay did not clear parent ledger: %v", err)
	}
}

func TestCancellationStillRunsCleanupAndWritesArtifacts(t *testing.T) {
	check := fakeCheck("started", nil)
	check.Cleanup = []string{"cleanup"}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var mu sync.Mutex
	cleanupCalls := 0
	runner := &Runner{executable: "test", stdout: func(string, ...any) {}, executor: func(ctx context.Context, argv []string, _ time.Duration, _ string) commandResult {
		if argv[0] == "cleanup" {
			mu.Lock()
			cleanupCalls++
			mu.Unlock()
			return commandResult{exitCode: 0}
		}
		close(started)
		<-ctx.Done()
		return commandResult{exitCode: 130}
	}}
	done := make(chan Summary, 1)
	root := t.TempDir()
	go func() {
		summary, _ := runner.Run(ctx, Manifest{Version: 1, Checks: []Check{check}}, Fingerprint{}, RunOptions{Gate: "fixture", Jobs: 1, ArtifactRoot: root})
		done <- summary
	}()
	<-started
	cancel()
	summary := <-done
	mu.Lock()
	gotCleanup := cleanupCalls
	mu.Unlock()
	if gotCleanup != 1 {
		t.Fatalf("cleanup did not run after cancellation: %d", gotCleanup)
	}
	if _, err := os.Stat(filepath.Join(summary.ArtifactDirectory, "summary.json")); err != nil {
		t.Fatalf("interrupted run did not preserve artifacts: %v", err)
	}
}

func TestAffectedFilesUnionIncludesCommittedBranchChanges(t *testing.T) {
	got := mergeChangedFiles([]string{"local.go"}, []string{"committed.go", "local.go"})
	if strings.Join(got, ",") != "committed.go,local.go" {
		t.Fatalf("wrong affected-file union: %v", got)
	}
}

func TestScenarioManifestCannotExecuteArbitraryCommand(t *testing.T) {
	scenario := Scenario{
		ID: "bounded", Title: "bounded", Objective: "bounded", TargetScope: "fixture",
		RequiredBinaries: []string{"go"}, RequiredPrivileges: "local", AllowedHosts: []string{"127.0.0.1"},
		Fixtures: []string{"internal/testgate/runner_test.go"}, DeterministicSeed: 1,
		ExpectedObservations: []string{"observation"}, ExpectedCanarySting: []string{"response"},
		ProhibitedOutcomes: []string{"escape"}, Timeout: "1s", AfterStateAssertions: []string{"clean"},
		IsolationKey: "fixture", Replay: "make adversarial-one SCENARIO=bounded",
		Command: []string{"sh", "-c", "echo escaped"}, FailureClass: "test defect",
		AttackerIntent: "bounded", AttackerAction: "bounded", GroundTruth: map[string]string{"response": "bounded"},
		RequiredTestPasses: []string{"TestOne"},
	}
	err := Validate(&Manifest{Version: 1}, &ScenarioManifest{Version: 1, Scenarios: []Scenario{scenario}})
	if err == nil || !strings.Contains(err.Error(), "command must be exactly go test") {
		t.Fatalf("arbitrary scenario command was accepted: %v", err)
	}
}

type fakeExecutor struct {
	mu      sync.Mutex
	results map[string][]commandResult
	calls   []string
}

func newFakeExecutor(results map[string][]commandResult) *fakeExecutor {
	return &fakeExecutor{results: results}
}
func (f *fakeExecutor) run(_ context.Context, argv []string, _ time.Duration, _ string) commandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := argv[0]
	f.calls = append(f.calls, id)
	values := f.results[id]
	if len(values) == 0 {
		return commandResult{exitCode: 0}
	}
	result := values[0]
	f.results[id] = values[1:]
	return result
}
func (f *fakeExecutor) called(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.calls {
		if got == id {
			return true
		}
	}
	return false
}
func (f *fakeExecutor) callCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, got := range f.calls {
		if got == id {
			count++
		}
	}
	return count
}

func fakeCheck(id string, deps []string) Check {
	return Check{ID: id, Label: id, Command: []string{id}, Dependencies: deps, Gates: []string{"fixture"}, Timeout: "1s", Privilege: "local", IsolationKey: id, ConcurrencyGroup: id, FailureClass: "test defect", Replay: "make check-one CHECK=" + id}
}
func runFixture(t *testing.T, manifest Manifest, executor *fakeExecutor, options RunOptions) Summary {
	t.Helper()
	options.ArtifactRoot = t.TempDir()
	runner := &Runner{executable: "test", stdout: func(string, ...any) {}, executor: executor.run}
	summary, err := runner.Run(context.Background(), manifest, Fingerprint{}, options)
	if err != nil {
		t.Fatal(err)
	}
	return summary
}
func findResult(t *testing.T, summary Summary, id string) Result {
	t.Helper()
	for _, result := range summary.Results {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("missing result %s", id)
	return Result{}
}
func assertStatus(t *testing.T, summary Summary, id string, status Status) {
	t.Helper()
	if got := findResult(t, summary, id).Status; got != status {
		t.Fatalf("%s: got %s want %s", id, got, status)
	}
}
