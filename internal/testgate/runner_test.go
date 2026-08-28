package testgate

import (
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
	exec := newFakeExecutor(map[string][]commandResult{"flaky": {{exitCode: 1}, {exitCode: 0}}})
	summary := runFixture(t, Manifest{Version: 1, Checks: []Check{fakeCheck("flaky", nil)}}, exec, RunOptions{Gate: "fixture", Jobs: 1, RetryFailures: true})
	result := findResult(t, summary, "flaky")
	if result.Status != StatusFail || result.FailureClass != "nondeterministic or flaky behavior" || result.Retry == nil || result.Retry.Status != StatusPass {
		t.Fatalf("retry incorrectly cleared failure: %+v", result)
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
