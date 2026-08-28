package testgate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	executable string
	stdout     func(string, ...any)
	executor   func(context.Context, []string, time.Duration, string) commandResult
}

func NewRunner() (*Runner, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve testgate executable: %w", err)
	}
	return &Runner{executable: executable, stdout: func(format string, args ...any) { fmt.Printf(format, args...) }, executor: executeCommand}, nil
}

type nodeExecution struct {
	result Result
	log    []byte
	retry  []byte
}

func (r *Runner) Run(ctx context.Context, manifest Manifest, fingerprint Fingerprint, options RunOptions) (Summary, error) {
	if options.Jobs < 1 {
		options.Jobs = 1
	}
	if options.ArtifactRoot == "" {
		options.ArtifactRoot = ".test-artifacts/gates"
	}
	checks, err := SelectChecks(manifest, options, fingerprint.ChangedFiles)
	if err != nil {
		return Summary{}, err
	}
	runID := time.Now().UTC().Format("20060102T150405.000000000Z")
	runDir := filepath.Join(options.ArtifactRoot, runID)
	if err := os.MkdirAll(filepath.Join(runDir, "logs"), 0o700); err != nil {
		return Summary{}, fmt.Errorf("create result directory: %w", err)
	}
	started := time.Now().UTC()
	summary := Summary{RunID: runID, ParentRunID: options.ParentRunID, Gate: options.Gate,
		StartedAt: started, Fingerprint: fingerprint, Counts: make(map[Status]int),
		ArtifactDirectory: runDir, Compatibility: options.Compatibility}

	byID := make(map[string]Check, len(checks))
	pending := make(map[string]bool, len(checks))
	dependencyUses := make(map[string]int)
	for _, check := range checks {
		byID[check.ID] = check
		pending[check.ID] = true
		for _, dependency := range check.Dependencies {
			dependencyUses[dependency]++
		}
	}
	results := make(map[string]nodeExecution, len(checks))
	safetyStop := false

	for len(pending) > 0 {
		progress := false
		ids := sortedKeys(pending)
		if ctx.Err() != nil {
			for _, id := range ids {
				check := byID[id]
				results[id] = nodeExecution{result: blockedResult(check, StatusBlocked, "not started because the gate was interrupted")}
				delete(pending, id)
			}
			break
		}
		// Resolve dependency failures before scheduling a new wave.
		for _, id := range ids {
			check := byID[id]
			if safetyStop && (check.Privilege != "local" || contains(check.Tags, "adversarial")) {
				results[id] = nodeExecution{result: blockedResult(check, StatusSafetyStop, "not started after safety stop")}
				delete(pending, id)
				progress = true
				continue
			}
			if reason, blocked := dependencyBlock(check, results); blocked {
				results[id] = nodeExecution{result: blockedResult(check, StatusBlocked, reason)}
				delete(pending, id)
				progress = true
			}
		}
		if len(pending) == 0 {
			break
		}

		ready := make([]Check, 0)
		usedGroups := make(map[string]bool)
		usedIsolation := make(map[string]bool)
		for _, id := range sortedKeys(pending) {
			check := byID[id]
			if !dependenciesComplete(check, results) {
				continue
			}
			if usedGroups[check.ConcurrencyGroup] || usedIsolation[check.IsolationKey] {
				continue
			}
			ready = append(ready, check)
			usedGroups[check.ConcurrencyGroup] = true
			usedIsolation[check.IsolationKey] = true
			if len(ready) == options.Jobs {
				break
			}
		}
		if len(ready) == 0 {
			if progress {
				continue
			}
			return Summary{}, fmt.Errorf("scheduler made no progress; manifest may contain an unresolved dependency")
		}
		var wg sync.WaitGroup
		completed := make(chan nodeExecution, len(ready))
		for _, check := range ready {
			delete(pending, check.ID)
			wg.Add(1)
			go func(check Check) {
				defer wg.Done()
				r.stdout("RUN     %-34s %s\n", check.ID, check.Label)
				completed <- r.execute(ctx, check, runDir, options.RetryFailures)
			}(check)
		}
		wg.Wait()
		close(completed)
		for execution := range completed {
			results[execution.result.ID] = execution
			if execution.result.Status == StatusSafetyStop {
				safetyStop = true
			}
			r.stdout("%-8s %-34s %.2fs  %s\n", execution.result.Status, execution.result.ID, execution.result.DurationSeconds, execution.result.Replay)
		}
	}

	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		execution := results[id]
		if uses := dependencyUses[id]; uses > 1 && execution.result.Status == StatusPass {
			execution.result.Cache = fmt.Sprintf("executed once; DAG reuse by %d dependents", uses)
			summary.CacheHits += uses - 1
		}
		summary.Results = append(summary.Results, execution.result)
		summary.Counts[execution.result.Status]++
		if execution.result.Cache == "executed" || strings.HasPrefix(execution.result.Cache, "executed once") {
			summary.CacheMisses++
		}
		if err := writeNodeLogs(runDir, execution); err != nil {
			return Summary{}, err
		}
	}
	summary.SafetyStop = safetyStop
	if options.ParentRunID != "" {
		summary.ReplayChanges = replayChanges(options.ParentStatuses, results)
	}
	summary.FinishedAt = time.Now().UTC()
	summary.DurationSeconds = summary.FinishedAt.Sub(started).Seconds()
	if err := WriteArtifacts(summary, manifest, runDir); err != nil {
		return Summary{}, err
	}
	if err := updatePointers(options.ArtifactRoot, summary, options.CompleteFailureReplay); err != nil {
		return Summary{}, err
	}
	r.stdout("\n%s\n", ConsoleSummary(summary))
	return summary, nil
}

func replayChanges(parent map[string]Status, current map[string]nodeExecution) map[string][]string {
	changes := map[string][]string{"fixed": {}, "still_failing": {}, "newly_blocked": {}, "newly_failing": {}}
	for id, execution := range current {
		before, existed := parent[id]
		after := execution.result.Status
		beforeFailed := before == StatusFail || before == StatusBlocked || before == StatusSafetyStop
		afterFailed := after == StatusFail || after == StatusBlocked || after == StatusSafetyStop
		switch {
		case existed && beforeFailed && !afterFailed:
			changes["fixed"] = append(changes["fixed"], id)
		case existed && beforeFailed && afterFailed:
			changes["still_failing"] = append(changes["still_failing"], id)
		case (!existed || !beforeFailed) && after == StatusBlocked:
			changes["newly_blocked"] = append(changes["newly_blocked"], id)
		case (!existed || !beforeFailed) && (after == StatusFail || after == StatusSafetyStop):
			changes["newly_failing"] = append(changes["newly_failing"], id)
		}
	}
	for key := range changes {
		sort.Strings(changes[key])
	}
	return changes
}

func (r *Runner) execute(ctx context.Context, check Check, runDir string, retry bool) nodeExecution {
	result := Result{ID: check.ID, Label: check.Label, FailureClass: check.FailureClass,
		Replay: check.Replay, Cache: "executed", Scenario: cloneScenario(check.Scenario)}
	result.LogPath = filepath.Join(runDir, "logs", sanitizeID(check.ID)+".log")
	if !platformAllowed(check) {
		result.Status = StatusSkipped
		result.Reason = fmt.Sprintf("unsupported on %s; supported platforms: %s", runtimeGOOS(), strings.Join(check.Platforms, ","))
		result.Cache = "not applicable"
		return nodeExecution{result: result, log: []byte(result.Reason + "\n")}
	}
	timeout, _ := time.ParseDuration(check.Timeout)
	result.StartedAt = time.Now().UTC()
	command := r.executor(ctx, check.Command, timeout, r.executable)
	result.FinishedAt = time.Now().UTC()
	result.Duration = command.duration
	result.DurationSeconds = command.duration.Seconds()
	result.ExitCode = command.exitCode
	result.Status = StatusPass
	if command.timedOut {
		result.Status = StatusFail
		result.FailureClass = "timeout"
		result.Reason = "command exceeded " + check.Timeout
	}
	if command.exitCode != 0 {
		result.Status = StatusFail
		result.Reason = fmt.Sprintf("command exited %d", command.exitCode)
	}
	if check.SafetyCritical && result.Status == StatusFail {
		result.Status = StatusSafetyStop
		result.FailureClass = "safety invariant violation"
		result.Reason = "safety-critical check failed: " + result.Reason
	}
	if command.secretFound {
		result.Status = StatusSafetyStop
		result.FailureClass = "safety invariant violation"
		result.Reason = "credential-like material appeared in output"
	}
	if command.truncated && result.Status == StatusPass {
		result.Reason = "log truncated at 4 MiB"
	}
	if result.Scenario != nil && command.processResidue {
		result.Status = StatusSafetyStop
		result.FailureClass = "safety invariant violation"
		result.Reason = "scenario process group remained after command exit"
	}
	applyResultParser(check, command.output, &result)

	cleanupStatus, cleanupOutput, cleanupSafety := r.cleanup(context.WithoutCancel(ctx), check)
	result.CleanupStatus = cleanupStatus
	log := append([]byte(nil), command.output...)
	if len(cleanupOutput) > 0 {
		log = append(log, []byte("\n--- cleanup ---\n")...)
		log = append(log, cleanupOutput...)
	}
	if cleanupStatus == "FAIL" {
		result.Status = StatusFail
		result.FailureClass = "cleanup defect"
		result.Reason = "cleanup handler failed"
		if cleanupSafety {
			result.Status = StatusSafetyStop
			result.FailureClass = "safety invariant violation"
			result.Reason = "safety-critical cleanup or after-state verification failed"
		}
	}
	if result.Scenario != nil {
		result.Scenario.CleanupResult = cleanupStatus
		if result.Status == StatusPass {
			result.Scenario.ResponseResult = "all manifest-required test assertions reported PASS"
		} else {
			result.Scenario.ResponseResult = "scenario did not complete successfully"
		}
	}
	execution := nodeExecution{result: result, log: log}
	if retry && result.Status == StatusFail && !check.SafetyCritical {
		retryCommand := r.executor(ctx, check.Command, timeout, r.executable)
		retryStatus := StatusFail
		if retryCommand.exitCode == 0 && !retryCommand.timedOut && !retryCommand.secretFound && !retryCommand.processResidue {
			retryStatus = StatusPass
		}
		retryParsed := Result{Status: retryStatus, FailureClass: check.FailureClass, Scenario: cloneScenario(check.Scenario)}
		applyResultParser(check, retryCommand.output, &retryParsed)
		retryStatus = retryParsed.Status
		retryCleanup, retryCleanupOutput, retryCleanupSafety := r.cleanup(context.WithoutCancel(ctx), check)
		execution.retry = append([]byte(nil), retryCommand.output...)
		if len(retryCleanupOutput) > 0 {
			execution.retry = append(execution.retry, []byte("\n--- cleanup ---\n")...)
			execution.retry = append(execution.retry, retryCleanupOutput...)
		}
		if retryCleanup == "FAIL" {
			retryStatus = StatusFail
		}
		execution.result.Retry = &RetryResult{Status: retryStatus, DurationSeconds: retryCommand.duration.Seconds(), LogPath: filepath.Join(runDir, "logs", sanitizeID(check.ID)+".retry.log"), CleanupStatus: retryCleanup}
		if retryCleanupSafety || retryCommand.secretFound || retryCommand.processResidue {
			execution.result.Status = StatusSafetyStop
			execution.result.FailureClass = "safety invariant violation"
			execution.result.Reason = "diagnostic retry violated output, process, cleanup, or after-state safety"
			return execution
		}
		if retryStatus == StatusPass {
			execution.result.FailureClass = "nondeterministic or flaky behavior"
			execution.result.Reason = "original failure passed diagnostic retry; gate remains failed"
			execution.result.Status = StatusFail
		}
	}
	return execution
}

func (r *Runner) cleanup(ctx context.Context, check Check) (string, []byte, bool) {
	if len(check.Cleanup) == 0 {
		return "not required", nil, false
	}
	result := r.executor(ctx, check.Cleanup, 30*time.Second, r.executable)
	if result.exitCode != 0 || result.timedOut || result.secretFound || result.processResidue {
		return "FAIL", result.output, check.CleanupSafetyCritical || result.secretFound || result.processResidue
	}
	return "PASS", result.output, false
}

func dependencyBlock(check Check, results map[string]nodeExecution) (string, bool) {
	var failed []string
	for _, dep := range check.Dependencies {
		result, ok := results[dep]
		if !ok {
			continue
		}
		if result.result.Status != StatusPass && result.result.Status != StatusSkipped {
			failed = append(failed, dep+"="+string(result.result.Status))
		}
	}
	if len(failed) == 0 {
		return "", false
	}
	sort.Strings(failed)
	return "prerequisite did not pass: " + strings.Join(failed, ", "), true
}

func dependenciesComplete(check Check, results map[string]nodeExecution) bool {
	for _, dep := range check.Dependencies {
		if _, ok := results[dep]; !ok {
			return false
		}
	}
	return true
}

func blockedResult(check Check, status Status, reason string) Result {
	return Result{ID: check.ID, Label: check.Label, Status: status, FailureClass: "missing prerequisite",
		Reason: reason, Replay: check.Replay, Cache: "not executed", Scenario: cloneScenario(check.Scenario)}
}

func cloneScenario(source *ScenarioMetadata) *ScenarioMetadata {
	if source == nil {
		return nil
	}
	copy := *source
	copy.ExpectedEvidence = append([]string(nil), source.ExpectedEvidence...)
	copy.GroundTruth = make(map[string]string, len(source.GroundTruth))
	for key, value := range source.GroundTruth {
		copy.GroundTruth[key] = value
	}
	return &copy
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var runtimeGOOS = func() string { return runtime.GOOS }
