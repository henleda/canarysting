package testgate

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func WriteArtifacts(summary Summary, manifest Manifest, runDir string) error {
	if err := writeJSON(filepath.Join(runDir, "summary.json"), summary); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "summary.txt"), []byte(ConsoleSummary(summary)+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "environment.json"), map[string]any{
		"fingerprint": summary.Fingerprint, "compatibility": summary.Compatibility,
	}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "dependency-graph.json"), graphFor(manifest, summary)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "failed-checks.json"), ledger(summary, StatusFail, StatusSafetyStop)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "blocked-checks.json"), ledger(summary, StatusBlocked)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "skipped-checks.json"), ledger(summary, StatusSkipped)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "timing.json"), timing(summary)); err != nil {
		return err
	}
	if err := writeJUnit(filepath.Join(runDir, "junit.xml"), summary); err != nil {
		return err
	}
	if err := writeRepro(filepath.Join(runDir, "repro.sh"), summary); err != nil {
		return err
	}
	return nil
}

func writeNodeLogs(runDir string, execution nodeExecution) error {
	if execution.result.LogPath != "" {
		if err := os.WriteFile(execution.result.LogPath, execution.log, 0o600); err != nil {
			return fmt.Errorf("write log: %w", err)
		}
	}
	if execution.result.Retry != nil {
		if err := os.WriteFile(execution.result.Retry.LogPath, execution.retry, 0o600); err != nil {
			return fmt.Errorf("write retry log: %w", err)
		}
	}
	return nil
}

func ConsoleSummary(summary Summary) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Gate %s: PASS=%d FAIL=%d BLOCKED=%d SKIPPED=%d SAFETY_STOP=%d duration=%.2fs\n",
		summary.Gate, summary.Counts[StatusPass], summary.Counts[StatusFail], summary.Counts[StatusBlocked], summary.Counts[StatusSkipped], summary.Counts[StatusSafetyStop], summary.DurationSeconds)
	if len(summary.ReplayChanges) > 0 {
		fmt.Fprintf(&builder, "Replay: fixed=%s still_failing=%s newly_blocked=%s newly_failing=%s\n",
			strings.Join(summary.ReplayChanges["fixed"], ","), strings.Join(summary.ReplayChanges["still_failing"], ","),
			strings.Join(summary.ReplayChanges["newly_blocked"], ","), strings.Join(summary.ReplayChanges["newly_failing"], ","))
	}
	for _, result := range summary.Results {
		if result.Status == StatusPass {
			continue
		}
		fmt.Fprintf(&builder, "%-11s %-34s class=%s duration=%.2fs\n", result.Status, result.ID, result.FailureClass, result.DurationSeconds)
		if result.Reason != "" {
			fmt.Fprintf(&builder, "  reason: %s\n", result.Reason)
		}
		if result.Status == StatusSafetyStop {
			fmt.Fprintf(&builder, "  recovery: inspect the log and execute only the manifest-declared cleanup/recovery procedure before privileged work resumes\n")
		}
		fmt.Fprintf(&builder, "  repro: %s\n", result.Replay)
		if result.LogPath != "" {
			fmt.Fprintf(&builder, "  log:   %s\n", result.LogPath)
		}
	}
	fmt.Fprintf(&builder, "Artifacts: %s", summary.ArtifactDirectory)
	return builder.String()
}

type ledgerFile struct {
	RunID       string      `json:"run_id"`
	Gate        string      `json:"gate"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Checks      []Result    `json:"checks"`
}

func ledger(summary Summary, statuses ...Status) ledgerFile {
	wanted := make(map[Status]bool)
	for _, status := range statuses {
		wanted[status] = true
	}
	result := ledgerFile{RunID: summary.RunID, Gate: summary.Gate, Fingerprint: summary.Fingerprint}
	for _, check := range summary.Results {
		if wanted[check.Status] {
			result.Checks = append(result.Checks, check)
		}
	}
	return result
}

func timing(summary Summary) map[string]any {
	checks := make(map[string]float64)
	for _, result := range summary.Results {
		checks[result.ID] = result.DurationSeconds
	}
	return map[string]any{"run_id": summary.RunID, "total_seconds": summary.DurationSeconds, "checks": checks,
		"cache_hits": summary.CacheHits, "cache_misses": summary.CacheMisses}
}

func graphFor(manifest Manifest, summary Summary) map[string]any {
	selected := make(map[string]bool)
	for _, result := range summary.Results {
		selected[result.ID] = true
	}
	nodes := make([]map[string]any, 0, len(selected))
	for _, check := range manifest.Checks {
		if !selected[check.ID] {
			continue
		}
		nodes = append(nodes, map[string]any{"id": check.ID, "label": check.Label, "dependencies": check.Dependencies,
			"timeout": check.Timeout, "privilege": check.Privilege, "isolation_key": check.IsolationKey,
			"concurrency_group": check.ConcurrencyGroup, "failure_class": check.FailureClass,
			"cleanup": check.Cleanup, "result_parser": check.ResultParser, "replay": check.Replay,
			"manual_recovery": check.ManualRecovery})
	}
	return map[string]any{"manifest_version": manifest.Version, "nodes": nodes}
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}
type junitCase struct {
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitMessage `xml:"failure,omitempty"`
	Skipped *junitMessage `xml:"skipped,omitempty"`
}
type junitMessage struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

func writeJUnit(path string, summary Summary) error {
	suite := junitSuite{Name: summary.Gate, Tests: len(summary.Results), Time: fmt.Sprintf("%.6f", summary.DurationSeconds)}
	for _, result := range summary.Results {
		item := junitCase{Name: result.ID, Time: fmt.Sprintf("%.6f", result.DurationSeconds)}
		switch result.Status {
		case StatusFail, StatusBlocked, StatusSafetyStop:
			item.Failure = &junitMessage{Message: string(result.Status) + ": " + result.FailureClass, Body: result.Reason + "\nrepro: " + result.Replay}
			suite.Failures++
		case StatusSkipped:
			item.Skipped = &junitMessage{Message: result.Reason}
			suite.Skipped++
		}
		suite.Cases = append(suite.Cases, item)
	}
	data, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func writeRepro(path string, summary Summary) error {
	lines := []string{"#!/usr/bin/env bash", "set -euo pipefail", "# Generated direct reproductions; inspect before running privileged or DGX checks."}
	seen := make(map[string]bool)
	for _, result := range summary.Results {
		if result.Status == StatusPass || result.Status == StatusSkipped || seen[result.Replay] {
			continue
		}
		seen[result.Replay] = true
		lines = append(lines, result.Replay)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o700)
}

func updatePointers(root string, summary Summary, completeFailureReplay bool) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "LATEST"), []byte(summary.RunID+"\n"), 0o600); err != nil {
		return err
	}
	// A subset replay (for example adversarial-only) must not replace or erase
	// a ledger that may still contain unrelated unresolved failures.
	if summary.ParentRunID != "" && !completeFailureReplay {
		return nil
	}
	if GateFailed(summary) {
		if err := os.WriteFile(filepath.Join(root, "LAST_FAILED"), []byte(summary.RunID+"\n"), 0o600); err != nil {
			return err
		}
	} else if summary.ParentRunID != "" {
		pointer := filepath.Join(root, "LAST_FAILED")
		if data, err := os.ReadFile(pointer); err == nil && strings.TrimSpace(string(data)) == summary.ParentRunID {
			if err := os.Remove(pointer); err != nil {
				return err
			}
		}
	}
	return nil
}

func GateFailed(summary Summary) bool {
	return summary.Counts[StatusFail] > 0 || summary.Counts[StatusBlocked] > 0 || summary.Counts[StatusSafetyStop] > 0
}

func LoadLastFailed(root string) (Summary, error) {
	id, err := os.ReadFile(filepath.Join(root, "LAST_FAILED"))
	if err != nil {
		return Summary{}, fmt.Errorf("no last-failed ledger: %w", err)
	}
	path := filepath.Join(root, strings.TrimSpace(string(id)), "summary.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, fmt.Errorf("read last-failed summary: %w", err)
	}
	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		return Summary{}, fmt.Errorf("decode last-failed summary: %w", err)
	}
	return summary, nil
}

func LastFailedIDs(summary Summary, adversarialOnly bool) []string {
	var ids []string
	for _, result := range summary.Results {
		if result.Status != StatusFail && result.Status != StatusBlocked && result.Status != StatusSafetyStop {
			continue
		}
		if adversarialOnly && !strings.HasPrefix(result.ID, "adversarial:") {
			continue
		}
		ids = append(ids, result.ID)
	}
	sort.Strings(ids)
	return ids
}

func sanitizeID(id string) string {
	var builder strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}
