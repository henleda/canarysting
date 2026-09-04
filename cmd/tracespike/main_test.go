package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunEmitsOnlyFixedProof(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{
		"-run-id", "m2b5-local-proof", "-scenario-id", operatorScenarioID, "-selfcheck",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("proof lines=%d want=9: %s", len(lines), output.String())
	}
	want := []string{
		"PROOF passive_partial=PASS canary_touch_required=false",
		"PROOF deterministic_id=PASS input_order_independent=true",
		"PROOF ambiguity=PASS candidates=2 chosen=false",
		"PROOF join_citations=PASS all_links_evidence_backed=true",
		"PROOF broken_raw=PASS availability=INTEGRITY_MISMATCH",
		"PROOF lifecycle=PASS held_visible=true expired_hidden=true",
		"PROOF invalidation=PASS exact_scope=true",
		"PROOF bounds=PASS truncation=false",
		"PROOF operator_projection=PASS scenario_id=m2b5-operator-conflict explanation_present=true raw_reference_metadata_present=true raw_availability=INTEGRITY_MISMATCH status=CONFLICTED missing=2 conflicts=2",
	}
	for index, line := range lines {
		if !strings.HasPrefix(line, "PROOF ") || !strings.Contains(line, "=PASS") {
			t.Fatalf("unexpected proof line %q", line)
		}
		if line != want[index] {
			t.Fatalf("proof line %d = %q, want %q", index+1, line, want[index])
		}
	}
	for _, prohibited := range []string{"rawref:", "tenant=", "scope_id=", "trace:sha256:", "request="} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("proof emitted prohibited identifier marker %q", prohibited)
		}
	}
}

func TestRunRejectsOpenInputs(t *testing.T) {
	for _, args := range [][]string{
		{"-run-id", "m2b4", "-scenario-id", operatorScenarioID},
		{"-run-id", "../escape", "-scenario-id", operatorScenarioID, "-selfcheck"},
		{"-run-id", "m2b4", "-scenario-id", "../escape", "-selfcheck"},
		{"-run-id", "m2b4", "-scenario-id", "scenario", "-selfcheck", "extra"},
		{"-run-id", "m2b4", "-scenario-id", "m2b4-trace-construction", "-selfcheck"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe args were accepted: %v", args)
		}
	}
}
