package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunEmitsOnlyFixedProof(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{
		"-run-id", "m2b4-local-proof", "-scenario-id", "m2b4-fixed-scenario", "-selfcheck",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("proof lines=%d want=9: %s", len(lines), output.String())
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "PROOF ") || !strings.Contains(line, "=PASS") {
			t.Fatalf("unexpected proof line %q", line)
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
		{"-run-id", "m2b4", "-scenario-id", "scenario"},
		{"-run-id", "../escape", "-scenario-id", "scenario", "-selfcheck"},
		{"-run-id", "m2b4", "-scenario-id", "../escape", "-selfcheck"},
		{"-run-id", "m2b4", "-scenario-id", "scenario", "-selfcheck", "extra"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe args were accepted: %v", args)
		}
	}
}
