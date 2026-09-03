package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/collector/dgxstack"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

func TestRunEmitsExactlyOneSyntheticObservationPerSource(t *testing.T) {
	manifest := writeManifest(t, nil)
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"-capture-manifest", manifest,
		"-run-id", "m2b2-local-proof",
		"-scenario-id", "m2b2-dgx-stack",
		"-pseudonym-key-sha256", digestText("proof-key"),
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "PROOF sources=7 records=7") ||
		!strings.Contains(stderr.String(), "synthetic=true raw_payload_retained=false") {
		t.Fatalf("proof summary = %q", stderr.String())
	}

	seen := map[string]bool{}
	scanner := bufio.NewScanner(&stdout)
	count := 0
	for scanner.Scan() {
		count++
		line := append([]byte(nil), scanner.Bytes()...)
		observation, err := model.UnmarshalObservationV3(line)
		if err != nil {
			t.Fatalf("decode line %d: %v", count, err)
		}
		seen[observation.Source().System()] = true
		if !observation.Envelope().Synthetic().Synthetic() || observation.Envelope().Synthetic().ScenarioID() != "m2b2-dgx-stack" {
			t.Fatalf("line %d lost synthetic classification", count)
		}
		if observation.Envelope().Lifecycle().RetentionProfile() != model.RetentionOverride ||
			observation.Envelope().Lifecycle().ExpiresAt().Sub(observation.Envelope().Lifecycle().RetentionStart()) != 24*time.Hour {
			t.Fatalf("line %d does not carry the 24h validation lifecycle", count)
		}
		raw, ok := observation.RawEvent()
		if !ok || raw.Availability() != model.RawDeleted || raw.HashValue() == "" {
			t.Fatalf("line %d lost raw reference/checksum tombstone", count)
		}
		for _, prohibited := range []string{"raw-capture-payload", "Bearer", "customer.example"} {
			if strings.Contains(string(line), prohibited) {
				t.Fatalf("line %d retained prohibited value %q", count, prohibited)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != len(dgxstack.SourceKinds()) {
		t.Fatalf("observation count = %d", count)
	}
	for _, kind := range dgxstack.SourceKinds() {
		if !seen[string(kind)] {
			t.Errorf("missing source %s", kind)
		}
	}
}

func TestRunRejectsIncompleteOrDuplicateCaptureSet(t *testing.T) {
	tests := map[string]func([]string) []string{
		"missing":   func(lines []string) []string { return lines[:len(lines)-1] },
		"duplicate": func(lines []string) []string { return append(lines, lines[1]) },
		"unknown": func(lines []string) []string {
			fields := strings.Split(lines[1], "\t")
			fields[0] = "unknown"
			lines[1] = strings.Join(fields, "\t")
			return lines
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := writeManifest(t, mutate)
			var stdout, stderr bytes.Buffer
			err := run([]string{
				"-capture-manifest", manifest,
				"-run-id", "m2b2-invalid",
				"-scenario-id", "m2b2-dgx-stack",
				"-pseudonym-key-sha256", digestText("proof-key"),
			}, &stdout, &stderr)
			if err == nil {
				t.Fatal("invalid capture set was accepted")
			}
		})
	}
}

func TestRunRejectsArbitraryArgumentsAndMalformedKey(t *testing.T) {
	manifest := writeManifest(t, nil)
	for name, args := range map[string][]string{
		"positional": {
			"-capture-manifest", manifest, "-run-id", "safe", "-scenario-id", "scenario",
			"-pseudonym-key-sha256", digestText("proof-key"), "arbitrary-command",
		},
		"bad key": {
			"-capture-manifest", manifest, "-run-id", "safe", "-scenario-id", "scenario",
			"-pseudonym-key-sha256", "ABC",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe arguments were accepted")
			}
		})
	}
}

func writeManifest(t *testing.T, mutate func([]string) []string) string {
	t.Helper()
	now := time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	lines := []string{"kind\tinstance\tevent_key\tsource_timestamp\tobserved_at\tingested_at\traw_reference_sha256\tcontent_sha256"}
	for _, kind := range dgxstack.SourceKinds() {
		lines = append(lines, strings.Join([]string{
			string(kind), "dgx-lab", digestText("event-" + string(kind)), now, now, now,
			digestText("reference-" + string(kind)), digestText("raw-capture-payload-" + string(kind)),
		}, "\t"))
	}
	if mutate != nil {
		lines = mutate(lines)
	}
	path := filepath.Join(t.TempDir(), "capture.tsv")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
