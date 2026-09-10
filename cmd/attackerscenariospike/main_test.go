package main

import (
	"bytes"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryattacker/scenarios"
)

func TestInitialJourneyIsStableAcrossRuntimeAddresses(t *testing.T) {
	first, err := scenarios.NewInitialJourney(netip.MustParseAddr("10.43.1.10"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := scenarios.NewInitialJourney(netip.MustParseAddr("10.43.99.220"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Scenario.Envelope().RecordID() != "scenario:m2c5-initial-journey:v1" {
		t.Fatalf("scenario ID = %q", first.Scenario.Envelope().RecordID())
	}
	if first.Scenario.SemanticSHA256() != second.Scenario.SemanticSHA256() {
		t.Fatal("runtime Service address changed stable scenario semantics")
	}
	firstSteps, secondSteps := first.Scenario.Steps(), second.Scenario.Steps()
	if len(firstSteps) != 5 || len(secondSteps) != 5 {
		t.Fatal("initial scenario must contain exactly five steps")
	}
	for index := range firstSteps {
		if firstSteps[index].ID() != secondSteps[index].ID() || firstSteps[index].Objective() != secondSteps[index].Objective() {
			t.Fatalf("step %d changed across runtime bindings", index+1)
		}
	}
}

func TestRunJourneyRejectsNonPrivateTargetBeforeExecution(t *testing.T) {
	var firstCorpus, firstProof bytes.Buffer
	if err := runJourney([]string{"-run-id", "m2c5-first", "-target-address", "127.0.0.1"}, &firstCorpus, &firstProof); err == nil {
		t.Fatal("loopback address must be rejected for the real Kubernetes scenario")
	}
	if firstCorpus.Len() != 0 || firstProof.Len() != 0 {
		t.Fatal("rejected address emitted partial evidence")
	}
}

func TestFixtureRequiresDiscoveryBeforeTouchAndDoesNotLogReadiness(t *testing.T) {
	var events bytes.Buffer
	handler := newFixtureHandler(&events)
	for _, path := range []string{"/ready", "/canary"} {
		request, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(scenarios.InitialTargetHost, strconv.Itoa(scenarios.InitialTargetPort))+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response := &responseRecorder{header: make(http.Header)}
		handler.ServeHTTP(response, request)
	}
	if events.Len() != 0 {
		t.Fatalf("readiness or denied touch entered event log: %q", events.String())
	}
}

func TestRunnerRejectsEscapeAndSensitiveOutput(t *testing.T) {
	for _, arguments := range [][]string{
		{"-run-id", "../escape", "-target-address", "10.43.0.2"},
		{"-run-id", "valid-run", "-target-address", "8.8.8.8"},
		{"-run-id", "valid-run", "-target-address", "127.0.0.1"},
		{"-run-id", "valid-run", "-target-address", "10.43.0.2", "--command", "id"},
	} {
		var stdout, stderr bytes.Buffer
		if err := runJourney(arguments, &stdout, &stderr); err == nil {
			t.Fatalf("unsafe arguments unexpectedly succeeded: %v", arguments)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("rejected runner arguments emitted partial evidence")
		}
	}
	for _, sensitive := range []string{"fixture-secret", "Authorization", "Basic Zml4dHVyZS11c2Vy"} {
		if strings.Contains(firstGoldenCorpus(t), sensitive) {
			t.Fatalf("synthetic corpus contains sensitive value %q", sensitive)
		}
	}
}

func firstGoldenCorpus(t *testing.T) string {
	t.Helper()
	journey, err := scenarios.NewInitialJourney(netip.MustParseAddr("10.43.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := groundtruth.MarshalScenarioV1(journey.Scenario)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header    { return r.header }
func (r *responseRecorder) WriteHeader(status int) { r.status = status }
func (r *responseRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(body)
}
