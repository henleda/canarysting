package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
)

func TestExecuteProofUsesKnownMinimizedFlows(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	downstream, err := correlation.NewNetworkTuple(
		correlation.ProtocolTCP, pseudonym(key, "address", "downstream-source"), 41001,
		pseudonym(key, "address", "downstream-destination"), 8443,
	)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := correlation.NewNetworkTuple(
		correlation.ProtocolTCP, pseudonym(key, "address", "upstream-source"), 42001,
		pseudonym(key, "address", "upstream-destination"), 9443,
	)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = executeProof(&output, proofConfig{
		runID: "m2b3-test", scenarioID: "m2b3-known-flow", key: key,
	}, knownFlows{
		downstream: downstream, upstream: upstream,
		cookieDigest: pseudonym(key, "socket-cookie", "12345"),
	}, time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	wantLines := []string{
		"PROOF live_loopback=PASS flows=2 raw_addresses_emitted=false",
		"PROOF socket_cookie=EXACT sole_sting_l7_kernel_join=true",
		"PROOF translated_tuple=STRONG hops=1 tuples_retained=true control_retained=true",
		"PROOF tuple_time=WEAK window_version=1",
		"PROOF otel_trace=STRONG trace_boundary=false",
		"PROOF missing_time=PASS rejected_contextual_join=true",
		"PROOF ambiguity=PASS candidates=2 chosen=false",
		"PROOF bounds=PASS candidate_limit=256 translation_hops=4 translation_paths=16",
	}
	for _, line := range wantLines {
		if !strings.Contains(output.String(), line+"\n") {
			t.Errorf("proof output missing %q\n%s", line, output.String())
		}
	}
	for _, prohibited := range []string{"127.0.0.1", "downstream-source", "upstream-destination", "12345"} {
		if strings.Contains(output.String(), prohibited) {
			t.Errorf("proof output disclosed %q", prohibited)
		}
	}
}

func TestRunFailsClosedBeforePlatformSpecificProof(t *testing.T) {
	t.Parallel()
	validKey := strings.Repeat("a", 64)
	tests := [][]string{
		{"-run-id", "valid", "-scenario-id", "valid", "-pseudonym-key-sha256", validKey},
		{"-selfcheck", "-run-id", "../bad", "-scenario-id", "valid", "-pseudonym-key-sha256", validKey},
		{"-selfcheck", "-run-id", "valid", "-scenario-id", "valid", "-pseudonym-key-sha256", "raw"},
	}
	for _, arguments := range tests {
		if err := run(arguments, &bytes.Buffer{}); err == nil {
			t.Errorf("unsafe arguments were accepted: %v", arguments)
		}
	}
}
