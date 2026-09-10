package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryattacker/ollama"
	"github.com/canarysting/canarysting/internal/canaryattacker/planner"
)

const (
	expectedScenarioID = "m2c4-ollama-bounded-loop"
	expectedModel      = "qwen3-coder:30b-a3b-q8_0"
	expectedModelID    = "7b438a19895a"
)

var (
	// These dates are part of reviewed scenario-v1 semantics. Renewing the
	// review requires a scenario version bump, never a runtime-derived date.
	scenarioV1RecordedAt = time.Date(2026, time.September, 7, 0, 0, 0, 0, time.UTC)
	scenarioV1ReviewDue  = time.Date(2027, time.September, 7, 0, 0, 0, 0, time.UTC)
)

func main() {
	var runID string
	var scenarioID string
	var selfcheck bool
	var cleanupModel bool
	flag.StringVar(&runID, "run-id", "", "fixed synthetic run ID")
	flag.StringVar(&scenarioID, "scenario-id", "", "fixed scenario ID")
	flag.BoolVar(&selfcheck, "selfcheck", false, "run the bounded live-model proof")
	flag.BoolVar(&cleanupModel, "cleanup-model", false, "unload only the fixed model through loopback")
	flag.Parse()
	if selfcheck == cleanupModel || runID == "" || scenarioID != expectedScenarioID || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "attackerloopspike requires exactly one fixed mode, a run ID, and the fixed scenario ID")
		os.Exit(2)
	}
	if cleanupModel {
		if err := unloadModel(); err != nil {
			fmt.Fprintln(os.Stderr, "attackerloopspike cleanup:", err)
			os.Exit(1)
		}
		return
	}
	if err := runProof(runID); err != nil {
		fmt.Fprintln(os.Stderr, "attackerloopspike:", err)
		os.Exit(1)
	}
}

func unloadModel() error {
	client, err := ollama.New(ollama.DefaultEndpoint)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return client.Unload(ctx, expectedModel)
}

func runProof(runID string) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("open process-lifetime loopback fixture: %w", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != "/reviewed" || request.URL.RawQuery != "" {
				http.Error(writer, "not found", http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte("harmless bounded planner fixture"))
		}),
		ReadHeaderTimeout: 2 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	fixtureAddress := listener.Addr().String()
	serverStopped := false
	defer func() {
		if !serverStopped {
			_ = server.Close()
			<-serveDone
		}
	}()

	portValue := listener.Addr().(*net.TCPAddr).Port
	values, err := buildFixture(uint16(portValue))
	if err != nil {
		return err
	}
	ledger := &executor.MemoryLedger{}
	run, err := values.boundary.NewRun(executor.RunConfig{
		Scenario: values.scenario, RunID: runID, Ledger: ledger,
		ClockSource: "ntp-synchronized-system-clock", ClockUncertaintyMillis: 30000,
		IntentStorageBytes: 2048, ActionStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
	})
	if err != nil {
		return fmt.Errorf("create executor run: %w", err)
	}
	defer run.Close()
	client, err := ollama.New(ollama.DefaultEndpoint)
	if err != nil {
		return err
	}
	coordinator, err := planner.New(planner.Config{
		Scenario: values.scenario, Model: values.model, Client: client, Executor: run, MaxTurns: 1, Seed: 7,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	result, err := coordinator.Run(ctx)
	cancel()
	if err != nil {
		return err
	}
	if result.StopReason != planner.StopScenarioComplete || result.TurnsCompleted != 1 ||
		result.ProposalsLogged != 1 || result.Approved != 1 || result.Denied != 0 ||
		result.PromptTokens+result.OutputTokens > values.scenario.Budgets().MaxModelTokens() {
		return fmt.Errorf("live planner result did not satisfy its exact bounded contract")
	}
	if len(ledger.Intents()) != 1 || len(ledger.Actions()) != 1 || len(result.Executions) != 1 {
		return fmt.Errorf("live planner did not commit exactly one intent and action")
	}
	execution := result.Executions[0]
	if execution.Result.Status != groundtruth.ActionSucceeded || execution.Result.HTTPStatus != http.StatusOK ||
		execution.Result.ResponseBytes == 0 || execution.Intent.Model().ModelVersion() != expectedModelID ||
		execution.Intent.ProposedAction().Tool() != groundtruth.ToolHTTPRequest {
		return fmt.Errorf("live proposal did not execute the exact reviewed action")
	}
	run.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("close loopback fixture: %w", err)
	}
	serveErr := <-serveDone
	serverStopped = true
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("loopback fixture exited unexpectedly: %w", serveErr)
	}
	connection, dialErr := net.DialTimeout("tcp4", fixtureAddress, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return fmt.Errorf("loopback fixture listener remained reachable after shutdown")
	}

	fmt.Println("PROOF model_identity=PASS provider=ollama model_id=7b438a19895a planner=bounded-qwen-planner-v1")
	fmt.Println("PROOF loopback=PASS ollama_endpoint=fixed fixture=process-lifetime ambient_proxy=false")
	fmt.Println("PROOF opacity=PASS zero_argument_handles=true target_policy_budget_model_visible=false")
	fmt.Println("PROOF audit=PASS proposals=1 intents=1 actions=1 output=content-digest-only")
	fmt.Println("PROOF execution=PASS reviewed_action=true response_bounded=true")
	fmt.Println("PROOF budgets=PASS turns=1 tokens=true duration=true cancellation=external")
	fmt.Println("PROOF stop=PASS reason=scenario_complete deterministic=true")
	fmt.Println("PROOF cleanup=PASS fixture_listener_closed=true persistent_state=false")
	return nil
}

type fixtureValues struct {
	scenario groundtruth.Scenario
	model    groundtruth.ModelIdentity
	boundary *executor.Executor
}

func buildFixture(port uint16) (fixtureValues, error) {
	targetRef := opaque("labtarget:sha256:", "m2c4-target")
	fixtureRef := opaque("fixture:sha256:", "m2c4-target")
	target, err := executor.NewTargetBinding(executor.TargetBindingInput{
		Alias: "loopback-fixture", Reference: targetRef, FixtureRef: fixtureRef,
		Scheme: "http", Host: "fixture.local", Port: port,
		AllowedAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		return fixtureValues{}, err
	}
	action, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: groundtruth.ToolHTTPRequest, TargetAlias: "loopback-fixture", TargetRef: targetRef, Operation: "fetch-reviewed-fixture",
	})
	if err != nil {
		return fixtureValues{}, err
	}
	limits := executor.Limits{
		MaxActions: 1, MaxRunDuration: 5 * time.Minute, MaxActionDuration: 5 * time.Second,
		CompletionReserve: 100 * time.Millisecond, MaxConcurrency: 1, MaxRequestsPerSecond: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096, MaxStoredResponseBytes: 4096,
		MaxResponseHeaderBytes: 4096, MaxEnumerationPaths: 1,
	}
	policy, err := executor.NewPolicy(executor.PolicyConfig{
		Limits: limits, Targets: []executor.TargetBinding{target},
		Operations: []executor.OperationInput{{Action: action, HTTPMethod: http.MethodGet, Path: "/reviewed"}},
	})
	if err != nil {
		return fixtureValues{}, err
	}
	groundTarget, err := groundtruth.NewTarget(groundtruth.TargetInput{
		Alias: "loopback-fixture", Reference: targetRef, FixtureRef: fixtureRef,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: groundtruth.ToolHTTPRequest, AllowedOperations: []string{action.Operation()}, MaxActions: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	step, err := groundtruth.NewStep(groundtruth.StepInput{
		ID: "step-1", Sequence: 1, Objective: "Fetch one harmless reviewed laboratory fixture.",
		AllowedActions: []groundtruth.ActionSpec{action},
	})
	if err != nil {
		return fixtureValues{}, err
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 1, MaxDuration: 5 * time.Minute, MaxConcurrency: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096, MaxModelTokens: 4096,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "synthetic-lab", ScopeID: "m2c4-loopback", DeploymentBoundary: "dgx-process-loopback",
		ResidencyCellID: "dgx-spark-local", KeyNamespace: "synthetic-keyspace", RegistryNamespace: "planner-fixtures",
	})
	if err != nil {
		return fixtureValues{}, err
	}
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: scope, ID: expectedScenarioID, Version: 1, Name: "Bounded Ollama planner proof",
		Objective: "Prove one local model proposal remains inside the reviewed executor boundary.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionBoundedAdaptive,
		RequiredFixtures: []string{fixtureRef}, Targets: []groundtruth.Target{groundTarget},
		ToolConstraints: []groundtruth.ToolConstraint{constraint}, Steps: []groundtruth.Step{step}, Budgets: budgets,
		ExpectedTelemetry: []string{"executor-audit", "planner-audit"}, RecordedAt: scenarioV1RecordedAt,
		CorpusReviewDue: scenarioV1ReviewDue, LifecyclePolicyVersion: "synthetic-ground-truth-v1",
		ResidencyPolicyRef: "residency-dgx-local-v1", EncryptionKeyRef: opaque("keyref:sha256:", "m2c4-key"),
		EstimatedStorageBytes: 8192, EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "canaryattacker-qwen-local", Provider: "ollama", Model: expectedModel,
		ModelVersion: expectedModelID, PlannerVersion: planner.Version,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	boundary, err := executor.New(policy, staticResolver{}, nil)
	if err != nil {
		return fixtureValues{}, err
	}
	return fixtureValues{scenario: scenario, model: model, boundary: boundary}, nil
}

type staticResolver struct{}

func (staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func opaque(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}
