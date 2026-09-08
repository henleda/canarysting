package planner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

func TestCoordinatorMapsOpaqueToolToReviewedAction(t *testing.T) {
	values := testValues(t, 2, 4, 1000)
	client := &fakeClient{responses: []TurnResponse{
		validResponse(values.model.Model(), 100, 20, Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)}),
		validResponse(values.model.Model(), 100, 20, Proposal{Name: "action_002", Arguments: json.RawMessage(`{}`)}),
	}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 2)
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.StopReason != StopScenarioComplete || result.ProposalsLogged != 2 || result.Approved != 2 || result.Denied != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	invocations := execution.snapshot()
	if len(invocations) != 2 || invocations[0].ProposedAction.Operation() != "operation-1" || invocations[1].ProposedAction.Operation() != "operation-2" {
		t.Fatalf("reviewed action mapping changed: %+v", invocations)
	}
	requests := client.snapshot()
	if len(requests) != 2 || len(requests[0].Tools) != 1 || requests[0].Tools[0].Name != "action_001" ||
		len(requests[1].Tools) != 1 || requests[1].Tools[0].Name != "action_002" {
		t.Fatalf("unexpected tool exposure: %+v", requests)
	}
	for _, request := range requests {
		encoded, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		for _, forbidden := range []string{"labtarget:sha256:", "fixture:sha256:", "operation-1", "127.0.0.1"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("model request exposed executor-owned value %q: %s", forbidden, encoded)
			}
		}
	}
}

func TestEveryAcceptedProposalProducesAnAuditedExecutorInvocation(t *testing.T) {
	values := testValues(t, 1, 4, 1000)
	client := &fakeClient{responses: []TurnResponse{
		validResponse(values.model.Model(), 100, 20, Proposal{Name: "invented_tool", Arguments: json.RawMessage(`{}`)}),
		validResponse(values.model.Model(), 100, 20, Proposal{Name: "action_001", Arguments: json.RawMessage(`{"target":"elsewhere"}`)}),
	}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 2)
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.StopReason != StopMaxTurns || result.ProposalsLogged != 2 || result.Denied != 2 {
		t.Fatalf("unexpected denial result: %+v", result)
	}
	for _, invocation := range execution.snapshot() {
		if invocation.ProposedAction.Tool() != "planner_rejected" || invocation.ProposedAction.Operation() != "proposal_rejected" {
			t.Fatalf("untrusted proposal reached executor fields: %+v", invocation.ProposedAction)
		}
		if invocation.PlannerOutputRef != "planner:sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("proposal did not carry content-bound output lineage: %q", invocation.PlannerOutputRef)
		}
	}
}

func TestSurplusToolCallsAreAuditedWithoutAdditionalExecution(t *testing.T) {
	values := testValues(t, 2, 4, 1000)
	client := &fakeClient{responses: []TurnResponse{
		validResponse(values.model.Model(), 100, 20,
			Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)},
			Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)},
		),
	}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 1)
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.StopReason != StopMaxTurns || result.ProposalsLogged != 2 || result.Approved != 1 || result.Denied != 1 {
		t.Fatalf("unexpected surplus-call result: %+v", result)
	}
	invocations := execution.snapshot()
	if len(invocations) != 2 || invocations[0].StepID != "step-1" || invocations[1].StepID != "step-1" ||
		invocations[0].ProposedAction.Operation() != "operation-1" ||
		invocations[1].ProposedAction.Tool() != "planner_rejected" || invocations[1].ProposedAction.Operation() != "proposal_rejected" {
		t.Fatalf("surplus call escaped same-step audited denial: %+v", invocations)
	}
	requests := client.snapshot()
	if len(requests) != 1 || requests[0].MaxProposals != 4 {
		t.Fatalf("proposal audit allowance = %+v", requests)
	}
}

func TestObservationBudgetStopsBeforeAnUnserviceableModelTurn(t *testing.T) {
	values := testValues(t, 1, AbsoluteMaxObservations+1, 1000)
	proposals := make([]Proposal, AbsoluteMaxObservations)
	for index := range proposals {
		proposals[index] = Proposal{Name: "invented_tool", Arguments: json.RawMessage(`{}`)}
	}
	client := &fakeClient{responses: []TurnResponse{
		validResponse(values.model.Model(), 100, 20, proposals...),
	}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 2)
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.StopReason != StopObservationBudget || result.ProposalsLogged != AbsoluteMaxObservations ||
		result.Denied != AbsoluteMaxObservations || len(execution.snapshot()) != AbsoluteMaxObservations || len(client.snapshot()) != 1 {
		t.Fatalf("unexpected observation-budget result: %+v", result)
	}
}

func TestExternalTokenBudgetStopsBeforeProposalExecution(t *testing.T) {
	values := testValues(t, 1, 2, 100)
	client := &fakeClient{responses: []TurnResponse{validResponse(values.model.Model(), 90, 20,
		Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)},
	)}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 1)
	result, err := coordinator.Run(context.Background())
	if !errors.Is(err, ErrInvalidModelResponse) || result.StopReason != StopModelError || len(execution.snapshot()) != 0 {
		t.Fatalf("budget result = %+v, err=%v, invocations=%d", result, err, len(execution.snapshot()))
	}
}

func TestPromptUsageCannotExceedPerTurnContextAllowance(t *testing.T) {
	values := testValues(t, 1, 2, 1000)
	client := &fakeClient{responses: []TurnResponse{validResponse(values.model.Model(), 501, 1,
		Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)},
	)}}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 1)
	result, err := coordinator.Run(context.Background())
	if !errors.Is(err, ErrInvalidModelResponse) || result.StopReason != StopModelError || len(execution.snapshot()) != 0 {
		t.Fatalf("context-limit result = %+v, err=%v, invocations=%d", result, err, len(execution.snapshot()))
	}
	requests := client.snapshot()
	if len(requests) != 1 || requests[0].ContextTokens != 500 {
		t.Fatalf("unexpected context allowance: %+v", requests)
	}
}

func TestEveryTurnAllowanceFitsRemainingCumulativeTokenBudget(t *testing.T) {
	values := testValues(t, 2, 4, 1000)
	client := &fakeClient{responses: []TurnResponse{
		validResponse(values.model.Model(), 400, 100, Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)}),
		validResponse(values.model.Model(), 100, 20, Proposal{Name: "action_002", Arguments: json.RawMessage(`{}`)}),
	}}
	coordinator := newCoordinator(t, values, client, &fakeExecutor{}, 2)
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.StopReason != StopScenarioComplete {
		t.Fatalf("unexpected result: %+v", result)
	}
	requests := client.snapshot()
	responses := client.responseSnapshot()
	if len(requests) != 2 || len(responses) != 2 {
		t.Fatalf("model request/response counts = %d/%d, want 2/2", len(requests), len(responses))
	}
	remaining := uint64(1000)
	for index, request := range requests {
		if request.ContextTokens+request.MaxOutputTokens > remaining {
			t.Fatalf("turn %d allowances %d+%d exceed remaining budget %d", index+1, request.ContextTokens, request.MaxOutputTokens, remaining)
		}
		remaining -= responses[index].PromptTokens + responses[index].OutputTokens
	}
}

func TestEmptyArgumentsAcceptsAnyEmptyJSONObjectEncoding(t *testing.T) {
	for _, raw := range []string{`{}`, `{ }`, "{\n\t}"} {
		if !emptyArguments(json.RawMessage(raw)) {
			t.Fatalf("semantically empty object %q was rejected", raw)
		}
	}
	for _, raw := range []string{`null`, `[]`, `{"value":1}`, `{`, `{ "value": 1, "value": 2 }`} {
		if emptyArguments(json.RawMessage(raw)) {
			t.Fatalf("non-empty or invalid argument value %q was accepted", raw)
		}
	}
}

func TestCancellationStopsModelLoopWithoutAnotherCall(t *testing.T) {
	values := testValues(t, 1, 2, 1000)
	client := &cancelClient{started: make(chan struct{})}
	execution := &fakeExecutor{}
	coordinator := newCoordinator(t, values, client, execution, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var result Result
	var runErr error
	go func() {
		result, runErr = coordinator.Run(ctx)
		close(done)
	}()
	<-client.started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled planner did not stop")
	}
	if runErr != nil || result.StopReason != StopCancelled || len(execution.snapshot()) != 0 || client.calls != 1 {
		t.Fatalf("cancel result = %+v, err=%v, calls=%d", result, runErr, client.calls)
	}
}

func TestMalformedModelResponseFailsClosed(t *testing.T) {
	values := testValues(t, 1, 2, 1000)
	for name, mutate := range map[string]func(*TurnResponse){
		"wrong model": func(response *TurnResponse) { response.Model = "different-model" },
		"not done":    func(response *TurnResponse) { response.Done = false },
		"bad digest":  func(response *TurnResponse) { response.OutputSHA256 = "bad" },
		"bad JSON": func(response *TurnResponse) {
			response.Proposals[0].Arguments = json.RawMessage(`{`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := validResponse(values.model.Model(), 10, 10, Proposal{Name: "action_001", Arguments: json.RawMessage(`{}`)})
			mutate(&response)
			execution := &fakeExecutor{}
			coordinator := newCoordinator(t, values, &fakeClient{responses: []TurnResponse{response}}, execution, 1)
			result, err := coordinator.Run(context.Background())
			if !errors.Is(err, ErrInvalidModelResponse) || result.StopReason != StopModelError || len(execution.snapshot()) != 0 {
				t.Fatalf("result = %+v, err=%v", result, err)
			}
		})
	}
}

func TestConstructorRequiresPinnedPlannerVersion(t *testing.T) {
	values := testValues(t, 1, 2, 1000)
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "bounded-qwen", Provider: "ollama", Model: "qwen3-coder:30b-a3b-q8_0",
		ModelVersion: "7b438a19895a", PlannerVersion: "unreviewed-planner",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{Scenario: values.scenario, Model: model, Client: &fakeClient{}, Executor: &fakeExecutor{}, MaxTurns: 1})
	if err == nil {
		t.Fatal("unreviewed planner version was accepted")
	}
}

func TestActionHandlesCoverWholeScenarioAggregateBound(t *testing.T) {
	for ordinal := 1; ordinal <= AbsoluteMaxCatalogActions; ordinal++ {
		handle, err := actionHandle(ordinal)
		if err != nil {
			t.Fatalf("valid action ordinal %d was rejected: %v", ordinal, err)
		}
		if ordinal == 1 && handle != "action_001" {
			t.Fatalf("first action handle = %q", handle)
		}
		if ordinal == AbsoluteMaxCatalogActions && handle != "action_1024" {
			t.Fatalf("last action handle = %q", handle)
		}
	}
	for _, ordinal := range []int{0, AbsoluteMaxCatalogActions + 1} {
		if _, err := actionHandle(ordinal); err == nil {
			t.Fatalf("out-of-range action ordinal %d was accepted", ordinal)
		}
	}
}

func TestConstructorRejectsStepBeyondTransportToolCapacity(t *testing.T) {
	values := testValuesWithSingleStepActions(t, AbsoluteMaxToolsPerTurn+1)
	_, err := New(Config{
		Scenario: values.scenario, Model: values.model, Client: &fakeClient{}, Executor: &fakeExecutor{}, MaxTurns: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "per-turn tool limit") {
		t.Fatalf("oversized active step error = %v", err)
	}
}

type testFixture struct {
	scenario groundtruth.Scenario
	model    groundtruth.ModelIdentity
}

func testValues(t *testing.T, stepCount int, maxActions uint32, maxTokens uint64) testFixture {
	t.Helper()
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "synthetic-lab", ScopeID: "planner-fixture", DeploymentBoundary: "loopback-process",
		ResidencyCellID: "dgx-local", KeyNamespace: "synthetic-keyspace", RegistryNamespace: "planner-fixtures",
	})
	if err != nil {
		t.Fatal(err)
	}
	targetRef := opaque("labtarget:sha256:", "planner-target")
	fixtureRef := opaque("fixture:sha256:", "planner-target")
	target, err := groundtruth.NewTarget(groundtruth.TargetInput{Alias: "lab-target", Reference: targetRef, FixtureRef: fixtureRef})
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]groundtruth.ActionSpec, stepCount)
	steps := make([]groundtruth.Step, stepCount)
	operations := make([]string, stepCount)
	for index := range actions {
		operations[index] = "operation-" + string(rune('1'+index))
		actions[index], err = groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
			Tool: groundtruth.ToolHTTPRequest, TargetAlias: "lab-target", TargetRef: targetRef, Operation: operations[index],
		})
		if err != nil {
			t.Fatal(err)
		}
		steps[index], err = groundtruth.NewStep(groundtruth.StepInput{
			ID: "step-" + string(rune('1'+index)), Sequence: uint32(index + 1),
			Objective: "Exercise one reviewed harmless laboratory action.", AllowedActions: []groundtruth.ActionSpec{actions[index]},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: groundtruth.ToolHTTPRequest, AllowedOperations: operations, MaxActions: maxActions,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: maxActions, MaxDuration: time.Minute, MaxConcurrency: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxModelTokens: maxTokens,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: scope, ID: "m2c4-bounded-loop", Version: 1, Name: "Bounded planner loop",
		Objective: "Exercise reviewed synthetic actions through an untrusted local model.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionBoundedAdaptive,
		RequiredFixtures: []string{fixtureRef}, Targets: []groundtruth.Target{target},
		ToolConstraints: []groundtruth.ToolConstraint{constraint}, Steps: steps, Budgets: budgets,
		ExpectedTelemetry: []string{"planner-audit"}, RecordedAt: now.Add(-time.Hour), CorpusReviewDue: now.AddDate(1, 0, 0),
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef: opaque("keyref:sha256:", "planner-key"), EstimatedStorageBytes: 8192,
		EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		t.Fatal(err)
	}
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "bounded-qwen", Provider: "ollama", Model: "qwen3-coder:30b-a3b-q8_0",
		ModelVersion: "7b438a19895a", PlannerVersion: Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testFixture{scenario: scenario, model: model}
}

func testValuesWithSingleStepActions(t *testing.T, actionCount int) testFixture {
	t.Helper()
	base := testValues(t, 1, uint32(actionCount), 1000)
	target := base.scenario.Targets()[0]
	actions := make([]groundtruth.ActionSpec, actionCount)
	operations := make([]string, actionCount)
	var err error
	for index := range actions {
		operations[index] = fmt.Sprintf("operation-%d", index+1)
		actions[index], err = groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
			Tool: groundtruth.ToolHTTPRequest, TargetAlias: target.Alias(), TargetRef: target.Reference(), Operation: operations[index],
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: groundtruth.ToolHTTPRequest, AllowedOperations: operations, MaxActions: uint32(actionCount),
		MaxRequestBytes: 1024, MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	step, err := groundtruth.NewStep(groundtruth.StepInput{
		ID: "step-1", Sequence: 1, Objective: "Exercise reviewed harmless laboratory actions.", AllowedActions: actions,
	})
	if err != nil {
		t.Fatal(err)
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: uint32(actionCount), MaxDuration: time.Minute, MaxConcurrency: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxModelTokens: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: base.scenario.Envelope().Scope(), ID: "m2c4-tool-cardinality", Version: 1, Name: "Planner tool cardinality",
		Objective: "Prove the active tool surface remains transport-serviceable.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionBoundedAdaptive,
		RequiredFixtures: base.scenario.RequiredFixtures(), Targets: []groundtruth.Target{target},
		ToolConstraints: []groundtruth.ToolConstraint{constraint}, Steps: []groundtruth.Step{step}, Budgets: budgets,
		ExpectedTelemetry: []string{"planner-audit"}, RecordedAt: now.Add(-time.Hour), CorpusReviewDue: now.AddDate(1, 0, 0),
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef: opaque("keyref:sha256:", "planner-cardinality-key"), EstimatedStorageBytes: 8192,
		EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testFixture{scenario: scenario, model: base.model}
}

func newCoordinator(t *testing.T, values testFixture, client Client, execution ActionExecutor, turns uint32) *Coordinator {
	t.Helper()
	coordinator, err := New(Config{
		Scenario: values.scenario, Model: values.model, Client: client, Executor: execution, MaxTurns: turns, Seed: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

type fakeClient struct {
	mu        sync.Mutex
	responses []TurnResponse
	requests  []TurnRequest
	returned  []TurnResponse
}

func (c *fakeClient) Complete(_ context.Context, request TurnRequest) (TurnResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
	if len(c.responses) == 0 {
		return TurnResponse{}, errors.New("unexpected model call")
	}
	response := c.responses[0]
	c.responses = c.responses[1:]
	c.returned = append(c.returned, response)
	return response, nil
}

func (c *fakeClient) snapshot() []TurnRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TurnRequest(nil), c.requests...)
}

func (c *fakeClient) responseSnapshot() []TurnResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TurnResponse(nil), c.returned...)
}

type fakeExecutor struct {
	mu          sync.Mutex
	invocations []executor.Invocation
}

func (e *fakeExecutor) Execute(_ context.Context, invocation executor.Invocation) (executor.Execution, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invocations = append(e.invocations, invocation)
	status := groundtruth.ActionSucceeded
	if invocation.ProposedAction.Tool() == "planner_rejected" {
		status = groundtruth.ActionDenied
	}
	return executor.Execution{Result: executor.Result{Status: status}}, nil
}

func (e *fakeExecutor) snapshot() []executor.Invocation {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]executor.Invocation(nil), e.invocations...)
}

type cancelClient struct {
	started chan struct{}
	calls   int
}

func (c *cancelClient) Complete(ctx context.Context, _ TurnRequest) (TurnResponse, error) {
	c.calls++
	close(c.started)
	<-ctx.Done()
	return TurnResponse{}, ctx.Err()
}

func validResponse(model string, promptTokens, outputTokens uint64, proposals ...Proposal) TurnResponse {
	return TurnResponse{
		Model: model, Done: true, DoneReason: "stop", PromptTokens: promptTokens, OutputTokens: outputTokens,
		OutputSHA256: strings.Repeat("a", 64), Proposals: proposals,
	}
}

func opaque(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}
