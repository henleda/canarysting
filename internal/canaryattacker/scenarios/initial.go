// Package scenarios contains reviewed, versioned CanaryAttacker laboratory
// journeys. Runtime target addresses and disposable fixture secrets remain in
// executor policy bindings and never become model-visible scenario fields.
package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

const (
	InitialScenarioID      = "m2c5-initial-journey"
	InitialScenarioVersion = 1
	InitialTargetHost      = "fixture.canaryattacker.invalid"
	InitialTargetPort      = 18080
	InitialSeed            = 525

	fixtureUsername = "fixture-user"
	// This value is deliberately disposable laboratory data. It is not read
	// from a Kubernetes Secret and is never serialized into ground truth.
	fixtureSecret = "fixture-secret"
)

var (
	initialRecordedAt = time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	initialReviewDue  = time.Date(2027, time.September, 10, 0, 0, 0, 0, time.UTC)
)

type InitialJourney struct {
	Scenario groundtruth.Scenario
	Policy   *executor.Policy
	Model    groundtruth.ModelIdentity
	Actions  []groundtruth.ActionSpec
	address  netip.Addr
}

// NewInitialJourney binds the stable scenario to one exact private or loopback
// laboratory address. The live runner requires private addressing; loopback is
// retained only for the in-process test fixture. The address is executor policy,
// not scenario or model input.
func NewInitialJourney(address netip.Addr) (InitialJourney, error) {
	return newInitialJourney(address, InitialTargetPort)
}

func newInitialJourney(address netip.Addr, port uint16) (InitialJourney, error) {
	address = address.Unmap()
	if !address.IsValid() || (!address.IsPrivate() && !address.IsLoopback()) || address.Zone() != "" {
		return InitialJourney{}, fmt.Errorf("initial scenario requires one exact private or loopback laboratory address")
	}
	if port == 0 {
		return InitialJourney{}, fmt.Errorf("initial scenario requires a target port")
	}
	targetRef := opaque("labtarget:sha256:", "m2c5-kubernetes-http-fixture")
	targetFixtureRef := opaque("fixture:sha256:", "m2c5-kubernetes-http-fixture")
	credentialRef := opaque("fixture:sha256:", "m2c5-disposable-basic-credential")
	target, err := executor.NewTargetBinding(executor.TargetBindingInput{
		Alias: "kubernetes-fixture", Reference: targetRef, FixtureRef: targetFixtureRef,
		Scheme: "http", Host: InitialTargetHost, Port: port,
		AllowedAddresses: []netip.Addr{address},
	})
	if err != nil {
		return InitialJourney{}, err
	}
	credential, err := executor.NewCredentialFixture(executor.CredentialFixtureInput{
		Reference: credentialRef, TargetFixtureRef: targetFixtureRef, Kind: executor.CredentialBasic,
		Username: fixtureUsername, Secret: []byte(fixtureSecret),
	})
	if err != nil {
		return InitialJourney{}, err
	}
	actionInputs := []groundtruth.ActionSpecInput{
		{Tool: groundtruth.ToolEnumerateEndpoint, TargetAlias: "kubernetes-fixture", TargetRef: targetRef, Operation: "enumerate-reviewed-paths"},
		{Tool: groundtruth.ToolHTTPRequest, TargetAlias: "kubernetes-fixture", TargetRef: targetRef, Operation: "probe-http"},
		{Tool: groundtruth.ToolTryCredential, TargetAlias: "kubernetes-fixture", TargetRef: targetRef, Operation: "try-disposable-credential", CredentialRef: credentialRef},
		{Tool: groundtruth.ToolHTTPRequest, TargetAlias: "kubernetes-fixture", TargetRef: targetRef, Operation: "discover-canary-link"},
		{Tool: groundtruth.ToolFollowLink, TargetAlias: "kubernetes-fixture", TargetRef: targetRef, Operation: "follow-canary-link"},
	}
	actions := make([]groundtruth.ActionSpec, len(actionInputs))
	for index, input := range actionInputs {
		actions[index], err = groundtruth.NewActionSpec(input)
		if err != nil {
			return InitialJourney{}, err
		}
	}
	limits := executor.Limits{
		MaxActions: 5, MaxRunDuration: 30 * time.Second, MaxActionDuration: 3 * time.Second,
		CompletionReserve: 100 * time.Millisecond, MaxConcurrency: 1, MaxRequestsPerSecond: 10,
		MaxRequestBytes: 2048, MaxResponseBytes: 4096, MaxStoredResponseBytes: 16384,
		MaxResponseHeaderBytes: 4096, MaxEnumerationPaths: 2,
	}
	policy, err := executor.NewPolicy(executor.PolicyConfig{
		Limits: limits, Targets: []executor.TargetBinding{target},
		CredentialFixtures: []executor.CredentialFixture{credential},
		Operations: []executor.OperationInput{
			{Action: actions[0], EnumerationPaths: []string{"/", "/catalog"}},
			{Action: actions[1], HTTPMethod: http.MethodGet, Path: "/probe"},
			{Action: actions[2], HTTPMethod: http.MethodGet, Path: "/credential"},
			{Action: actions[3], HTTPMethod: http.MethodGet, Path: "/discover"},
			{Action: actions[4], SourceOrdinal: 4, LinkIndex: 0},
		},
	})
	if err != nil {
		return InitialJourney{}, err
	}
	groundTarget, err := groundtruth.NewTarget(groundtruth.TargetInput{
		Alias: "kubernetes-fixture", Reference: targetRef, FixtureRef: targetFixtureRef,
	})
	if err != nil {
		return InitialJourney{}, err
	}
	constraintInputs := []groundtruth.ToolConstraintInput{
		{Tool: groundtruth.ToolEnumerateEndpoint, AllowedOperations: []string{actions[0].Operation()}, MaxActions: 1, MaxRequestBytes: 2048, MaxResponseBytes: 4096},
		{Tool: groundtruth.ToolHTTPRequest, AllowedOperations: []string{actions[1].Operation(), actions[3].Operation()}, MaxActions: 2, MaxRequestBytes: 2048, MaxResponseBytes: 4096},
		{Tool: groundtruth.ToolTryCredential, AllowedOperations: []string{actions[2].Operation()}, MaxActions: 1, MaxRequestBytes: 2048, MaxResponseBytes: 4096},
		{Tool: groundtruth.ToolFollowLink, AllowedOperations: []string{actions[4].Operation()}, MaxActions: 1, MaxRequestBytes: 2048, MaxResponseBytes: 4096},
	}
	constraints := make([]groundtruth.ToolConstraint, len(constraintInputs))
	for index, input := range constraintInputs {
		constraints[index], err = groundtruth.NewToolConstraint(input)
		if err != nil {
			return InitialJourney{}, err
		}
	}
	objectives := []string{
		"Enumerate two reviewed harmless laboratory endpoints.",
		"Probe one reviewed harmless HTTP endpoint.",
		"Try one disposable laboratory credential.",
		"Discover one same-target canary link.",
		"Touch the discovered harmless canary.",
	}
	stepIDs := []string{"enumerate-endpoints", "probe-http", "try-harmless-credential", "discover-canary", "touch-canary"}
	steps := make([]groundtruth.Step, len(actions))
	for index := range actions {
		steps[index], err = groundtruth.NewStep(groundtruth.StepInput{
			ID: stepIDs[index], Sequence: uint32(index + 1), Objective: objectives[index],
			AllowedActions: []groundtruth.ActionSpec{actions[index]},
		})
		if err != nil {
			return InitialJourney{}, err
		}
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 5, MaxDuration: limits.MaxRunDuration, MaxConcurrency: 1,
		MaxRequestBytes: limits.MaxRequestBytes, MaxResponseBytes: limits.MaxResponseBytes, MaxModelTokens: 1,
	})
	if err != nil {
		return InitialJourney{}, err
	}
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "synthetic-lab", ScopeID: "m2c5-dgx-kubernetes", DeploymentBoundary: "dgx-kubernetes-fixture",
		ResidencyCellID: "dgx-spark-local", KeyNamespace: "synthetic-keyspace", RegistryNamespace: "initial-scenarios",
	})
	if err != nil {
		return InitialJourney{}, err
	}
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: scope, ID: InitialScenarioID, Version: InitialScenarioVersion, Name: "Initial reproducible CanaryAttacker journey",
		Objective: "Produce repeatable synthetic ground truth for five bounded laboratory actions.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionOrdered,
		RequiredFixtures: []string{targetFixtureRef, credentialRef}, Targets: []groundtruth.Target{groundTarget},
		ToolConstraints: constraints, Steps: steps, Budgets: budgets,
		ExpectedTelemetry: []string{"canary-touch", "executor-audit", "fixture-http"},
		RecordedAt:        initialRecordedAt, CorpusReviewDue: initialReviewDue,
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef: opaque("keyref:sha256:", "m2c5-initial-scenario-key"), EstimatedStorageBytes: 32768,
		EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		return InitialJourney{}, err
	}
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "canaryattacker-static-journey", Provider: "deterministic-fixture", Model: "reviewed-ordered-plan",
		ModelVersion: "initial-v1", PlannerVersion: "static-plan-v1",
	})
	if err != nil {
		return InitialJourney{}, err
	}
	return InitialJourney{Scenario: scenario, Policy: policy, Model: model, Actions: actions, address: address}, nil
}

// Run executes exactly one ordered journey. The runtime resolver returns only
// the private address already admitted by the executor policy.
func (j InitialJourney) Run(ctx context.Context, runID string) (groundtruth.Corpus, []executor.Execution, error) {
	ledger := &executor.MemoryLedger{}
	boundary, err := executor.New(j.Policy, exactResolver{host: InitialTargetHost, address: j.address}, nil)
	if err != nil {
		return groundtruth.Corpus{}, nil, err
	}
	run, err := boundary.NewRun(executor.RunConfig{
		Scenario: j.Scenario, RunID: runID, Ledger: ledger,
		ClockSource: "ntp-synchronized-system-clock", ClockUncertaintyMillis: 30000,
		IntentStorageBytes: 2048, ActionStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
	})
	if err != nil {
		return groundtruth.Corpus{}, nil, err
	}
	defer run.Close()
	steps := j.Scenario.Steps()
	executions := make([]executor.Execution, 0, len(j.Actions))
	for index, action := range j.Actions {
		execution, executeErr := run.Execute(ctx, executor.Invocation{
			StepID: steps[index].ID(), Objective: steps[index].Objective(), Model: j.Model,
			ProposedAction: action, EmittedAt: time.Now().UTC(),
			PlannerOutputRef: opaque("planner:sha256:", "m2c5-static-step-"+strconv.Itoa(index+1)),
		})
		if executeErr != nil {
			return groundtruth.Corpus{}, executions, fmt.Errorf("execute step %d: %w", index+1, executeErr)
		}
		if execution.Result.Status != groundtruth.ActionSucceeded || execution.Result.HTTPStatus != http.StatusOK {
			return groundtruth.Corpus{}, executions, fmt.Errorf("step %d did not succeed", index+1)
		}
		executions = append(executions, execution)
	}
	run.Close()
	corpus, err := groundtruth.NewCorpus(j.Scenario, runID, InitialSeed, ledger.Intents(), ledger.Actions())
	if err != nil {
		return groundtruth.Corpus{}, executions, err
	}
	return corpus, executions, nil
}

// SemanticSHA256 is stable across run IDs, timestamps, and dynamically
// allocated private Service addresses. It covers the reviewed ordered steps,
// proposed action semantics, and terminal outcomes.
func (j InitialJourney) SemanticSHA256(executions []executor.Execution) (string, error) {
	if len(executions) != len(j.Actions) {
		return "", fmt.Errorf("semantic proof requires exactly %d executions", len(j.Actions))
	}
	parts := []string{j.Scenario.Envelope().RecordID(), j.Scenario.SemanticSHA256()}
	steps := j.Scenario.Steps()
	for index, execution := range executions {
		action := execution.Intent.ProposedAction()
		if execution.Intent.Ordinal() != uint32(index+1) || execution.Intent.StepID() != steps[index].ID() ||
			action.Tool() != j.Actions[index].Tool() || action.TargetAlias() != j.Actions[index].TargetAlias() ||
			action.TargetRef() != j.Actions[index].TargetRef() || action.Operation() != j.Actions[index].Operation() ||
			action.InputFixture() != j.Actions[index].InputFixture() || action.CredentialRef() != j.Actions[index].CredentialRef() ||
			execution.Action.Status() != groundtruth.ActionSucceeded || !execution.Action.Attempted() {
			return "", fmt.Errorf("execution %d differs from the reviewed journey", index+1)
		}
		parts = append(parts, strconv.Itoa(index+1), steps[index].ID(), steps[index].Objective(),
			string(action.Tool()), action.TargetAlias(), action.TargetRef(), action.Operation(), action.InputFixture(),
			action.CredentialRef(), string(execution.Action.Status()), strconv.FormatBool(execution.Action.Attempted()))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:]), nil
}

type exactResolver struct {
	host    string
	address netip.Addr
}

func (r exactResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if host != r.host || (network != "ip" && network != "ip4") {
		return nil, fmt.Errorf("resolver request is outside the exact initial-scenario binding")
	}
	return []netip.Addr{r.address}, nil
}

func opaque(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}
