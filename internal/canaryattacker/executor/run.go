package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

var (
	ErrActionBudget = errors.New("executor action budget exhausted")
	ErrRunDuration  = errors.New("executor run duration exhausted")
	ErrRunTerminal  = errors.New("executor audit ledger is terminal")
	ErrStepSequence = errors.New("executor ordered step sequence regressed")
)

type RunConfig struct {
	Scenario               groundtruth.Scenario
	RunID                  string
	Ledger                 Ledger
	ClockSource            string
	ClockUncertaintyMillis uint64
	IntentStorageBytes     uint64
	ActionStorageBytes     uint64
	EstimateBasis          groundtruth.EstimateBasis
}

type Invocation struct {
	StepID           string
	Objective        string
	Model            groundtruth.ModelIdentity
	ProposedAction   groundtruth.ActionSpec
	EmittedAt        time.Time
	PlannerOutputRef string
}

type Execution struct {
	Intent groundtruth.AttackerIntent
	Action groundtruth.AttackerAction
	Result Result
}

type Executor struct {
	policy   *Policy
	resolver Resolver
	dialer   Dialer
}

func New(policy *Policy, resolver Resolver, dialer Dialer) (*Executor, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is required")
	}
	if resolver == nil {
		resolver = systemResolver{}
	}
	if dialer == nil {
		dialer = &systemDialer{}
	}
	return &Executor{policy: policy, resolver: resolver, dialer: dialer}, nil
}

type Run struct {
	executor        *Executor
	config          RunConfig
	started         time.Time
	deadline        time.Time
	auditCtx        context.Context
	auditCancel     context.CancelFunc
	executionCtx    context.Context
	executionCancel context.CancelFunc
	sem             chan struct{}
	active          sync.WaitGroup
	closeOnce       sync.Once

	mu               sync.Mutex
	ordinal          uint32
	lastStepSequence uint32
	toolAttempts     map[groundtruth.ToolName]uint32
	stored           map[uint32]storedResponse
	storedBytes      uint64
	nextRequestAt    time.Time
	terminalLedger   bool
	closed           bool
}

type storedResponse struct {
	targetRef string
	status    uint16
	links     []string
	body      []byte
}

func (e *Executor) NewRun(config RunConfig) (*Run, error) {
	if err := e.policy.validateScenario(config.Scenario); err != nil {
		return nil, err
	}
	if config.Ledger == nil {
		return nil, fmt.Errorf("audit ledger is required")
	}
	if !validIdentifier(config.RunID) || !validIdentifier(config.ClockSource) || config.IntentStorageBytes == 0 || config.ActionStorageBytes == 0 {
		return nil, fmt.Errorf("run identity, clock source, and storage estimates are required")
	}
	if config.ClockUncertaintyMillis > uint64((10 * time.Minute).Milliseconds()) {
		return nil, fmt.Errorf("clock uncertainty exceeds the laboratory ceiling")
	}
	switch config.EstimateBasis {
	case groundtruth.EstimateAssumed, groundtruth.EstimateMeasured, groundtruth.EstimateBenchmarked:
	default:
		return nil, fmt.Errorf("storage estimate basis is required")
	}
	started := time.Now().UTC()
	deadline := started.Add(config.Scenario.Budgets().MaxDuration())
	if !config.Scenario.Envelope().CorpusReviewDue().After(deadline) {
		return nil, fmt.Errorf("scenario corpus review must remain valid for the complete run")
	}
	auditCtx, auditCancel := context.WithDeadline(context.Background(), deadline)
	executionCtx, executionCancel := context.WithCancel(context.Background())
	concurrency := config.Scenario.Budgets().MaxConcurrency()
	if concurrency > e.policy.limits.MaxConcurrency {
		concurrency = e.policy.limits.MaxConcurrency
	}
	return &Run{
		executor: e, config: config, started: started,
		deadline: deadline, auditCtx: auditCtx, auditCancel: auditCancel,
		executionCtx: executionCtx, executionCancel: executionCancel,
		sem: make(chan struct{}, concurrency), toolAttempts: make(map[groundtruth.ToolName]uint32),
		stored: make(map[uint32]storedResponse),
	}, nil
}

func (r *Run) Close() {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.executionCancel()
		r.mu.Unlock()
		r.active.Wait()
		r.auditCancel()
	})
}

func (r *Run) Execute(ctx context.Context, invocation Invocation) (Execution, error) {
	if err := r.beginExecution(); err != nil {
		return Execution{}, err
	}
	defer r.active.Done()
	if err := r.validateInvocation(invocation); err != nil {
		return Execution{}, err
	}
	ordinal, operation, reason, err := r.authorize(invocation)
	if err != nil {
		return Execution{}, err
	}
	decisionInput := groundtruth.PolicyDecisionInput{
		Outcome: groundtruth.PolicyDenied, PolicyVersion: PolicyVersion, ReasonCode: reason,
	}
	if operation != nil {
		decisionInput.Outcome = groundtruth.PolicyApproved
		decisionInput.ReasonCode = "exact_policy_match"
		approved := operation.action
		decisionInput.ApprovedAction = &approved
	}
	decision, err := groundtruth.NewPolicyDecision(decisionInput)
	if err != nil {
		return Execution{}, fmt.Errorf("construct policy decision: %w", err)
	}
	emittedAt := invocation.EmittedAt.UTC()
	if emittedAt.IsZero() {
		emittedAt = time.Now().UTC()
	}
	committedAt := strictNow(emittedAt)
	intent, err := groundtruth.NewAttackerIntent(groundtruth.AttackerIntentInput{
		Scenario: r.config.Scenario, RunID: r.config.RunID, Ordinal: ordinal,
		StepID: invocation.StepID, Objective: invocation.Objective, Model: invocation.Model,
		ProposedAction: invocation.ProposedAction, Policy: decision,
		EmittedAt: emittedAt, CommittedAt: committedAt, ClockSource: r.config.ClockSource,
		ClockUncertaintyMillis: r.config.ClockUncertaintyMillis,
		PlannerOutputRef:       invocation.PlannerOutputRef,
		EstimatedStorageBytes:  r.config.IntentStorageBytes, EstimateBasis: r.config.EstimateBasis,
	})
	if err != nil {
		return Execution{}, fmt.Errorf("construct attacker intent: %w", err)
	}
	if err := r.config.Ledger.AppendIntent(r.auditCtx, intent); err != nil {
		r.markTerminal()
		return Execution{Intent: intent}, fmt.Errorf("commit attacker intent before execution: %w", err)
	}
	if operation == nil {
		return r.recordDenied(intent)
	}
	if ctx.Err() != nil {
		return r.recordAttempt(intent, *operation, time.Now().UTC(), execResult{status: groundtruth.ActionCancelled, errorCode: "caller_cancelled"})
	}

	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return r.recordAttempt(intent, *operation, time.Now().UTC(), execResult{status: groundtruth.ActionCancelled, errorCode: "caller_cancelled"})
	case <-r.executionCtx.Done():
		return r.recordAttempt(intent, *operation, time.Now().UTC(), execResult{status: groundtruth.ActionCancelled, errorCode: "run_cancelled"})
	case <-time.After(time.Until(r.executionDeadline())):
		return r.recordAttempt(intent, *operation, time.Now().UTC(), execResult{status: groundtruth.ActionCancelled, errorCode: "run_timeout"})
	}

	startedAt := strictNow(intent.CommittedAt())
	remaining := time.Until(r.executionDeadline())
	if remaining <= 0 {
		return r.recordAttempt(intent, *operation, startedAt, execResult{status: groundtruth.ActionCancelled, errorCode: "run_timeout"})
	}
	actionDuration := r.executor.policy.limits.MaxActionDuration
	if remaining < actionDuration {
		actionDuration = remaining
	}
	executionCtx, cancel := context.WithTimeout(r.executionCtx, actionDuration)
	stopCallerCancellation := context.AfterFunc(ctx, cancel)
	result := r.executeOperation(executionCtx, ordinal, *operation)
	stopCallerCancellation()
	cancel()
	if errors.Is(ctx.Err(), context.Canceled) {
		result.status, result.errorCode = groundtruth.ActionCancelled, "caller_cancelled"
	} else if errors.Is(r.executionCtx.Err(), context.Canceled) {
		result.status, result.errorCode = groundtruth.ActionCancelled, "run_cancelled"
	} else if result.errorCode == "deadline_exceeded" {
		result.status, result.errorCode = groundtruth.ActionCancelled, "action_timeout"
	}
	return r.recordAttempt(intent, *operation, startedAt, result)
}

func (r *Run) authorize(invocation Invocation) (uint32, *Operation, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminalLedger || r.closed {
		return 0, nil, "", ErrRunTerminal
	}
	if !time.Now().Before(r.executionDeadline()) {
		return 0, nil, "", ErrRunDuration
	}
	maxActions := r.config.Scenario.Budgets().MaxActions()
	if maxActions > r.executor.policy.limits.MaxActions {
		maxActions = r.executor.policy.limits.MaxActions
	}
	if r.ordinal >= maxActions {
		return 0, nil, "", ErrActionBudget
	}
	if r.config.Scenario.ExecutionMode() == groundtruth.ExecutionOrdered {
		sequence, ok := stepSequence(r.config.Scenario, invocation.StepID)
		if !ok {
			return 0, nil, "", fmt.Errorf("invocation step is outside the reviewed scenario")
		}
		if sequence < r.lastStepSequence {
			return 0, nil, "", ErrStepSequence
		}
		r.lastStepSequence = sequence
	}
	r.ordinal++
	ordinal := r.ordinal
	operation, registered := r.executor.policy.operations[actionKey(invocation.ProposedAction)]
	if !registered || !scenarioPermits(r.config.Scenario, invocation.StepID, invocation.ProposedAction) {
		return ordinal, nil, "outside_reviewed_policy", nil
	}
	constraint, ok := toolConstraint(r.config.Scenario, operation.action.Tool())
	if !ok {
		return ordinal, nil, "outside_reviewed_policy", nil
	}
	if r.toolAttempts[operation.action.Tool()] >= constraint.MaxActions() {
		return ordinal, nil, "tool_budget_exhausted", nil
	}
	if (operation.action.Tool() == groundtruth.ToolFollowLink || operation.action.Tool() == groundtruth.ToolInspectResponse) &&
		!r.hasStoredTarget(operation.sourceOrdinal, operation.action.TargetRef()) {
		return ordinal, nil, "source_response_missing", nil
	}
	r.toolAttempts[operation.action.Tool()]++
	copyValue := operation
	copyValue.enumerationPaths = append([]string(nil), operation.enumerationPaths...)
	return ordinal, &copyValue, "", nil
}

func (r *Run) beginExecution() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminalLedger {
		return ErrRunTerminal
	}
	r.active.Add(1)
	return nil
}

func (r *Run) validateInvocation(invocation Invocation) error {
	var reviewed *groundtruth.Step
	for _, step := range r.config.Scenario.Steps() {
		if step.ID() == invocation.StepID {
			copyValue := step
			reviewed = &copyValue
			break
		}
	}
	if reviewed == nil || invocation.Objective != reviewed.Objective() {
		return fmt.Errorf("invocation must name an exact reviewed scenario step and objective")
	}
	if _, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: invocation.Model.AttackerID(), Provider: invocation.Model.Provider(), Model: invocation.Model.Model(),
		ModelVersion: invocation.Model.ModelVersion(), PlannerVersion: invocation.Model.PlannerVersion(),
	}); err != nil {
		return fmt.Errorf("invocation model identity: %w", err)
	}
	if _, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: invocation.ProposedAction.Tool(), TargetAlias: invocation.ProposedAction.TargetAlias(),
		TargetRef: invocation.ProposedAction.TargetRef(), Operation: invocation.ProposedAction.Operation(),
		InputFixture: invocation.ProposedAction.InputFixture(), CredentialRef: invocation.ProposedAction.CredentialRef(),
	}); err != nil {
		return fmt.Errorf("invocation action: %w", err)
	}
	if !validOpaqueReference(invocation.PlannerOutputRef, "planner:sha256:") {
		return fmt.Errorf("invocation planner output reference is invalid")
	}
	now := time.Now().UTC()
	if invocation.EmittedAt.IsZero() || invocation.EmittedAt.Before(r.started) || invocation.EmittedAt.After(now.Add(time.Duration(r.config.ClockUncertaintyMillis)*time.Millisecond)) {
		return fmt.Errorf("invocation emission time is outside the active run clock boundary")
	}
	return nil
}

func (r *Run) recordDenied(intent groundtruth.AttackerIntent) (Execution, error) {
	recordedAt := strictNow(intent.CommittedAt())
	action, err := groundtruth.NewAttackerAction(groundtruth.AttackerActionInput{
		Intent: intent, Status: groundtruth.ActionDenied, Action: intent.ProposedAction(),
		RecordedAt: recordedAt, ClockSource: r.config.ClockSource,
		ClockUncertaintyMillis: r.config.ClockUncertaintyMillis, ErrorCode: "policy_denied",
		ToolPolicyVersion:     PolicyVersion,
		EvidenceRefs:          []string{digestReference("evidence:sha256:", intent.Envelope().RecordID(), "policy-denied")},
		EstimatedStorageBytes: r.config.ActionStorageBytes, EstimateBasis: r.config.EstimateBasis,
	})
	if err != nil {
		return Execution{Intent: intent}, fmt.Errorf("construct denied action: %w", err)
	}
	if err := r.config.Ledger.AppendAction(r.auditCtx, action); err != nil {
		r.markTerminal()
		return Execution{Intent: intent, Action: action}, fmt.Errorf("commit denied action: %w", err)
	}
	return Execution{Intent: intent, Action: action, Result: Result{Status: groundtruth.ActionDenied, ErrorCode: "policy_denied"}}, nil
}

func (r *Run) recordAttempt(intent groundtruth.AttackerIntent, operation Operation, startedAt time.Time, result execResult) (Execution, error) {
	if !startedAt.After(intent.CommittedAt()) {
		startedAt = intent.CommittedAt().Add(time.Nanosecond)
	}
	endedAt := strictNow(startedAt)
	recordedAt := strictNow(endedAt)
	var response *groundtruth.ResponseMetadata
	if result.responseBytes > 0 || result.httpStatus != 0 {
		metadata, err := groundtruth.NewResponseMetadata(groundtruth.ResponseMetadataInput{
			StatusCode: result.httpStatus, Bytes: result.responseBytes, SHA256: result.responseSHA256,
		})
		if err != nil {
			return Execution{Intent: intent}, fmt.Errorf("construct response metadata: %w", err)
		}
		response = &metadata
	}
	action, err := groundtruth.NewAttackerAction(groundtruth.AttackerActionInput{
		Intent: intent, Status: result.status, Action: operation.action, Attempted: true,
		StartedAt: startedAt, EndedAt: endedAt, RecordedAt: recordedAt,
		ClockSource: r.config.ClockSource, ClockUncertaintyMillis: r.config.ClockUncertaintyMillis,
		ErrorCode: result.errorCode, ExecutorVersion: ExecutorVersion, ToolPolicyVersion: PolicyVersion,
		Response:              response,
		EvidenceRefs:          []string{digestReference("evidence:sha256:", intent.Envelope().RecordID(), string(result.status), result.errorCode)},
		NetworkRefs:           result.networkRefs,
		EstimatedStorageBytes: r.config.ActionStorageBytes, EstimateBasis: r.config.EstimateBasis,
	})
	if err != nil {
		return Execution{Intent: intent}, fmt.Errorf("construct attempted action: %w", err)
	}
	if err := r.config.Ledger.AppendAction(r.auditCtx, action); err != nil {
		r.markTerminal()
		return Execution{Intent: intent, Action: action}, fmt.Errorf("commit attempted action: %w", err)
	}
	public := Result{
		Status: result.status, ErrorCode: result.errorCode, HTTPStatus: result.httpStatus,
		ResponseBytes: result.responseBytes,
	}
	if result.responseSHA256 != "" {
		public.ResponseRef = "response:sha256:" + result.responseSHA256
	}
	public.Content = append([]byte(nil), result.content...)
	return Execution{Intent: intent, Action: action, Result: public}, nil
}

func (r *Run) executionDeadline() time.Time {
	return r.deadline.Add(-r.executor.policy.limits.CompletionReserve)
}

func (r *Run) markTerminal() {
	r.mu.Lock()
	r.terminalLedger = true
	r.mu.Unlock()
	r.executionCancel()
}

func (r *Run) hasStoredTarget(ordinal uint32, targetRef string) bool {
	response, ok := r.stored[ordinal]
	return ok && response.targetRef == targetRef
}

func toolConstraint(scenario groundtruth.Scenario, tool groundtruth.ToolName) (groundtruth.ToolConstraint, bool) {
	for _, constraint := range scenario.ToolConstraints() {
		if constraint.Tool() == tool {
			return constraint, true
		}
	}
	return groundtruth.ToolConstraint{}, false
}

func stepSequence(scenario groundtruth.Scenario, stepID string) (uint32, bool) {
	for _, step := range scenario.Steps() {
		if step.ID() == stepID {
			return step.Sequence(), true
		}
	}
	return 0, false
}

func strictNow(after time.Time) time.Time {
	now := time.Now().UTC()
	if !now.After(after) {
		return after.Add(time.Nanosecond)
	}
	return now
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || !lowerAlphaNumeric(value[0]) || !lowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == ':' || character == '/' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func digestReference(prefix string, fields ...string) string {
	hash := sha256.New()
	for _, field := range fields {
		hash.Write([]byte{0})
		hash.Write([]byte(field))
	}
	return prefix + hex.EncodeToString(hash.Sum(nil))
}
