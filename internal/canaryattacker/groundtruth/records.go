package groundtruth

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type ModelIdentity struct {
	attackerID     string
	provider       string
	model          string
	modelVersion   string
	plannerVersion string
}

type ModelIdentityInput struct {
	AttackerID     string
	Provider       string
	Model          string
	ModelVersion   string
	PlannerVersion string
}

func NewModelIdentity(in ModelIdentityInput) (ModelIdentity, error) {
	for _, field := range []struct{ label, value string }{
		{"attacker id", in.AttackerID}, {"model provider", in.Provider}, {"model", in.Model},
		{"model version", in.ModelVersion}, {"planner version", in.PlannerVersion},
	} {
		if err := identifier(field.label, field.value); err != nil {
			return ModelIdentity{}, err
		}
	}
	return ModelIdentity{
		attackerID: in.AttackerID, provider: in.Provider, model: in.Model,
		modelVersion: in.ModelVersion, plannerVersion: in.PlannerVersion,
	}, nil
}

func (m ModelIdentity) AttackerID() string     { return m.attackerID }
func (m ModelIdentity) Provider() string       { return m.provider }
func (m ModelIdentity) Model() string          { return m.model }
func (m ModelIdentity) ModelVersion() string   { return m.modelVersion }
func (m ModelIdentity) PlannerVersion() string { return m.plannerVersion }

func (m ModelIdentity) validate() error {
	_, err := NewModelIdentity(ModelIdentityInput{
		AttackerID: m.attackerID, Provider: m.provider, Model: m.model,
		ModelVersion: m.modelVersion, PlannerVersion: m.plannerVersion,
	})
	return err
}

type PolicyDecision struct {
	outcome        PolicyOutcome
	policyVersion  string
	reasonCode     string
	approvedAction *ActionSpec
}

type PolicyDecisionInput struct {
	Outcome        PolicyOutcome
	PolicyVersion  string
	ReasonCode     string
	ApprovedAction *ActionSpec
}

func NewPolicyDecision(in PolicyDecisionInput) (PolicyDecision, error) {
	if !in.Outcome.valid() {
		return PolicyDecision{}, fmt.Errorf("unsupported policy outcome %q", in.Outcome)
	}
	if err := identifier("tool policy version", in.PolicyVersion); err != nil {
		return PolicyDecision{}, err
	}
	if err := identifier("policy reason code", in.ReasonCode); err != nil {
		return PolicyDecision{}, err
	}
	var approved *ActionSpec
	if in.Outcome == PolicyApproved {
		if in.ApprovedAction == nil {
			return PolicyDecision{}, fmt.Errorf("approved policy decision requires a normalized action")
		}
		if err := in.ApprovedAction.validate(); err != nil {
			return PolicyDecision{}, fmt.Errorf("approved action: %w", err)
		}
		copyValue := *in.ApprovedAction
		approved = &copyValue
	} else if in.ApprovedAction != nil {
		return PolicyDecision{}, fmt.Errorf("denied policy decision cannot carry an approved action")
	}
	return PolicyDecision{
		outcome: in.Outcome, policyVersion: in.PolicyVersion,
		reasonCode: in.ReasonCode, approvedAction: approved,
	}, nil
}

func (p PolicyDecision) Outcome() PolicyOutcome { return p.outcome }
func (p PolicyDecision) PolicyVersion() string  { return p.policyVersion }
func (p PolicyDecision) ReasonCode() string     { return p.reasonCode }
func (p PolicyDecision) ApprovedAction() (ActionSpec, bool) {
	if p.approvedAction == nil {
		return ActionSpec{}, false
	}
	return *p.approvedAction, true
}

func (p PolicyDecision) validate() error {
	_, err := NewPolicyDecision(PolicyDecisionInput{
		Outcome: p.outcome, PolicyVersion: p.policyVersion,
		ReasonCode: p.reasonCode, ApprovedAction: p.approvedAction,
	})
	return err
}

type AttackerIntent struct {
	envelope               Envelope
	ordinal                uint32
	stepID                 string
	objective              string
	model                  ModelIdentity
	proposedAction         ActionSpec
	policy                 PolicyDecision
	emittedAt              time.Time
	committedAt            time.Time
	clockSource            string
	clockUncertaintyMillis uint64
	plannerOutputRef       string
	budgets                Budgets
}

type AttackerIntentInput struct {
	Scenario               Scenario
	RunID                  string
	Ordinal                uint32
	StepID                 string
	Objective              string
	Model                  ModelIdentity
	ProposedAction         ActionSpec
	Policy                 PolicyDecision
	EmittedAt              time.Time
	CommittedAt            time.Time
	ClockSource            string
	ClockUncertaintyMillis uint64
	PlannerOutputRef       string
	EstimatedStorageBytes  uint64
	EstimateBasis          EstimateBasis
}

func NewAttackerIntent(in AttackerIntentInput) (AttackerIntent, error) {
	if err := in.Scenario.validate(); err != nil {
		return AttackerIntent{}, fmt.Errorf("scenario: %w", err)
	}
	if err := identifier("run id", in.RunID); err != nil {
		return AttackerIntent{}, err
	}
	if in.Ordinal == 0 || in.Ordinal > in.Scenario.budgets.maxActions {
		return AttackerIntent{}, fmt.Errorf("intent ordinal must be within the scenario action budget")
	}
	step, ok := in.Scenario.step(in.StepID)
	if !ok {
		return AttackerIntent{}, fmt.Errorf("intent step %q is not in the scenario", in.StepID)
	}
	if err := safeText("intent objective", in.Objective); err != nil {
		return AttackerIntent{}, err
	}
	if in.Objective != step.objective {
		return AttackerIntent{}, fmt.Errorf("intent objective must equal the reviewed scenario-step objective")
	}
	if err := in.Model.validate(); err != nil {
		return AttackerIntent{}, fmt.Errorf("model identity: %w", err)
	}
	if err := in.ProposedAction.validate(); err != nil {
		return AttackerIntent{}, fmt.Errorf("proposed action: %w", err)
	}
	if err := in.Policy.validate(); err != nil {
		return AttackerIntent{}, fmt.Errorf("policy decision: %w", err)
	}
	if approved, present := in.Policy.ApprovedAction(); present && !in.Scenario.permits(in.StepID, approved) {
		return AttackerIntent{}, fmt.Errorf("approved action is outside the reviewed scenario step")
	}
	if in.EmittedAt.IsZero() || in.CommittedAt.IsZero() || in.CommittedAt.Before(in.EmittedAt) {
		return AttackerIntent{}, fmt.Errorf("intent emitted/committed timestamps are required and ordered")
	}
	if err := identifier("clock source", in.ClockSource); err != nil {
		return AttackerIntent{}, err
	}
	if in.ClockUncertaintyMillis > uint64((10 * time.Minute).Milliseconds()) {
		return AttackerIntent{}, fmt.Errorf("clock uncertainty exceeds the ten-minute laboratory ceiling")
	}
	if err := opaqueReference("planner output reference", in.PlannerOutputRef, "planner:sha256:"); err != nil {
		return AttackerIntent{}, err
	}
	approvedKey := "-"
	if approved, present := in.Policy.ApprovedAction(); present {
		approvedKey = actionSpecKey(approved)
	}
	identityDigest := stableDigest(
		in.Scenario.envelope.recordID, in.Scenario.semanticDigest(), scopeKey(in.Scenario.envelope.scope), in.RunID,
		fmt.Sprint(in.Ordinal), in.StepID, in.Objective, in.Model.attackerID,
		in.Model.provider, in.Model.model, in.Model.modelVersion, in.Model.plannerVersion,
		actionSpecKey(in.ProposedAction), string(in.Policy.outcome), in.Policy.policyVersion,
		in.Policy.reasonCode, approvedKey, timestampKey(in.EmittedAt), timestampKey(in.CommittedAt),
		in.ClockSource, fmt.Sprint(in.ClockUncertaintyMillis), in.PlannerOutputRef,
		budgetsKey(in.Scenario.budgets), timestampKey(in.Scenario.envelope.corpusReviewDue),
		in.Scenario.envelope.lifecyclePolicyVersion, in.Scenario.envelope.residencyPolicyRef,
		in.Scenario.envelope.encryptionKeyRef, fmt.Sprint(in.EstimatedStorageBytes), string(in.EstimateBasis),
	)
	record := "intent:sha256:" + identityDigest
	envelope, err := newEnvelope(envelopeInput{
		recordID: record, recordKind: RecordIntent, scope: in.Scenario.envelope.scope,
		scenarioID: in.Scenario.envelope.scenarioID, scenarioVersion: in.Scenario.envelope.scenarioVersion,
		runID: in.RunID, recordedAt: in.CommittedAt, corpusReviewDue: in.Scenario.envelope.corpusReviewDue,
		lifecyclePolicyVersion: in.Scenario.envelope.lifecyclePolicyVersion,
		residencyPolicyRef:     in.Scenario.envelope.residencyPolicyRef,
		encryptionKeyRef:       in.Scenario.envelope.encryptionKeyRef,
		estimatedStorageBytes:  in.EstimatedStorageBytes, estimateBasis: in.EstimateBasis,
		lineage: []RecordReference{in.Scenario.Reference()},
	})
	if err != nil {
		return AttackerIntent{}, fmt.Errorf("envelope: %w", err)
	}
	return AttackerIntent{
		envelope: envelope, ordinal: in.Ordinal, stepID: in.StepID, objective: in.Objective,
		model: in.Model, proposedAction: in.ProposedAction, policy: in.Policy,
		emittedAt: in.EmittedAt.UTC(), committedAt: in.CommittedAt.UTC(),
		clockSource: in.ClockSource, clockUncertaintyMillis: in.ClockUncertaintyMillis,
		plannerOutputRef: in.PlannerOutputRef, budgets: in.Scenario.budgets,
	}, nil
}

func (i AttackerIntent) Envelope() Envelope             { return i.envelope }
func (i AttackerIntent) Ordinal() uint32                { return i.ordinal }
func (i AttackerIntent) StepID() string                 { return i.stepID }
func (i AttackerIntent) Objective() string              { return i.objective }
func (i AttackerIntent) Model() ModelIdentity           { return i.model }
func (i AttackerIntent) ProposedAction() ActionSpec     { return i.proposedAction }
func (i AttackerIntent) Policy() PolicyDecision         { return i.policy }
func (i AttackerIntent) EmittedAt() time.Time           { return i.emittedAt }
func (i AttackerIntent) CommittedAt() time.Time         { return i.committedAt }
func (i AttackerIntent) ClockSource() string            { return i.clockSource }
func (i AttackerIntent) ClockUncertaintyMillis() uint64 { return i.clockUncertaintyMillis }
func (i AttackerIntent) PlannerOutputRef() string       { return i.plannerOutputRef }
func (i AttackerIntent) Budgets() Budgets               { return i.budgets }
func (i AttackerIntent) Reference() RecordReference {
	return newRecordReference(RecordIntent, i.envelope.recordID)
}

func (i AttackerIntent) validateAgainst(scenario Scenario) error {
	if err := i.envelope.validate(); err != nil {
		return err
	}
	if i.budgets != scenario.budgets {
		return fmt.Errorf("intent budgets do not match its scenario")
	}
	rebuilt, err := NewAttackerIntent(AttackerIntentInput{
		Scenario: scenario, RunID: i.envelope.runID, Ordinal: i.ordinal, StepID: i.stepID,
		Objective: i.objective, Model: i.model, ProposedAction: i.proposedAction, Policy: i.policy,
		EmittedAt: i.emittedAt, CommittedAt: i.committedAt, ClockSource: i.clockSource,
		ClockUncertaintyMillis: i.clockUncertaintyMillis, PlannerOutputRef: i.plannerOutputRef,
		EstimatedStorageBytes: i.envelope.estimatedStorageBytes, EstimateBasis: i.envelope.estimateBasis,
	})
	if err != nil {
		return err
	}
	if rebuilt.envelope.recordID != i.envelope.recordID || !sameScope(rebuilt.envelope.scope, i.envelope.scope) {
		return fmt.Errorf("intent identity or scope does not match its scenario")
	}
	return nil
}

type ResponseMetadata struct {
	statusCode uint16
	bytes      uint64
	sha256     string
}

type ResponseMetadataInput struct {
	StatusCode uint16
	Bytes      uint64
	SHA256     string
}

func NewResponseMetadata(in ResponseMetadataInput) (ResponseMetadata, error) {
	if in.StatusCode != 0 && (in.StatusCode < 100 || in.StatusCode > 599) {
		return ResponseMetadata{}, fmt.Errorf("response status code must be zero or an HTTP status")
	}
	if in.Bytes > 0 {
		if err := opaqueReference("response hash", "response:sha256:"+in.SHA256, "response:sha256:"); err != nil {
			return ResponseMetadata{}, err
		}
	} else if in.SHA256 != "" {
		return ResponseMetadata{}, fmt.Errorf("empty response cannot carry a response hash")
	}
	return ResponseMetadata{statusCode: in.StatusCode, bytes: in.Bytes, sha256: in.SHA256}, nil
}

func (r ResponseMetadata) StatusCode() uint16 { return r.statusCode }
func (r ResponseMetadata) Bytes() uint64      { return r.bytes }
func (r ResponseMetadata) SHA256() string     { return r.sha256 }

type AttackerAction struct {
	envelope               Envelope
	parentIntentID         string
	status                 ActionStatus
	action                 ActionSpec
	attempted              bool
	startedAt              time.Time
	endedAt                time.Time
	recordedAt             time.Time
	clockSource            string
	clockUncertaintyMillis uint64
	errorCode              string
	executorVersion        string
	toolPolicyVersion      string
	response               *ResponseMetadata
	evidenceRefs           []string
	networkRefs            []string
}

type AttackerActionInput struct {
	Intent                 AttackerIntent
	Status                 ActionStatus
	Action                 ActionSpec
	Attempted              bool
	StartedAt              time.Time
	EndedAt                time.Time
	RecordedAt             time.Time
	ClockSource            string
	ClockUncertaintyMillis uint64
	ErrorCode              string
	ExecutorVersion        string
	ToolPolicyVersion      string
	Response               *ResponseMetadata
	EvidenceRefs           []string
	NetworkRefs            []string
	EstimatedStorageBytes  uint64
	EstimateBasis          EstimateBasis
}

func NewAttackerAction(in AttackerActionInput) (AttackerAction, error) {
	if err := in.Intent.envelope.validate(); err != nil {
		return AttackerAction{}, fmt.Errorf("intent envelope: %w", err)
	}
	if in.Intent.envelope.recordKind != RecordIntent {
		return AttackerAction{}, fmt.Errorf("action parent must be an attacker intent")
	}
	if err := in.Intent.model.validate(); err != nil {
		return AttackerAction{}, fmt.Errorf("intent model identity: %w", err)
	}
	if err := in.Intent.policy.validate(); err != nil {
		return AttackerAction{}, fmt.Errorf("intent policy: %w", err)
	}
	if err := in.Intent.budgets.validate(); err != nil {
		return AttackerAction{}, fmt.Errorf("intent budgets: %w", err)
	}
	if !in.Status.valid() {
		return AttackerAction{}, fmt.Errorf("unsupported action status %q", in.Status)
	}
	if err := in.Action.validate(); err != nil {
		return AttackerAction{}, fmt.Errorf("action: %w", err)
	}
	if in.ToolPolicyVersion != in.Intent.policy.policyVersion {
		return AttackerAction{}, fmt.Errorf("action tool-policy version differs from its intent decision")
	}
	if err := identifier("clock source", in.ClockSource); err != nil {
		return AttackerAction{}, err
	}
	if in.ClockUncertaintyMillis > uint64((10 * time.Minute).Milliseconds()) {
		return AttackerAction{}, fmt.Errorf("clock uncertainty exceeds the ten-minute laboratory ceiling")
	}
	if in.RecordedAt.IsZero() || !in.RecordedAt.After(in.Intent.committedAt) {
		return AttackerAction{}, fmt.Errorf("action record must follow the committed intent")
	}
	approvedAction, approved := in.Intent.policy.ApprovedAction()
	if in.Intent.policy.outcome == PolicyDenied {
		if in.Status != ActionDenied || in.Attempted || !in.StartedAt.IsZero() || !in.EndedAt.IsZero() || in.ExecutorVersion != "" || in.Response != nil || len(in.NetworkRefs) != 0 {
			return AttackerAction{}, fmt.Errorf("denied intent must produce a denied no-execution action")
		}
		if actionSpecKey(in.Action) != actionSpecKey(in.Intent.proposedAction) {
			return AttackerAction{}, fmt.Errorf("denied action must preserve the proposed action")
		}
		if in.ErrorCode != "policy_denied" {
			return AttackerAction{}, fmt.Errorf("denied action requires policy_denied error code")
		}
	} else {
		if !approved || !in.Attempted || in.Status == ActionDenied {
			return AttackerAction{}, fmt.Errorf("approved intent requires one attempted non-denied action")
		}
		if actionSpecKey(in.Action) != actionSpecKey(approvedAction) {
			return AttackerAction{}, fmt.Errorf("executed action differs from the policy-approved normalized action")
		}
		if in.StartedAt.IsZero() || in.EndedAt.IsZero() || !in.StartedAt.After(in.Intent.committedAt) || !in.EndedAt.After(in.StartedAt) || in.RecordedAt.Before(in.EndedAt) {
			return AttackerAction{}, fmt.Errorf("attempted action timestamps must follow the committed intent and be ordered")
		}
		if err := identifier("executor version", in.ExecutorVersion); err != nil {
			return AttackerAction{}, err
		}
		if in.Status == ActionSucceeded && in.ErrorCode != "" {
			return AttackerAction{}, fmt.Errorf("successful action cannot carry an error code")
		}
		if in.Status != ActionSucceeded {
			if err := identifier("action error code", in.ErrorCode); err != nil {
				return AttackerAction{}, err
			}
		}
		if in.Response != nil && in.Response.bytes > in.Intent.budgets.maxResponseBytes {
			return AttackerAction{}, fmt.Errorf("response metadata exceeds the scenario response-byte budget")
		}
	}
	if len(in.EvidenceRefs) > maximumReferencesPerRecord || len(in.NetworkRefs) > maximumReferencesPerRecord {
		return AttackerAction{}, fmt.Errorf("action evidence or network references exceed the per-record bound of %d", maximumReferencesPerRecord)
	}
	evidence, err := canonicalOpaqueReferences("action evidence references", in.EvidenceRefs, "evidence:sha256:", true)
	if err != nil {
		return AttackerAction{}, err
	}
	network, err := canonicalOpaqueReferences("network references", in.NetworkRefs, "network:sha256:", false)
	if err != nil {
		return AttackerAction{}, err
	}
	var response *ResponseMetadata
	if in.Response != nil {
		canonical, err := NewResponseMetadata(ResponseMetadataInput{
			StatusCode: in.Response.statusCode, Bytes: in.Response.bytes, SHA256: in.Response.sha256,
		})
		if err != nil {
			return AttackerAction{}, err
		}
		response = &canonical
	}
	responseKey := "-"
	if response != nil {
		responseKey = fmt.Sprintf("%d\x00%d\x00%s", response.statusCode, response.bytes, response.sha256)
	}
	record := "action:sha256:" + stableDigest(
		in.Intent.envelope.recordID, string(in.Status), actionSpecKey(in.Action), fmt.Sprint(in.Attempted),
		timestampKey(in.StartedAt), timestampKey(in.EndedAt), timestampKey(in.RecordedAt),
		in.ClockSource, fmt.Sprint(in.ClockUncertaintyMillis), in.ErrorCode, in.ExecutorVersion,
		in.ToolPolicyVersion, responseKey, fmt.Sprint(in.EstimatedStorageBytes), string(in.EstimateBasis),
		strings.Join(evidence, "\x00"), strings.Join(network, "\x00"),
	)
	envelope, err := newEnvelope(envelopeInput{
		recordID: record, recordKind: RecordAction, scope: in.Intent.envelope.scope,
		scenarioID: in.Intent.envelope.scenarioID, scenarioVersion: in.Intent.envelope.scenarioVersion,
		runID: in.Intent.envelope.runID, recordedAt: in.RecordedAt,
		corpusReviewDue:        in.Intent.envelope.corpusReviewDue,
		lifecyclePolicyVersion: in.Intent.envelope.lifecyclePolicyVersion,
		residencyPolicyRef:     in.Intent.envelope.residencyPolicyRef,
		encryptionKeyRef:       in.Intent.envelope.encryptionKeyRef,
		estimatedStorageBytes:  in.EstimatedStorageBytes, estimateBasis: in.EstimateBasis,
		lineage: []RecordReference{in.Intent.Reference()},
	})
	if err != nil {
		return AttackerAction{}, fmt.Errorf("envelope: %w", err)
	}
	return AttackerAction{
		envelope: envelope, parentIntentID: in.Intent.envelope.recordID, status: in.Status,
		action: in.Action, attempted: in.Attempted, startedAt: in.StartedAt.UTC(),
		endedAt: in.EndedAt.UTC(), recordedAt: in.RecordedAt.UTC(), clockSource: in.ClockSource,
		clockUncertaintyMillis: in.ClockUncertaintyMillis, errorCode: in.ErrorCode,
		executorVersion: in.ExecutorVersion, toolPolicyVersion: in.ToolPolicyVersion,
		response: response, evidenceRefs: evidence, networkRefs: network,
	}, nil
}

func (a AttackerAction) Envelope() Envelope             { return a.envelope }
func (a AttackerAction) ParentIntentID() string         { return a.parentIntentID }
func (a AttackerAction) Status() ActionStatus           { return a.status }
func (a AttackerAction) Action() ActionSpec             { return a.action }
func (a AttackerAction) Attempted() bool                { return a.attempted }
func (a AttackerAction) StartedAt() time.Time           { return a.startedAt }
func (a AttackerAction) EndedAt() time.Time             { return a.endedAt }
func (a AttackerAction) RecordedAt() time.Time          { return a.recordedAt }
func (a AttackerAction) ClockSource() string            { return a.clockSource }
func (a AttackerAction) ClockUncertaintyMillis() uint64 { return a.clockUncertaintyMillis }
func (a AttackerAction) ErrorCode() string              { return a.errorCode }
func (a AttackerAction) ExecutorVersion() string        { return a.executorVersion }
func (a AttackerAction) ToolPolicyVersion() string      { return a.toolPolicyVersion }
func (a AttackerAction) EvidenceRefs() []string         { return append([]string(nil), a.evidenceRefs...) }
func (a AttackerAction) NetworkRefs() []string          { return append([]string(nil), a.networkRefs...) }
func (a AttackerAction) Reference() RecordReference {
	return newRecordReference(RecordAction, a.envelope.recordID)
}
func (a AttackerAction) Response() (ResponseMetadata, bool) {
	if a.response == nil {
		return ResponseMetadata{}, false
	}
	return *a.response, true
}

func (a AttackerAction) validateAgainst(intent AttackerIntent) error {
	if err := a.envelope.validate(); err != nil {
		return err
	}
	rebuilt, err := NewAttackerAction(AttackerActionInput{
		Intent: intent, Status: a.status, Action: a.action, Attempted: a.attempted,
		StartedAt: a.startedAt, EndedAt: a.endedAt, RecordedAt: a.recordedAt,
		ClockSource: a.clockSource, ClockUncertaintyMillis: a.clockUncertaintyMillis,
		ErrorCode: a.errorCode, ExecutorVersion: a.executorVersion,
		ToolPolicyVersion: a.toolPolicyVersion, Response: a.response,
		EvidenceRefs: a.evidenceRefs, NetworkRefs: a.networkRefs,
		EstimatedStorageBytes: a.envelope.estimatedStorageBytes, EstimateBasis: a.envelope.estimateBasis,
	})
	if err != nil {
		return err
	}
	if rebuilt.envelope.recordID != a.envelope.recordID || a.parentIntentID != intent.envelope.recordID || !sameScope(a.envelope.scope, intent.envelope.scope) {
		return fmt.Errorf("action identity, parent, or scope does not match its intent")
	}
	return nil
}

type Corpus struct {
	id       string
	scenario Scenario
	runID    string
	seed     uint64
	intents  []AttackerIntent
	actions  []AttackerAction
}

func NewCorpus(scenario Scenario, runID string, seed uint64, intents []AttackerIntent, actions []AttackerAction) (Corpus, error) {
	if err := scenario.validate(); err != nil {
		return Corpus{}, fmt.Errorf("scenario: %w", err)
	}
	if err := identifier("run id", runID); err != nil {
		return Corpus{}, err
	}
	if seed == 0 {
		return Corpus{}, fmt.Errorf("deterministic seed must be non-zero")
	}
	if len(intents) == 0 || len(intents) != len(actions) || len(intents) > int(scenario.budgets.maxActions) {
		return Corpus{}, fmt.Errorf("corpus requires one bounded action record for every intent")
	}
	canonicalIntents := append([]AttackerIntent(nil), intents...)
	sort.Slice(canonicalIntents, func(i, j int) bool {
		if canonicalIntents[i].ordinal == canonicalIntents[j].ordinal {
			return canonicalIntents[i].envelope.recordID < canonicalIntents[j].envelope.recordID
		}
		return canonicalIntents[i].ordinal < canonicalIntents[j].ordinal
	})
	intentByID := make(map[string]AttackerIntent, len(canonicalIntents))
	lastStepSequence := uint32(0)
	for index, intent := range canonicalIntents {
		if intent.envelope.runID != runID || !sameScope(intent.envelope.scope, scenario.envelope.scope) {
			return Corpus{}, fmt.Errorf("intent crosses the corpus run or scope boundary")
		}
		if err := intent.validateAgainst(scenario); err != nil {
			return Corpus{}, fmt.Errorf("intent: %w", err)
		}
		if intent.ordinal != uint32(index+1) {
			return Corpus{}, fmt.Errorf("intent ordinals must be contiguous from 1")
		}
		if _, duplicate := intentByID[intent.envelope.recordID]; duplicate {
			return Corpus{}, fmt.Errorf("duplicate intent %q", intent.envelope.recordID)
		}
		intentByID[intent.envelope.recordID] = intent
		if scenario.executionMode == ExecutionOrdered {
			step, _ := scenario.step(intent.stepID)
			if step.sequence < lastStepSequence {
				return Corpus{}, fmt.Errorf("ordered scenario intent step sequence regressed")
			}
			lastStepSequence = step.sequence
		}
	}
	canonicalActions := append([]AttackerAction(nil), actions...)
	sort.Slice(canonicalActions, func(i, j int) bool {
		left := intentByID[canonicalActions[i].parentIntentID].ordinal
		right := intentByID[canonicalActions[j].parentIntentID].ordinal
		if left == right {
			return canonicalActions[i].envelope.recordID < canonicalActions[j].envelope.recordID
		}
		return left < right
	})
	seenParents := make(map[string]struct{}, len(canonicalActions))
	toolExecutions := make(map[ToolName]uint32)
	for _, action := range canonicalActions {
		intent, exists := intentByID[action.parentIntentID]
		if !exists {
			return Corpus{}, fmt.Errorf("action cites an intent outside the corpus")
		}
		if _, duplicate := seenParents[action.parentIntentID]; duplicate {
			return Corpus{}, fmt.Errorf("intent has more than one action record")
		}
		seenParents[action.parentIntentID] = struct{}{}
		if err := action.validateAgainst(intent); err != nil {
			return Corpus{}, fmt.Errorf("action: %w", err)
		}
		if action.attempted {
			toolExecutions[action.action.tool]++
		}
	}
	for tool, count := range toolExecutions {
		constraint, ok := findConstraint(scenario.toolConstraints, tool)
		if !ok || count > constraint.maxActions {
			return Corpus{}, fmt.Errorf("tool %q execution count exceeds its reviewed constraint", tool)
		}
	}
	if err := validateRunBudgets(scenario, canonicalIntents, canonicalActions); err != nil {
		return Corpus{}, err
	}
	identityParts := []string{scenario.envelope.recordID, scenario.semanticDigest(), runID, fmt.Sprint(seed)}
	for index := range canonicalIntents {
		identityParts = append(identityParts, canonicalIntents[index].envelope.recordID, canonicalActions[index].envelope.recordID)
	}
	return Corpus{
		id: "corpus:sha256:" + stableDigest(identityParts...), scenario: scenario, runID: runID,
		seed: seed, intents: canonicalIntents, actions: canonicalActions,
	}, nil
}

type concurrencyEvent struct {
	at    time.Time
	delta int
}

func validateRunBudgets(scenario Scenario, intents []AttackerIntent, actions []AttackerAction) error {
	earliest := intents[0].emittedAt
	latest := actions[0].recordedAt
	events := make([]concurrencyEvent, 0, len(actions)*2)
	for index, intent := range intents {
		if intent.emittedAt.Before(earliest) {
			earliest = intent.emittedAt
		}
		action := actions[index]
		if action.recordedAt.After(latest) {
			latest = action.recordedAt
		}
		if !action.attempted {
			continue
		}
		constraint, ok := findConstraint(scenario.toolConstraints, action.action.tool)
		if !ok {
			return fmt.Errorf("executed tool %q has no reviewed constraint", action.action.tool)
		}
		if action.response != nil && action.response.bytes > constraint.maxResponseBytes {
			return fmt.Errorf("tool %q response exceeds its reviewed response-byte ceiling", action.action.tool)
		}
		events = append(events,
			concurrencyEvent{at: action.startedAt, delta: 1},
			concurrencyEvent{at: action.endedAt, delta: -1},
		)
	}
	if latest.Sub(earliest) > scenario.budgets.maxDuration {
		return fmt.Errorf("corpus run duration exceeds the reviewed scenario budget")
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at.Equal(events[j].at) {
			return events[i].delta < events[j].delta
		}
		return events[i].at.Before(events[j].at)
	})
	concurrent := 0
	for _, event := range events {
		concurrent += event.delta
		if concurrent > int(scenario.budgets.maxConcurrency) {
			return fmt.Errorf("concurrent tool executions exceed the reviewed scenario budget")
		}
	}
	return nil
}

func (c Corpus) ID() string                  { return c.id }
func (c Corpus) SchemaVersion() uint32       { return CurrentSchemaVersion }
func (c Corpus) Scenario() Scenario          { return c.scenario }
func (c Corpus) RunID() string               { return c.runID }
func (c Corpus) Seed() uint64                { return c.seed }
func (c Corpus) Intents() []AttackerIntent   { return append([]AttackerIntent(nil), c.intents...) }
func (c Corpus) Actions() []AttackerAction   { return append([]AttackerAction(nil), c.actions...) }
func (c Corpus) Synthetic() bool             { return true }
func (c Corpus) DataClass() string           { return DataClass }
func (c Corpus) PerTenantModelUse() string   { return ModelUsePolicy }
func (c Corpus) CrossTenantModelUse() string { return ModelUsePolicy }
