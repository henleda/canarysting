package groundtruth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
)

type corpusV1 struct {
	SchemaVersion uint32     `json:"schema_version"`
	CorpusID      string     `json:"corpus_id"`
	Scenario      scenarioV1 `json:"scenario"`
	Run           runV1      `json:"run"`
}

type runV1 struct {
	RunID   string     `json:"run_id"`
	Seed    uint64     `json:"seed"`
	Intents []intentV1 `json:"intents"`
	Actions []actionV1 `json:"actions"`
}

type envelopeV1 struct {
	SchemaVersion          uint32              `json:"schema_version"`
	RecordID               string              `json:"record_id"`
	RecordKind             RecordKind          `json:"record_kind"`
	DataClass              string              `json:"data_class"`
	Sensitivity            string              `json:"sensitivity"`
	Synthetic              bool                `json:"synthetic"`
	LabDomain              string              `json:"lab_domain"`
	Scope                  scopeV1             `json:"scope"`
	ScenarioID             string              `json:"scenario_id"`
	ScenarioVersion        uint32              `json:"scenario_version"`
	RunID                  string              `json:"run_id"`
	RecordedAt             string              `json:"recorded_at"`
	RetentionPolicy        string              `json:"retention_policy"`
	ExpiresAt              *string             `json:"expires_at"`
	CorpusReviewDue        string              `json:"corpus_review_due"`
	LifecycleOwner         string              `json:"lifecycle_owner"`
	LifecyclePolicyVersion string              `json:"lifecycle_policy_version"`
	ResidencyPolicyRef     string              `json:"residency_policy_ref"`
	EncryptionKeyRef       string              `json:"encryption_key_ref"`
	OperationalPolicyRef   string              `json:"operational_policy_ref"`
	PerTenantModelUse      string              `json:"per_tenant_model_use"`
	CrossTenantModelUse    string              `json:"cross_tenant_model_use"`
	EstimatedStorageBytes  uint64              `json:"estimated_storage_bytes"`
	EstimateBasis          EstimateBasis       `json:"estimate_basis"`
	Lineage                []recordReferenceV1 `json:"lineage"`
}

type scopeV1 struct {
	Domain             string `json:"domain"`
	TenantID           string `json:"tenant_id"`
	ScopeID            string `json:"scope_id"`
	DeploymentBoundary string `json:"deployment_boundary"`
	ResidencyCellID    string `json:"residency_cell_id"`
	KeyNamespace       string `json:"key_namespace"`
	RegistryNamespace  string `json:"registry_namespace"`
}

type recordReferenceV1 struct {
	Kind          RecordKind `json:"kind"`
	ID            string     `json:"id"`
	SchemaVersion uint32     `json:"schema_version"`
}

type budgetsV1 struct {
	MaxActions        uint32 `json:"max_actions"`
	MaxDurationMillis uint64 `json:"max_duration_ms"`
	MaxConcurrency    uint32 `json:"max_concurrency"`
	MaxRequestBytes   uint64 `json:"max_request_bytes"`
	MaxResponseBytes  uint64 `json:"max_response_bytes"`
	MaxModelTokens    uint64 `json:"max_model_tokens"`
}

type targetV1 struct {
	Alias      string `json:"alias"`
	Reference  string `json:"reference"`
	FixtureRef string `json:"fixture_ref"`
}

type actionSpecV1 struct {
	Tool          ToolName `json:"tool"`
	TargetAlias   string   `json:"target_alias"`
	TargetRef     string   `json:"target_ref"`
	Operation     string   `json:"operation"`
	InputFixture  string   `json:"input_fixture_ref"`
	CredentialRef string   `json:"credential_fixture_ref"`
}

type toolConstraintV1 struct {
	Tool              ToolName `json:"tool"`
	AllowedOperations []string `json:"allowed_operations"`
	MaxActions        uint32   `json:"max_actions"`
	MaxRequestBytes   uint64   `json:"max_request_bytes"`
	MaxResponseBytes  uint64   `json:"max_response_bytes"`
}

type stepV1 struct {
	ID             string         `json:"id"`
	Sequence       uint32         `json:"sequence"`
	Objective      string         `json:"objective"`
	AllowedActions []actionSpecV1 `json:"allowed_actions"`
}

type scenarioV1 struct {
	Envelope          envelopeV1         `json:"envelope"`
	SemanticSHA256    string             `json:"semantic_sha256"`
	Name              string             `json:"name"`
	Objective         string             `json:"objective"`
	Safety            SafetyClass        `json:"safety"`
	ExecutionMode     ExecutionMode      `json:"execution_mode"`
	RequiredFixtures  []string           `json:"required_fixtures"`
	Targets           []targetV1         `json:"targets"`
	ToolConstraints   []toolConstraintV1 `json:"tool_constraints"`
	Steps             []stepV1           `json:"steps"`
	Budgets           budgetsV1          `json:"budgets"`
	ExpectedTelemetry []string           `json:"expected_telemetry"`
}

type modelIdentityV1 struct {
	AttackerID     string `json:"attacker_id"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	ModelVersion   string `json:"model_version"`
	PlannerVersion string `json:"planner_version"`
}

type policyDecisionV1 struct {
	Outcome        PolicyOutcome `json:"outcome"`
	PolicyVersion  string        `json:"policy_version"`
	ReasonCode     string        `json:"reason_code"`
	ApprovedAction *actionSpecV1 `json:"approved_action"`
}

type intentV1 struct {
	Envelope               envelopeV1       `json:"envelope"`
	Ordinal                uint32           `json:"ordinal"`
	StepID                 string           `json:"step_id"`
	Objective              string           `json:"objective"`
	Model                  modelIdentityV1  `json:"model_identity"`
	ProposedAction         actionSpecV1     `json:"proposed_action"`
	Policy                 policyDecisionV1 `json:"policy_decision"`
	EmittedAt              string           `json:"emitted_at"`
	CommittedAt            string           `json:"committed_at"`
	ClockSource            string           `json:"clock_source"`
	ClockUncertaintyMillis uint64           `json:"clock_uncertainty_ms"`
	PlannerOutputRef       string           `json:"planner_output_ref"`
	Budgets                budgetsV1        `json:"applicable_budgets"`
}

type responseMetadataV1 struct {
	StatusCode uint16 `json:"status_code"`
	Bytes      uint64 `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type actionV1 struct {
	Envelope               envelopeV1          `json:"envelope"`
	ParentIntentID         string              `json:"parent_intent_id"`
	Status                 ActionStatus        `json:"status"`
	Action                 actionSpecV1        `json:"action"`
	Attempted              bool                `json:"attempted"`
	StartedAt              *string             `json:"started_at"`
	EndedAt                *string             `json:"ended_at"`
	RecordedAt             string              `json:"recorded_at"`
	ClockSource            string              `json:"clock_source"`
	ClockUncertaintyMillis uint64              `json:"clock_uncertainty_ms"`
	ErrorCode              string              `json:"error_code"`
	ExecutorVersion        string              `json:"executor_version"`
	ToolPolicyVersion      string              `json:"tool_policy_version"`
	Response               *responseMetadataV1 `json:"response_metadata"`
	EvidenceRefs           []string            `json:"evidence_refs"`
	NetworkRefs            []string            `json:"network_refs"`
}

// MarshalScenarioV1 returns a deterministic standalone scenario record.
func MarshalScenarioV1(scenario Scenario) ([]byte, error) {
	if err := scenario.validate(); err != nil {
		return nil, fmt.Errorf("validate scenario: %w", err)
	}
	return marshalV1("scenario", toScenarioV1(scenario))
}

// UnmarshalScenarioV1 reconstructs and validates a standalone scenario.
func UnmarshalScenarioV1(blob []byte) (Scenario, error) {
	var wire scenarioV1
	if err := unmarshalV1("scenario", blob, &wire); err != nil {
		return Scenario{}, err
	}
	return scenarioFromV1(wire)
}

// MarshalAttackerIntentV1 returns a deterministic intent record only after
// binding it to the exact reviewed scenario. Executors can persist this blob
// before attempting the later action.
func MarshalAttackerIntentV1(scenario Scenario, intent AttackerIntent) ([]byte, error) {
	if err := intent.validateAgainst(scenario); err != nil {
		return nil, fmt.Errorf("validate intent: %w", err)
	}
	return marshalV1("intent", toIntentV1(intent))
}

// UnmarshalAttackerIntentV1 reconstructs an intent under its exact scenario.
func UnmarshalAttackerIntentV1(scenario Scenario, blob []byte) (AttackerIntent, error) {
	var wire intentV1
	if err := unmarshalV1("intent", blob, &wire); err != nil {
		return AttackerIntent{}, err
	}
	return intentFromV1(scenario, wire)
}

// MarshalAttackerActionV1 returns a deterministic action record bound to its
// already-persisted parent intent.
func MarshalAttackerActionV1(intent AttackerIntent, action AttackerAction) ([]byte, error) {
	if err := action.validateAgainst(intent); err != nil {
		return nil, fmt.Errorf("validate action: %w", err)
	}
	return marshalV1("action", toActionV1(action))
}

// UnmarshalAttackerActionV1 reconstructs an action under its parent intent.
func UnmarshalAttackerActionV1(intent AttackerIntent, blob []byte) (AttackerAction, error) {
	var wire actionV1
	if err := unmarshalV1("action", blob, &wire); err != nil {
		return AttackerAction{}, err
	}
	return actionFromV1(intent, wire)
}

// MarshalCorpusV1 returns deterministic, indented JSON suitable for the
// reviewable repository corpus. The trailing newline is part of every schema-
// v1 fixture format.
func MarshalCorpusV1(corpus Corpus) ([]byte, error) {
	canonical, err := NewCorpus(corpus.scenario, corpus.runID, corpus.seed, corpus.intents, corpus.actions)
	if err != nil {
		return nil, fmt.Errorf("validate corpus: %w", err)
	}
	if canonical.id != corpus.id {
		return nil, fmt.Errorf("corpus id does not match its canonical contents")
	}
	return marshalV1("corpus", toCorpusV1(canonical))
}

// UnmarshalCorpusV1 rejects unknown fields, trailing data, unsupported schema
// versions, and any record whose declared identity differs from reconstructed
// canonical semantics.
func UnmarshalCorpusV1(blob []byte) (Corpus, error) {
	var wire corpusV1
	if err := unmarshalV1("corpus", blob, &wire); err != nil {
		return Corpus{}, err
	}
	if wire.SchemaVersion != CurrentSchemaVersion {
		return Corpus{}, fmt.Errorf("unsupported corpus schema version %d", wire.SchemaVersion)
	}
	scenario, err := scenarioFromV1(wire.Scenario)
	if err != nil {
		return Corpus{}, err
	}
	intents := make([]AttackerIntent, 0, len(wire.Run.Intents))
	intentByID := make(map[string]AttackerIntent, len(wire.Run.Intents))
	for _, encoded := range wire.Run.Intents {
		intent, err := intentFromV1(scenario, encoded)
		if err != nil {
			return Corpus{}, err
		}
		intents = append(intents, intent)
		intentByID[intent.envelope.recordID] = intent
	}
	actions := make([]AttackerAction, 0, len(wire.Run.Actions))
	for _, encoded := range wire.Run.Actions {
		intent, ok := intentByID[encoded.ParentIntentID]
		if !ok {
			return Corpus{}, fmt.Errorf("action cites unknown parent intent %q", encoded.ParentIntentID)
		}
		action, err := actionFromV1(intent, encoded)
		if err != nil {
			return Corpus{}, err
		}
		actions = append(actions, action)
	}
	corpus, err := NewCorpus(scenario, wire.Run.RunID, wire.Run.Seed, intents, actions)
	if err != nil {
		return Corpus{}, fmt.Errorf("validate corpus: %w", err)
	}
	if corpus.id != wire.CorpusID {
		return Corpus{}, fmt.Errorf("corpus id does not match reconstructed contents")
	}
	return corpus, nil
}

func marshalV1(label string, wire any) ([]byte, error) {
	blob, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", label, err)
	}
	if len(blob)+1 > MaximumCorpusBytes {
		return nil, fmt.Errorf("canonical %s exceeds the %d-byte schema-v1 limit", label, MaximumCorpusBytes)
	}
	return append(blob, '\n'), nil
}

func unmarshalV1(label string, blob []byte, target any) error {
	if len(blob) == 0 || len(blob) > MaximumCorpusBytes {
		return fmt.Errorf("%s input must be between 1 and %d bytes", label, MaximumCorpusBytes)
	}
	if err := rejectDuplicateObjectKeys(blob); err != nil {
		return fmt.Errorf("inspect %s JSON object keys: %w", label, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	return requireEOF(decoder)
}

func rejectDuplicateObjectKeys(blob []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(blob))
	return scanJSONValue(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("JSON object has unexpected closing token %v", closing)
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("JSON array has unexpected closing token %v", closing)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value is not allowed")
		}
		return fmt.Errorf("decode trailing data: %w", err)
	}
	return nil
}

func toCorpusV1(corpus Corpus) corpusV1 {
	intents := make([]intentV1, len(corpus.intents))
	for index, intent := range corpus.intents {
		intents[index] = toIntentV1(intent)
	}
	actions := make([]actionV1, len(corpus.actions))
	for index, action := range corpus.actions {
		actions[index] = toActionV1(action)
	}
	return corpusV1{
		SchemaVersion: CurrentSchemaVersion, CorpusID: corpus.id,
		Scenario: toScenarioV1(corpus.scenario),
		Run:      runV1{RunID: corpus.runID, Seed: corpus.seed, Intents: intents, Actions: actions},
	}
}

func toEnvelopeV1(envelope Envelope) envelopeV1 {
	lineage := make([]recordReferenceV1, len(envelope.lineage))
	for index, reference := range envelope.lineage {
		lineage[index] = recordReferenceV1{Kind: reference.kind, ID: reference.id, SchemaVersion: reference.schemaVersion}
	}
	return envelopeV1{
		SchemaVersion: CurrentSchemaVersion, RecordID: envelope.recordID, RecordKind: envelope.recordKind,
		DataClass: DataClass, Sensitivity: Sensitivity, Synthetic: true, LabDomain: LabDomain,
		Scope: scopeV1{
			Domain: LabDomain, TenantID: envelope.scope.tenantID, ScopeID: envelope.scope.scopeID,
			DeploymentBoundary: envelope.scope.deploymentBoundary, ResidencyCellID: envelope.scope.residencyCellID,
			KeyNamespace: envelope.scope.keyNamespace, RegistryNamespace: envelope.scope.registryNamespace,
		},
		ScenarioID: envelope.scenarioID, ScenarioVersion: envelope.scenarioVersion, RunID: envelope.runID,
		RecordedAt: formatTime(envelope.recordedAt), RetentionPolicy: RetentionPolicy, ExpiresAt: nil,
		CorpusReviewDue: formatTime(envelope.corpusReviewDue), LifecycleOwner: LifecycleOwner,
		LifecyclePolicyVersion: envelope.lifecyclePolicyVersion, ResidencyPolicyRef: envelope.residencyPolicyRef,
		EncryptionKeyRef: envelope.encryptionKeyRef, OperationalPolicyRef: OperationalPolicy,
		PerTenantModelUse: ModelUsePolicy, CrossTenantModelUse: ModelUsePolicy,
		EstimatedStorageBytes: envelope.estimatedStorageBytes, EstimateBasis: envelope.estimateBasis,
		Lineage: lineage,
	}
}

func toBudgetsV1(budgets Budgets) budgetsV1 {
	return budgetsV1{
		MaxActions: budgets.maxActions, MaxDurationMillis: uint64(budgets.maxDuration.Milliseconds()),
		MaxConcurrency: budgets.maxConcurrency, MaxRequestBytes: budgets.maxRequestBytes,
		MaxResponseBytes: budgets.maxResponseBytes, MaxModelTokens: budgets.maxModelTokens,
	}
}

func toActionSpecV1(action ActionSpec) actionSpecV1 {
	return actionSpecV1{
		Tool: action.tool, TargetAlias: action.targetAlias, TargetRef: action.targetRef,
		Operation: action.operation, InputFixture: action.inputFixture, CredentialRef: action.credentialRef,
	}
}

func toScenarioV1(scenario Scenario) scenarioV1 {
	targets := make([]targetV1, len(scenario.targets))
	for index, target := range scenario.targets {
		targets[index] = targetV1{Alias: target.alias, Reference: target.reference, FixtureRef: target.fixtureRef}
	}
	constraints := make([]toolConstraintV1, len(scenario.toolConstraints))
	for index, constraint := range scenario.toolConstraints {
		constraints[index] = toolConstraintV1{
			Tool: constraint.tool, AllowedOperations: append([]string(nil), constraint.allowedOperations...),
			MaxActions: constraint.maxActions, MaxRequestBytes: constraint.maxRequestBytes,
			MaxResponseBytes: constraint.maxResponseBytes,
		}
	}
	steps := make([]stepV1, len(scenario.steps))
	for index, step := range scenario.steps {
		actions := make([]actionSpecV1, len(step.allowedActions))
		for actionIndex, action := range step.allowedActions {
			actions[actionIndex] = toActionSpecV1(action)
		}
		steps[index] = stepV1{ID: step.id, Sequence: step.sequence, Objective: step.objective, AllowedActions: actions}
	}
	return scenarioV1{
		Envelope: toEnvelopeV1(scenario.envelope), SemanticSHA256: scenario.semanticDigest(),
		Name: scenario.name, Objective: scenario.objective,
		Safety: scenario.safety, ExecutionMode: scenario.executionMode,
		RequiredFixtures: append([]string(nil), scenario.requiredFixtures...), Targets: targets,
		ToolConstraints: constraints, Steps: steps, Budgets: toBudgetsV1(scenario.budgets),
		ExpectedTelemetry: append([]string(nil), scenario.expectedTelemetry...),
	}
}

func toIntentV1(intent AttackerIntent) intentV1 {
	var approved *actionSpecV1
	if action, ok := intent.policy.ApprovedAction(); ok {
		wire := toActionSpecV1(action)
		approved = &wire
	}
	return intentV1{
		Envelope: toEnvelopeV1(intent.envelope), Ordinal: intent.ordinal, StepID: intent.stepID,
		Objective: intent.objective,
		Model: modelIdentityV1{
			AttackerID: intent.model.attackerID, Provider: intent.model.provider, Model: intent.model.model,
			ModelVersion: intent.model.modelVersion, PlannerVersion: intent.model.plannerVersion,
		},
		ProposedAction: toActionSpecV1(intent.proposedAction),
		Policy: policyDecisionV1{
			Outcome: intent.policy.outcome, PolicyVersion: intent.policy.policyVersion,
			ReasonCode: intent.policy.reasonCode, ApprovedAction: approved,
		},
		EmittedAt: formatTime(intent.emittedAt), CommittedAt: formatTime(intent.committedAt),
		ClockSource: intent.clockSource, ClockUncertaintyMillis: intent.clockUncertaintyMillis,
		PlannerOutputRef: intent.plannerOutputRef, Budgets: toBudgetsV1(intent.budgets),
	}
}

func toActionV1(action AttackerAction) actionV1 {
	var startedAt, endedAt *string
	if !action.startedAt.IsZero() {
		value := formatTime(action.startedAt)
		startedAt = &value
	}
	if !action.endedAt.IsZero() {
		value := formatTime(action.endedAt)
		endedAt = &value
	}
	var response *responseMetadataV1
	if action.response != nil {
		response = &responseMetadataV1{StatusCode: action.response.statusCode, Bytes: action.response.bytes, SHA256: action.response.sha256}
	}
	return actionV1{
		Envelope: toEnvelopeV1(action.envelope), ParentIntentID: action.parentIntentID,
		Status: action.status, Action: toActionSpecV1(action.action), Attempted: action.attempted,
		StartedAt: startedAt, EndedAt: endedAt, RecordedAt: formatTime(action.recordedAt),
		ClockSource: action.clockSource, ClockUncertaintyMillis: action.clockUncertaintyMillis,
		ErrorCode: action.errorCode, ExecutorVersion: action.executorVersion,
		ToolPolicyVersion: action.toolPolicyVersion, Response: response,
		EvidenceRefs: append([]string{}, action.evidenceRefs...), NetworkRefs: append([]string{}, action.networkRefs...),
	}
}

func scenarioFromV1(wire scenarioV1) (Scenario, error) {
	scope, err := scopeFromV1(wire.Envelope.Scope)
	if err != nil {
		return Scenario{}, err
	}
	targets := make([]Target, 0, len(wire.Targets))
	for _, encoded := range wire.Targets {
		target, err := NewTarget(TargetInput{Alias: encoded.Alias, Reference: encoded.Reference, FixtureRef: encoded.FixtureRef})
		if err != nil {
			return Scenario{}, fmt.Errorf("decode target: %w", err)
		}
		targets = append(targets, target)
	}
	constraints := make([]ToolConstraint, 0, len(wire.ToolConstraints))
	for _, encoded := range wire.ToolConstraints {
		constraint, err := NewToolConstraint(ToolConstraintInput{
			Tool: encoded.Tool, AllowedOperations: encoded.AllowedOperations, MaxActions: encoded.MaxActions,
			MaxRequestBytes: encoded.MaxRequestBytes, MaxResponseBytes: encoded.MaxResponseBytes,
		})
		if err != nil {
			return Scenario{}, fmt.Errorf("decode tool constraint: %w", err)
		}
		constraints = append(constraints, constraint)
	}
	steps := make([]Step, 0, len(wire.Steps))
	for _, encoded := range wire.Steps {
		actions := make([]ActionSpec, 0, len(encoded.AllowedActions))
		for _, actionWire := range encoded.AllowedActions {
			action, err := actionSpecFromV1(actionWire)
			if err != nil {
				return Scenario{}, fmt.Errorf("decode allowed action: %w", err)
			}
			actions = append(actions, action)
		}
		step, err := NewStep(StepInput{ID: encoded.ID, Sequence: encoded.Sequence, Objective: encoded.Objective, AllowedActions: actions})
		if err != nil {
			return Scenario{}, fmt.Errorf("decode step: %w", err)
		}
		steps = append(steps, step)
	}
	budgets, err := budgetsFromV1(wire.Budgets)
	if err != nil {
		return Scenario{}, err
	}
	recordedAt, err := parseTime("scenario recorded_at", wire.Envelope.RecordedAt)
	if err != nil {
		return Scenario{}, err
	}
	reviewDue, err := parseTime("scenario corpus_review_due", wire.Envelope.CorpusReviewDue)
	if err != nil {
		return Scenario{}, err
	}
	scenario, err := NewScenario(ScenarioInput{
		Scope: scope, ID: wire.Envelope.ScenarioID, Version: wire.Envelope.ScenarioVersion,
		Name: wire.Name, Objective: wire.Objective, Safety: wire.Safety, ExecutionMode: wire.ExecutionMode,
		RequiredFixtures: wire.RequiredFixtures, Targets: targets, ToolConstraints: constraints,
		Steps: steps, Budgets: budgets, ExpectedTelemetry: wire.ExpectedTelemetry,
		RecordedAt: recordedAt, CorpusReviewDue: reviewDue,
		LifecyclePolicyVersion: wire.Envelope.LifecyclePolicyVersion,
		ResidencyPolicyRef:     wire.Envelope.ResidencyPolicyRef,
		EncryptionKeyRef:       wire.Envelope.EncryptionKeyRef,
		EstimatedStorageBytes:  wire.Envelope.EstimatedStorageBytes, EstimateBasis: wire.Envelope.EstimateBasis,
	})
	if err != nil {
		return Scenario{}, fmt.Errorf("decode scenario: %w", err)
	}
	if err := requireEnvelope(wire.Envelope, scenario.envelope); err != nil {
		return Scenario{}, fmt.Errorf("scenario envelope: %w", err)
	}
	if wire.SemanticSHA256 != scenario.semanticDigest() {
		return Scenario{}, fmt.Errorf("scenario semantic digest does not match reconstructed contents")
	}
	return scenario, nil
}

func intentFromV1(scenario Scenario, wire intentV1) (AttackerIntent, error) {
	modelIdentity, err := NewModelIdentity(ModelIdentityInput{
		AttackerID: wire.Model.AttackerID, Provider: wire.Model.Provider, Model: wire.Model.Model,
		ModelVersion: wire.Model.ModelVersion, PlannerVersion: wire.Model.PlannerVersion,
	})
	if err != nil {
		return AttackerIntent{}, err
	}
	proposed, err := actionSpecFromV1(wire.ProposedAction)
	if err != nil {
		return AttackerIntent{}, err
	}
	var approved *ActionSpec
	if wire.Policy.ApprovedAction != nil {
		value, err := actionSpecFromV1(*wire.Policy.ApprovedAction)
		if err != nil {
			return AttackerIntent{}, err
		}
		approved = &value
	}
	policy, err := NewPolicyDecision(PolicyDecisionInput{
		Outcome: wire.Policy.Outcome, PolicyVersion: wire.Policy.PolicyVersion,
		ReasonCode: wire.Policy.ReasonCode, ApprovedAction: approved,
	})
	if err != nil {
		return AttackerIntent{}, err
	}
	emittedAt, err := parseTime("intent emitted_at", wire.EmittedAt)
	if err != nil {
		return AttackerIntent{}, err
	}
	committedAt, err := parseTime("intent committed_at", wire.CommittedAt)
	if err != nil {
		return AttackerIntent{}, err
	}
	intent, err := NewAttackerIntent(AttackerIntentInput{
		Scenario: scenario, RunID: wire.Envelope.RunID, Ordinal: wire.Ordinal, StepID: wire.StepID,
		Objective: wire.Objective, Model: modelIdentity, ProposedAction: proposed, Policy: policy,
		EmittedAt: emittedAt, CommittedAt: committedAt, ClockSource: wire.ClockSource,
		ClockUncertaintyMillis: wire.ClockUncertaintyMillis, PlannerOutputRef: wire.PlannerOutputRef,
		EstimatedStorageBytes: wire.Envelope.EstimatedStorageBytes, EstimateBasis: wire.Envelope.EstimateBasis,
	})
	if err != nil {
		return AttackerIntent{}, fmt.Errorf("decode intent: %w", err)
	}
	if !reflect.DeepEqual(wire.Budgets, toBudgetsV1(intent.budgets)) {
		return AttackerIntent{}, fmt.Errorf("intent applicable budgets differ from its scenario")
	}
	if err := requireEnvelope(wire.Envelope, intent.envelope); err != nil {
		return AttackerIntent{}, fmt.Errorf("intent envelope: %w", err)
	}
	return intent, nil
}

func actionFromV1(intent AttackerIntent, wire actionV1) (AttackerAction, error) {
	actionSpec, err := actionSpecFromV1(wire.Action)
	if err != nil {
		return AttackerAction{}, err
	}
	startedAt, err := parseOptionalTime("action started_at", wire.StartedAt)
	if err != nil {
		return AttackerAction{}, err
	}
	endedAt, err := parseOptionalTime("action ended_at", wire.EndedAt)
	if err != nil {
		return AttackerAction{}, err
	}
	recordedAt, err := parseTime("action recorded_at", wire.RecordedAt)
	if err != nil {
		return AttackerAction{}, err
	}
	var response *ResponseMetadata
	if wire.Response != nil {
		value, err := NewResponseMetadata(ResponseMetadataInput{
			StatusCode: wire.Response.StatusCode, Bytes: wire.Response.Bytes, SHA256: wire.Response.SHA256,
		})
		if err != nil {
			return AttackerAction{}, err
		}
		response = &value
	}
	action, err := NewAttackerAction(AttackerActionInput{
		Intent: intent, Status: wire.Status, Action: actionSpec, Attempted: wire.Attempted,
		StartedAt: startedAt, EndedAt: endedAt, RecordedAt: recordedAt,
		ClockSource: wire.ClockSource, ClockUncertaintyMillis: wire.ClockUncertaintyMillis,
		ErrorCode: wire.ErrorCode, ExecutorVersion: wire.ExecutorVersion,
		ToolPolicyVersion: wire.ToolPolicyVersion, Response: response,
		EvidenceRefs: wire.EvidenceRefs, NetworkRefs: wire.NetworkRefs,
		EstimatedStorageBytes: wire.Envelope.EstimatedStorageBytes, EstimateBasis: wire.Envelope.EstimateBasis,
	})
	if err != nil {
		return AttackerAction{}, fmt.Errorf("decode action: %w", err)
	}
	if wire.ParentIntentID != intent.envelope.recordID {
		return AttackerAction{}, fmt.Errorf("action parent does not match its reconstructed intent")
	}
	if err := requireEnvelope(wire.Envelope, action.envelope); err != nil {
		return AttackerAction{}, fmt.Errorf("action envelope: %w", err)
	}
	return action, nil
}

func actionSpecFromV1(wire actionSpecV1) (ActionSpec, error) {
	return NewActionSpec(ActionSpecInput{
		Tool: wire.Tool, TargetAlias: wire.TargetAlias, TargetRef: wire.TargetRef,
		Operation: wire.Operation, InputFixture: wire.InputFixture, CredentialRef: wire.CredentialRef,
	})
}

func budgetsFromV1(wire budgetsV1) (Budgets, error) {
	if wire.MaxDurationMillis == 0 || wire.MaxDurationMillis > uint64((24*time.Hour).Milliseconds()) {
		return Budgets{}, fmt.Errorf("max duration milliseconds are outside the supported bound")
	}
	return NewBudgets(BudgetsInput{
		MaxActions: wire.MaxActions, MaxDuration: time.Duration(wire.MaxDurationMillis) * time.Millisecond,
		MaxConcurrency: wire.MaxConcurrency, MaxRequestBytes: wire.MaxRequestBytes,
		MaxResponseBytes: wire.MaxResponseBytes, MaxModelTokens: wire.MaxModelTokens,
	})
}

func scopeFromV1(wire scopeV1) (Scope, error) {
	if wire.Domain != LabDomain {
		return Scope{}, fmt.Errorf("scope domain must be %q", LabDomain)
	}
	return NewScope(ScopeInput{
		TenantID: wire.TenantID, ScopeID: wire.ScopeID, DeploymentBoundary: wire.DeploymentBoundary,
		ResidencyCellID: wire.ResidencyCellID, KeyNamespace: wire.KeyNamespace,
		RegistryNamespace: wire.RegistryNamespace,
	})
}

func requireEnvelope(wire envelopeV1, canonical Envelope) error {
	if !reflect.DeepEqual(wire, toEnvelopeV1(canonical)) {
		return fmt.Errorf("declared classification, scope, lifecycle, lineage, or identity differs from canonical values")
	}
	return nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(label, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", label, err)
	}
	if value != formatTime(parsed) {
		return time.Time{}, fmt.Errorf("%s must be canonical UTC RFC3339Nano", label)
	}
	return parsed.UTC(), nil
}

func parseOptionalTime(label string, value *string) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	return parseTime(label, *value)
}
