package groundtruth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// CurrentSchemaVersion is independent of the CanaryView observation schema
	// and of any future external protobuf package version.
	CurrentSchemaVersion uint32 = 1

	LabDomain         = "canaryattacker-development"
	DataClass         = "SYNTHETIC_GROUND_TRUTH"
	Sensitivity       = "INTERNAL"
	RetentionPolicy   = "INDEFINITE_VERSIONED_CORPUS"
	LifecycleOwner    = "canaryattacker-development-laboratory"
	OperationalPolicy = "canaryattacker-lab-evaluation-only-v1"
	ModelUsePolicy    = "DISABLED"
	// MaximumCorpusBytes bounds schema-v1 input before JSON allocation grows
	// with attacker-controlled collection sizes.
	MaximumCorpusBytes         = 32 << 20
	maximumConfiguredElements  = 1024
	maximumReferencesPerRecord = 32
)

type RecordKind string

const (
	RecordScenario RecordKind = "SCENARIO"
	RecordIntent   RecordKind = "ATTACKER_INTENT"
	RecordAction   RecordKind = "ATTACKER_ACTION"
)

func (k RecordKind) valid() bool {
	return k == RecordScenario || k == RecordIntent || k == RecordAction
}

type SafetyClass string

const (
	SafetyHarmlessLab SafetyClass = "HARMLESS_LAB_ONLY"
)

func (s SafetyClass) valid() bool { return s == SafetyHarmlessLab }

type ExecutionMode string

const (
	ExecutionOrdered         ExecutionMode = "ORDERED"
	ExecutionBoundedAdaptive ExecutionMode = "BOUNDED_ADAPTIVE"
)

func (m ExecutionMode) valid() bool {
	return m == ExecutionOrdered || m == ExecutionBoundedAdaptive
}

type ToolName string

const (
	ToolHTTPRequest       ToolName = "http_request"
	ToolDNSLookup         ToolName = "dns_lookup"
	ToolTCPConnect        ToolName = "tcp_connect"
	ToolEnumerateEndpoint ToolName = "enumerate_endpoint"
	ToolFollowLink        ToolName = "follow_link"
	ToolTryCredential     ToolName = "try_credential"
	ToolInspectResponse   ToolName = "inspect_response"
)

func (t ToolName) valid() bool {
	switch t {
	case ToolHTTPRequest, ToolDNSLookup, ToolTCPConnect, ToolEnumerateEndpoint,
		ToolFollowLink, ToolTryCredential, ToolInspectResponse:
		return true
	default:
		return false
	}
}

type PolicyOutcome string

const (
	PolicyApproved PolicyOutcome = "APPROVED"
	PolicyDenied   PolicyOutcome = "DENIED"
)

func (o PolicyOutcome) valid() bool { return o == PolicyApproved || o == PolicyDenied }

type ActionStatus string

const (
	ActionSucceeded ActionStatus = "SUCCEEDED"
	ActionFailed    ActionStatus = "FAILED"
	ActionDenied    ActionStatus = "DENIED"
	ActionCancelled ActionStatus = "CANCELLED"
)

func (s ActionStatus) valid() bool {
	switch s {
	case ActionSucceeded, ActionFailed, ActionDenied, ActionCancelled:
		return true
	default:
		return false
	}
}

type EstimateBasis string

const (
	EstimateAssumed     EstimateBasis = "ASSUMED"
	EstimateMeasured    EstimateBasis = "MEASURED"
	EstimateBenchmarked EstimateBasis = "BENCHMARKED"
)

func (b EstimateBasis) valid() bool {
	return b == EstimateAssumed || b == EstimateMeasured || b == EstimateBenchmarked
}

// Scope is an exact internal laboratory boundary. The fixed Domain prevents a
// missing classification from silently becoming a customer/production scope.
type Scope struct {
	tenantID           string
	scopeID            string
	deploymentBoundary string
	residencyCellID    string
	keyNamespace       string
	registryNamespace  string
}

type ScopeInput struct {
	TenantID           string
	ScopeID            string
	DeploymentBoundary string
	ResidencyCellID    string
	KeyNamespace       string
	RegistryNamespace  string
}

func NewScope(in ScopeInput) (Scope, error) {
	for _, field := range []struct{ label, value string }{
		{"tenant id", in.TenantID}, {"scope id", in.ScopeID},
		{"deployment boundary", in.DeploymentBoundary}, {"residency cell id", in.ResidencyCellID},
		{"key namespace", in.KeyNamespace}, {"registry namespace", in.RegistryNamespace},
	} {
		if err := identifier(field.label, field.value); err != nil {
			return Scope{}, err
		}
	}
	return Scope{
		tenantID: in.TenantID, scopeID: in.ScopeID, deploymentBoundary: in.DeploymentBoundary,
		residencyCellID: in.ResidencyCellID, keyNamespace: in.KeyNamespace,
		registryNamespace: in.RegistryNamespace,
	}, nil
}

func (s Scope) Domain() string             { return LabDomain }
func (s Scope) TenantID() string           { return s.tenantID }
func (s Scope) ScopeID() string            { return s.scopeID }
func (s Scope) DeploymentBoundary() string { return s.deploymentBoundary }
func (s Scope) ResidencyCellID() string    { return s.residencyCellID }
func (s Scope) KeyNamespace() string       { return s.keyNamespace }
func (s Scope) RegistryNamespace() string  { return s.registryNamespace }

func (s Scope) validate() error {
	_, err := NewScope(ScopeInput{
		TenantID: s.tenantID, ScopeID: s.scopeID, DeploymentBoundary: s.deploymentBoundary,
		ResidencyCellID: s.residencyCellID, KeyNamespace: s.keyNamespace,
		RegistryNamespace: s.registryNamespace,
	})
	return err
}

func sameScope(left, right Scope) bool { return left == right }

// RecordReference is a versioned, payload-free lineage reference.
type RecordReference struct {
	kind          RecordKind
	id            string
	schemaVersion uint32
}

func newRecordReference(kind RecordKind, id string) RecordReference {
	return RecordReference{kind: kind, id: id, schemaVersion: CurrentSchemaVersion}
}

func (r RecordReference) Kind() RecordKind      { return r.kind }
func (r RecordReference) ID() string            { return r.id }
func (r RecordReference) SchemaVersion() uint32 { return r.schemaVersion }

func (r RecordReference) validate() error {
	if !r.kind.valid() {
		return fmt.Errorf("unsupported record kind %q", r.kind)
	}
	if err := recordID(r.kind, r.id); err != nil {
		return err
	}
	if r.schemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported record reference schema version %d", r.schemaVersion)
	}
	return nil
}

// Envelope carries the immutable classification, lifecycle, scope, and direct
// lineage shared by every durable ground-truth record. Synthetic corpus records
// have no expiry and both production model-use grants are permanently disabled.
type Envelope struct {
	recordID               string
	recordKind             RecordKind
	scope                  Scope
	scenarioID             string
	scenarioVersion        uint32
	runID                  string
	recordedAt             time.Time
	corpusReviewDue        time.Time
	lifecyclePolicyVersion string
	residencyPolicyRef     string
	encryptionKeyRef       string
	estimatedStorageBytes  uint64
	estimateBasis          EstimateBasis
	lineage                []RecordReference
}

type envelopeInput struct {
	recordID               string
	recordKind             RecordKind
	scope                  Scope
	scenarioID             string
	scenarioVersion        uint32
	runID                  string
	recordedAt             time.Time
	corpusReviewDue        time.Time
	lifecyclePolicyVersion string
	residencyPolicyRef     string
	encryptionKeyRef       string
	estimatedStorageBytes  uint64
	estimateBasis          EstimateBasis
	lineage                []RecordReference
}

func newEnvelope(in envelopeInput) (Envelope, error) {
	if !in.recordKind.valid() {
		return Envelope{}, fmt.Errorf("unsupported record kind %q", in.recordKind)
	}
	if err := recordID(in.recordKind, in.recordID); err != nil {
		return Envelope{}, err
	}
	if err := in.scope.validate(); err != nil {
		return Envelope{}, fmt.Errorf("scope: %w", err)
	}
	if err := identifier("scenario id", in.scenarioID); err != nil {
		return Envelope{}, err
	}
	if in.scenarioVersion == 0 {
		return Envelope{}, fmt.Errorf("scenario version is required")
	}
	if in.recordKind == RecordScenario {
		if in.runID != "" {
			return Envelope{}, fmt.Errorf("scenario record cannot carry a run id")
		}
	} else if err := identifier("run id", in.runID); err != nil {
		return Envelope{}, err
	}
	if in.recordedAt.IsZero() || in.corpusReviewDue.IsZero() {
		return Envelope{}, fmt.Errorf("recorded time and corpus review due time are required")
	}
	if !in.corpusReviewDue.After(in.recordedAt) {
		return Envelope{}, fmt.Errorf("corpus review must be after record creation")
	}
	if err := identifier("lifecycle policy version", in.lifecyclePolicyVersion); err != nil {
		return Envelope{}, err
	}
	if err := identifier("residency policy reference", in.residencyPolicyRef); err != nil {
		return Envelope{}, err
	}
	if err := opaqueReference("encryption key reference", in.encryptionKeyRef, "keyref:sha256:"); err != nil {
		return Envelope{}, err
	}
	if in.estimatedStorageBytes == 0 {
		return Envelope{}, fmt.Errorf("estimated storage bytes must be greater than zero")
	}
	if !in.estimateBasis.valid() {
		return Envelope{}, fmt.Errorf("unsupported estimate basis %q", in.estimateBasis)
	}
	lineage := append([]RecordReference(nil), in.lineage...)
	sort.Slice(lineage, func(i, j int) bool {
		if lineage[i].kind == lineage[j].kind {
			return lineage[i].id < lineage[j].id
		}
		return lineage[i].kind < lineage[j].kind
	})
	for index, reference := range lineage {
		if err := reference.validate(); err != nil {
			return Envelope{}, fmt.Errorf("lineage: %w", err)
		}
		if reference.id == in.recordID {
			return Envelope{}, fmt.Errorf("record cannot cite itself in direct lineage")
		}
		if index > 0 && lineage[index-1] == reference {
			return Envelope{}, fmt.Errorf("duplicate lineage reference %q", reference.id)
		}
	}
	return Envelope{
		recordID: in.recordID, recordKind: in.recordKind, scope: in.scope,
		scenarioID: in.scenarioID, scenarioVersion: in.scenarioVersion, runID: in.runID,
		recordedAt: in.recordedAt.UTC(), corpusReviewDue: in.corpusReviewDue.UTC(),
		lifecyclePolicyVersion: in.lifecyclePolicyVersion, residencyPolicyRef: in.residencyPolicyRef,
		encryptionKeyRef: in.encryptionKeyRef, estimatedStorageBytes: in.estimatedStorageBytes,
		estimateBasis: in.estimateBasis, lineage: lineage,
	}, nil
}

func (e Envelope) RecordID() string               { return e.recordID }
func (e Envelope) RecordKind() RecordKind         { return e.recordKind }
func (e Envelope) SchemaVersion() uint32          { return CurrentSchemaVersion }
func (e Envelope) DataClass() string              { return DataClass }
func (e Envelope) Sensitivity() string            { return Sensitivity }
func (e Envelope) Synthetic() bool                { return true }
func (e Envelope) LabDomain() string              { return LabDomain }
func (e Envelope) Scope() Scope                   { return e.scope }
func (e Envelope) ScenarioID() string             { return e.scenarioID }
func (e Envelope) ScenarioVersion() uint32        { return e.scenarioVersion }
func (e Envelope) RunID() string                  { return e.runID }
func (e Envelope) RecordedAt() time.Time          { return e.recordedAt }
func (e Envelope) RetentionPolicy() string        { return RetentionPolicy }
func (e Envelope) ExpiresAt() *time.Time          { return nil }
func (e Envelope) CorpusReviewDue() time.Time     { return e.corpusReviewDue }
func (e Envelope) LifecycleOwner() string         { return LifecycleOwner }
func (e Envelope) LifecyclePolicyVersion() string { return e.lifecyclePolicyVersion }
func (e Envelope) ResidencyPolicyRef() string     { return e.residencyPolicyRef }
func (e Envelope) EncryptionKeyRef() string       { return e.encryptionKeyRef }
func (e Envelope) OperationalPolicyRef() string   { return OperationalPolicy }
func (e Envelope) PerTenantModelUse() string      { return ModelUsePolicy }
func (e Envelope) CrossTenantModelUse() string    { return ModelUsePolicy }
func (e Envelope) EstimatedStorageBytes() uint64  { return e.estimatedStorageBytes }
func (e Envelope) EstimateBasis() EstimateBasis   { return e.estimateBasis }
func (e Envelope) Lineage() []RecordReference     { return append([]RecordReference(nil), e.lineage...) }

func (e Envelope) validate() error {
	_, err := newEnvelope(envelopeInput{
		recordID: e.recordID, recordKind: e.recordKind, scope: e.scope,
		scenarioID: e.scenarioID, scenarioVersion: e.scenarioVersion, runID: e.runID,
		recordedAt: e.recordedAt, corpusReviewDue: e.corpusReviewDue,
		lifecyclePolicyVersion: e.lifecyclePolicyVersion, residencyPolicyRef: e.residencyPolicyRef,
		encryptionKeyRef: e.encryptionKeyRef, estimatedStorageBytes: e.estimatedStorageBytes,
		estimateBasis: e.estimateBasis, lineage: e.lineage,
	})
	return err
}

type Budgets struct {
	maxActions       uint32
	maxDuration      time.Duration
	maxConcurrency   uint32
	maxRequestBytes  uint64
	maxResponseBytes uint64
	maxModelTokens   uint64
}

type BudgetsInput struct {
	MaxActions       uint32
	MaxDuration      time.Duration
	MaxConcurrency   uint32
	MaxRequestBytes  uint64
	MaxResponseBytes uint64
	MaxModelTokens   uint64
}

func NewBudgets(in BudgetsInput) (Budgets, error) {
	if in.MaxActions == 0 || in.MaxActions > maximumConfiguredElements {
		return Budgets{}, fmt.Errorf("max actions must be between 1 and %d", maximumConfiguredElements)
	}
	if in.MaxDuration < time.Millisecond || in.MaxDuration > 24*time.Hour || in.MaxDuration%time.Millisecond != 0 {
		return Budgets{}, fmt.Errorf("max duration must be a whole number of milliseconds between 1ms and 24h")
	}
	if in.MaxConcurrency == 0 || in.MaxConcurrency > 32 || in.MaxConcurrency > in.MaxActions {
		return Budgets{}, fmt.Errorf("max concurrency must be between 1 and min(32, max actions)")
	}
	for _, field := range []struct {
		label string
		value uint64
	}{
		{"max request bytes", in.MaxRequestBytes}, {"max response bytes", in.MaxResponseBytes},
		{"max model tokens", in.MaxModelTokens},
	} {
		if field.value == 0 || field.value > 1<<30 {
			return Budgets{}, fmt.Errorf("%s must be between 1 and %d", field.label, uint64(1<<30))
		}
	}
	return Budgets{
		maxActions: in.MaxActions, maxDuration: in.MaxDuration, maxConcurrency: in.MaxConcurrency,
		maxRequestBytes: in.MaxRequestBytes, maxResponseBytes: in.MaxResponseBytes,
		maxModelTokens: in.MaxModelTokens,
	}, nil
}

func (b Budgets) MaxActions() uint32         { return b.maxActions }
func (b Budgets) MaxDuration() time.Duration { return b.maxDuration }
func (b Budgets) MaxConcurrency() uint32     { return b.maxConcurrency }
func (b Budgets) MaxRequestBytes() uint64    { return b.maxRequestBytes }
func (b Budgets) MaxResponseBytes() uint64   { return b.maxResponseBytes }
func (b Budgets) MaxModelTokens() uint64     { return b.maxModelTokens }

func (b Budgets) validate() error {
	_, err := NewBudgets(BudgetsInput{
		MaxActions: b.maxActions, MaxDuration: b.maxDuration, MaxConcurrency: b.maxConcurrency,
		MaxRequestBytes: b.maxRequestBytes, MaxResponseBytes: b.maxResponseBytes,
		MaxModelTokens: b.maxModelTokens,
	})
	return err
}

type Target struct {
	alias      string
	reference  string
	fixtureRef string
}

type TargetInput struct {
	Alias      string
	Reference  string
	FixtureRef string
}

func NewTarget(in TargetInput) (Target, error) {
	if err := identifier("target alias", in.Alias); err != nil {
		return Target{}, err
	}
	if err := opaqueReference("target reference", in.Reference, "labtarget:sha256:"); err != nil {
		return Target{}, err
	}
	if err := opaqueReference("target fixture reference", in.FixtureRef, "fixture:sha256:"); err != nil {
		return Target{}, err
	}
	return Target{alias: in.Alias, reference: in.Reference, fixtureRef: in.FixtureRef}, nil
}

func (t Target) Alias() string      { return t.alias }
func (t Target) Reference() string  { return t.reference }
func (t Target) FixtureRef() string { return t.fixtureRef }

func (t Target) validate() error {
	_, err := NewTarget(TargetInput{Alias: t.alias, Reference: t.reference, FixtureRef: t.fixtureRef})
	return err
}

// ActionSpec carries only normalized, non-secret identifiers. Payloads,
// credentials, URLs, addresses, headers, and response bodies are deliberately
// absent; later executors resolve approved fixture references outside the model.
type ActionSpec struct {
	tool          ToolName
	targetAlias   string
	targetRef     string
	operation     string
	inputFixture  string
	credentialRef string
}

type ActionSpecInput struct {
	Tool          ToolName
	TargetAlias   string
	TargetRef     string
	Operation     string
	InputFixture  string
	CredentialRef string
}

func NewActionSpec(in ActionSpecInput) (ActionSpec, error) {
	if err := identifier("tool name", string(in.Tool)); err != nil {
		return ActionSpec{}, err
	}
	if err := identifier("target alias", in.TargetAlias); err != nil {
		return ActionSpec{}, err
	}
	if err := opaqueReference("target reference", in.TargetRef, "labtarget:sha256:"); err != nil {
		return ActionSpec{}, err
	}
	if err := identifier("operation", in.Operation); err != nil {
		return ActionSpec{}, err
	}
	if in.InputFixture != "" {
		if err := opaqueReference("input fixture reference", in.InputFixture, "fixture:sha256:"); err != nil {
			return ActionSpec{}, err
		}
	}
	if in.CredentialRef != "" {
		if err := opaqueReference("credential fixture reference", in.CredentialRef, "fixture:sha256:"); err != nil {
			return ActionSpec{}, err
		}
	}
	return ActionSpec{
		tool: in.Tool, targetAlias: in.TargetAlias, targetRef: in.TargetRef, operation: in.Operation,
		inputFixture: in.InputFixture, credentialRef: in.CredentialRef,
	}, nil
}

func (a ActionSpec) Tool() ToolName        { return a.tool }
func (a ActionSpec) TargetAlias() string   { return a.targetAlias }
func (a ActionSpec) TargetRef() string     { return a.targetRef }
func (a ActionSpec) Operation() string     { return a.operation }
func (a ActionSpec) InputFixture() string  { return a.inputFixture }
func (a ActionSpec) CredentialRef() string { return a.credentialRef }

func (a ActionSpec) validate() error {
	_, err := NewActionSpec(ActionSpecInput{
		Tool: a.tool, TargetAlias: a.targetAlias, TargetRef: a.targetRef, Operation: a.operation,
		InputFixture: a.inputFixture, CredentialRef: a.credentialRef,
	})
	return err
}

type ToolConstraint struct {
	tool              ToolName
	allowedOperations []string
	maxActions        uint32
	maxRequestBytes   uint64
	maxResponseBytes  uint64
}

type ToolConstraintInput struct {
	Tool              ToolName
	AllowedOperations []string
	MaxActions        uint32
	MaxRequestBytes   uint64
	MaxResponseBytes  uint64
}

func NewToolConstraint(in ToolConstraintInput) (ToolConstraint, error) {
	if !in.Tool.valid() {
		return ToolConstraint{}, fmt.Errorf("unsupported executable tool %q", in.Tool)
	}
	operations, err := canonicalIdentifiers("allowed operations", in.AllowedOperations, true)
	if err != nil {
		return ToolConstraint{}, err
	}
	if in.MaxActions == 0 || in.MaxActions > maximumConfiguredElements {
		return ToolConstraint{}, fmt.Errorf("tool max actions must be between 1 and %d", maximumConfiguredElements)
	}
	if in.MaxRequestBytes == 0 || in.MaxResponseBytes == 0 {
		return ToolConstraint{}, fmt.Errorf("tool request and response byte limits are required")
	}
	return ToolConstraint{
		tool: in.Tool, allowedOperations: operations, maxActions: in.MaxActions,
		maxRequestBytes: in.MaxRequestBytes, maxResponseBytes: in.MaxResponseBytes,
	}, nil
}

func (c ToolConstraint) Tool() ToolName { return c.tool }
func (c ToolConstraint) AllowedOperations() []string {
	return append([]string(nil), c.allowedOperations...)
}
func (c ToolConstraint) MaxActions() uint32       { return c.maxActions }
func (c ToolConstraint) MaxRequestBytes() uint64  { return c.maxRequestBytes }
func (c ToolConstraint) MaxResponseBytes() uint64 { return c.maxResponseBytes }

func (c ToolConstraint) validate() error {
	_, err := NewToolConstraint(ToolConstraintInput{
		Tool: c.tool, AllowedOperations: c.allowedOperations, MaxActions: c.maxActions,
		MaxRequestBytes: c.maxRequestBytes, MaxResponseBytes: c.maxResponseBytes,
	})
	return err
}

func (c ToolConstraint) permits(operation string) bool {
	index := sort.SearchStrings(c.allowedOperations, operation)
	return index < len(c.allowedOperations) && c.allowedOperations[index] == operation
}

type Step struct {
	id             string
	sequence       uint32
	objective      string
	allowedActions []ActionSpec
}

type StepInput struct {
	ID             string
	Sequence       uint32
	Objective      string
	AllowedActions []ActionSpec
}

func NewStep(in StepInput) (Step, error) {
	if err := identifier("step id", in.ID); err != nil {
		return Step{}, err
	}
	if in.Sequence == 0 {
		return Step{}, fmt.Errorf("step sequence is required")
	}
	if err := safeText("step objective", in.Objective); err != nil {
		return Step{}, err
	}
	if len(in.AllowedActions) == 0 || len(in.AllowedActions) > maximumConfiguredElements {
		return Step{}, fmt.Errorf("step must define between 1 and %d allowed actions", maximumConfiguredElements)
	}
	actions := append([]ActionSpec(nil), in.AllowedActions...)
	sort.Slice(actions, func(i, j int) bool { return actionSpecKey(actions[i]) < actionSpecKey(actions[j]) })
	for index, action := range actions {
		if err := action.validate(); err != nil {
			return Step{}, fmt.Errorf("allowed action: %w", err)
		}
		if index > 0 && actionSpecKey(actions[index-1]) == actionSpecKey(action) {
			return Step{}, fmt.Errorf("duplicate allowed action %q", actionSpecKey(action))
		}
	}
	return Step{id: in.ID, sequence: in.Sequence, objective: in.Objective, allowedActions: actions}, nil
}

func (s Step) ID() string                   { return s.id }
func (s Step) Sequence() uint32             { return s.sequence }
func (s Step) Objective() string            { return s.objective }
func (s Step) AllowedActions() []ActionSpec { return append([]ActionSpec(nil), s.allowedActions...) }

func (s Step) permits(action ActionSpec) bool {
	key := actionSpecKey(action)
	index := sort.Search(len(s.allowedActions), func(i int) bool { return actionSpecKey(s.allowedActions[i]) >= key })
	return index < len(s.allowedActions) && actionSpecKey(s.allowedActions[index]) == key
}

type Scenario struct {
	envelope          Envelope
	name              string
	objective         string
	safety            SafetyClass
	executionMode     ExecutionMode
	requiredFixtures  []string
	targets           []Target
	toolConstraints   []ToolConstraint
	steps             []Step
	budgets           Budgets
	expectedTelemetry []string
}

type ScenarioInput struct {
	Scope                  Scope
	ID                     string
	Version                uint32
	Name                   string
	Objective              string
	Safety                 SafetyClass
	ExecutionMode          ExecutionMode
	RequiredFixtures       []string
	Targets                []Target
	ToolConstraints        []ToolConstraint
	Steps                  []Step
	Budgets                Budgets
	ExpectedTelemetry      []string
	RecordedAt             time.Time
	CorpusReviewDue        time.Time
	LifecyclePolicyVersion string
	ResidencyPolicyRef     string
	EncryptionKeyRef       string
	EstimatedStorageBytes  uint64
	EstimateBasis          EstimateBasis
}

func NewScenario(in ScenarioInput) (Scenario, error) {
	if err := identifier("scenario id", in.ID); err != nil {
		return Scenario{}, err
	}
	if in.Version == 0 {
		return Scenario{}, fmt.Errorf("scenario version is required")
	}
	if err := safeText("scenario name", in.Name); err != nil {
		return Scenario{}, err
	}
	if err := safeText("scenario objective", in.Objective); err != nil {
		return Scenario{}, err
	}
	if !in.Safety.valid() {
		return Scenario{}, fmt.Errorf("unsupported safety class %q", in.Safety)
	}
	if !in.ExecutionMode.valid() {
		return Scenario{}, fmt.Errorf("unsupported execution mode %q", in.ExecutionMode)
	}
	if err := in.Budgets.validate(); err != nil {
		return Scenario{}, fmt.Errorf("budgets: %w", err)
	}
	fixtures, err := canonicalOpaqueReferences("required fixtures", in.RequiredFixtures, "fixture:sha256:", true)
	if err != nil {
		return Scenario{}, err
	}
	telemetry, err := canonicalIdentifiers("expected telemetry", in.ExpectedTelemetry, true)
	if err != nil {
		return Scenario{}, err
	}
	targets := append([]Target(nil), in.Targets...)
	if len(targets) == 0 || len(targets) > maximumConfiguredElements {
		return Scenario{}, fmt.Errorf("scenario must define between 1 and %d targets", maximumConfiguredElements)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].alias < targets[j].alias })
	for index, target := range targets {
		if err := target.validate(); err != nil {
			return Scenario{}, fmt.Errorf("target: %w", err)
		}
		if index > 0 && targets[index-1].alias == target.alias {
			return Scenario{}, fmt.Errorf("duplicate target alias %q", target.alias)
		}
	}
	constraints := append([]ToolConstraint(nil), in.ToolConstraints...)
	if len(constraints) == 0 || len(constraints) > maximumConfiguredElements {
		return Scenario{}, fmt.Errorf("scenario must define between 1 and %d tool constraints", maximumConfiguredElements)
	}
	sort.Slice(constraints, func(i, j int) bool { return constraints[i].tool < constraints[j].tool })
	totalOperations := 0
	for index, constraint := range constraints {
		if err := constraint.validate(); err != nil {
			return Scenario{}, fmt.Errorf("tool constraint: %w", err)
		}
		if constraint.maxActions > in.Budgets.maxActions || constraint.maxRequestBytes > in.Budgets.maxRequestBytes || constraint.maxResponseBytes > in.Budgets.maxResponseBytes {
			return Scenario{}, fmt.Errorf("tool constraint %q exceeds global budgets", constraint.tool)
		}
		if index > 0 && constraints[index-1].tool == constraint.tool {
			return Scenario{}, fmt.Errorf("duplicate tool constraint %q", constraint.tool)
		}
		totalOperations += len(constraint.allowedOperations)
		if totalOperations > maximumConfiguredElements {
			return Scenario{}, fmt.Errorf("scenario tool operations exceed the configured aggregate bound")
		}
	}
	steps := append([]Step(nil), in.Steps...)
	if len(steps) == 0 || len(steps) > int(in.Budgets.maxActions) {
		return Scenario{}, fmt.Errorf("scenario steps must be between 1 and max actions")
	}
	sort.Slice(steps, func(i, j int) bool {
		if steps[i].sequence == steps[j].sequence {
			return steps[i].id < steps[j].id
		}
		return steps[i].sequence < steps[j].sequence
	})
	stepIDs := make(map[string]struct{}, len(steps))
	totalAllowedActions := 0
	for index, step := range steps {
		if _, err := NewStep(StepInput{ID: step.id, Sequence: step.sequence, Objective: step.objective, AllowedActions: step.allowedActions}); err != nil {
			return Scenario{}, fmt.Errorf("step: %w", err)
		}
		if step.sequence != uint32(index+1) {
			return Scenario{}, fmt.Errorf("step sequences must be contiguous from 1")
		}
		if _, duplicate := stepIDs[step.id]; duplicate {
			return Scenario{}, fmt.Errorf("duplicate step id %q", step.id)
		}
		stepIDs[step.id] = struct{}{}
		totalAllowedActions += len(step.allowedActions)
		if totalAllowedActions > maximumConfiguredElements {
			return Scenario{}, fmt.Errorf("scenario allowed actions exceed the configured aggregate bound")
		}
		for _, action := range step.allowedActions {
			if !targetExists(targets, action.targetAlias, action.targetRef) {
				return Scenario{}, fmt.Errorf("step %q cites an unknown target", step.id)
			}
			constraint, ok := findConstraint(constraints, action.tool)
			if !ok || !constraint.permits(action.operation) {
				return Scenario{}, fmt.Errorf("step %q action is outside the tool constraints", step.id)
			}
		}
	}
	recordID := fmt.Sprintf("scenario:%s:v%d", in.ID, in.Version)
	envelope, err := newEnvelope(envelopeInput{
		recordID: recordID, recordKind: RecordScenario, scope: in.Scope, scenarioID: in.ID,
		scenarioVersion: in.Version, recordedAt: in.RecordedAt, corpusReviewDue: in.CorpusReviewDue,
		lifecyclePolicyVersion: in.LifecyclePolicyVersion, residencyPolicyRef: in.ResidencyPolicyRef,
		encryptionKeyRef: in.EncryptionKeyRef, estimatedStorageBytes: in.EstimatedStorageBytes,
		estimateBasis: in.EstimateBasis,
	})
	if err != nil {
		return Scenario{}, fmt.Errorf("envelope: %w", err)
	}
	return Scenario{
		envelope: envelope, name: in.Name, objective: in.Objective, safety: in.Safety,
		executionMode: in.ExecutionMode, requiredFixtures: fixtures, targets: targets,
		toolConstraints: constraints, steps: steps, budgets: in.Budgets,
		expectedTelemetry: telemetry,
	}, nil
}

func (s Scenario) Envelope() Envelope           { return s.envelope }
func (s Scenario) Name() string                 { return s.name }
func (s Scenario) Objective() string            { return s.objective }
func (s Scenario) Safety() SafetyClass          { return s.safety }
func (s Scenario) ExecutionMode() ExecutionMode { return s.executionMode }
func (s Scenario) RequiredFixtures() []string   { return append([]string(nil), s.requiredFixtures...) }
func (s Scenario) Targets() []Target            { return append([]Target(nil), s.targets...) }
func (s Scenario) ToolConstraints() []ToolConstraint {
	return append([]ToolConstraint(nil), s.toolConstraints...)
}
func (s Scenario) Steps() []Step               { return append([]Step(nil), s.steps...) }
func (s Scenario) Budgets() Budgets            { return s.budgets }
func (s Scenario) ExpectedTelemetry() []string { return append([]string(nil), s.expectedTelemetry...) }
func (s Scenario) SemanticSHA256() string      { return s.semanticDigest() }
func (s Scenario) Reference() RecordReference {
	return newRecordReference(RecordScenario, s.envelope.recordID)
}

func (s Scenario) step(id string) (Step, bool) {
	for _, step := range s.steps {
		if step.id == id {
			return step, true
		}
	}
	return Step{}, false
}

func (s Scenario) permits(stepID string, action ActionSpec) bool {
	step, ok := s.step(stepID)
	return ok && step.permits(action)
}

func (s Scenario) validate() error {
	_, err := NewScenario(ScenarioInput{
		Scope: s.envelope.scope, ID: s.envelope.scenarioID, Version: s.envelope.scenarioVersion,
		Name: s.name, Objective: s.objective, Safety: s.safety, ExecutionMode: s.executionMode,
		RequiredFixtures: s.requiredFixtures, Targets: s.targets, ToolConstraints: s.toolConstraints,
		Steps: s.steps, Budgets: s.budgets, ExpectedTelemetry: s.expectedTelemetry,
		RecordedAt: s.envelope.recordedAt, CorpusReviewDue: s.envelope.corpusReviewDue,
		LifecyclePolicyVersion: s.envelope.lifecyclePolicyVersion, ResidencyPolicyRef: s.envelope.residencyPolicyRef,
		EncryptionKeyRef: s.envelope.encryptionKeyRef, EstimatedStorageBytes: s.envelope.estimatedStorageBytes,
		EstimateBasis: s.envelope.estimateBasis,
	})
	return err
}

func targetExists(targets []Target, alias, reference string) bool {
	index := sort.Search(len(targets), func(i int) bool { return targets[i].alias >= alias })
	return index < len(targets) && targets[index].alias == alias && targets[index].reference == reference
}

func findConstraint(constraints []ToolConstraint, tool ToolName) (ToolConstraint, bool) {
	index := sort.Search(len(constraints), func(i int) bool { return constraints[i].tool >= tool })
	if index < len(constraints) && constraints[index].tool == tool {
		return constraints[index], true
	}
	return ToolConstraint{}, false
}

func actionSpecKey(action ActionSpec) string {
	return strings.Join([]string{string(action.tool), action.targetAlias, action.targetRef, action.operation, action.inputFixture, action.credentialRef}, "\x00")
}

func scopeKey(scope Scope) string {
	return strings.Join([]string{
		LabDomain, scope.tenantID, scope.scopeID, scope.deploymentBoundary,
		scope.residencyCellID, scope.keyNamespace, scope.registryNamespace,
	}, "\x00")
}

func budgetsKey(budgets Budgets) string {
	return strings.Join([]string{
		fmt.Sprint(budgets.maxActions), fmt.Sprint(budgets.maxDuration.Nanoseconds()),
		fmt.Sprint(budgets.maxConcurrency), fmt.Sprint(budgets.maxRequestBytes),
		fmt.Sprint(budgets.maxResponseBytes), fmt.Sprint(budgets.maxModelTokens),
	}, "\x00")
}

func timestampKey(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// semanticDigest binds a corpus to the complete reviewed scenario while the
// human-facing scenario record ID remains stable for an explicit version.
func (s Scenario) semanticDigest() string {
	parts := []string{
		scopeKey(s.envelope.scope), s.envelope.recordID, s.envelope.scenarioID,
		fmt.Sprint(s.envelope.scenarioVersion), timestampKey(s.envelope.recordedAt),
		timestampKey(s.envelope.corpusReviewDue), s.envelope.lifecyclePolicyVersion,
		s.envelope.residencyPolicyRef, s.envelope.encryptionKeyRef,
		fmt.Sprint(s.envelope.estimatedStorageBytes), string(s.envelope.estimateBasis),
		s.name, s.objective, string(s.safety), string(s.executionMode), budgetsKey(s.budgets),
	}
	for _, fixture := range s.requiredFixtures {
		parts = append(parts, "fixture", fixture)
	}
	for _, target := range s.targets {
		parts = append(parts, "target", target.alias, target.reference, target.fixtureRef)
	}
	for _, constraint := range s.toolConstraints {
		parts = append(parts, "constraint", string(constraint.tool), fmt.Sprint(constraint.maxActions),
			fmt.Sprint(constraint.maxRequestBytes), fmt.Sprint(constraint.maxResponseBytes))
		for _, operation := range constraint.allowedOperations {
			parts = append(parts, "operation", operation)
		}
	}
	for _, step := range s.steps {
		parts = append(parts, "step", step.id, fmt.Sprint(step.sequence), step.objective)
		for _, action := range step.allowedActions {
			parts = append(parts, "allowed-action", actionSpecKey(action))
		}
	}
	for _, telemetry := range s.expectedTelemetry {
		parts = append(parts, "telemetry", telemetry)
	}
	return stableDigest(parts...)
}

func stableDigest(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:])
}
