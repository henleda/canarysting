package groundtruth_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/store"
)

var fixtureStart = time.Date(2026, 9, 6, 20, 0, 0, 0, time.UTC)

func TestCorpusGoldenRoundTripAndCanonicalOrdering(t *testing.T) {
	corpus := fixtureCorpus(t, "scope-lab-a", false)
	blob, err := groundtruth.MarshalCorpusV1(corpus)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/ground_truth_v1.json")
	if err != nil {
		t.Fatalf("read golden: %v\nGOLDEN_START\n%sGOLDEN_END", err, blob)
	}
	if !bytes.Equal(blob, want) {
		t.Fatalf("canonical corpus differs from golden\nGOLDEN_START\n%sGOLDEN_END", blob)
	}
	decoded, err := groundtruth.UnmarshalCorpusV1(want)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := groundtruth.MarshalCorpusV1(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Fatal("round-trip serialization is not byte stable")
	}

	reordered, err := groundtruth.MarshalCorpusV1(fixtureCorpus(t, "scope-lab-a", true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reordered, want) {
		t.Fatal("set-like input ordering changed canonical serialization")
	}

	scenarioBlob, err := groundtruth.MarshalScenarioV1(corpus.Scenario())
	if err != nil {
		t.Fatal(err)
	}
	standaloneScenario, err := groundtruth.UnmarshalScenarioV1(scenarioBlob)
	if err != nil {
		t.Fatal(err)
	}
	intents := corpus.Intents()
	actions := corpus.Actions()
	for index := range intents {
		intentBlob, err := groundtruth.MarshalAttackerIntentV1(standaloneScenario, intents[index])
		if err != nil {
			t.Fatal(err)
		}
		standaloneIntent, err := groundtruth.UnmarshalAttackerIntentV1(standaloneScenario, intentBlob)
		if err != nil {
			t.Fatal(err)
		}
		if standaloneIntent.Envelope().RecordID() != intents[index].Envelope().RecordID() {
			t.Fatalf("standalone intent %d changed identity", index)
		}
		actionBlob, err := groundtruth.MarshalAttackerActionV1(standaloneIntent, actions[index])
		if err != nil {
			t.Fatal(err)
		}
		standaloneAction, err := groundtruth.UnmarshalAttackerActionV1(standaloneIntent, actionBlob)
		if err != nil {
			t.Fatal(err)
		}
		if standaloneAction.Envelope().RecordID() != actions[index].Envelope().RecordID() {
			t.Fatalf("standalone action %d changed identity", index)
		}
	}
}

func TestIntentIsCommittedBeforeEveryActionAndOutcomesRemainDistinct(t *testing.T) {
	corpus := fixtureCorpus(t, "scope-lab-a", false)
	intents := corpus.Intents()
	actions := corpus.Actions()
	if len(intents) != 3 || len(actions) != 3 {
		t.Fatalf("records=%d/%d, want 3/3", len(intents), len(actions))
	}
	for index := range intents {
		if !actions[index].RecordedAt().After(intents[index].CommittedAt()) {
			t.Fatalf("action %d was not recorded after its intent", index)
		}
		if actions[index].ParentIntentID() != intents[index].Envelope().RecordID() {
			t.Fatalf("action %d parent mismatch", index)
		}
	}
	if actions[0].Status() != groundtruth.ActionSucceeded || !actions[0].Attempted() {
		t.Fatal("successful execution truth was not retained")
	}
	if actions[1].Status() != groundtruth.ActionFailed || actions[1].ErrorCode() != "fixture_rejected" || !actions[1].Attempted() {
		t.Fatal("failed execution truth was not retained")
	}
	if actions[2].Status() != groundtruth.ActionDenied || actions[2].Attempted() || actions[2].ErrorCode() != "policy_denied" {
		t.Fatal("policy-denied no-action truth was not retained")
	}
	if _, present := actions[2].Response(); present || !actions[2].StartedAt().IsZero() || !actions[2].EndedAt().IsZero() {
		t.Fatal("denied action fabricated executor timing or response evidence")
	}

	bad := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt(), 128)
	if _, err := groundtruth.NewAttackerAction(bad); err == nil || !strings.Contains(err.Error(), "timestamps") {
		t.Fatalf("action at intent commit was accepted: %v", err)
	}
}

func TestScopeScenarioAndParentIsolationFailClosed(t *testing.T) {
	left := fixtureCorpus(t, "scope-lab-a", false)
	right := fixtureCorpus(t, "scope-lab-b", false)

	foreignIntents := left.Intents()
	foreignIntents[1] = right.Intents()[1]
	if _, err := groundtruth.NewCorpus(left.Scenario(), left.RunID(), left.Seed(), foreignIntents, left.Actions()); err == nil || !strings.Contains(err.Error(), "scope boundary") {
		t.Fatalf("cross-scope intent was accepted: %v", err)
	}

	foreignActions := left.Actions()
	foreignActions[1] = right.Actions()[1]
	if _, err := groundtruth.NewCorpus(left.Scenario(), left.RunID(), left.Seed(), left.Intents(), foreignActions); err == nil {
		t.Fatal("cross-scope action was accepted")
	}

	blob, err := groundtruth.MarshalCorpusV1(left)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(blob, []byte(`"scope_id": "scope-lab-a"`), []byte(`"scope_id": "scope-lab-b"`), 1)
	if _, err := groundtruth.UnmarshalCorpusV1(tampered); err == nil {
		t.Fatal("record-local scope tampering was accepted")
	}
}

func TestSyntheticLifecycleLineageAndModelUseAreExplicit(t *testing.T) {
	corpus := fixtureCorpus(t, "scope-lab-a", false)
	if !corpus.Synthetic() || corpus.DataClass() != groundtruth.DataClass || corpus.PerTenantModelUse() != groundtruth.ModelUsePolicy || corpus.CrossTenantModelUse() != groundtruth.ModelUsePolicy {
		t.Fatal("corpus classification or model-use boundary is not explicit")
	}
	checkEnvelope := func(envelope groundtruth.Envelope, kind groundtruth.RecordKind, lineageKind groundtruth.RecordKind) {
		t.Helper()
		if envelope.RecordKind() != kind || envelope.SchemaVersion() != groundtruth.CurrentSchemaVersion || envelope.DataClass() != groundtruth.DataClass || envelope.Sensitivity() != groundtruth.Sensitivity || !envelope.Synthetic() {
			t.Fatalf("invalid classification for %s", envelope.RecordID())
		}
		if envelope.LabDomain() != groundtruth.LabDomain || envelope.Scope().Domain() != groundtruth.LabDomain || envelope.ExpiresAt() != nil || envelope.RetentionPolicy() != groundtruth.RetentionPolicy {
			t.Fatalf("invalid lab lifecycle for %s", envelope.RecordID())
		}
		if envelope.PerTenantModelUse() != groundtruth.ModelUsePolicy || envelope.CrossTenantModelUse() != groundtruth.ModelUsePolicy || envelope.EstimatedStorageBytes() == 0 {
			t.Fatalf("invalid model-use or storage metadata for %s", envelope.RecordID())
		}
		lineage := envelope.Lineage()
		if kind == groundtruth.RecordScenario {
			if len(lineage) != 0 {
				t.Fatal("scenario unexpectedly has parent lineage")
			}
			return
		}
		if len(lineage) != 1 || lineage[0].Kind() != lineageKind || lineage[0].SchemaVersion() != groundtruth.CurrentSchemaVersion {
			t.Fatalf("invalid direct lineage for %s", envelope.RecordID())
		}
	}
	checkEnvelope(corpus.Scenario().Envelope(), groundtruth.RecordScenario, "")
	if len(corpus.Scenario().SemanticSHA256()) != sha256.Size*2 {
		t.Fatal("scenario semantic digest is not explicit")
	}
	for _, intent := range corpus.Intents() {
		checkEnvelope(intent.Envelope(), groundtruth.RecordIntent, groundtruth.RecordScenario)
	}
	for _, action := range corpus.Actions() {
		checkEnvelope(action.Envelope(), groundtruth.RecordAction, groundtruth.RecordIntent)
	}
}

func TestSensitiveContentAndUnboundedInputAreStructurallyRejected(t *testing.T) {
	if _, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: groundtruth.ToolHTTPRequest, TargetAlias: "lab-api", TargetRef: "http://customer.internal",
		Operation: "probe-root", CredentialRef: "password=not-allowed",
	}); err == nil {
		t.Fatal("clear target or credential content was accepted")
	}
	fixture := fixtureValuesForScope(t, "scope-lab-a", false)
	input := fixture.scenarioInput
	input.Name = "Probe password=not-allowed"
	if _, err := groundtruth.NewScenario(input); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("credential-like scenario text was accepted: %v", err)
	}
	input = fixture.scenarioInput
	input.Objective = "Probe http://customer.internal directly"
	if _, err := groundtruth.NewScenario(input); err == nil || !strings.Contains(err.Error(), "locator") {
		t.Fatalf("URL-like scenario text was accepted: %v", err)
	}
	for _, unsafeObjective := range []string{"Probe customer.internal directly", "Probe 2001:db8::1 directly"} {
		input = fixture.scenarioInput
		input.Objective = unsafeObjective
		if _, err := groundtruth.NewScenario(input); err == nil || !strings.Contains(err.Error(), "locator") {
			t.Fatalf("address-like scenario text %q was accepted: %v", unsafeObjective, err)
		}
	}
	if _, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: "shell", AllowedOperations: []string{"execute-command"}, MaxActions: 1,
		MaxRequestBytes: 1, MaxResponseBytes: 1,
	}); err == nil || !strings.Contains(err.Error(), "unsupported executable tool") {
		t.Fatalf("unreviewed executable tool was accepted: %v", err)
	}
	if _, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 1025, MaxDuration: time.Second, MaxConcurrency: 1,
		MaxRequestBytes: 1, MaxResponseBytes: 1, MaxModelTokens: 1,
	}); err == nil {
		t.Fatal("unbounded action budget was accepted")
	}

	blob, err := groundtruth.MarshalCorpusV1(fixtureCorpus(t, "scope-lab-a", false))
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"password=", "authorization:", "bearer ", "http://", "https://", "10.42.", "customer.internal"} {
		if bytes.Contains(bytes.ToLower(blob), []byte(prohibited)) {
			t.Fatalf("serialized corpus contains prohibited clear content %q", prohibited)
		}
	}
}

func TestProductionObservationIngestionRejectsCorpusWire(t *testing.T) {
	corpus := fixtureCorpus(t, "scope-lab-a", false)
	blob, err := groundtruth.MarshalCorpusV1(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.UnmarshalObservationV3(blob); err == nil {
		t.Fatal("production observation ingestion accepted a synthetic ground-truth corpus")
	}
	production, err := store.NewProductionObservationStore(store.Limits{
		ObservationsPerScope: 8, QueryResults: 8, JoinRecords: 8,
	}, func() time.Time { return fixtureStart.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	if err := production.Put(syntheticObservationProjection(t, corpus)); !errors.Is(err, store.ErrSynthetic) {
		t.Fatalf("production store projection rejection=%v, want %v", err, store.ErrSynthetic)
	}

	tampered := bytes.Replace(blob, []byte(`"synthetic": true`), []byte(`"synthetic": false`), 1)
	if _, err := groundtruth.UnmarshalCorpusV1(tampered); err == nil {
		t.Fatal("synthetic classification removal was accepted")
	}
	unknown := bytes.Replace(blob, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "future_unreviewed": true,`), 1)
	if _, err := groundtruth.UnmarshalCorpusV1(unknown); err == nil {
		t.Fatal("unknown corpus field was accepted without a schema review")
	}
	trailing := append(append([]byte(nil), blob...), []byte(`{"second":true}`)...)
	if _, err := groundtruth.UnmarshalCorpusV1(trailing); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if _, err := groundtruth.UnmarshalCorpusV1(make([]byte, groundtruth.MaximumCorpusBytes+1)); err == nil || !strings.Contains(err.Error(), "corpus input") {
		t.Fatalf("oversized corpus input was accepted: %v", err)
	}
}

func TestCanonicalIdentityBindsRecordAndScenarioSemantics(t *testing.T) {
	blob, err := groundtruth.MarshalCorpusV1(fixtureCorpus(t, "scope-lab-a", false))
	if err != nil {
		t.Fatal(err)
	}
	changedIntent := bytes.Replace(blob, []byte(`"planner_version": "planner-v1"`), []byte(`"planner_version": "planner-v2"`), 1)
	if _, err := groundtruth.UnmarshalCorpusV1(changedIntent); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("intent semantic change retained its declared identity: %v", err)
	}
	changedScenario := bytes.Replace(blob, []byte(`"name": "Bounded HTTP ground truth"`), []byte(`"name": "Changed HTTP ground truth"`), 1)
	if _, err := groundtruth.UnmarshalCorpusV1(changedScenario); err == nil || (!strings.Contains(err.Error(), "identity") && !strings.Contains(err.Error(), "corpus id") && !strings.Contains(err.Error(), "semantic digest")) {
		t.Fatalf("scenario semantic change retained its corpus identity: %v", err)
	}
}

func TestBudgetsAreSerializationSafeAndEnforcedByCorpus(t *testing.T) {
	if _, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 1, MaxDuration: time.Nanosecond, MaxConcurrency: 1,
		MaxRequestBytes: 1, MaxResponseBytes: 1, MaxModelTokens: 1,
	}); err == nil || !strings.Contains(err.Error(), "milliseconds") {
		t.Fatalf("non-serializable duration budget was accepted: %v", err)
	}

	corpus := fixtureCorpus(t, "scope-lab-a", false)
	intents := corpus.Intents()
	actions := corpus.Actions()
	overlong := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt().Add(3*time.Minute), 128)
	actions[0] = mustAction(t, overlong)
	if _, err := groundtruth.NewCorpus(corpus.Scenario(), corpus.RunID(), corpus.Seed(), intents, actions); err == nil || !strings.Contains(err.Error(), "duration") {
		t.Fatalf("overlong corpus run was accepted: %v", err)
	}

	actions = corpus.Actions()
	tooLargeForTool := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt().Add(time.Millisecond), 2048)
	actions[0] = mustAction(t, tooLargeForTool)
	if _, err := groundtruth.NewCorpus(corpus.Scenario(), corpus.RunID(), corpus.Seed(), intents, actions); err == nil || !strings.Contains(err.Error(), "response-byte ceiling") {
		t.Fatalf("tool-specific response ceiling was not enforced: %v", err)
	}

	actions = corpus.Actions()
	overlapping := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt().Add(time.Millisecond), 128)
	overlapping.EndedAt = intents[1].CommittedAt().Add(20 * time.Millisecond)
	overlapping.RecordedAt = overlapping.EndedAt.Add(time.Millisecond)
	actions[0] = mustAction(t, overlapping)
	if _, err := groundtruth.NewCorpus(corpus.Scenario(), corpus.RunID(), corpus.Seed(), intents, actions); err == nil || !strings.Contains(err.Error(), "concurrent") {
		t.Fatalf("concurrency ceiling was not enforced: %v", err)
	}

	tooManyReferences := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt().Add(time.Millisecond), 128)
	tooManyReferences.EvidenceRefs = make([]string, 33)
	for index := range tooManyReferences.EvidenceRefs {
		tooManyReferences.EvidenceRefs[index] = opaque("evidence:sha256:", "evidence-"+string(rune(index+1)))
	}
	if _, err := groundtruth.NewAttackerAction(tooManyReferences); err == nil || !strings.Contains(err.Error(), "per-record bound") {
		t.Fatalf("oversized evidence-reference set was accepted: %v", err)
	}
}

func TestScenarioRejectsMultiplicativeDefinitionGrowth(t *testing.T) {
	values := fixtureValuesForScope(t, "scope-lab-a", false)
	target := values.scenario.Targets()[0]
	operations := make([]string, 1024)
	actions := make([]groundtruth.ActionSpec, 1024)
	for index := range operations {
		operations[index] = fmt.Sprintf("operation-%04d", index)
		var err error
		actions[index], err = groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
			Tool: groundtruth.ToolHTTPRequest, TargetAlias: target.Alias(), TargetRef: target.Reference(),
			Operation: operations[index],
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: groundtruth.ToolHTTPRequest, AllowedOperations: operations, MaxActions: 4,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := groundtruth.NewStep(groundtruth.StepInput{
		ID: "aggregate-step-a", Sequence: 1, Objective: "Exercise the bounded reviewed operation catalog.",
		AllowedActions: actions,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := groundtruth.NewStep(groundtruth.StepInput{
		ID: "aggregate-step-b", Sequence: 2, Objective: "Repeat one reviewed operation under the same bound.",
		AllowedActions: []groundtruth.ActionSpec{actions[0]},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := values.scenarioInput
	input.ToolConstraints = []groundtruth.ToolConstraint{constraint}
	input.Steps = []groundtruth.Step{first, second}
	if _, err := groundtruth.NewScenario(input); err == nil || !strings.Contains(err.Error(), "aggregate bound") {
		t.Fatalf("multiplicative scenario-definition growth was accepted: %v", err)
	}
}

func TestRecordAccessorsReturnCopies(t *testing.T) {
	corpus := fixtureCorpus(t, "scope-lab-a", false)
	intents := corpus.Intents()
	actions := corpus.Actions()
	intents[0] = groundtruth.AttackerIntent{}
	actions[0] = groundtruth.AttackerAction{}
	if corpus.Intents()[0].Envelope().RecordID() == "" || corpus.Actions()[0].Envelope().RecordID() == "" {
		t.Fatal("corpus accessors exposed mutable record slices")
	}
	fixtures := corpus.Scenario().RequiredFixtures()
	fixtures[0] = "changed"
	if corpus.Scenario().RequiredFixtures()[0] == "changed" {
		t.Fatal("scenario accessor exposed mutable fixture slice")
	}
	evidence := corpus.Actions()[0].EvidenceRefs()
	evidence[0] = "changed"
	if corpus.Actions()[0].EvidenceRefs()[0] == "changed" {
		t.Fatal("action accessor exposed mutable evidence slice")
	}
}

func syntheticObservationProjection(t *testing.T, corpus groundtruth.Corpus) model.Observation {
	t.Helper()
	scenarioEnvelope := corpus.Scenario().Envelope()
	scope, err := model.NewScope(
		scenarioEnvelope.Scope().TenantID(), scenarioEnvelope.Scope().ScopeID(),
		scenarioEnvelope.Scope().DeploymentBoundary(), scenarioEnvelope.Scope().ResidencyCellID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := model.NewModelUseGrant(false, "")
	if err != nil {
		t.Fatal(err)
	}
	estimate, err := model.NewStorageEstimate(2048, model.EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassNormalizedObservation, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionOverride, PolicyVersion: "synthetic-projection-v1",
		RetentionDecisionRef: "retention/synthetic-projection", OverrideVersion: "lab-only-v1",
		RetentionClock: model.RetentionFromObserved, RetentionStart: fixtureStart,
		ExpiresAt: fixtureStart.AddDate(1, 0, 0), State: model.LifecycleActive,
		ResidencyPolicyRef: "residency/dgx-local-v1", EncryptionKeyRef: "key://canaryattacker/lab",
		OperationalPolicyRef: "operational/evaluation-only-v1", PerTenantModelUse: disabled,
		CrossTenantModelUse: disabled, EstimatedStorageImpact: estimate,
	})
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := model.NewSyntheticContext(scenarioEnvelope.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: "synthetic-projection-001", SchemaVersion: model.CurrentSchemaVersion,
		Scope: scope, Lifecycle: lifecycle, Synthetic: synthetic,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := model.NewRecordReference(envelope.RecordID(), model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := model.NewProvenance(root, "project.canaryattacker-ground-truth", "v1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	confidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: model.ConfidenceHigh, Method: model.ConfidenceDirectSource,
		SourceQuality: model.AssuranceDeclared, IdentityAssurance: model.AssuranceUnverified,
		Completeness: model.EvidencePartial, CandidateCount: 1, TimeUncertainty: model.TimeExact,
		AlgorithmID: "project.canaryattacker-ground-truth", AlgorithmVersion: "v1",
		Calibration: model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := model.NewKnowledge(model.KnowledgeInput{
		State: model.KnowledgeSourceObservation, AssertionMode: model.AssertionObserved,
		Producer: model.ProducerDeterministic, Confidence: confidence, Provenance: provenance,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := model.NewSourceIdentity("canaryattacker-groundtruth", corpus.RunID())
	if err != nil {
		t.Fatal(err)
	}
	collector, err := model.NewCollectorIdentity("canaryattacker-projector", "v1")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := model.NewObservation(model.ObservationInput{
		Envelope: envelope, Basis: model.ObservationSourceReport, Knowledge: knowledge,
		ObservationType: "canaryattacker.ground_truth", Source: source, Collector: collector,
		ObservedTimestamp: fixtureStart, IngestedAt: fixtureStart.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

type fixtureValues struct {
	scenarioInput groundtruth.ScenarioInput
	scenario      groundtruth.Scenario
	allowed       []groundtruth.ActionSpec
	denied        groundtruth.ActionSpec
	model         groundtruth.ModelIdentity
}

func fixtureValuesForScope(t *testing.T, scopeID string, reverse bool) fixtureValues {
	t.Helper()
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "tenant-canaryattacker-lab", ScopeID: scopeID, DeploymentBoundary: "dgx-correlation-lab",
		ResidencyCellID: "dgx-spark-local", KeyNamespace: "keyspace-canaryattacker-lab",
		RegistryNamespace: "registry-canaryattacker-evaluation",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := groundtruth.NewTarget(groundtruth.TargetInput{
		Alias: "lab-api", Reference: opaque("labtarget:sha256:", scopeID+"-target"),
		FixtureRef: opaque("fixture:sha256:", "target-fixture"),
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := make([]groundtruth.ActionSpec, 3)
	for index, input := range []groundtruth.ActionSpecInput{
		{Tool: groundtruth.ToolHTTPRequest, TargetAlias: "lab-api", TargetRef: target.Reference(), Operation: "enumerate-root"},
		{Tool: groundtruth.ToolHTTPRequest, TargetAlias: "lab-api", TargetRef: target.Reference(), Operation: "credential-check", CredentialRef: opaque("fixture:sha256:", "credential-fixture")},
		{Tool: groundtruth.ToolHTTPRequest, TargetAlias: "lab-api", TargetRef: target.Reference(), Operation: "inspect-status"},
	} {
		allowed[index], err = groundtruth.NewActionSpec(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	denied, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: "shell", TargetAlias: "outside-policy", TargetRef: opaque("labtarget:sha256:", "outside-policy-target"),
		Operation: "execute-command", InputFixture: opaque("fixture:sha256:", "denied-input"),
	})
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool:              groundtruth.ToolHTTPRequest,
		AllowedOperations: []string{"inspect-status", "credential-check", "enumerate-root"},
		MaxActions:        3, MaxRequestBytes: 1024, MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	steps := make([]groundtruth.Step, 3)
	objectives := []string{
		"Enumerate the harmless laboratory root endpoint.",
		"Attempt the disposable fixture credential against the approved endpoint.",
		"Confirm policy denial for an unregistered tool.",
	}
	for index := range steps {
		steps[index], err = groundtruth.NewStep(groundtruth.StepInput{
			ID: "step-" + string(rune('a'+index)), Sequence: uint32(index + 1),
			Objective: objectives[index], AllowedActions: []groundtruth.ActionSpec{allowed[index]},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 4, MaxDuration: 2 * time.Minute, MaxConcurrency: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096, MaxModelTokens: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []string{opaque("fixture:sha256:", "target-fixture"), opaque("fixture:sha256:", "credential-fixture")}
	telemetry := []string{"canarysting", "cilium", "ebpf", "envoy", "hubble"}
	if reverse {
		reverseStrings(fixtures)
		reverseStrings(telemetry)
	}
	input := groundtruth.ScenarioInput{
		Scope: scope, ID: "m2c2-http-ground-truth", Version: 1,
		Name: "Bounded HTTP ground truth", Objective: "Produce deterministic intent and action truth for one harmless lab target.",
		Safety: groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionOrdered,
		RequiredFixtures: fixtures, Targets: []groundtruth.Target{target},
		ToolConstraints: []groundtruth.ToolConstraint{constraint}, Steps: steps, Budgets: budgets,
		ExpectedTelemetry: telemetry, RecordedAt: fixtureStart, CorpusReviewDue: fixtureStart.AddDate(1, 0, 0),
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef:      opaque("keyref:sha256:", "ground-truth-key"),
		EstimatedStorageBytes: 8192, EstimateBasis: groundtruth.EstimateAssumed,
	}
	scenario, err := groundtruth.NewScenario(input)
	if err != nil {
		t.Fatal(err)
	}
	modelIdentity, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "canaryattacker-qwen-local", Provider: "ollama", Model: "qwen3-coder:30b-a3b-q8_0",
		ModelVersion: "7b438a19895a", PlannerVersion: "planner-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureValues{scenarioInput: input, scenario: scenario, allowed: allowed, denied: denied, model: modelIdentity}
}

func fixtureCorpus(t *testing.T, scopeID string, reverse bool) groundtruth.Corpus {
	t.Helper()
	values := fixtureValuesForScope(t, scopeID, reverse)
	runID := "run-m2c2-fixture-001"
	intents := make([]groundtruth.AttackerIntent, 3)
	proposals := []groundtruth.ActionSpec{values.allowed[0], values.allowed[1], values.denied}
	for index := range intents {
		var approved *groundtruth.ActionSpec
		outcome := groundtruth.PolicyApproved
		reason := "allowlist-match"
		if index < 2 {
			copyValue := values.allowed[index]
			approved = &copyValue
		} else {
			outcome = groundtruth.PolicyDenied
			reason = "tool-not-registered"
		}
		policy, err := groundtruth.NewPolicyDecision(groundtruth.PolicyDecisionInput{
			Outcome: outcome, PolicyVersion: "tool-policy-v1", ReasonCode: reason, ApprovedAction: approved,
		})
		if err != nil {
			t.Fatal(err)
		}
		at := fixtureStart.Add(time.Duration(index+1) * time.Second)
		intents[index], err = groundtruth.NewAttackerIntent(groundtruth.AttackerIntentInput{
			Scenario: values.scenario, RunID: runID, Ordinal: uint32(index + 1),
			StepID: "step-" + string(rune('a'+index)), Objective: values.scenario.Steps()[index].Objective(),
			Model: values.model, ProposedAction: proposals[index], Policy: policy,
			EmittedAt: at, CommittedAt: at.Add(time.Millisecond), ClockSource: "ntp-synchronized-system-clock",
			ClockUncertaintyMillis: 5, PlannerOutputRef: opaque("planner:sha256:", "planner-output-"+string(rune('a'+index))),
			EstimatedStorageBytes: 4096, EstimateBasis: groundtruth.EstimateAssumed,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	actions := make([]groundtruth.AttackerAction, 3)
	firstInput := fixtureActionInput(t, intents[0], groundtruth.ActionSucceeded, intents[0].CommittedAt().Add(time.Millisecond), 128)
	secondInput := fixtureActionInput(t, intents[1], groundtruth.ActionFailed, intents[1].CommittedAt().Add(time.Millisecond), 16)
	if reverse {
		reverseStrings(firstInput.EvidenceRefs)
		reverseStrings(secondInput.EvidenceRefs)
	}
	actions[0] = mustAction(t, firstInput)
	actions[1] = mustAction(t, secondInput)
	deniedInput := groundtruth.AttackerActionInput{
		Intent: intents[2], Status: groundtruth.ActionDenied, Action: values.denied,
		Attempted: false, RecordedAt: intents[2].CommittedAt().Add(time.Millisecond),
		ClockSource: "ntp-synchronized-system-clock", ClockUncertaintyMillis: 5,
		ErrorCode: "policy_denied", ToolPolicyVersion: "tool-policy-v1",
		EvidenceRefs:          []string{opaque("evidence:sha256:", "policy-denial")},
		EstimatedStorageBytes: 2048, EstimateBasis: groundtruth.EstimateAssumed,
	}
	actions[2] = mustAction(t, deniedInput)
	corpus, err := groundtruth.NewCorpus(values.scenario, runID, 42, intents, actions)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

func fixtureActionInput(t *testing.T, intent groundtruth.AttackerIntent, status groundtruth.ActionStatus, startedAt time.Time, responseBytes uint64) groundtruth.AttackerActionInput {
	t.Helper()
	action, ok := intent.Policy().ApprovedAction()
	if !ok {
		t.Fatal("fixture expected approved action")
	}
	endedAt := startedAt.Add(10 * time.Millisecond)
	response, err := groundtruth.NewResponseMetadata(groundtruth.ResponseMetadataInput{
		StatusCode: map[groundtruth.ActionStatus]uint16{groundtruth.ActionSucceeded: 200, groundtruth.ActionFailed: 401}[status],
		Bytes:      responseBytes, SHA256: digest("response-" + string(status)),
	})
	if err != nil {
		t.Fatal(err)
	}
	errorCode := ""
	if status == groundtruth.ActionFailed {
		errorCode = "fixture_rejected"
	}
	return groundtruth.AttackerActionInput{
		Intent: intent, Status: status, Action: action, Attempted: true,
		StartedAt: startedAt, EndedAt: endedAt, RecordedAt: endedAt.Add(time.Millisecond),
		ClockSource: "ntp-synchronized-system-clock", ClockUncertaintyMillis: 5,
		ErrorCode: errorCode, ExecutorVersion: "executor-v1", ToolPolicyVersion: "tool-policy-v1",
		Response:              &response,
		EvidenceRefs:          []string{opaque("evidence:sha256:", "executor-result"), opaque("evidence:sha256:", "policy-decision")},
		NetworkRefs:           []string{opaque("network:sha256:", "request-id")},
		EstimatedStorageBytes: 4096, EstimateBasis: groundtruth.EstimateAssumed,
	}
}

func mustAction(t *testing.T, input groundtruth.AttackerActionInput) groundtruth.AttackerAction {
	t.Helper()
	action, err := groundtruth.NewAttackerAction(input)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func opaque(prefix, value string) string { return prefix + digest(value) }

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
