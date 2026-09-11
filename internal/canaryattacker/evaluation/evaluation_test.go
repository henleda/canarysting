package evaluation_test

import (
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/evaluation"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

var evaluationTime = time.Date(2026, time.September, 6, 20, 0, 30, 0, time.UTC)

type evaluationTraceCase struct {
	name    string
	value   trace.Trace
	binding evaluation.TraceRunBinding
	want    string
}

func TestIngestKeepsDeclarationsSeparateAndScenarioStepsComplete(t *testing.T) {
	run, blob := fixtureRun(t)
	source := run.Source()
	if source.Kind() != evaluation.SourceDeclaredGroundTruth || source.AssertionMode() != model.AssertionDeclared ||
		source.DataClass() != groundtruth.DataClass || source.LabDomain() != groundtruth.LabDomain || !source.Synthetic() {
		t.Fatalf("source classification = %+v", source)
	}
	if source.RetentionPolicy() != groundtruth.RetentionPolicy || source.ReviewDue().IsZero() ||
		source.PerTenantModelUse() != groundtruth.ModelUsePolicy || source.CrossTenantModelUse() != groundtruth.ModelUsePolicy ||
		source.KeyNamespace() == "" || source.RegistryNamespace() == "" || source.EstimatedStorageBytes() == 0 ||
		source.EstimateBasis() != groundtruth.EstimateAssumed || source.ExpiresAt() != nil || source.LegalHoldSupported() {
		t.Fatalf("source lifecycle/model-use classification was not retained: %+v", source)
	}
	if run.CorpusID() == "" || run.RunID() == "" || run.Seed() == 0 || run.SchemaVersion() != groundtruth.CurrentSchemaVersion {
		t.Fatalf("run identity is incomplete: corpus=%q run=%q seed=%d schema=%d", run.CorpusID(), run.RunID(), run.Seed(), run.SchemaVersion())
	}
	steps := run.Steps()
	if len(steps) != 3 {
		t.Fatalf("steps=%d want=3", len(steps))
	}
	for index, want := range []string{"step-a", "step-b", "step-c"} {
		if steps[index].ID() != want || steps[index].Sequence() != uint32(index+1) || len(steps[index].Attempts()) != 1 {
			t.Fatalf("step %d = id=%q sequence=%d attempts=%d", index, steps[index].ID(), steps[index].Sequence(), len(steps[index].Attempts()))
		}
		attempt := steps[index].Attempts()[0]
		if attempt.Intent().Kind() != groundtruth.RecordIntent || attempt.Action().Kind() != groundtruth.RecordAction ||
			attempt.Intent().AssertionMode() != model.AssertionDeclared || attempt.Action().AssertionMode() != model.AssertionDeclared {
			t.Fatalf("step %q lost declared record kinds", want)
		}
		if !attempt.Hint().WindowEnd().After(attempt.Hint().WindowStart()) {
			t.Fatalf("step %q has invalid bounded hint window", want)
		}
	}
	steps[0] = evaluation.Step{}
	if run.Steps()[0].ID() != "step-a" {
		t.Fatal("run exposed mutable step storage")
	}
	if _, err := model.UnmarshalObservationV3(blob); err == nil {
		t.Fatal("ground-truth corpus decoded as a production observation")
	}
}

func TestEvaluateReportsAssistedUnassistedAndUnmatchedSteps(t *testing.T) {
	run, _ := fixtureRun(t)
	value, binding := fixtureEvaluationTrace(t, run, run.Scope(), run.ScenarioID(), []string{"vendor-hop-a", "kernel-hop-b"}, "trace-high-water")
	hops := value.Hops()
	firstAction := run.Steps()[0].Attempts()[0].Action().Reference()
	secondAction := run.Steps()[1].Attempts()[0].Action().Reference()
	hint := run.Steps()[1].Attempts()[0].Hint().Action()
	report, err := evaluation.Evaluate(run, value, binding, []evaluation.AssociationInput{
		{StepID: "step-b", Action: secondAction, Hop: hops[2].Reference(), Mode: evaluation.JoinAssistedScenarioHint, HintReference: &hint},
		{StepID: "step-a", Action: firstAction, Hop: hops[1].Reference(), Mode: evaluation.JoinUnassisted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.AssistedAssociations() != 1 || report.UnassistedAssociations() != 1 || report.UnmatchedSteps() != 1 {
		t.Fatalf("counts assisted=%d unassisted=%d unmatched=%d", report.AssistedAssociations(), report.UnassistedAssociations(), report.UnmatchedSteps())
	}
	results := report.Steps()
	if len(results) != 3 || results[0].Step().ID() != "step-a" || results[1].Step().ID() != "step-b" || results[2].Step().ID() != "step-c" || results[2].Matched() {
		t.Fatalf("scenario order or unmatched retention changed: %+v", results)
	}
	if got := results[0].Associations()[0].Mode(); got != evaluation.JoinUnassisted {
		t.Fatalf("step-a mode=%q", got)
	}
	assisted := results[1].Associations()[0]
	if assisted.Action().ID() != secondAction.ID() {
		t.Fatalf("assisted action=%q want=%q", assisted.Action().ID(), secondAction.ID())
	}
	gotHint, ok := assisted.HintReference()
	if !ok || gotHint.ID() != hint.ID() || gotHint.Kind() != groundtruth.RecordAction {
		t.Fatalf("assisted hint = %+v present=%v", gotHint, ok)
	}
	if report.IntegritySHA256() == "" || strings.Contains(report.IntegritySHA256(), ":") {
		t.Fatalf("invalid report integrity digest %q", report.IntegritySHA256())
	}
	if report.RunBinding().RunID() != run.RunID() || report.RunBinding().ScenarioID() != run.ScenarioID() ||
		report.RunBinding().ScenarioVersion() != run.ScenarioVersion() || report.RunBinding().Hop() != value.Hops()[0].Reference() {
		t.Fatalf("report run binding = %+v", report.RunBinding())
	}
	if len(value.Hops()) != 3 {
		t.Fatal("evaluation mutated the independent trace")
	}
	groundTruthIDs := declarationIDs(run)
	for _, hop := range value.Hops() {
		if groundTruthIDs[hop.Reference().ID()] {
			t.Fatalf("ground truth appeared as trace hop %q", hop.Reference().ID())
		}
	}

	reversed, err := evaluation.Evaluate(run, value, binding, []evaluation.AssociationInput{
		{StepID: "step-a", Action: firstAction, Hop: hops[1].Reference(), Mode: evaluation.JoinUnassisted},
		{StepID: "step-b", Action: secondAction, Hop: hops[2].Reference(), Mode: evaluation.JoinAssistedScenarioHint, HintReference: &hint},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reversed.IntegritySHA256() != report.IntegritySHA256() {
		t.Fatal("association input order changed report identity")
	}
}

func TestEvaluateFailsClosedAcrossScopeScenarioAndSourceBoundaries(t *testing.T) {
	run, _ := fixtureRun(t)
	otherScope, err := model.NewScope(run.Scope().TenantID(), "other-scope", run.Scope().DeploymentBoundary(), run.Scope().ResidencyCellID())
	if err != nil {
		t.Fatal(err)
	}
	firstIntent := run.Steps()[0].Attempts()[0].Intent().Reference()
	corpusReference, err := model.NewRecordReference(run.CorpusID(), run.SchemaVersion())
	if err != nil {
		t.Fatal(err)
	}
	tests := []evaluationTraceCase{
		fixtureEvaluationTraceEntry(t, "scope", run, otherScope, run.ScenarioID(), []string{"hop"}, "high-water", "outside ground-truth scope"),
		fixtureEvaluationTraceEntry(t, "scenario", run, run.Scope(), "other-scenario", []string{"hop"}, "high-water", "exact synthetic"),
		fixtureProductionEvaluationTraceEntry(t, "production", run, []string{"production-hop"}, "production-high-water", "exact synthetic"),
		fixtureEvaluationTraceEntry(t, "ground truth hop", run, run.Scope(), run.ScenarioID(), []string{firstIntent.ID()}, "high-water", "cannot appear as a trace hop"),
		fixtureEvaluationTraceEntry(t, "ground truth lineage", run, run.Scope(), run.ScenarioID(), []string{"hop"}, firstIntent.ID(), "cannot appear in independent trace lineage"),
		fixtureEvaluationTraceEntry(t, "corpus hop", run, run.Scope(), run.ScenarioID(), []string{corpusReference.ID()}, "high-water", "cannot appear as a trace hop"),
		fixtureEvaluationTraceEntry(t, "corpus lineage", run, run.Scope(), run.ScenarioID(), []string{"hop"}, corpusReference.ID(), "cannot appear in independent trace lineage"),
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := evaluation.Evaluate(run, test.value, test.binding, nil); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestEvaluateRequiresExactIndependentRunBinding(t *testing.T) {
	run, _ := fixtureRun(t)
	value, _ := fixtureEvaluationTrace(t, run, run.Scope(), run.ScenarioID(), []string{"run-marker", "telemetry-hop"}, "high-water")
	evidence := value.Hops()[0].Reference()
	nonce := traceRunNonce(t, "exact-binding")
	missingEvidence, err := model.NewRecordReference("missing-run-marker", model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		runID    string
		scenario string
		version  uint32
		evidence model.RecordReference
		want     string
	}{
		{name: "other run", runID: "other-run", scenario: run.ScenarioID(), version: run.ScenarioVersion(), evidence: evidence, want: "exact ground-truth run"},
		{name: "other scenario", runID: run.RunID(), scenario: "other-scenario", version: run.ScenarioVersion(), evidence: evidence, want: "exact ground-truth run"},
		{name: "other version", runID: run.RunID(), scenario: run.ScenarioID(), version: run.ScenarioVersion() + 1, evidence: evidence, want: "exact ground-truth run"},
		{name: "missing evidence", runID: run.RunID(), scenario: run.ScenarioID(), version: run.ScenarioVersion(), evidence: missingEvidence, want: "not in the independent trace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runEvidence := traceRunEvidence(t, test.runID, test.scenario, test.version, nonce)
			binding, bindErr := evaluation.NewTraceRunBinding(test.runID, test.scenario, test.version, test.evidence, runEvidence, nonce)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			if _, evalErr := evaluation.Evaluate(run, value, binding, nil); evalErr == nil || !strings.Contains(evalErr.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", evalErr, test.want)
			}
		})
	}
}

func TestEvaluateRejectsReconstructedBindingWithSameHopReference(t *testing.T) {
	run, _ := fixtureRun(t)
	otherNonce := traceRunNonce(t, "other-source-issuance")
	otherEvidence := traceRunEvidence(t, "other-run", run.ScenarioID(), run.ScenarioVersion(), otherNonce)
	value := fixtureTraceWithEvidence(t, run.Scope(), run.ScenarioID(), []string{"shared-run-marker", "telemetry-hop"}, "high-water", otherEvidence)
	targetNonce := traceRunNonce(t, "target-source-issuance")
	targetEvidence := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), targetNonce)
	binding, err := evaluation.NewTraceRunBinding(
		run.RunID(), run.ScenarioID(), run.ScenarioVersion(), value.Hops()[0].Reference(), targetEvidence, targetNonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluation.Evaluate(run, value, binding, nil); err == nil || !strings.Contains(err.Error(), "not retained on trace hop") {
		t.Fatalf("reconstructed same-reference binding error=%v", err)
	}
}

func TestTraceRunBindingRejectsMissingOrMismatchedOpaqueEvidence(t *testing.T) {
	run, _ := fixtureRun(t)
	nonce := traceRunNonce(t, "binding-evidence")
	reference, err := model.NewRecordReference("run-marker", model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	withoutKey, err := model.NewEvidenceReference("evidence:sha256:"+strings.Repeat("1", 64), model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluation.NewTraceRunBinding(run.RunID(), run.ScenarioID(), run.ScenarioVersion(), reference, withoutKey, nonce); err == nil || !strings.Contains(err.Error(), "not the exact opaque run key") {
		t.Fatalf("missing-key error=%v", err)
	}
	withWrongKey := traceRunEvidence(t, "other-run", run.ScenarioID(), run.ScenarioVersion(), nonce)
	if _, err := evaluation.NewTraceRunBinding(run.RunID(), run.ScenarioID(), run.ScenarioVersion(), reference, withWrongKey, nonce); err == nil || !strings.Contains(err.Error(), "not the exact opaque run key") {
		t.Fatalf("wrong-key error=%v", err)
	}
	wrongNonce := traceRunNonce(t, "wrong-binding-evidence")
	validEvidence := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), nonce)
	if _, err := evaluation.NewTraceRunBinding(run.RunID(), run.ScenarioID(), run.ScenarioVersion(), reference, validEvidence, wrongNonce); err == nil || !strings.Contains(err.Error(), "not the exact opaque run key") {
		t.Fatalf("wrong-nonce error=%v", err)
	}
}

func TestTraceRunEvidenceRequiresIndependentSourceEntropy(t *testing.T) {
	run, _ := fixtureRun(t)
	if _, err := evaluation.NewTraceRunNonce(make([]byte, evaluation.TraceRunNonceBytes)); err == nil || !strings.Contains(err.Error(), "all zero") {
		t.Fatalf("zero nonce error=%v", err)
	}
	if _, err := evaluation.NewTraceRunNonce(make([]byte, evaluation.TraceRunNonceBytes-1)); err == nil || !strings.Contains(err.Error(), "exactly") {
		t.Fatalf("short nonce error=%v", err)
	}
	first := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), traceRunNonce(t, "source-a"))
	second := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), traceRunNonce(t, "source-b"))
	if first == second {
		t.Fatal("corpus-visible run identity produced the same evidence across independent source nonces")
	}
}

func TestEvaluateRejectsInvalidOrMisattributedAssociations(t *testing.T) {
	run, _ := fixtureRun(t)
	value, binding := fixtureEvaluationTrace(t, run, run.Scope(), run.ScenarioID(), []string{"hop-a", "hop-b"}, "high-water")
	hop := value.Hops()[1].Reference()
	marker := value.Hops()[0].Reference()
	stepAAction := run.Steps()[0].Attempts()[0].Action().Reference()
	stepBAction := run.Steps()[1].Attempts()[0].Action().Reference()
	stepAHint := run.Steps()[0].Attempts()[0].Hint().Intent()
	stepBHint := run.Steps()[1].Attempts()[0].Hint().Action()
	missingHop, err := model.NewRecordReference("missing-hop", model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		inputs []evaluation.AssociationInput
		want   string
	}{
		{name: "unknown step", inputs: []evaluation.AssociationInput{{StepID: "missing-step", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted}}, want: "unknown step"},
		{name: "foreign action", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepBAction, Hop: hop, Mode: evaluation.JoinUnassisted}}, want: "action is outside step"},
		{name: "unknown hop", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: missingHop, Mode: evaluation.JoinUnassisted}}, want: "not in the trace"},
		{name: "run marker", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: marker, Mode: evaluation.JoinUnassisted}}, want: "provenance-only"},
		{name: "assisted missing hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinAssistedScenarioHint}}, want: "requires an exact"},
		{name: "unassisted with hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted, HintReference: &stepAHint}}, want: "cannot carry"},
		{name: "foreign step hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinAssistedScenarioHint, HintReference: &stepBHint}}, want: "outside step"},
		{name: "duplicate", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted}, {StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted}}, want: "duplicate association"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := evaluation.Evaluate(run, value, binding, test.inputs); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func traceRunBinding(t *testing.T, run evaluation.Run, hop model.RecordReference, evidence model.EvidenceReference, nonce evaluation.TraceRunNonce) evaluation.TraceRunBinding {
	t.Helper()
	binding, err := evaluation.NewTraceRunBinding(run.RunID(), run.ScenarioID(), run.ScenarioVersion(), hop, evidence, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func traceRunEvidence(t *testing.T, runID, scenarioID string, scenarioVersion uint32, nonce evaluation.TraceRunNonce) model.EvidenceReference {
	t.Helper()
	evidence, err := evaluation.NewTraceRunEvidence(runID, scenarioID, scenarioVersion, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func traceRunNonce(t *testing.T, sourceEvent string) evaluation.TraceRunNonce {
	t.Helper()
	value := sha256.Sum256([]byte("independent-trace-source\x00" + sourceEvent))
	nonce, err := evaluation.NewTraceRunNonce(value[:])
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestIngestRejectsTamperedOrOversizedCorpus(t *testing.T) {
	_, blob := fixtureRun(t)
	tampered := strings.Replace(string(blob), `"data_class": "SYNTHETIC_GROUND_TRUTH"`, `"data_class": "NORMALIZED_OBSERVATION"`, 1)
	if _, err := evaluation.IngestCorpusV1([]byte(tampered)); err == nil {
		t.Fatal("tampered corpus was accepted")
	}
	if _, err := evaluation.IngestCorpusV1(make([]byte, groundtruth.MaximumCorpusBytes+1)); err == nil {
		t.Fatal("oversized corpus was accepted")
	}
}

func fixtureRun(t *testing.T) (evaluation.Run, []byte) {
	t.Helper()
	blob, err := os.ReadFile("../groundtruth/testdata/ground_truth_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	run, err := evaluation.IngestCorpusV1(blob)
	if err != nil {
		t.Fatal(err)
	}
	return run, blob
}

func fixtureTrace(t *testing.T, scope model.Scope, scenarioID string, hopIDs []string, highWaterID string) trace.Trace {
	t.Helper()
	synthetic, err := model.NewSyntheticContext(scenarioID)
	if err != nil {
		t.Fatal(err)
	}
	return buildTrace(t, scope, synthetic, hopIDs, highWaterID, nil)
}

func fixtureTraceWithEvidence(t *testing.T, scope model.Scope, scenarioID string, hopIDs []string, highWaterID string, evidence model.EvidenceReference) trace.Trace {
	t.Helper()
	synthetic, err := model.NewSyntheticContext(scenarioID)
	if err != nil {
		t.Fatal(err)
	}
	return buildTrace(t, scope, synthetic, hopIDs, highWaterID, &evidence)
}

func fixtureEvaluationTrace(t *testing.T, run evaluation.Run, scope model.Scope, scenarioID string, hopIDs []string, highWaterID string) (trace.Trace, evaluation.TraceRunBinding) {
	t.Helper()
	nonce := traceRunNonce(t, "fixture:"+highWaterID)
	evidence := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), nonce)
	allHopIDs := append([]string{"run-binding-marker"}, hopIDs...)
	value := fixtureTraceWithEvidence(t, scope, scenarioID, allHopIDs, highWaterID, evidence)
	binding := traceRunBinding(t, run, value.Hops()[0].Reference(), evidence, nonce)
	return value, binding
}

func fixtureEvaluationTraceEntry(t *testing.T, name string, run evaluation.Run, scope model.Scope, scenarioID string, hopIDs []string, highWaterID, want string) evaluationTraceCase {
	t.Helper()
	value, binding := fixtureEvaluationTrace(t, run, scope, scenarioID, hopIDs, highWaterID)
	return evaluationTraceCase{name: name, value: value, binding: binding, want: want}
}

func fixtureProductionEvaluationTraceEntry(t *testing.T, name string, run evaluation.Run, hopIDs []string, highWaterID, want string) evaluationTraceCase {
	t.Helper()
	nonce := traceRunNonce(t, "production:"+highWaterID)
	evidence := traceRunEvidence(t, run.RunID(), run.ScenarioID(), run.ScenarioVersion(), nonce)
	allHopIDs := append([]string{"run-binding-marker"}, hopIDs...)
	value := buildTrace(t, run.Scope(), model.ProductionContext(), allHopIDs, highWaterID, &evidence)
	binding := traceRunBinding(t, run, value.Hops()[0].Reference(), evidence, nonce)
	return evaluationTraceCase{name: name, value: value, binding: binding, want: want}
}

func fixtureProductionTrace(t *testing.T, scope model.Scope) trace.Trace {
	t.Helper()
	return buildTrace(t, scope, model.ProductionContext(), []string{"production-hop"}, "production-high-water", nil)
}

func buildTrace(t *testing.T, scope model.Scope, synthetic model.SyntheticContext, hopIDs []string, highWaterID string, firstEvidence *model.EvidenceReference) trace.Trace {
	t.Helper()
	hops := make([]trace.HopInput, len(hopIDs))
	for index, id := range hopIDs {
		reference, err := model.NewRecordReference(id, model.CurrentSchemaVersion)
		if err != nil {
			t.Fatal(err)
		}
		eventTime, err := correlation.NewEventTime(evaluationTime.Add(time.Duration(index)*time.Second), 5*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		record, err := correlation.NewRecord(correlation.RecordInput{
			Reference: reference, Scope: scope, Vantage: correlation.SourceVantageGeneral,
			Time: &eventTime, Synthetic: synthetic,
		})
		if err != nil {
			t.Fatal(err)
		}
		hops[index] = trace.HopInput{Record: record, Kind: trace.HopObservation}
		if index == 0 && firstEvidence != nil {
			hops[index].Evidence = []model.EvidenceReference{*firstEvidence}
		}
	}
	highWater, err := model.NewRecordReference(highWaterID, model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	estimate, err := model.NewStorageEstimate(4096, model.EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	closedAt := evaluationTime.Add(time.Minute)
	lifecycle, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassCorrelatedTrace, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionLean, PolicyVersion: "m2d1-trace-v1",
		RetentionDecisionRef: "retention/m2d1-trace-v1", RetentionClock: model.RetentionFromTraceClose,
		RetentionStart: closedAt, ExpiresAt: closedAt.Add(90 * 24 * time.Hour), State: model.LifecycleActive,
		ResidencyPolicyRef: "residency/dgx-local-v1", EncryptionKeyRef: "key://dgx-local/m2d1",
		OperationalPolicyRef: "operational/m2d1-evaluation-v1",
		PerTenantModelUse:    model.ModelUseGrant{}, CrossTenantModelUse: model.ModelUseGrant{},
		EstimatedStorageImpact: estimate,
	})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := trace.NewBuilder(trace.DefaultBuilderConfig())
	if err != nil {
		t.Fatal(err)
	}
	value, err := builder.Build(trace.BuildInput{
		Scope: scope, Hops: hops, Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Second), HighWaterMark: highWater,
		Lifecycle: lifecycle, Synthetic: synthetic,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func declarationIDs(run evaluation.Run) map[string]bool {
	result := map[string]bool{run.ScenarioReference().ID(): true}
	for _, step := range run.Steps() {
		for _, attempt := range step.Attempts() {
			result[attempt.Intent().Reference().ID()] = true
			result[attempt.Action().Reference().ID()] = true
		}
	}
	return result
}
