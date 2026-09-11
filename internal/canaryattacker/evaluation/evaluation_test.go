package evaluation_test

import (
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
	value := fixtureTrace(t, run.Scope(), run.ScenarioID(), []string{"vendor-hop-a", "kernel-hop-b"}, "trace-high-water")
	hops := value.Hops()
	firstAction := run.Steps()[0].Attempts()[0].Action().Reference()
	secondAction := run.Steps()[1].Attempts()[0].Action().Reference()
	hint := run.Steps()[1].Attempts()[0].Hint().Action()
	report, err := evaluation.Evaluate(run, value, []evaluation.AssociationInput{
		{StepID: "step-b", Action: secondAction, Hop: hops[1].Reference(), Mode: evaluation.JoinAssistedScenarioHint, HintReference: &hint},
		{StepID: "step-a", Action: firstAction, Hop: hops[0].Reference(), Mode: evaluation.JoinUnassisted},
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
	if len(value.Hops()) != 2 {
		t.Fatal("evaluation mutated the independent trace")
	}
	groundTruthIDs := declarationIDs(run)
	for _, hop := range value.Hops() {
		if groundTruthIDs[hop.Reference().ID()] {
			t.Fatalf("ground truth appeared as trace hop %q", hop.Reference().ID())
		}
	}

	reversed, err := evaluation.Evaluate(run, value, []evaluation.AssociationInput{
		{StepID: "step-a", Action: firstAction, Hop: hops[0].Reference(), Mode: evaluation.JoinUnassisted},
		{StepID: "step-b", Action: secondAction, Hop: hops[1].Reference(), Mode: evaluation.JoinAssistedScenarioHint, HintReference: &hint},
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
	tests := []struct {
		name  string
		value trace.Trace
		want  string
	}{
		{name: "scope", value: fixtureTrace(t, otherScope, run.ScenarioID(), []string{"hop"}, "high-water"), want: "outside ground-truth scope"},
		{name: "scenario", value: fixtureTrace(t, run.Scope(), "other-scenario", []string{"hop"}, "high-water"), want: "exact synthetic"},
		{name: "production", value: fixtureProductionTrace(t, run.Scope()), want: "exact synthetic"},
		{name: "ground truth hop", value: fixtureTrace(t, run.Scope(), run.ScenarioID(), []string{firstIntent.ID()}, "high-water"), want: "cannot appear as a trace hop"},
		{name: "ground truth lineage", value: fixtureTrace(t, run.Scope(), run.ScenarioID(), []string{"hop"}, firstIntent.ID()), want: "cannot appear in independent trace lineage"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := evaluation.Evaluate(run, test.value, nil); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestEvaluateRejectsInvalidOrMisattributedAssociations(t *testing.T) {
	run, _ := fixtureRun(t)
	value := fixtureTrace(t, run.Scope(), run.ScenarioID(), []string{"hop-a", "hop-b"}, "high-water")
	hop := value.Hops()[0].Reference()
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
		{name: "assisted missing hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinAssistedScenarioHint}}, want: "requires an exact"},
		{name: "unassisted with hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted, HintReference: &stepAHint}}, want: "cannot carry"},
		{name: "foreign step hint", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinAssistedScenarioHint, HintReference: &stepBHint}}, want: "outside step"},
		{name: "duplicate", inputs: []evaluation.AssociationInput{{StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted}, {StepID: "step-a", Action: stepAAction, Hop: hop, Mode: evaluation.JoinUnassisted}}, want: "duplicate association"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := evaluation.Evaluate(run, value, test.inputs); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
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
	return buildTrace(t, scope, synthetic, hopIDs, highWaterID)
}

func fixtureProductionTrace(t *testing.T, scope model.Scope) trace.Trace {
	t.Helper()
	return buildTrace(t, scope, model.ProductionContext(), []string{"production-hop"}, "production-high-water")
}

func buildTrace(t *testing.T, scope model.Scope, synthetic model.SyntheticContext, hopIDs []string, highWaterID string) trace.Trace {
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
