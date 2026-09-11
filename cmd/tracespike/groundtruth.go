package main

import (
	"fmt"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/evaluation"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

// evaluateGroundTruthProof builds a native declared corpus alongside the
// already-independent trace. The evaluator may associate trace hops, but it
// cannot insert corpus records into the trace observation path.
func evaluateGroundTruthProof(runID string, value trace.Trace, runMarker correlation.Record, runEvidence model.EvidenceReference, runNonce evaluation.TraceRunNonce) error {
	corpus, err := proofGroundTruthCorpus(runID, value.Envelope().Scope(), value.Envelope().Synthetic().ScenarioID())
	if err != nil {
		return err
	}
	blob, err := groundtruth.MarshalCorpusV1(corpus)
	if err != nil {
		return err
	}
	run, err := evaluation.IngestCorpusV1(blob)
	if err != nil {
		return err
	}
	hops := make([]trace.Hop, 0, len(value.Hops())-1)
	for _, hop := range value.Hops() {
		if hop.Reference() != runMarker.Reference() {
			hops = append(hops, hop)
		}
	}
	steps := run.Steps()
	if len(hops) < 2 || len(steps) != 3 || len(steps[1].Attempts()) != 1 {
		return fmt.Errorf("ground-truth proof fixture is incomplete")
	}
	firstAction := steps[0].Attempts()[0].Action().Reference()
	secondAction := steps[1].Attempts()[0].Action().Reference()
	hint := steps[1].Attempts()[0].Hint().Action()
	binding, err := evaluation.NewTraceRunBinding(runID, value.Envelope().Synthetic().ScenarioID(), 1, runMarker.Reference(), runEvidence, runNonce)
	if err != nil {
		return err
	}
	report, err := evaluation.Evaluate(run, value, binding, []evaluation.AssociationInput{
		{StepID: steps[0].ID(), Action: firstAction, Hop: hops[0].Reference(), Mode: evaluation.JoinUnassisted},
		{StepID: steps[1].ID(), Action: secondAction, Hop: hops[1].Reference(), Mode: evaluation.JoinAssistedScenarioHint, HintReference: &hint},
	})
	if err != nil {
		return err
	}
	if run.Source().Kind() != evaluation.SourceDeclaredGroundTruth || run.Source().AssertionMode() != model.AssertionDeclared ||
		report.RunBinding().Hop() != runMarker.Reference() || report.RunBinding().Evidence() != runEvidence ||
		report.UnassistedAssociations() != 1 || report.AssistedAssociations() != 1 || report.UnmatchedSteps() != 1 {
		return fmt.Errorf("ground-truth proof did not retain its declared source or evaluation disposition")
	}
	return nil
}

func proofGroundTruthCorpus(runID string, scope model.Scope, scenarioID string) (groundtruth.Corpus, error) {
	groundScope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: scope.TenantID(), ScopeID: scope.ScopeID(), DeploymentBoundary: scope.DeploymentBoundary(),
		ResidencyCellID: scope.ResidencyCellID(), KeyNamespace: "m2d1-synthetic-keys", RegistryNamespace: "m2d1-evaluation",
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	fixtureRef := "fixture:sha256:" + digest("m2d1-ground-truth-fixture", scenarioID)
	targetRef := "labtarget:sha256:" + digest("m2d1-ground-truth-target", scenarioID)
	target, err := groundtruth.NewTarget(groundtruth.TargetInput{Alias: "trace-fixture", Reference: targetRef, FixtureRef: fixtureRef})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	action, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: groundtruth.ToolInspectResponse, TargetAlias: target.Alias(), TargetRef: target.Reference(), Operation: "inspect-reviewed-result",
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	constraint, err := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
		Tool: action.Tool(), AllowedOperations: []string{action.Operation()}, MaxActions: 2, MaxRequestBytes: 1024, MaxResponseBytes: 1024,
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	objectives := []string{
		"Inspect the first reviewed synthetic trace result.",
		"Inspect the second reviewed synthetic trace result.",
		"Retain one reviewed step without a telemetry association.",
	}
	steps := make([]groundtruth.Step, len(objectives))
	for index, objective := range objectives {
		steps[index], err = groundtruth.NewStep(groundtruth.StepInput{
			ID: fmt.Sprintf("evaluation-step-%d", index+1), Sequence: uint32(index + 1), Objective: objective,
			AllowedActions: []groundtruth.ActionSpec{action},
		})
		if err != nil {
			return groundtruth.Corpus{}, err
		}
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 3, MaxDuration: time.Minute, MaxConcurrency: 1,
		MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxModelTokens: 1,
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	started := time.Date(2026, time.September, 3, 11, 59, 55, 0, time.UTC)
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: groundScope, ID: scenarioID, Version: 1, Name: "Ground truth separation proof",
		Objective: "Compare declared laboratory steps with an independent synthetic trace.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionOrdered,
		RequiredFixtures: []string{fixtureRef}, Targets: []groundtruth.Target{target},
		ToolConstraints: []groundtruth.ToolConstraint{constraint}, Steps: steps, Budgets: budgets,
		ExpectedTelemetry: []string{"kernel", "vendor"}, RecordedAt: started.Add(-time.Minute),
		CorpusReviewDue: started.AddDate(1, 0, 0), LifecyclePolicyVersion: "synthetic-ground-truth-v1",
		ResidencyPolicyRef: "residency-dgx-local-v1", EncryptionKeyRef: "keyref:sha256:" + digest("m2d1-ground-truth-key", scenarioID),
		EstimatedStorageBytes: 8192, EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	attacker, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "m2d1-static-evaluator", Provider: "deterministic-fixture", Model: "reviewed-static-plan",
		ModelVersion: "v1", PlannerVersion: "v1",
	})
	if err != nil {
		return groundtruth.Corpus{}, err
	}
	intents := make([]groundtruth.AttackerIntent, 2)
	actions := make([]groundtruth.AttackerAction, 2)
	for index := range intents {
		policy, policyErr := groundtruth.NewPolicyDecision(groundtruth.PolicyDecisionInput{
			Outcome: groundtruth.PolicyApproved, PolicyVersion: "evaluation-policy-v1", ReasonCode: "reviewed-fixture", ApprovedAction: &action,
		})
		if policyErr != nil {
			return groundtruth.Corpus{}, policyErr
		}
		emittedAt := started.Add(time.Duration(index) * time.Second)
		intents[index], err = groundtruth.NewAttackerIntent(groundtruth.AttackerIntentInput{
			Scenario: scenario, RunID: runID, Ordinal: uint32(index + 1), StepID: steps[index].ID(),
			Objective: steps[index].Objective(), Model: attacker, ProposedAction: action, Policy: policy,
			EmittedAt: emittedAt, CommittedAt: emittedAt.Add(time.Millisecond), ClockSource: "fixed-proof-clock",
			ClockUncertaintyMillis: 5, PlannerOutputRef: "planner:sha256:" + digest("m2d1-planner", fmt.Sprint(index)),
			EstimatedStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
		})
		if err != nil {
			return groundtruth.Corpus{}, err
		}
		response, responseErr := groundtruth.NewResponseMetadata(groundtruth.ResponseMetadataInput{
			StatusCode: 200, Bytes: 32, SHA256: digest("m2d1-response", fmt.Sprint(index)),
		})
		if responseErr != nil {
			return groundtruth.Corpus{}, responseErr
		}
		actions[index], err = groundtruth.NewAttackerAction(groundtruth.AttackerActionInput{
			Intent: intents[index], Status: groundtruth.ActionSucceeded, Action: action, Attempted: true,
			StartedAt: emittedAt.Add(2 * time.Millisecond), EndedAt: emittedAt.Add(3 * time.Millisecond),
			RecordedAt: emittedAt.Add(4 * time.Millisecond), ClockSource: "fixed-proof-clock", ClockUncertaintyMillis: 5,
			ExecutorVersion: "fixed-proof-v1", ToolPolicyVersion: "evaluation-policy-v1", Response: &response,
			EvidenceRefs:          []string{"evidence:sha256:" + digest("m2d1-evidence", fmt.Sprint(index))},
			EstimatedStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
		})
		if err != nil {
			return groundtruth.Corpus{}, err
		}
	}
	return groundtruth.NewCorpus(scenario, runID, 211, intents, actions)
}
