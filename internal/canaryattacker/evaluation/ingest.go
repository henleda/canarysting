package evaluation

import (
	"fmt"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

// IngestCorpusV1 decodes the strict native corpus and constructs a separate
// declared-source view. It deliberately has no Observation return path.
func IngestCorpusV1(blob []byte) (Run, error) {
	corpus, err := groundtruth.UnmarshalCorpusV1(blob)
	if err != nil {
		return Run{}, fmt.Errorf("decode ground-truth corpus: %w", err)
	}
	scenario := corpus.Scenario()
	envelope := scenario.Envelope()
	groundScope := envelope.Scope()
	scope, err := model.NewScope(
		groundScope.TenantID(), groundScope.ScopeID(),
		groundScope.DeploymentBoundary(), groundScope.ResidencyCellID(),
	)
	if err != nil {
		return Run{}, fmt.Errorf("map exact laboratory scope: %w", err)
	}

	steps := scenario.Steps()
	view := make([]Step, len(steps))
	stepIndex := make(map[string]int, len(steps))
	for index, step := range steps {
		view[index] = Step{id: step.ID(), sequence: step.Sequence(), objective: step.Objective()}
		stepIndex[step.ID()] = index
	}
	actions := make(map[string]groundtruth.AttackerAction, len(corpus.Actions()))
	for _, action := range corpus.Actions() {
		actions[action.ParentIntentID()] = action
	}
	for _, intent := range corpus.Intents() {
		action, ok := actions[intent.Reference().ID()]
		if !ok {
			return Run{}, fmt.Errorf("intent %q has no paired action", intent.Reference().ID())
		}
		index, ok := stepIndex[intent.StepID()]
		if !ok {
			return Run{}, fmt.Errorf("intent step %q is absent from its scenario", intent.StepID())
		}
		uncertainty := time.Duration(maxUint64(intent.ClockUncertaintyMillis(), action.ClockUncertaintyMillis())) * time.Millisecond
		windowStart := intent.EmittedAt().Add(-uncertainty).UTC()
		windowEnd := action.RecordedAt().Add(uncertainty).UTC()
		view[index].attempts = append(view[index].attempts, Attempt{
			ordinal: intent.Ordinal(),
			intent:  declaration(intent.Envelope(), intent.Reference()),
			action:  declaration(action.Envelope(), action.Reference()),
			status:  action.Status(), attempted: action.Attempted(),
			hint: ScenarioHint{
				stepID: intent.StepID(), sequence: view[index].sequence,
				intent: intent.Reference(), action: action.Reference(),
				windowStart: windowStart, windowEnd: windowEnd,
			},
		})
	}
	for index := range view {
		sort.Slice(view[index].attempts, func(left, right int) bool {
			return view[index].attempts[left].ordinal < view[index].attempts[right].ordinal
		})
	}

	return Run{
		corpusID: corpus.ID(), schemaVersion: corpus.SchemaVersion(),
		scenarioReference: scenario.Reference(), scenarioID: envelope.ScenarioID(),
		scenarioVersion: envelope.ScenarioVersion(), runID: corpus.RunID(), seed: corpus.Seed(),
		scope: scope,
		source: Source{
			kind: SourceDeclaredGroundTruth, dataClass: envelope.DataClass(), labDomain: envelope.LabDomain(),
			assertionMode: model.AssertionDeclared, retentionPolicy: envelope.RetentionPolicy(),
			reviewDue: envelope.CorpusReviewDue(), lifecycleOwner: envelope.LifecycleOwner(),
			lifecyclePolicyVersion: envelope.LifecyclePolicyVersion(), residencyPolicyRef: envelope.ResidencyPolicyRef(),
			encryptionKeyRef: envelope.EncryptionKeyRef(), operationalPolicyRef: envelope.OperationalPolicyRef(),
			perTenantModelUse: envelope.PerTenantModelUse(), crossTenantModelUse: envelope.CrossTenantModelUse(),
			keyNamespace: groundScope.KeyNamespace(), registryNamespace: groundScope.RegistryNamespace(),
			estimatedStorageBytes: envelope.EstimatedStorageBytes(), estimateBasis: envelope.EstimateBasis(),
			synthetic: true,
		},
		expectedTelemetry: scenario.ExpectedTelemetry(), steps: view,
	}, nil
}

func declaration(envelope groundtruth.Envelope, reference groundtruth.RecordReference) Declaration {
	return Declaration{
		kind: envelope.RecordKind(), reference: reference,
		lineage: envelope.Lineage(), recordedAt: envelope.RecordedAt(),
	}
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}
