package evaluation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

type JoinMode string

const (
	JoinUnassisted           JoinMode = "UNASSISTED"
	JoinAssistedScenarioHint JoinMode = "ASSISTED_SCENARIO_HINT"
)

func (m JoinMode) valid() bool { return m == JoinUnassisted || m == JoinAssistedScenarioHint }

// AssociationInput associates one already-existing trace hop with an executed
// scenario step. Assisted joins must cite the exact intent/action hint used;
// unassisted joins are forbidden from carrying a ground-truth hint.
type AssociationInput struct {
	StepID        string
	Action        groundtruth.RecordReference
	Hop           model.RecordReference
	Mode          JoinMode
	HintReference *groundtruth.RecordReference
}

type Association struct {
	stepID        string
	action        groundtruth.RecordReference
	hop           model.RecordReference
	mode          JoinMode
	hintReference *groundtruth.RecordReference
}

func (a Association) StepID() string                      { return a.stepID }
func (a Association) Action() groundtruth.RecordReference { return a.action }
func (a Association) Hop() model.RecordReference          { return a.hop }
func (a Association) Mode() JoinMode                      { return a.mode }
func (a Association) HintReference() (groundtruth.RecordReference, bool) {
	if a.hintReference == nil {
		return groundtruth.RecordReference{}, false
	}
	return *a.hintReference, true
}

type StepResult struct {
	step         Step
	associations []Association
}

func (r StepResult) Step() Step { return copySteps([]Step{r.step})[0] }
func (r StepResult) Associations() []Association {
	return copyAssociations(r.associations)
}
func (r StepResult) Matched() bool { return len(r.associations) > 0 }

// Report is an ephemeral comparison between one native ground-truth run and
// one independently constructed trace. It does not mutate either input.
type Report struct {
	corpusID        string
	traceReference  model.RecordReference
	runBinding      TraceRunBinding
	steps           []StepResult
	assisted        int
	unassisted      int
	unmatched       int
	integritySHA256 string
}

func (r Report) CorpusID() string                      { return r.corpusID }
func (r Report) TraceReference() model.RecordReference { return r.traceReference }
func (r Report) RunBinding() TraceRunBinding           { return r.runBinding }
func (r Report) AssistedAssociations() int             { return r.assisted }
func (r Report) UnassistedAssociations() int           { return r.unassisted }
func (r Report) UnmatchedSteps() int                   { return r.unmatched }
func (r Report) IntegritySHA256() string               { return r.integritySHA256 }
func (r Report) Steps() []StepResult {
	result := append([]StepResult(nil), r.steps...)
	for index := range result {
		result[index].step = copySteps([]Step{result[index].step})[0]
		result[index].associations = copyAssociations(result[index].associations)
	}
	return result
}

// Evaluate compares a separate declared run with a synthetic lab trace whose
// exact run and scenario version are supplied by an independent trace hop.
func Evaluate(run Run, value trace.Trace, binding TraceRunBinding, inputs []AssociationInput) (Report, error) {
	if err := validateRun(run); err != nil {
		return Report{}, err
	}
	if err := binding.validate(); err != nil {
		return Report{}, err
	}
	if len(inputs) > MaximumAssociations {
		return Report{}, fmt.Errorf("associations exceed hard limit %d", MaximumAssociations)
	}
	envelope := value.Envelope()
	if !sameScope(run.scope, envelope.Scope()) {
		return Report{}, fmt.Errorf("trace is outside ground-truth scope")
	}
	synthetic := envelope.Synthetic()
	if err := synthetic.Validate(); err != nil {
		return Report{}, fmt.Errorf("trace synthetic context: %w", err)
	}
	if !synthetic.Synthetic() || synthetic.ScenarioID() != run.scenarioID {
		return Report{}, fmt.Errorf("trace must use the exact synthetic ground-truth scenario")
	}
	if binding.runID != run.runID || binding.scenarioID != run.scenarioID || binding.scenarioVersion != run.scenarioVersion {
		return Report{}, fmt.Errorf("trace run binding must match the exact ground-truth run and scenario version")
	}

	groundTruthIDs := run.referenceIDs()
	traceHops := make(map[string]model.RecordReference, len(value.Hops()))
	bindingEvidenceFound := false
	for _, hop := range value.Hops() {
		key := modelReferenceKey(hop.Reference())
		if groundTruthIDs[hop.Reference().ID()] {
			return Report{}, fmt.Errorf("ground-truth record %q cannot appear as a trace hop", hop.Reference().ID())
		}
		traceHops[key] = hop.Reference()
		if hop.Reference() == binding.hop {
			for _, evidence := range hop.Evidence() {
				if evidence == binding.evidence {
					bindingEvidenceFound = true
					break
				}
			}
		}
	}
	for _, parent := range envelope.DerivationLineage() {
		if groundTruthIDs[parent.ID()] {
			return Report{}, fmt.Errorf("ground-truth record %q cannot appear in independent trace lineage", parent.ID())
		}
	}
	if _, ok := traceHops[modelReferenceKey(binding.hop)]; !ok {
		return Report{}, fmt.Errorf("trace run-binding hop %q is not in the independent trace", binding.hop.ID())
	}
	if !bindingEvidenceFound {
		return Report{}, fmt.Errorf("exact opaque run-binding evidence is not retained on trace hop %q", binding.hop.ID())
	}

	stepIndex := make(map[string]int, len(run.steps))
	results := make([]StepResult, len(run.steps))
	for index, step := range run.steps {
		stepIndex[step.id] = index
		results[index].step = step
	}
	seen := make(map[string]bool, len(inputs))
	for index, input := range inputs {
		stepPosition, ok := stepIndex[input.StepID]
		if !ok {
			return Report{}, fmt.Errorf("association %d names unknown step %q", index, input.StepID)
		}
		step := run.steps[stepPosition]
		attempt, ok := step.attemptForAction(input.Action)
		if !ok {
			return Report{}, fmt.Errorf("association %d action is outside step %q", index, input.StepID)
		}
		if !input.Mode.valid() {
			return Report{}, fmt.Errorf("association %d has unsupported join mode %q", index, input.Mode)
		}
		if _, err := model.NewRecordReference(input.Hop.ID(), input.Hop.SchemaVersion()); err != nil {
			return Report{}, fmt.Errorf("association %d hop: %w", index, err)
		}
		hopKey := modelReferenceKey(input.Hop)
		if hopKey == modelReferenceKey(binding.hop) {
			return Report{}, fmt.Errorf("association %d cannot use the provenance-only run-binding hop", index)
		}
		hop, ok := traceHops[hopKey]
		if !ok {
			return Report{}, fmt.Errorf("association %d hop %q is not in the trace", index, input.Hop.ID())
		}
		associationKey := input.StepID + "\x00" + hopKey
		if seen[associationKey] {
			return Report{}, fmt.Errorf("duplicate association for step %q and hop %q", input.StepID, input.Hop.ID())
		}
		seen[associationKey] = true
		var hint *groundtruth.RecordReference
		switch input.Mode {
		case JoinUnassisted:
			if input.HintReference != nil {
				return Report{}, fmt.Errorf("unassisted association cannot carry a scenario hint")
			}
		case JoinAssistedScenarioHint:
			if input.HintReference == nil {
				return Report{}, fmt.Errorf("assisted association requires an exact intent/action hint reference")
			}
			if !attempt.hint.contains(*input.HintReference) {
				return Report{}, fmt.Errorf("assisted association hint is outside step %q", input.StepID)
			}
			copyValue := *input.HintReference
			hint = &copyValue
		}
		results[stepPosition].associations = append(results[stepPosition].associations, Association{
			stepID: input.StepID, action: input.Action, hop: hop, mode: input.Mode, hintReference: hint,
		})
	}

	assisted, unassisted, unmatched := 0, 0, 0
	parts := []string{
		run.corpusID, envelope.RecordID(), fmt.Sprint(envelope.SchemaVersion()),
		binding.runID, binding.scenarioID, fmt.Sprint(binding.scenarioVersion),
		binding.hop.ID(), fmt.Sprint(binding.hop.SchemaVersion()),
		binding.evidence.ID(), fmt.Sprint(binding.evidence.SchemaVersion()), string(binding.evidence.Role()),
	}
	for index := range results {
		sort.Slice(results[index].associations, func(left, right int) bool {
			leftKey := modelReferenceKey(results[index].associations[left].hop)
			rightKey := modelReferenceKey(results[index].associations[right].hop)
			if leftKey != rightKey {
				return leftKey < rightKey
			}
			return results[index].associations[left].mode < results[index].associations[right].mode
		})
		parts = append(parts, results[index].step.id, fmt.Sprint(results[index].step.sequence))
		if len(results[index].associations) == 0 {
			unmatched++
			parts = append(parts, "UNMATCHED")
			continue
		}
		for _, association := range results[index].associations {
			parts = append(parts, association.action.ID(), fmt.Sprint(association.action.SchemaVersion()), association.hop.ID(), fmt.Sprint(association.hop.SchemaVersion()), string(association.mode))
			if association.mode == JoinAssistedScenarioHint {
				assisted++
				parts = append(parts, association.hintReference.ID(), fmt.Sprint(association.hintReference.SchemaVersion()))
			} else {
				unassisted++
				parts = append(parts, "NO_HINT")
			}
		}
	}
	traceReference, err := model.NewRecordReference(envelope.RecordID(), envelope.SchemaVersion())
	if err != nil {
		return Report{}, fmt.Errorf("trace reference: %w", err)
	}
	return Report{
		corpusID: run.corpusID, traceReference: traceReference, runBinding: binding, steps: results,
		assisted: assisted, unassisted: unassisted, unmatched: unmatched,
		integritySHA256: digestParts(parts...),
	}, nil
}

func validateRun(run Run) error {
	if run.corpusID == "" || run.schemaVersion != groundtruth.CurrentSchemaVersion || run.scenarioID == "" || run.scenarioVersion == 0 || run.runID == "" || run.seed == 0 {
		return fmt.Errorf("validated ground-truth run is required")
	}
	if _, err := model.NewScope(run.scope.TenantID(), run.scope.ScopeID(), run.scope.DeploymentBoundary(), run.scope.ResidencyCellID()); err != nil {
		return fmt.Errorf("ground-truth scope: %w", err)
	}
	if run.source.kind != SourceDeclaredGroundTruth || run.source.assertionMode != model.AssertionDeclared || !run.source.synthetic || run.source.dataClass != groundtruth.DataClass || run.source.labDomain != groundtruth.LabDomain || run.source.perTenantModelUse != groundtruth.ModelUsePolicy || run.source.crossTenantModelUse != groundtruth.ModelUsePolicy {
		return fmt.Errorf("ground-truth source classification is invalid")
	}
	if len(run.steps) == 0 {
		return fmt.Errorf("ground-truth run has no reviewed steps")
	}
	return nil
}

func (r Run) referenceIDs() map[string]bool {
	result := map[string]bool{r.corpusID: true, r.scenarioReference.ID(): true}
	for _, step := range r.steps {
		for _, attempt := range step.attempts {
			result[attempt.intent.reference.ID()] = true
			result[attempt.action.reference.ID()] = true
		}
	}
	return result
}

func sameScope(left, right model.Scope) bool {
	return left.TenantID() == right.TenantID() && left.ScopeID() == right.ScopeID() &&
		left.DeploymentBoundary() == right.DeploymentBoundary() && left.ResidencyCellID() == right.ResidencyCellID()
}

func modelReferenceKey(reference model.RecordReference) string {
	return reference.ID() + "\x00" + fmt.Sprint(reference.SchemaVersion())
}

func copyAssociations(values []Association) []Association {
	result := append([]Association(nil), values...)
	for index := range result {
		if result[index].hintReference != nil {
			copyValue := *result[index].hintReference
			result[index].hintReference = &copyValue
		}
	}
	return result
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
