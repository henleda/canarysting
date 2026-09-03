package trace

import (
	"fmt"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

func (t Trace) validate() error {
	canonicalEnvelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: t.envelope.RecordID(), SchemaVersion: t.envelope.SchemaVersion(),
		Scope: t.envelope.Scope(), Lifecycle: t.envelope.Lifecycle(),
		DerivationLineage: t.envelope.DerivationLineage(), Synthetic: t.envelope.Synthetic(),
	})
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	if !t.status.valid() {
		return fmt.Errorf("unsupported trace status %q", t.status)
	}
	if t.validFrom.IsZero() || t.validTo.IsZero() || t.closedAt.IsZero() || t.builtAt.IsZero() {
		return fmt.Errorf("trace validity, close, and build times are required")
	}
	if t.validTo.Before(t.validFrom) {
		return fmt.Errorf("trace validity end cannot precede start")
	}
	if t.closedAt.Before(t.validTo) || t.builtAt.Before(t.closedAt) {
		return fmt.Errorf("trace close/build ordering is invalid")
	}
	if len(t.hops) == 0 || len(t.expectations) == 0 {
		return fmt.Errorf("trace requires hops and declared-coverage expectations")
	}
	if err := validateReference(t.highWaterMark); err != nil {
		return fmt.Errorf("input high-water mark: %w", err)
	}
	if _, err := canonicalTraceLifecycle(canonicalEnvelope.Lifecycle(), t.closedAt); err != nil {
		return err
	}

	wantStatus := StatusComplete
	if len(t.missingTelemetry) > 0 {
		wantStatus = StatusPartial
	}
	if len(t.conflicts) > 0 {
		wantStatus = StatusConflicted
	}
	if t.status != wantStatus {
		return fmt.Errorf("trace status %s does not match evidence state %s", t.status, wantStatus)
	}

	knowledge, err := canonicalKnowledge(t.knowledge)
	if err != nil {
		return fmt.Errorf("knowledge: %w", err)
	}
	provenance := knowledge.Provenance()
	root := provenance.Root()
	if root.ID() != canonicalEnvelope.RecordID() || root.SchemaVersion() != canonicalEnvelope.SchemaVersion() {
		return fmt.Errorf("provenance root must match trace envelope")
	}
	if !sameReferences(provenance.Inputs(), canonicalEnvelope.DerivationLineage()) {
		return fmt.Errorf("provenance inputs must match trace envelope lineage")
	}
	confidence := knowledge.Confidence()
	if confidence.AlgorithmID() != provenance.TransformationID() || confidence.AlgorithmVersion() != provenance.TransformationVersion() {
		return fmt.Errorf("trace confidence and provenance algorithms must match")
	}
	wantCompleteness := model.EvidenceComplete
	if len(t.missingTelemetry) > 0 {
		wantCompleteness = model.EvidencePartial
	}
	if confidence.Completeness() != wantCompleteness {
		return fmt.Errorf("trace confidence completeness %s does not match missing evidence state %s", confidence.Completeness(), wantCompleteness)
	}

	lineage, err := traceLineage(t.highWaterMark, t.hops, t.correlations, t.conflicts)
	if err != nil {
		return err
	}
	if !sameReferences(lineage, canonicalEnvelope.DerivationLineage()) {
		return fmt.Errorf("trace envelope lineage does not match retained evidence")
	}
	semantic := semanticParts(
		canonicalEnvelope.Scope(), canonicalEnvelope.Synthetic(), t.status, t.validFrom, t.validTo, t.closedAt,
		t.highWaterMark, t.hops, t.correlations, t.expectations, t.missingTelemetry, t.conflicts,
	)
	wantID := "trace:sha256:" + digest(append([]string{provenance.TransformationID(), provenance.TransformationVersion()}, semantic...)...)
	if canonicalEnvelope.RecordID() != wantID {
		return fmt.Errorf("trace record ID does not match deterministic semantics")
	}
	integrityParts := append([]string{wantID, t.builtAt.UTC().Format(timeFormat)}, semantic...)
	integrityParts = append(integrityParts, lifecycleParts(canonicalEnvelope.Lifecycle())...)
	wantIntegrity := "trace-integrity:sha256:" + digest(integrityParts...)
	if t.integrityDigest != wantIntegrity {
		return fmt.Errorf("trace integrity digest does not match record content")
	}
	return nil
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

func canonicalKnowledge(value model.Knowledge) (model.Knowledge, error) {
	confidence := value.Confidence()
	canonicalConfidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: confidence.Level(), Method: confidence.Method(), SourceQuality: confidence.SourceQuality(),
		IdentityAssurance: confidence.IdentityAssurance(), Completeness: confidence.Completeness(),
		CandidateCount: confidence.CandidateCount(), TimeUncertainty: confidence.TimeUncertainty(),
		TimeWindow: confidence.TimeWindow(), AlgorithmID: confidence.AlgorithmID(),
		AlgorithmVersion: confidence.AlgorithmVersion(), Calibration: confidence.Calibration(),
		HumanReview: confidence.HumanReview(),
	})
	if err != nil {
		return model.Knowledge{}, err
	}
	provenance := value.Provenance()
	canonicalProvenance, err := model.NewProvenance(
		provenance.Root(), provenance.TransformationID(), provenance.TransformationVersion(),
		provenance.Inputs(), provenance.Links(),
	)
	if err != nil {
		return model.Knowledge{}, err
	}
	var verification *model.Verification
	if valueVerification, ok := value.Verification(); ok {
		canonical, verificationErr := model.NewVerification(
			valueVerification.ProcedureID(), valueVerification.ProcedureVersion(),
			valueVerification.Producer(), valueVerification.Evidence(),
		)
		if verificationErr != nil {
			return model.Knowledge{}, verificationErr
		}
		verification = &canonical
	}
	return model.NewKnowledge(model.KnowledgeInput{
		State: value.State(), AssertionMode: value.AssertionMode(), Producer: value.Producer(),
		Confidence: canonicalConfidence, Provenance: canonicalProvenance,
		MissingEvidence: value.MissingEvidence(), ConflictingEvidence: value.ConflictingEvidence(),
		Verification: verification,
	})
}

func traceLineage(highWater model.RecordReference, hops []Hop, correlations []CorrelationSet, conflicts []Conflict) ([]model.RecordReference, error) {
	refs := []model.RecordReference{highWater}
	for _, hop := range hops {
		refs = append(refs, hop.reference)
		for _, evidence := range hop.evidence {
			refs = append(refs, evidenceReference(evidence))
		}
		for _, identity := range hop.identities {
			if verification, ok := identity.Verification(); ok {
				for _, evidence := range verification.Evidence() {
					refs = append(refs, evidenceReference(evidence))
				}
			}
		}
	}
	for _, set := range correlations {
		for _, candidate := range set.candidates {
			for _, explanation := range candidate.explanations {
				for _, step := range explanation.translations {
					refs = append(refs, step.reference)
				}
			}
		}
	}
	for _, conflict := range conflicts {
		for _, evidence := range conflict.evidence {
			refs = append(refs, evidenceReference(evidence))
		}
	}
	refs, err := uniqueReferences(refs)
	if err != nil {
		return nil, fmt.Errorf("trace lineage: %w", err)
	}
	return refs, nil
}

func sameReferences(left, right []model.RecordReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsReference(values []model.RecordReference, wanted model.RecordReference) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
