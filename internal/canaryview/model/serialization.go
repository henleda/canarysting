package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	errObservationV1RequiresReingestion = errors.New("observation schema v1 requires trusted-source re-ingestion as schema v3")
	errObservationV2RequiresReingestion = errors.New("observation schema v2 requires trusted-source re-ingestion as schema v3")
)

// MarshalObservationV1 refuses to emit the unsafe pre-consumer schema. Version
// 1 did not encode the mandatory observation basis, explicit synthetic
// classification, or trusted retention decision and clock. Those values cannot
// be reconstructed safely from an in-memory version 3 observation.
func MarshalObservationV1(Observation) ([]byte, error) {
	return nil, errObservationV1RequiresReingestion
}

// UnmarshalObservationV1 refuses to invent security-relevant fields absent
// from version 1. Callers must re-ingest the trusted source record as version 3.
func UnmarshalObservationV1([]byte) (Observation, error) {
	return Observation{}, errObservationV1RequiresReingestion
}

// MarshalObservationV2 refuses to erase mandatory schema-v3 knowledge state.
func MarshalObservationV2(Observation) ([]byte, error) {
	return nil, errObservationV2RequiresReingestion
}

// UnmarshalObservationV2 refuses to invent security-relevant knowledge state.
func UnmarshalObservationV2([]byte) (Observation, error) {
	return Observation{}, errObservationV2RequiresReingestion
}

// MarshalObservationV3 serializes the storage-neutral canonical JSON fixture.
// It is not the separately planned external protobuf transport.
func MarshalObservationV3(observation Observation) ([]byte, error) {
	if err := observation.validate(); err != nil {
		return nil, fmt.Errorf("marshal observation v3: %w", err)
	}
	blob, err := json.Marshal(toObservationV3(observation))
	if err != nil {
		return nil, fmt.Errorf("marshal observation v3: %w", err)
	}
	return blob, nil
}

// UnmarshalObservationV3 decodes and validates schema version 3. Unknown JSON
// fields are ignored so additive v3 fields remain forward compatible; an
// unsupported schema version always fails closed.
func UnmarshalObservationV3(blob []byte) (Observation, error) {
	var wire observationV3
	if err := json.Unmarshal(blob, &wire); err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v3: %w", err)
	}
	observation, err := wire.toModel()
	if err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v3: %w", err)
	}
	return observation, nil
}

type observationV3 struct {
	Envelope          envelopeV2            `json:"envelope"`
	Basis             ObservationBasis      `json:"basis"`
	Knowledge         knowledgeV3           `json:"knowledge"`
	ObservationType   string                `json:"observation_type"`
	Source            sourceIdentityV2      `json:"source"`
	Collector         collectorIdentityV2   `json:"collector"`
	Control           *controlIdentityV2    `json:"control,omitempty"`
	SourceTimestamp   *time.Time            `json:"source_timestamp,omitempty"`
	ObservedTimestamp time.Time             `json:"observed_timestamp"`
	IngestedAt        time.Time             `json:"ingested_at"`
	Subject           *entityReferenceV3    `json:"subject,omitempty"`
	Object            *entityReferenceV3    `json:"object,omitempty"`
	RawEvent          *rawEventReferenceV2  `json:"raw_event,omitempty"`
	Evidence          []evidenceReferenceV2 `json:"evidence,omitempty"`
}

type envelopeV2 struct {
	RecordID          string              `json:"record_id"`
	SchemaVersion     uint32              `json:"schema_version"`
	Scope             scopeV2             `json:"scope"`
	Lifecycle         lifecycleV2         `json:"lifecycle"`
	DerivationLineage []recordReferenceV2 `json:"derivation_lineage,omitempty"`
	Synthetic         *bool               `json:"synthetic"`
	ScenarioID        string              `json:"scenario_id,omitempty"`
}

type scopeV2 struct {
	TenantID           string `json:"tenant_id"`
	ScopeID            string `json:"scope_id"`
	DeploymentBoundary string `json:"deployment_boundary"`
	ResidencyCellID    string `json:"residency_cell_id"`
}

type lifecycleV2 struct {
	DataClass              DataClass         `json:"data_class"`
	Sensitivity            Sensitivity       `json:"sensitivity"`
	RetentionProfile       RetentionProfile  `json:"retention_profile"`
	PolicyVersion          string            `json:"policy_version"`
	RetentionDecisionRef   string            `json:"retention_decision_ref"`
	OverrideVersion        string            `json:"override_version,omitempty"`
	RetentionClock         RetentionClock    `json:"retention_clock"`
	RetentionStart         time.Time         `json:"retention_start"`
	ExpiresAt              time.Time         `json:"expires_at"`
	State                  LifecycleState    `json:"state"`
	LegalHoldIDs           []string          `json:"legal_hold_ids,omitempty"`
	ResidencyPolicyRef     string            `json:"residency_policy_ref"`
	EncryptionKeyRef       string            `json:"encryption_key_ref"`
	OperationalPolicyRef   string            `json:"operational_policy_ref"`
	PerTenantModelUse      modelUseGrantV2   `json:"per_tenant_model_use"`
	CrossTenantModelUse    modelUseGrantV2   `json:"cross_tenant_model_use"`
	EstimatedStorageImpact storageEstimateV2 `json:"estimated_storage_impact"`
}

type modelUseGrantV2 struct {
	Allowed   bool   `json:"allowed"`
	PolicyRef string `json:"policy_ref,omitempty"`
}

type storageEstimateV2 struct {
	Bytes uint64        `json:"bytes"`
	Basis EstimateBasis `json:"basis"`
}

type recordReferenceV2 struct {
	ID            string `json:"id"`
	SchemaVersion uint32 `json:"schema_version"`
}

type sourceIdentityV2 struct {
	System   string `json:"system"`
	Instance string `json:"instance,omitempty"`
}

type collectorIdentityV2 struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type controlIdentityV2 struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type entityReferenceV3 struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	AssertionMode AssertionMode   `json:"assertion_mode"`
	Verification  *verificationV3 `json:"verification,omitempty"`
}

type evidenceReferenceV2 struct {
	ID                 string       `json:"id"`
	SchemaVersion      uint32       `json:"schema_version"`
	Role               EvidenceRole `json:"role"`
	ExtensionNamespace string       `json:"extension_namespace,omitempty"`
	ExtensionVersion   string       `json:"extension_version,omitempty"`
}

type rawEventReferenceV2 struct {
	Reference     string          `json:"reference"`
	Availability  RawAvailability `json:"availability"`
	HashAlgorithm string          `json:"hash_algorithm,omitempty"`
	HashValue     string          `json:"hash_value,omitempty"`
}

type confidenceV3 struct {
	Level             ConfidenceLevel      `json:"level"`
	Method            ConfidenceMethod     `json:"method"`
	SourceQuality     AssuranceLevel       `json:"source_quality"`
	IdentityAssurance AssuranceLevel       `json:"identity_assurance"`
	Completeness      EvidenceCompleteness `json:"completeness"`
	CandidateCount    uint32               `json:"candidate_count"`
	TimeUncertainty   TimeUncertainty      `json:"time_uncertainty"`
	TimeWindowNanos   int64                `json:"time_window_nanos,omitempty"`
	AlgorithmID       string               `json:"algorithm_id"`
	AlgorithmVersion  string               `json:"algorithm_version"`
	Calibration       CalibrationState     `json:"calibration"`
	HumanReview       HumanReviewState     `json:"human_review"`
}

type verificationV3 struct {
	ProcedureID      string                `json:"procedure_id"`
	ProcedureVersion string                `json:"procedure_version"`
	Producer         ProducerType          `json:"producer"`
	Evidence         []evidenceReferenceV2 `json:"evidence"`
}

type lineageLinkV3 struct {
	Child  recordReferenceV2 `json:"child"`
	Parent recordReferenceV2 `json:"parent"`
}

type provenanceV3 struct {
	Root                  recordReferenceV2   `json:"root"`
	TransformationID      string              `json:"transformation_id"`
	TransformationVersion string              `json:"transformation_version"`
	Inputs                []recordReferenceV2 `json:"inputs,omitempty"`
	Links                 []lineageLinkV3     `json:"links,omitempty"`
}

type knowledgeV3 struct {
	State               KnowledgeState        `json:"state"`
	AssertionMode       AssertionMode         `json:"assertion_mode"`
	Producer            ProducerType          `json:"producer"`
	Confidence          confidenceV3          `json:"confidence"`
	Provenance          provenanceV3          `json:"provenance"`
	MissingEvidence     []MissingEvidenceKind `json:"missing_evidence,omitempty"`
	ConflictingEvidence []evidenceReferenceV2 `json:"conflicting_evidence,omitempty"`
	Verification        *verificationV3       `json:"verification,omitempty"`
}

func toObservationV3(observation Observation) observationV3 {
	w := observationV3{
		Envelope: toEnvelopeV2(observation.envelope), Basis: observation.basis,
		Knowledge:         toKnowledgeV3(observation.knowledge),
		ObservationType:   observation.observationType,
		Source:            sourceIdentityV2{System: observation.source.system, Instance: observation.source.instance},
		Collector:         collectorIdentityV2{ID: observation.collector.id, Version: observation.collector.version},
		SourceTimestamp:   copyTime(observation.sourceTimestamp),
		ObservedTimestamp: observation.observedTimestamp, IngestedAt: observation.ingestedAt,
	}
	if observation.control != nil {
		w.Control = &controlIdentityV2{ID: observation.control.id, Kind: observation.control.kind}
	}
	if observation.subject != nil {
		value := toEntityReferenceV3(*observation.subject)
		w.Subject = &value
	}
	if observation.object != nil {
		value := toEntityReferenceV3(*observation.object)
		w.Object = &value
	}
	if observation.rawEvent != nil {
		w.RawEvent = &rawEventReferenceV2{
			Reference: observation.rawEvent.reference, Availability: observation.rawEvent.availability,
			HashAlgorithm: observation.rawEvent.hashAlgorithm, HashValue: observation.rawEvent.hashValue,
		}
	}
	for _, evidence := range observation.evidence {
		w.Evidence = append(w.Evidence, evidenceReferenceV2{
			ID: evidence.id, SchemaVersion: evidence.schemaVersion,
			Role: evidence.role, ExtensionNamespace: evidence.extensionNamespace,
			ExtensionVersion: evidence.extensionVersion,
		})
	}
	return w
}

func toKnowledgeV3(knowledge Knowledge) knowledgeV3 {
	w := knowledgeV3{
		State: knowledge.state, AssertionMode: knowledge.assertionMode, Producer: knowledge.producer,
		Confidence: confidenceV3{
			Level: knowledge.confidence.level, Method: knowledge.confidence.method,
			SourceQuality:     knowledge.confidence.sourceQuality,
			IdentityAssurance: knowledge.confidence.identityAssurance,
			Completeness:      knowledge.confidence.completeness,
			CandidateCount:    knowledge.confidence.candidateCount,
			TimeUncertainty:   knowledge.confidence.timeUncertainty,
			TimeWindowNanos:   int64(knowledge.confidence.timeWindow),
			AlgorithmID:       knowledge.confidence.algorithmID,
			AlgorithmVersion:  knowledge.confidence.algorithmVersion,
			Calibration:       knowledge.confidence.calibration,
			HumanReview:       knowledge.confidence.humanReview,
		},
		Provenance: provenanceV3{
			Root:                  recordReferenceV2{ID: knowledge.provenance.root.id, SchemaVersion: knowledge.provenance.root.schemaVersion},
			TransformationID:      knowledge.provenance.transformationID,
			TransformationVersion: knowledge.provenance.transformationVersion,
		},
		MissingEvidence: append([]MissingEvidenceKind(nil), knowledge.missingEvidence...),
	}
	for _, input := range knowledge.provenance.inputs {
		w.Provenance.Inputs = append(w.Provenance.Inputs, recordReferenceV2{ID: input.id, SchemaVersion: input.schemaVersion})
	}
	for _, link := range knowledge.provenance.links {
		w.Provenance.Links = append(w.Provenance.Links, lineageLinkV3{
			Child:  recordReferenceV2{ID: link.child.id, SchemaVersion: link.child.schemaVersion},
			Parent: recordReferenceV2{ID: link.parent.id, SchemaVersion: link.parent.schemaVersion},
		})
	}
	for _, conflict := range knowledge.conflictingEvidence {
		w.ConflictingEvidence = append(w.ConflictingEvidence, toEvidenceReferenceV2(conflict))
	}
	if knowledge.verification != nil {
		value := toVerificationV3(*knowledge.verification)
		w.Verification = &value
	}
	return w
}

func toEntityReferenceV3(entity EntityReference) entityReferenceV3 {
	w := entityReferenceV3{ID: entity.id, Kind: entity.kind, AssertionMode: entity.assertionMode}
	if entity.verification != nil {
		value := toVerificationV3(*entity.verification)
		w.Verification = &value
	}
	return w
}

func toVerificationV3(verification Verification) verificationV3 {
	w := verificationV3{
		ProcedureID: verification.procedureID, ProcedureVersion: verification.procedureVersion,
		Producer: verification.producer,
	}
	for _, evidence := range verification.evidence {
		w.Evidence = append(w.Evidence, toEvidenceReferenceV2(evidence))
	}
	return w
}

func toEvidenceReferenceV2(evidence EvidenceReference) evidenceReferenceV2 {
	return evidenceReferenceV2{
		ID: evidence.id, SchemaVersion: evidence.schemaVersion, Role: evidence.role,
		ExtensionNamespace: evidence.extensionNamespace, ExtensionVersion: evidence.extensionVersion,
	}
}

func toEnvelopeV2(envelope Envelope) envelopeV2 {
	lifecycle := envelope.lifecycle
	synthetic := envelope.synthetic.synthetic
	w := envelopeV2{
		RecordID: envelope.recordID, SchemaVersion: envelope.schemaVersion,
		Scope: scopeV2{
			TenantID: envelope.scope.tenantID, ScopeID: envelope.scope.scopeID,
			DeploymentBoundary: envelope.scope.deploymentBoundary,
			ResidencyCellID:    envelope.scope.residencyCellID,
		},
		Lifecycle: lifecycleV2{
			DataClass: lifecycle.dataClass, Sensitivity: lifecycle.sensitivity,
			RetentionProfile: lifecycle.retentionProfile, PolicyVersion: lifecycle.policyVersion,
			RetentionDecisionRef: lifecycle.retentionDecisionRef,
			OverrideVersion:      lifecycle.overrideVersion, RetentionClock: lifecycle.retentionClock,
			RetentionStart: lifecycle.retentionStart,
			ExpiresAt:      lifecycle.expiresAt, State: lifecycle.state,
			LegalHoldIDs:           append([]string(nil), lifecycle.legalHoldIDs...),
			ResidencyPolicyRef:     lifecycle.residencyPolicyRef,
			EncryptionKeyRef:       lifecycle.encryptionKeyRef,
			OperationalPolicyRef:   lifecycle.operationalPolicyRef,
			PerTenantModelUse:      modelUseGrantV2{Allowed: lifecycle.perTenantModelUse.allowed, PolicyRef: lifecycle.perTenantModelUse.policyRef},
			CrossTenantModelUse:    modelUseGrantV2{Allowed: lifecycle.crossTenantModelUse.allowed, PolicyRef: lifecycle.crossTenantModelUse.policyRef},
			EstimatedStorageImpact: storageEstimateV2{Bytes: lifecycle.estimatedStorageImpact.bytes, Basis: lifecycle.estimatedStorageImpact.basis},
		},
		Synthetic: &synthetic, ScenarioID: envelope.synthetic.scenarioID,
	}
	for _, lineage := range envelope.derivationLineage {
		w.DerivationLineage = append(w.DerivationLineage, recordReferenceV2{ID: lineage.id, SchemaVersion: lineage.schemaVersion})
	}
	return w
}

func (w observationV3) toModel() (Observation, error) {
	envelope, err := w.Envelope.toModel()
	if err != nil {
		return Observation{}, err
	}
	source, err := NewSourceIdentity(w.Source.System, w.Source.Instance)
	if err != nil {
		return Observation{}, err
	}
	collector, err := NewCollectorIdentity(w.Collector.ID, w.Collector.Version)
	if err != nil {
		return Observation{}, err
	}
	control, err := optionalControlFromV2(w.Control)
	if err != nil {
		return Observation{}, err
	}
	subject, err := optionalEntityFromV3(w.Subject)
	if err != nil {
		return Observation{}, err
	}
	object, err := optionalEntityFromV3(w.Object)
	if err != nil {
		return Observation{}, err
	}
	rawEvent, err := optionalRawEventFromV2(w.RawEvent)
	if err != nil {
		return Observation{}, err
	}
	evidence := make([]EvidenceReference, 0, len(w.Evidence))
	for _, value := range w.Evidence {
		ref, err := NewEvidenceReference(value.ID, value.SchemaVersion, value.Role, value.ExtensionNamespace, value.ExtensionVersion)
		if err != nil {
			return Observation{}, err
		}
		evidence = append(evidence, ref)
	}
	knowledge, err := w.Knowledge.toModel()
	if err != nil {
		return Observation{}, fmt.Errorf("knowledge: %w", err)
	}
	return NewObservation(ObservationInput{
		Envelope: envelope, Basis: w.Basis, Knowledge: knowledge,
		ObservationType: w.ObservationType,
		Source:          source, Collector: collector, Control: control,
		SourceTimestamp: copyTime(w.SourceTimestamp), ObservedTimestamp: w.ObservedTimestamp,
		IngestedAt: w.IngestedAt, Subject: subject, Object: object, RawEvent: rawEvent,
		Evidence: evidence,
	})
}

func (w knowledgeV3) toModel() (Knowledge, error) {
	confidence, err := NewConfidence(ConfidenceInput{
		Level: w.Confidence.Level, Method: w.Confidence.Method,
		SourceQuality:     w.Confidence.SourceQuality,
		IdentityAssurance: w.Confidence.IdentityAssurance,
		Completeness:      w.Confidence.Completeness,
		CandidateCount:    w.Confidence.CandidateCount,
		TimeUncertainty:   w.Confidence.TimeUncertainty,
		TimeWindow:        time.Duration(w.Confidence.TimeWindowNanos),
		AlgorithmID:       w.Confidence.AlgorithmID,
		AlgorithmVersion:  w.Confidence.AlgorithmVersion,
		Calibration:       w.Confidence.Calibration,
		HumanReview:       w.Confidence.HumanReview,
	})
	if err != nil {
		return Knowledge{}, err
	}
	root, err := w.Provenance.Root.toModel()
	if err != nil {
		return Knowledge{}, err
	}
	inputs := make([]RecordReference, 0, len(w.Provenance.Inputs))
	for _, value := range w.Provenance.Inputs {
		ref, err := value.toModel()
		if err != nil {
			return Knowledge{}, err
		}
		inputs = append(inputs, ref)
	}
	links := make([]LineageLink, 0, len(w.Provenance.Links))
	for _, value := range w.Provenance.Links {
		child, err := value.Child.toModel()
		if err != nil {
			return Knowledge{}, err
		}
		parent, err := value.Parent.toModel()
		if err != nil {
			return Knowledge{}, err
		}
		link, err := NewLineageLink(child, parent)
		if err != nil {
			return Knowledge{}, err
		}
		links = append(links, link)
	}
	provenance, err := NewProvenance(root, w.Provenance.TransformationID, w.Provenance.TransformationVersion, inputs, links)
	if err != nil {
		return Knowledge{}, err
	}
	conflicts, err := evidenceReferencesFromV2(w.ConflictingEvidence)
	if err != nil {
		return Knowledge{}, err
	}
	verification, err := optionalVerificationFromV3(w.Verification)
	if err != nil {
		return Knowledge{}, err
	}
	return NewKnowledge(KnowledgeInput{
		State: w.State, AssertionMode: w.AssertionMode, Producer: w.Producer,
		Confidence: confidence, Provenance: provenance,
		MissingEvidence: w.MissingEvidence, ConflictingEvidence: conflicts,
		Verification: verification,
	})
}

func (w recordReferenceV2) toModel() (RecordReference, error) {
	return NewRecordReference(w.ID, w.SchemaVersion)
}

func evidenceReferencesFromV2(values []evidenceReferenceV2) ([]EvidenceReference, error) {
	result := make([]EvidenceReference, 0, len(values))
	for _, value := range values {
		ref, err := NewEvidenceReference(value.ID, value.SchemaVersion, value.Role, value.ExtensionNamespace, value.ExtensionVersion)
		if err != nil {
			return nil, err
		}
		result = append(result, ref)
	}
	return result, nil
}

func optionalVerificationFromV3(value *verificationV3) (*Verification, error) {
	if value == nil {
		return nil, nil
	}
	evidence, err := evidenceReferencesFromV2(value.Evidence)
	if err != nil {
		return nil, err
	}
	verification, err := NewVerification(value.ProcedureID, value.ProcedureVersion, value.Producer, evidence)
	if err != nil {
		return nil, err
	}
	return &verification, nil
}

func (w envelopeV2) toModel() (Envelope, error) {
	scope, err := NewScope(w.Scope.TenantID, w.Scope.ScopeID, w.Scope.DeploymentBoundary, w.Scope.ResidencyCellID)
	if err != nil {
		return Envelope{}, err
	}
	perTenant, err := NewModelUseGrant(w.Lifecycle.PerTenantModelUse.Allowed, w.Lifecycle.PerTenantModelUse.PolicyRef)
	if err != nil {
		return Envelope{}, err
	}
	crossTenant, err := NewModelUseGrant(w.Lifecycle.CrossTenantModelUse.Allowed, w.Lifecycle.CrossTenantModelUse.PolicyRef)
	if err != nil {
		return Envelope{}, err
	}
	estimate, err := NewStorageEstimate(w.Lifecycle.EstimatedStorageImpact.Bytes, w.Lifecycle.EstimatedStorageImpact.Basis)
	if err != nil {
		return Envelope{}, err
	}
	lifecycle, err := NewLifecycle(LifecycleInput{
		DataClass: w.Lifecycle.DataClass, Sensitivity: w.Lifecycle.Sensitivity,
		RetentionProfile: w.Lifecycle.RetentionProfile, PolicyVersion: w.Lifecycle.PolicyVersion,
		RetentionDecisionRef: w.Lifecycle.RetentionDecisionRef,
		OverrideVersion:      w.Lifecycle.OverrideVersion, RetentionClock: w.Lifecycle.RetentionClock,
		RetentionStart: w.Lifecycle.RetentionStart,
		ExpiresAt:      w.Lifecycle.ExpiresAt, State: w.Lifecycle.State,
		LegalHoldIDs: w.Lifecycle.LegalHoldIDs, ResidencyPolicyRef: w.Lifecycle.ResidencyPolicyRef,
		EncryptionKeyRef:     w.Lifecycle.EncryptionKeyRef,
		OperationalPolicyRef: w.Lifecycle.OperationalPolicyRef,
		PerTenantModelUse:    perTenant, CrossTenantModelUse: crossTenant,
		EstimatedStorageImpact: estimate,
	})
	if err != nil {
		return Envelope{}, err
	}
	lineage := make([]RecordReference, 0, len(w.DerivationLineage))
	for _, value := range w.DerivationLineage {
		ref, err := NewRecordReference(value.ID, value.SchemaVersion)
		if err != nil {
			return Envelope{}, err
		}
		lineage = append(lineage, ref)
	}
	if w.Synthetic == nil {
		return Envelope{}, fmt.Errorf("production or synthetic classification is required")
	}
	var synthetic SyntheticContext
	if *w.Synthetic {
		synthetic, err = NewSyntheticContext(w.ScenarioID)
		if err != nil {
			return Envelope{}, err
		}
	} else {
		if w.ScenarioID != "" {
			return Envelope{}, fmt.Errorf("production record cannot carry a scenario id")
		}
		synthetic = ProductionContext()
	}
	return NewEnvelope(EnvelopeInput{
		RecordID: w.RecordID, SchemaVersion: w.SchemaVersion, Scope: scope,
		Lifecycle: lifecycle, DerivationLineage: lineage, Synthetic: synthetic,
	})
}

func optionalControlFromV2(value *controlIdentityV2) (*ControlIdentity, error) {
	if value == nil {
		return nil, nil
	}
	control, err := NewControlIdentity(value.ID, value.Kind)
	if err != nil {
		return nil, err
	}
	return &control, nil
}

func optionalEntityFromV3(value *entityReferenceV3) (*EntityReference, error) {
	if value == nil {
		return nil, nil
	}
	verification, err := optionalVerificationFromV3(value.Verification)
	if err != nil {
		return nil, err
	}
	entity, err := NewEntityReferenceWithAssertion(value.ID, value.Kind, value.AssertionMode, verification)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func optionalRawEventFromV2(value *rawEventReferenceV2) (*RawEventReference, error) {
	if value == nil {
		return nil, nil
	}
	ref, err := NewRawEventReference(value.Reference, value.Availability, value.HashAlgorithm, value.HashValue)
	if err != nil {
		return nil, err
	}
	return &ref, nil
}
