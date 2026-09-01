package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var errObservationV1RequiresReingestion = errors.New("observation schema v1 requires trusted-source re-ingestion as schema v2")

// MarshalObservationV1 refuses to emit the unsafe pre-consumer schema. Version
// 1 did not encode the mandatory observation basis, explicit synthetic
// classification, or trusted retention decision and clock. Those values cannot
// be reconstructed safely from an in-memory version 2 observation.
func MarshalObservationV1(Observation) ([]byte, error) {
	return nil, errObservationV1RequiresReingestion
}

// UnmarshalObservationV1 refuses to invent security-relevant fields absent
// from version 1. Callers must re-ingest the trusted source record as version 2.
func UnmarshalObservationV1([]byte) (Observation, error) {
	return Observation{}, errObservationV1RequiresReingestion
}

// MarshalObservationV2 serializes an observation into the storage-neutral
// canonical JSON fixture representation for schema version 2. It is not the
// separately planned external protobuf transport.
func MarshalObservationV2(observation Observation) ([]byte, error) {
	if err := observation.validate(); err != nil {
		return nil, fmt.Errorf("marshal observation v2: %w", err)
	}
	blob, err := json.Marshal(toObservationV2(observation))
	if err != nil {
		return nil, fmt.Errorf("marshal observation v2: %w", err)
	}
	return blob, nil
}

// UnmarshalObservationV2 decodes and validates schema version 2. Unknown JSON
// fields are ignored so additive v2 fields remain forward compatible; an
// unsupported schema version always fails closed.
func UnmarshalObservationV2(blob []byte) (Observation, error) {
	var wire observationV2
	if err := json.Unmarshal(blob, &wire); err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v2: %w", err)
	}
	observation, err := wire.toModel()
	if err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v2: %w", err)
	}
	return observation, nil
}

type observationV2 struct {
	Envelope          envelopeV2            `json:"envelope"`
	Basis             ObservationBasis      `json:"basis"`
	ObservationType   string                `json:"observation_type"`
	Source            sourceIdentityV2      `json:"source"`
	Collector         collectorIdentityV2   `json:"collector"`
	Control           *controlIdentityV2    `json:"control,omitempty"`
	SourceTimestamp   *time.Time            `json:"source_timestamp,omitempty"`
	ObservedTimestamp time.Time             `json:"observed_timestamp"`
	IngestedAt        time.Time             `json:"ingested_at"`
	Subject           *entityReferenceV2    `json:"subject,omitempty"`
	Object            *entityReferenceV2    `json:"object,omitempty"`
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

type entityReferenceV2 struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
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

func toObservationV2(observation Observation) observationV2 {
	w := observationV2{
		Envelope: toEnvelopeV2(observation.envelope), Basis: observation.basis,
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
		w.Subject = &entityReferenceV2{ID: observation.subject.id, Kind: observation.subject.kind}
	}
	if observation.object != nil {
		w.Object = &entityReferenceV2{ID: observation.object.id, Kind: observation.object.kind}
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

func (w observationV2) toModel() (Observation, error) {
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
	subject, err := optionalEntityFromV2(w.Subject)
	if err != nil {
		return Observation{}, err
	}
	object, err := optionalEntityFromV2(w.Object)
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
	return NewObservation(ObservationInput{
		Envelope: envelope, Basis: w.Basis, ObservationType: w.ObservationType,
		Source: source, Collector: collector, Control: control,
		SourceTimestamp: copyTime(w.SourceTimestamp), ObservedTimestamp: w.ObservedTimestamp,
		IngestedAt: w.IngestedAt, Subject: subject, Object: object, RawEvent: rawEvent,
		Evidence: evidence,
	})
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

func optionalEntityFromV2(value *entityReferenceV2) (*EntityReference, error) {
	if value == nil {
		return nil, nil
	}
	entity, err := NewEntityReference(value.ID, value.Kind)
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
