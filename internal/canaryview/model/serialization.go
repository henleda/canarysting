package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// MarshalObservationV1 serializes an observation into the storage-neutral
// canonical JSON fixture representation for schema version 1. It is not the
// separately planned external protobuf transport.
func MarshalObservationV1(observation Observation) ([]byte, error) {
	if err := observation.validate(); err != nil {
		return nil, fmt.Errorf("marshal observation v1: %w", err)
	}
	blob, err := json.Marshal(toObservationV1(observation))
	if err != nil {
		return nil, fmt.Errorf("marshal observation v1: %w", err)
	}
	return blob, nil
}

// UnmarshalObservationV1 decodes and validates schema version 1. Unknown JSON
// fields are ignored so additive v1 fields remain forward compatible; an
// unsupported schema version always fails closed.
func UnmarshalObservationV1(blob []byte) (Observation, error) {
	var wire observationV1
	if err := json.Unmarshal(blob, &wire); err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v1: %w", err)
	}
	observation, err := wire.toModel()
	if err != nil {
		return Observation{}, fmt.Errorf("unmarshal observation v1: %w", err)
	}
	return observation, nil
}

type observationV1 struct {
	Envelope          envelopeV1            `json:"envelope"`
	ObservationType   string                `json:"observation_type"`
	Source            sourceIdentityV1      `json:"source"`
	Collector         collectorIdentityV1   `json:"collector"`
	Control           *controlIdentityV1    `json:"control,omitempty"`
	SourceTimestamp   *time.Time            `json:"source_timestamp,omitempty"`
	ObservedTimestamp time.Time             `json:"observed_timestamp"`
	IngestedAt        time.Time             `json:"ingested_at"`
	Subject           *entityReferenceV1    `json:"subject,omitempty"`
	Object            *entityReferenceV1    `json:"object,omitempty"`
	RawEvent          *rawEventReferenceV1  `json:"raw_event,omitempty"`
	Evidence          []evidenceReferenceV1 `json:"evidence,omitempty"`
	MissingFields     []string              `json:"missing_fields,omitempty"`
	ParserWarnings    []string              `json:"parser_warnings,omitempty"`
}

type envelopeV1 struct {
	RecordID          string              `json:"record_id"`
	SchemaVersion     uint32              `json:"schema_version"`
	Scope             scopeV1             `json:"scope"`
	Lifecycle         lifecycleV1         `json:"lifecycle"`
	DerivationLineage []recordReferenceV1 `json:"derivation_lineage,omitempty"`
	Synthetic         bool                `json:"synthetic"`
	ScenarioID        string              `json:"scenario_id,omitempty"`
}

type scopeV1 struct {
	TenantID           string `json:"tenant_id"`
	ScopeID            string `json:"scope_id"`
	DeploymentBoundary string `json:"deployment_boundary"`
	ResidencyCellID    string `json:"residency_cell_id"`
}

type lifecycleV1 struct {
	DataClass              DataClass         `json:"data_class"`
	Sensitivity            Sensitivity       `json:"sensitivity"`
	RetentionProfile       RetentionProfile  `json:"retention_profile"`
	PolicyVersion          string            `json:"policy_version"`
	OverrideVersion        string            `json:"override_version,omitempty"`
	RetentionStart         time.Time         `json:"retention_start"`
	ExpiresAt              time.Time         `json:"expires_at"`
	State                  LifecycleState    `json:"state"`
	LegalHoldIDs           []string          `json:"legal_hold_ids,omitempty"`
	ResidencyPolicyRef     string            `json:"residency_policy_ref"`
	EncryptionKeyRef       string            `json:"encryption_key_ref"`
	OperationalPolicyRef   string            `json:"operational_policy_ref"`
	PerTenantModelUse      modelUseGrantV1   `json:"per_tenant_model_use"`
	CrossTenantModelUse    modelUseGrantV1   `json:"cross_tenant_model_use"`
	EstimatedStorageImpact storageEstimateV1 `json:"estimated_storage_impact"`
}

type modelUseGrantV1 struct {
	Allowed   bool   `json:"allowed"`
	PolicyRef string `json:"policy_ref,omitempty"`
}

type storageEstimateV1 struct {
	Bytes uint64        `json:"bytes"`
	Basis EstimateBasis `json:"basis"`
}

type recordReferenceV1 struct {
	ID            string `json:"id"`
	SchemaVersion uint32 `json:"schema_version"`
}

type sourceIdentityV1 struct {
	System   string `json:"system"`
	Instance string `json:"instance,omitempty"`
}

type collectorIdentityV1 struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type controlIdentityV1 struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type entityReferenceV1 struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type evidenceReferenceV1 struct {
	ID                 string       `json:"id"`
	SchemaVersion      uint32       `json:"schema_version"`
	Role               EvidenceRole `json:"role"`
	ExtensionNamespace string       `json:"extension_namespace,omitempty"`
	ExtensionVersion   string       `json:"extension_version,omitempty"`
}

type rawEventReferenceV1 struct {
	Reference     string          `json:"reference"`
	Availability  RawAvailability `json:"availability"`
	HashAlgorithm string          `json:"hash_algorithm,omitempty"`
	HashValue     string          `json:"hash_value,omitempty"`
}

func toObservationV1(observation Observation) observationV1 {
	w := observationV1{
		Envelope: toEnvelopeV1(observation.envelope), ObservationType: observation.observationType,
		Source:            sourceIdentityV1{System: observation.source.system, Instance: observation.source.instance},
		Collector:         collectorIdentityV1{ID: observation.collector.id, Version: observation.collector.version},
		SourceTimestamp:   copyTime(observation.sourceTimestamp),
		ObservedTimestamp: observation.observedTimestamp, IngestedAt: observation.ingestedAt,
		MissingFields:  append([]string(nil), observation.missingFields...),
		ParserWarnings: append([]string(nil), observation.parserWarnings...),
	}
	if observation.control != nil {
		w.Control = &controlIdentityV1{ID: observation.control.id, Kind: observation.control.kind}
	}
	if observation.subject != nil {
		w.Subject = &entityReferenceV1{ID: observation.subject.id, Kind: observation.subject.kind}
	}
	if observation.object != nil {
		w.Object = &entityReferenceV1{ID: observation.object.id, Kind: observation.object.kind}
	}
	if observation.rawEvent != nil {
		w.RawEvent = &rawEventReferenceV1{
			Reference: observation.rawEvent.reference, Availability: observation.rawEvent.availability,
			HashAlgorithm: observation.rawEvent.hashAlgorithm, HashValue: observation.rawEvent.hashValue,
		}
	}
	for _, evidence := range observation.evidence {
		w.Evidence = append(w.Evidence, evidenceReferenceV1{
			ID: evidence.id, SchemaVersion: evidence.schemaVersion,
			Role: evidence.role, ExtensionNamespace: evidence.extensionNamespace,
			ExtensionVersion: evidence.extensionVersion,
		})
	}
	return w
}

func toEnvelopeV1(envelope Envelope) envelopeV1 {
	lifecycle := envelope.lifecycle
	w := envelopeV1{
		RecordID: envelope.recordID, SchemaVersion: envelope.schemaVersion,
		Scope: scopeV1{
			TenantID: envelope.scope.tenantID, ScopeID: envelope.scope.scopeID,
			DeploymentBoundary: envelope.scope.deploymentBoundary,
			ResidencyCellID:    envelope.scope.residencyCellID,
		},
		Lifecycle: lifecycleV1{
			DataClass: lifecycle.dataClass, Sensitivity: lifecycle.sensitivity,
			RetentionProfile: lifecycle.retentionProfile, PolicyVersion: lifecycle.policyVersion,
			OverrideVersion: lifecycle.overrideVersion, RetentionStart: lifecycle.retentionStart,
			ExpiresAt: lifecycle.expiresAt, State: lifecycle.state,
			LegalHoldIDs:           append([]string(nil), lifecycle.legalHoldIDs...),
			ResidencyPolicyRef:     lifecycle.residencyPolicyRef,
			EncryptionKeyRef:       lifecycle.encryptionKeyRef,
			OperationalPolicyRef:   lifecycle.operationalPolicyRef,
			PerTenantModelUse:      modelUseGrantV1{Allowed: lifecycle.perTenantModelUse.allowed, PolicyRef: lifecycle.perTenantModelUse.policyRef},
			CrossTenantModelUse:    modelUseGrantV1{Allowed: lifecycle.crossTenantModelUse.allowed, PolicyRef: lifecycle.crossTenantModelUse.policyRef},
			EstimatedStorageImpact: storageEstimateV1{Bytes: lifecycle.estimatedStorageImpact.bytes, Basis: lifecycle.estimatedStorageImpact.basis},
		},
		Synthetic: envelope.synthetic.synthetic, ScenarioID: envelope.synthetic.scenarioID,
	}
	for _, lineage := range envelope.derivationLineage {
		w.DerivationLineage = append(w.DerivationLineage, recordReferenceV1{ID: lineage.id, SchemaVersion: lineage.schemaVersion})
	}
	return w
}

func (w observationV1) toModel() (Observation, error) {
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
	control, err := optionalControlFromV1(w.Control)
	if err != nil {
		return Observation{}, err
	}
	subject, err := optionalEntityFromV1(w.Subject)
	if err != nil {
		return Observation{}, err
	}
	object, err := optionalEntityFromV1(w.Object)
	if err != nil {
		return Observation{}, err
	}
	rawEvent, err := optionalRawEventFromV1(w.RawEvent)
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
		Envelope: envelope, ObservationType: w.ObservationType,
		Source: source, Collector: collector, Control: control,
		SourceTimestamp: copyTime(w.SourceTimestamp), ObservedTimestamp: w.ObservedTimestamp,
		IngestedAt: w.IngestedAt, Subject: subject, Object: object, RawEvent: rawEvent,
		Evidence: evidence, MissingFields: w.MissingFields, ParserWarnings: w.ParserWarnings,
	})
}

func (w envelopeV1) toModel() (Envelope, error) {
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
		OverrideVersion: w.Lifecycle.OverrideVersion, RetentionStart: w.Lifecycle.RetentionStart,
		ExpiresAt: w.Lifecycle.ExpiresAt, State: w.Lifecycle.State,
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
	var synthetic SyntheticContext
	if w.Synthetic {
		synthetic, err = NewSyntheticContext(w.ScenarioID)
		if err != nil {
			return Envelope{}, err
		}
	} else if w.ScenarioID != "" {
		return Envelope{}, fmt.Errorf("production record cannot carry a scenario id")
	}
	return NewEnvelope(EnvelopeInput{
		RecordID: w.RecordID, SchemaVersion: w.SchemaVersion, Scope: scope,
		Lifecycle: lifecycle, DerivationLineage: lineage, Synthetic: synthetic,
	})
}

func optionalControlFromV1(value *controlIdentityV1) (*ControlIdentity, error) {
	if value == nil {
		return nil, nil
	}
	control, err := NewControlIdentity(value.ID, value.Kind)
	if err != nil {
		return nil, err
	}
	return &control, nil
}

func optionalEntityFromV1(value *entityReferenceV1) (*EntityReference, error) {
	if value == nil {
		return nil, nil
	}
	entity, err := NewEntityReference(value.ID, value.Kind)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func optionalRawEventFromV1(value *rawEventReferenceV1) (*RawEventReference, error) {
	if value == nil {
		return nil, nil
	}
	ref, err := NewRawEventReference(value.Reference, value.Availability, value.HashAlgorithm, value.HashValue)
	if err != nil {
		return nil, err
	}
	return &ref, nil
}
