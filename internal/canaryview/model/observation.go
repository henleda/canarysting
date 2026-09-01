package model

import (
	"fmt"
	"sort"
	"time"
)

// RecordReference is a versioned lineage link to another immutable record.
type RecordReference struct {
	id            string
	schemaVersion uint32
}

func NewRecordReference(id string, schemaVersion uint32) (RecordReference, error) {
	if err := required("record reference id", id); err != nil {
		return RecordReference{}, err
	}
	if schemaVersion == 0 {
		return RecordReference{}, fmt.Errorf("record reference schema version is required")
	}
	return RecordReference{id: id, schemaVersion: schemaVersion}, nil
}

func (r RecordReference) ID() string            { return r.id }
func (r RecordReference) SchemaVersion() uint32 { return r.schemaVersion }

func (r RecordReference) validate() error {
	_, err := NewRecordReference(r.id, r.schemaVersion)
	return err
}

// SyntheticContext distinguishes lab evidence from production records. Its zero
// value is production context; synthetic records require a scenario ID.
type SyntheticContext struct {
	synthetic  bool
	scenarioID string
}

func ProductionContext() SyntheticContext { return SyntheticContext{} }

func NewSyntheticContext(scenarioID string) (SyntheticContext, error) {
	if err := required("synthetic scenario id", scenarioID); err != nil {
		return SyntheticContext{}, err
	}
	return SyntheticContext{synthetic: true, scenarioID: scenarioID}, nil
}

func (s SyntheticContext) Synthetic() bool    { return s.synthetic }
func (s SyntheticContext) ScenarioID() string { return s.scenarioID }

func (s SyntheticContext) validate() error {
	if !s.synthetic {
		if s.scenarioID != "" {
			return fmt.Errorf("production context cannot carry a scenario id")
		}
		return nil
	}
	_, err := NewSyntheticContext(s.scenarioID)
	return err
}

// EnvelopeInput is copied into an immutable Envelope.
type EnvelopeInput struct {
	RecordID          string
	SchemaVersion     uint32
	Scope             Scope
	Lifecycle         Lifecycle
	DerivationLineage []RecordReference
	Synthetic         SyntheticContext
}

// Envelope carries identity, isolation, lifecycle, lineage, and synthetic state
// common to every durable canonical record.
type Envelope struct {
	recordID          string
	schemaVersion     uint32
	scope             Scope
	lifecycle         Lifecycle
	derivationLineage []RecordReference
	synthetic         SyntheticContext
}

func NewEnvelope(in EnvelopeInput) (Envelope, error) {
	if err := required("record id", in.RecordID); err != nil {
		return Envelope{}, err
	}
	if in.SchemaVersion != CurrentSchemaVersion {
		return Envelope{}, fmt.Errorf("unsupported schema version %d", in.SchemaVersion)
	}
	if err := in.Scope.validate(); err != nil {
		return Envelope{}, fmt.Errorf("scope: %w", err)
	}
	if err := in.Lifecycle.validate(); err != nil {
		return Envelope{}, fmt.Errorf("lifecycle: %w", err)
	}
	if err := in.Synthetic.validate(); err != nil {
		return Envelope{}, fmt.Errorf("synthetic context: %w", err)
	}
	lineage := append([]RecordReference(nil), in.DerivationLineage...)
	sort.Slice(lineage, func(i, j int) bool {
		if lineage[i].id == lineage[j].id {
			return lineage[i].schemaVersion < lineage[j].schemaVersion
		}
		return lineage[i].id < lineage[j].id
	})
	for i, ref := range lineage {
		if err := ref.validate(); err != nil {
			return Envelope{}, fmt.Errorf("derivation lineage: %w", err)
		}
		if i > 0 && lineage[i-1] == ref {
			return Envelope{}, fmt.Errorf("duplicate derivation lineage reference %q", ref.id)
		}
	}
	return Envelope{
		recordID: in.RecordID, schemaVersion: in.SchemaVersion, scope: in.Scope,
		lifecycle: in.Lifecycle, derivationLineage: lineage, synthetic: in.Synthetic,
	}, nil
}

func (e Envelope) RecordID() string            { return e.recordID }
func (e Envelope) SchemaVersion() uint32       { return e.schemaVersion }
func (e Envelope) Scope() Scope                { return e.scope }
func (e Envelope) Lifecycle() Lifecycle        { return e.lifecycle }
func (e Envelope) Synthetic() SyntheticContext { return e.synthetic }
func (e Envelope) DerivationLineage() []RecordReference {
	return append([]RecordReference(nil), e.derivationLineage...)
}

func (e Envelope) validate() error {
	_, err := NewEnvelope(EnvelopeInput{
		RecordID: e.recordID, SchemaVersion: e.schemaVersion, Scope: e.scope,
		Lifecycle: e.lifecycle, DerivationLineage: e.derivationLineage, Synthetic: e.synthetic,
	})
	return err
}

// EvidenceReference links supporting, contradicting, or vendor-extension
// evidence without embedding the source payload.
type EvidenceReference struct {
	id                 string
	schemaVersion      uint32
	role               EvidenceRole
	extensionNamespace string
	extensionVersion   string
}

func NewEvidenceReference(id string, schemaVersion uint32, role EvidenceRole, extensionNamespace, extensionVersion string) (EvidenceReference, error) {
	if err := required("evidence id", id); err != nil {
		return EvidenceReference{}, err
	}
	if schemaVersion == 0 {
		return EvidenceReference{}, fmt.Errorf("evidence schema version is required")
	}
	if !role.valid() {
		return EvidenceReference{}, fmt.Errorf("unsupported evidence role %q", role)
	}
	if role == EvidenceVendorExtension {
		if err := required("vendor extension namespace", extensionNamespace); err != nil {
			return EvidenceReference{}, err
		}
		if err := required("vendor extension version", extensionVersion); err != nil {
			return EvidenceReference{}, err
		}
	} else if extensionNamespace != "" || extensionVersion != "" {
		return EvidenceReference{}, fmt.Errorf("only vendor-extension evidence may carry an extension namespace/version")
	}
	return EvidenceReference{id: id, schemaVersion: schemaVersion, role: role, extensionNamespace: extensionNamespace, extensionVersion: extensionVersion}, nil
}

func (e EvidenceReference) ID() string                 { return e.id }
func (e EvidenceReference) SchemaVersion() uint32      { return e.schemaVersion }
func (e EvidenceReference) Role() EvidenceRole         { return e.role }
func (e EvidenceReference) ExtensionNamespace() string { return e.extensionNamespace }
func (e EvidenceReference) ExtensionVersion() string   { return e.extensionVersion }

func (e EvidenceReference) validate() error {
	_, err := NewEvidenceReference(e.id, e.schemaVersion, e.role, e.extensionNamespace, e.extensionVersion)
	return err
}

// RawEventReference points to source-owned material and records its availability
// and optional integrity digest. It intentionally has no content/payload field.
type RawEventReference struct {
	reference     string
	availability  RawAvailability
	hashAlgorithm string
	hashValue     string
}

func NewRawEventReference(reference string, availability RawAvailability, hashAlgorithm, hashValue string) (RawEventReference, error) {
	if err := required("raw event reference", reference); err != nil {
		return RawEventReference{}, err
	}
	if !availability.valid() {
		return RawEventReference{}, fmt.Errorf("unsupported raw availability %q", availability)
	}
	if (hashAlgorithm == "") != (hashValue == "") {
		return RawEventReference{}, fmt.Errorf("raw event hash algorithm and value must be supplied together")
	}
	if hashAlgorithm != "" {
		if err := required("raw event hash algorithm", hashAlgorithm); err != nil {
			return RawEventReference{}, err
		}
		if err := required("raw event hash value", hashValue); err != nil {
			return RawEventReference{}, err
		}
	}
	return RawEventReference{reference: reference, availability: availability, hashAlgorithm: hashAlgorithm, hashValue: hashValue}, nil
}

func (r RawEventReference) Reference() string             { return r.reference }
func (r RawEventReference) Availability() RawAvailability { return r.availability }
func (r RawEventReference) HashAlgorithm() string         { return r.hashAlgorithm }
func (r RawEventReference) HashValue() string             { return r.hashValue }

func (r RawEventReference) validate() error {
	_, err := NewRawEventReference(r.reference, r.availability, r.hashAlgorithm, r.hashValue)
	return err
}

// ObservationInput is copied into an immutable Observation. SourceTimestamp,
// subject/object, control, raw reference, and evidence are optional so partial
// source reports remain representable without invented values.
type ObservationInput struct {
	Envelope          Envelope
	ObservationType   string
	Source            SourceIdentity
	Collector         CollectorIdentity
	Control           *ControlIdentity
	SourceTimestamp   *time.Time
	ObservedTimestamp time.Time
	IngestedAt        time.Time
	Subject           *EntityReference
	Object            *EntityReference
	RawEvent          *RawEventReference
	Evidence          []EvidenceReference
	MissingFields     []string
	ParserWarnings    []string
}

// Observation is an immutable normalized claim about what one source reported.
// It is not a correlation, inference, recommendation, or action.
type Observation struct {
	envelope          Envelope
	observationType   string
	source            SourceIdentity
	collector         CollectorIdentity
	control           *ControlIdentity
	sourceTimestamp   *time.Time
	observedTimestamp time.Time
	ingestedAt        time.Time
	subject           *EntityReference
	object            *EntityReference
	rawEvent          *RawEventReference
	evidence          []EvidenceReference
	missingFields     []string
	parserWarnings    []string
}

func NewObservation(in ObservationInput) (Observation, error) {
	if err := in.Envelope.validate(); err != nil {
		return Observation{}, fmt.Errorf("envelope: %w", err)
	}
	if in.Envelope.lifecycle.dataClass != DataClassNormalizedObservation {
		return Observation{}, fmt.Errorf("observation requires data class %s", DataClassNormalizedObservation)
	}
	if err := required("observation type", in.ObservationType); err != nil {
		return Observation{}, err
	}
	if err := in.Source.validate(); err != nil {
		return Observation{}, fmt.Errorf("source: %w", err)
	}
	if err := in.Collector.validate(); err != nil {
		return Observation{}, fmt.Errorf("collector: %w", err)
	}
	if in.ObservedTimestamp.IsZero() || in.IngestedAt.IsZero() {
		return Observation{}, fmt.Errorf("observed timestamp and ingest time are required")
	}
	control, err := copyOptional(in.Control, func(value ControlIdentity) error { return value.validate() })
	if err != nil {
		return Observation{}, fmt.Errorf("control: %w", err)
	}
	subject, err := copyOptional(in.Subject, func(value EntityReference) error { return value.validate() })
	if err != nil {
		return Observation{}, fmt.Errorf("subject: %w", err)
	}
	object, err := copyOptional(in.Object, func(value EntityReference) error { return value.validate() })
	if err != nil {
		return Observation{}, fmt.Errorf("object: %w", err)
	}
	rawEvent, err := copyOptional(in.RawEvent, func(value RawEventReference) error { return value.validate() })
	if err != nil {
		return Observation{}, fmt.Errorf("raw event: %w", err)
	}
	evidence := append([]EvidenceReference(nil), in.Evidence...)
	for _, ref := range evidence {
		if err := ref.validate(); err != nil {
			return Observation{}, fmt.Errorf("evidence: %w", err)
		}
	}
	sourceTimestamp := copyTime(in.SourceTimestamp)
	return Observation{
		envelope: in.Envelope, observationType: in.ObservationType,
		source: in.Source, collector: in.Collector, control: control,
		sourceTimestamp: sourceTimestamp, observedTimestamp: in.ObservedTimestamp.UTC(),
		ingestedAt: in.IngestedAt.UTC(), subject: subject, object: object,
		rawEvent: rawEvent, evidence: evidence,
		missingFields:  append([]string(nil), in.MissingFields...),
		parserWarnings: append([]string(nil), in.ParserWarnings...),
	}, nil
}

func (o Observation) Envelope() Envelope           { return o.envelope }
func (o Observation) ObservationType() string      { return o.observationType }
func (o Observation) Source() SourceIdentity       { return o.source }
func (o Observation) Collector() CollectorIdentity { return o.collector }
func (o Observation) ObservedTimestamp() time.Time { return o.observedTimestamp }
func (o Observation) IngestedAt() time.Time        { return o.ingestedAt }
func (o Observation) Evidence() []EvidenceReference {
	return append([]EvidenceReference(nil), o.evidence...)
}
func (o Observation) MissingFields() []string  { return append([]string(nil), o.missingFields...) }
func (o Observation) ParserWarnings() []string { return append([]string(nil), o.parserWarnings...) }

func (o Observation) SourceTimestamp() (time.Time, bool)  { return valueTime(o.sourceTimestamp) }
func (o Observation) Control() (ControlIdentity, bool)    { return valueOptional(o.control) }
func (o Observation) Subject() (EntityReference, bool)    { return valueOptional(o.subject) }
func (o Observation) Object() (EntityReference, bool)     { return valueOptional(o.object) }
func (o Observation) RawEvent() (RawEventReference, bool) { return valueOptional(o.rawEvent) }

func (o Observation) validate() error {
	_, err := NewObservation(ObservationInput{
		Envelope: o.envelope, ObservationType: o.observationType,
		Source: o.source, Collector: o.collector, Control: o.control,
		SourceTimestamp: o.sourceTimestamp, ObservedTimestamp: o.observedTimestamp,
		IngestedAt: o.ingestedAt, Subject: o.subject, Object: o.object,
		RawEvent: o.rawEvent, Evidence: o.evidence, MissingFields: o.missingFields,
		ParserWarnings: o.parserWarnings,
	})
	return err
}

func copyOptional[T any](value *T, validate func(T) error) (*T, error) {
	if value == nil {
		return nil, nil
	}
	copyValue := *value
	if err := validate(copyValue); err != nil {
		return nil, err
	}
	return &copyValue, nil
}

func valueOptional[T any](value *T) (T, bool) {
	if value == nil {
		var zero T
		return zero, false
	}
	return *value, true
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
}

func valueTime(value *time.Time) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}
	return *value, true
}
