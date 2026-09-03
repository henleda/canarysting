package model

import (
	"fmt"
	"strings"
)

// CurrentSchemaVersion is the canonical record schema implemented by this
// package. It is independent of any future protobuf package version.
const CurrentSchemaVersion uint32 = 3

// DataClass binds a durable record to its reviewed lifecycle policy.
type DataClass string

const (
	DataClassEdgeReplaySpool       DataClass = "EDGE_REPLAY_SPOOL"
	DataClassRawTelemetryReference DataClass = "RAW_TELEMETRY_REFERENCE"
	DataClassRawEvidenceSnapshot   DataClass = "RAW_EVIDENCE_SNAPSHOT"
	DataClassSensitivePayload      DataClass = "SENSITIVE_PAYLOAD"
	DataClassNormalizedObservation DataClass = "NORMALIZED_OBSERVATION"
	DataClassCorrelatedTrace       DataClass = "CORRELATED_TRACE"
	DataClassRelationshipEvent     DataClass = "RELATIONSHIP_EVENT"
	DataClassGraphCurrentState     DataClass = "GRAPH_CURRENT_STATE"
	DataClassGraphSummary          DataClass = "GRAPH_SUMMARY"
	DataClassSecurityCase          DataClass = "SECURITY_CASE"
	DataClassCanaryEvidence        DataClass = "CANARY_EVIDENCE"
	DataClassActionAudit           DataClass = "ACTION_AUDIT"
	DataClassConnectorConfig       DataClass = "CONNECTOR_CONFIGURATION"
	DataClassConnectorHealth       DataClass = "CONNECTOR_HEALTH"
	DataClassFeatureBaseline       DataClass = "FEATURE_BASELINE"
	DataClassModelArtifact         DataClass = "MODEL_ARTIFACT"
	DataClassSyntheticGroundTruth  DataClass = "SYNTHETIC_GROUND_TRUTH"
)

func (d DataClass) valid() bool {
	switch d {
	case DataClassEdgeReplaySpool, DataClassRawTelemetryReference,
		DataClassRawEvidenceSnapshot, DataClassSensitivePayload,
		DataClassNormalizedObservation, DataClassCorrelatedTrace,
		DataClassRelationshipEvent, DataClassGraphCurrentState,
		DataClassGraphSummary, DataClassSecurityCase, DataClassCanaryEvidence,
		DataClassActionAudit, DataClassConnectorConfig, DataClassConnectorHealth,
		DataClassFeatureBaseline, DataClassModelArtifact,
		DataClassSyntheticGroundTruth:
		return true
	default:
		return false
	}
}

// Sensitivity is the reviewed disclosure-impact class for a durable record.
type Sensitivity string

const (
	SensitivityInternal     Sensitivity = "INTERNAL"
	SensitivityConfidential Sensitivity = "CONFIDENTIAL"
	SensitivityRestricted   Sensitivity = "RESTRICTED"
)

func (s Sensitivity) valid() bool {
	return s == SensitivityInternal || s == SensitivityConfidential || s == SensitivityRestricted
}

// RetentionProfile selects the reviewed lifecycle profile or an approved
// profile-specific override. It never grants model use.
type RetentionProfile string

const (
	RetentionLean      RetentionProfile = "LEAN"
	RetentionStandard  RetentionProfile = "STANDARD"
	RetentionRegulated RetentionProfile = "REGULATED"
	RetentionOverride  RetentionProfile = "APPROVED_OVERRIDE"
)

func (r RetentionProfile) valid() bool {
	return r == RetentionLean || r == RetentionStandard || r == RetentionRegulated || r == RetentionOverride
}

// RetentionClock records which trusted CanaryView timestamp started retention.
// Source/vendor time is never a retention clock.
type RetentionClock string

const (
	RetentionFromObserved   RetentionClock = "OBSERVED_TIME"
	RetentionFromIngest     RetentionClock = "INGEST_TIME_FALLBACK"
	RetentionFromTraceClose RetentionClock = "TRACE_CLOSE"
)

func (c RetentionClock) valid() bool {
	return c == RetentionFromObserved || c == RetentionFromIngest || c == RetentionFromTraceClose
}

// ObservationBasis makes schema-v3 Observation records source reports only.
// Correlation, inference, recommendation, and action modes belong to later
// canonical record types and cannot be encoded as an Observation.
type ObservationBasis string

const ObservationSourceReport ObservationBasis = "SOURCE_REPORT"

func (b ObservationBasis) valid() bool { return b == ObservationSourceReport }

// KnowledgeState distinguishes facts about source reports from later joins,
// interpretations, proposals, and mutations. These values are intentionally
// not a lifecycle: one state cannot be promoted into another in place.
type KnowledgeState string

const (
	KnowledgeSourceObservation KnowledgeState = "SOURCE_OBSERVATION"
	KnowledgeCorrelation       KnowledgeState = "CORRELATION"
	KnowledgeInference         KnowledgeState = "INFERENCE"
	KnowledgeRecommendation    KnowledgeState = "RECOMMENDATION"
	KnowledgeAction            KnowledgeState = "ACTION"
)

func (s KnowledgeState) valid() bool {
	switch s {
	case KnowledgeSourceObservation, KnowledgeCorrelation, KnowledgeInference,
		KnowledgeRecommendation, KnowledgeAction:
		return true
	default:
		return false
	}
}

// AssertionMode states how a claim was established. VERIFIED is reserved for
// a claim carrying a defined verification procedure and supporting evidence.
type AssertionMode string

const (
	AssertionObserved AssertionMode = "OBSERVED"
	AssertionDeclared AssertionMode = "DECLARED"
	AssertionVerified AssertionMode = "VERIFIED"
	AssertionInferred AssertionMode = "INFERRED"
)

func (m AssertionMode) valid() bool {
	return m == AssertionObserved || m == AssertionDeclared || m == AssertionVerified || m == AssertionInferred
}

// ProducerType identifies the class of producer, independently of the claim's
// knowledge state and assertion mode.
type ProducerType string

const (
	ProducerDeterministic  ProducerType = "DETERMINISTIC"
	ProducerCorrelation    ProducerType = "CORRELATION"
	ProducerInference      ProducerType = "INFERENCE"
	ProducerModelGenerated ProducerType = "MODEL_GENERATED"
	ProducerOperator       ProducerType = "OPERATOR"
)

func (p ProducerType) valid() bool {
	switch p {
	case ProducerDeterministic, ProducerCorrelation, ProducerInference,
		ProducerModelGenerated, ProducerOperator:
		return true
	default:
		return false
	}
}

// ConfidenceLevel is ordinal and deliberately non-numeric until a calibrated
// confidence model exists.
type ConfidenceLevel string

const (
	ConfidenceLow    ConfidenceLevel = "LOW"
	ConfidenceMedium ConfidenceLevel = "MEDIUM"
	ConfidenceHigh   ConfidenceLevel = "HIGH"
)

func (l ConfidenceLevel) valid() bool {
	return l == ConfidenceLow || l == ConfidenceMedium || l == ConfidenceHigh
}

// ConfidenceMethod names the evidence-combination method without claiming a
// numeric probability.
type ConfidenceMethod string

const (
	ConfidenceDirectSource           ConfidenceMethod = "DIRECT_SOURCE"
	ConfidenceExactIdentifier        ConfidenceMethod = "EXACT_IDENTIFIER"
	ConfidenceVerifiedIdentity       ConfidenceMethod = "VERIFIED_IDENTITY"
	ConfidenceDeclaredMapping        ConfidenceMethod = "DECLARED_MAPPING"
	ConfidenceTupleTimeWindow        ConfidenceMethod = "TUPLE_TIME_WINDOW"
	ConfidenceCompositeCorrelation   ConfidenceMethod = "COMPOSITE_CORRELATION"
	ConfidenceProbabilisticInference ConfidenceMethod = "PROBABILISTIC_INFERENCE"
	ConfidenceModelInterpretation    ConfidenceMethod = "MODEL_INTERPRETATION"
)

func (m ConfidenceMethod) valid() bool {
	switch m {
	case ConfidenceDirectSource, ConfidenceExactIdentifier,
		ConfidenceVerifiedIdentity, ConfidenceDeclaredMapping,
		ConfidenceTupleTimeWindow, ConfidenceCompositeCorrelation, ConfidenceProbabilisticInference,
		ConfidenceModelInterpretation:
		return true
	default:
		return false
	}
}

type AssuranceLevel string

const (
	AssuranceUnverified AssuranceLevel = "UNVERIFIED"
	AssuranceDeclared   AssuranceLevel = "DECLARED"
	AssuranceVerified   AssuranceLevel = "VERIFIED"
)

func (a AssuranceLevel) valid() bool {
	return a == AssuranceUnverified || a == AssuranceDeclared || a == AssuranceVerified
}

type EvidenceCompleteness string

const (
	EvidencePartial  EvidenceCompleteness = "PARTIAL"
	EvidenceComplete EvidenceCompleteness = "COMPLETE"
)

func (c EvidenceCompleteness) valid() bool { return c == EvidencePartial || c == EvidenceComplete }

type TimeUncertainty string

const (
	TimeExact   TimeUncertainty = "EXACT"
	TimeBounded TimeUncertainty = "BOUNDED"
	TimeUnknown TimeUncertainty = "UNKNOWN"
)

func (u TimeUncertainty) valid() bool { return u == TimeExact || u == TimeBounded || u == TimeUnknown }

type CalibrationState string

const (
	CalibrationNotApplicable CalibrationState = "NOT_APPLICABLE"
	CalibrationUncalibrated  CalibrationState = "UNCALIBRATED"
	CalibrationCalibrated    CalibrationState = "CALIBRATED"
)

func (s CalibrationState) valid() bool {
	return s == CalibrationNotApplicable || s == CalibrationUncalibrated || s == CalibrationCalibrated
}

type HumanReviewState string

const (
	HumanUnreviewed HumanReviewState = "UNREVIEWED"
	HumanConfirmed  HumanReviewState = "CONFIRMED"
	HumanRejected   HumanReviewState = "REJECTED"
)

func (s HumanReviewState) valid() bool {
	return s == HumanUnreviewed || s == HumanConfirmed || s == HumanRejected
}

// MissingEvidenceKind is a typed diagnostic. Free-form parser or model text is
// intentionally excluded from the canonical record.
type MissingEvidenceKind string

const (
	MissingSourceTimestamp      MissingEvidenceKind = "SOURCE_TIMESTAMP"
	MissingControlIdentity      MissingEvidenceKind = "CONTROL_IDENTITY"
	MissingSubjectIdentity      MissingEvidenceKind = "SUBJECT_IDENTITY"
	MissingObjectIdentity       MissingEvidenceKind = "OBJECT_IDENTITY"
	MissingRawEvent             MissingEvidenceKind = "RAW_EVENT"
	MissingSupportingEvidence   MissingEvidenceKind = "SUPPORTING_EVIDENCE"
	MissingVerificationEvidence MissingEvidenceKind = "VERIFICATION_EVIDENCE"
)

func (k MissingEvidenceKind) valid() bool {
	switch k {
	case MissingSourceTimestamp, MissingControlIdentity, MissingSubjectIdentity,
		MissingObjectIdentity, MissingRawEvent, MissingSupportingEvidence,
		MissingVerificationEvidence:
		return true
	default:
		return false
	}
}

// LifecycleState distinguishes expiry, hold, deletion, and invalidation. These
// states are never interchangeable.
type LifecycleState string

const (
	LifecycleActive          LifecycleState = "ACTIVE"
	LifecycleExpiryDue       LifecycleState = "EXPIRY_DUE"
	LifecycleHeld            LifecycleState = "HELD"
	LifecycleDeletionPending LifecycleState = "DELETION_PENDING"
	LifecycleDeleted         LifecycleState = "DELETED"
	LifecycleInvalidated     LifecycleState = "INVALIDATED"
	LifecycleDeletionFailed  LifecycleState = "DELETION_FAILED"
)

func (s LifecycleState) valid() bool {
	switch s {
	case LifecycleActive, LifecycleExpiryDue, LifecycleHeld,
		LifecycleDeletionPending, LifecycleDeleted, LifecycleInvalidated,
		LifecycleDeletionFailed:
		return true
	default:
		return false
	}
}

// EstimateBasis states whether a storage estimate is measured or an explicit
// approximation. An assumption must never be represented as a measurement.
type EstimateBasis string

const (
	EstimateMeasured         EstimateBasis = "MEASURED"
	EstimateCustomerSupplied EstimateBasis = "CUSTOMER_SUPPLIED"
	EstimateBenchmarked      EstimateBasis = "BENCHMARKED"
	EstimateAssumed          EstimateBasis = "ASSUMED"
)

func (b EstimateBasis) valid() bool {
	return b == EstimateMeasured || b == EstimateCustomerSupplied || b == EstimateBenchmarked || b == EstimateAssumed
}

// EvidenceRole keeps vendor extensions and contradictory material in the
// evidence plane rather than adding vendor-specific canonical fields.
type EvidenceRole string

const (
	EvidenceSupporting      EvidenceRole = "SUPPORTING"
	EvidenceContradicting   EvidenceRole = "CONTRADICTING"
	EvidenceVendorExtension EvidenceRole = "VENDOR_EXTENSION"
)

func (r EvidenceRole) valid() bool {
	return r == EvidenceSupporting || r == EvidenceContradicting || r == EvidenceVendorExtension
}

// RawAvailability records why source-owned raw evidence can or cannot be read.
type RawAvailability string

const (
	RawAvailable         RawAvailability = "AVAILABLE"
	RawExpired           RawAvailability = "EXPIRED"
	RawDeleted           RawAvailability = "DELETED"
	RawAccessDenied      RawAvailability = "ACCESS_DENIED"
	RawMoved             RawAvailability = "MOVED"
	RawIntegrityMismatch RawAvailability = "INTEGRITY_MISMATCH"
)

func (a RawAvailability) valid() bool {
	switch a {
	case RawAvailable, RawExpired, RawDeleted, RawAccessDenied, RawMoved, RawIntegrityMismatch:
		return true
	default:
		return false
	}
}

func required(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is required and must not have surrounding whitespace", label)
	}
	return nil
}
