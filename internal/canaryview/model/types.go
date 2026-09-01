package model

import (
	"fmt"
	"strings"
)

// CurrentSchemaVersion is the canonical record schema implemented by this
// package. It is independent of any future protobuf package version.
const CurrentSchemaVersion uint32 = 1

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
