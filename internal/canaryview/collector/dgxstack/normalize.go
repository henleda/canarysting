package dgxstack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	normalizerVersion = "0.1.0"
	maximumTextBytes  = 512
	minimumKeyBytes   = 32
)

// SourceKind is the closed set covered by the M2B.2 reference-stack proof.
// It is not a connector capability or support manifest.
type SourceKind string

const (
	SourceCanarySting SourceKind = "canarysting"
	SourceEngine      SourceKind = "canarysting-engine"
	SourceKernel      SourceKind = "kernel-ebpf"
	SourceEnvoy       SourceKind = "envoy"
	SourceKubernetes  SourceKind = "kubernetes"
	SourceCilium      SourceKind = "cilium"
	SourceHubble      SourceKind = "hubble"
)

var allSourceKinds = []SourceKind{
	SourceCanarySting,
	SourceEngine,
	SourceKernel,
	SourceEnvoy,
	SourceKubernetes,
	SourceCilium,
	SourceHubble,
}

func (k SourceKind) valid() bool {
	for _, candidate := range allSourceKinds {
		if k == candidate {
			return true
		}
	}
	return false
}

// SourceKinds returns the proof catalog in deterministic order.
func SourceKinds() []SourceKind { return append([]SourceKind(nil), allSourceKinds...) }

// Policy is the already-reviewed lifecycle decision applied to one normalized
// observation. Model use remains default-off. RetentionOverride is accepted
// only with an explicit duration and override version.
type Policy struct {
	Scope                model.Scope
	RetentionProfile     model.RetentionProfile
	RetentionDuration    time.Duration
	PolicyVersion        string
	RetentionDecisionRef string
	OverrideVersion      string
	ResidencyPolicyRef   string
	EncryptionKeyRef     string
	OperationalPolicyRef string
	EstimatedBytes       uint64
	EstimatedBytesBasis  model.EstimateBasis
	PseudonymizationKey  []byte
}

// Context supplies immutable source identity, timing, evidence, and explicit
// production/synthetic classification for one source report.
type Context struct {
	SourceInstance string
	EventKey       string
	ObservedAt     time.Time
	IngestedAt     time.Time
	Raw            RawEvidence
	Synthetic      model.SyntheticContext
}

// RawEvidence contains only opaque digests and availability. The normalizer has
// no field capable of retaining a source locator or raw content.
type RawEvidence struct {
	ReferenceSHA256 string
	ContentSHA256   string
	Availability    model.RawAvailability
}

// Normalizer maps source reports into immutable schema-v3 observations.
type Normalizer struct {
	policy Policy
	key    []byte
}

func NewNormalizer(policy Policy) (*Normalizer, error) {
	if _, err := model.NewScope(
		policy.Scope.TenantID(), policy.Scope.ScopeID(),
		policy.Scope.DeploymentBoundary(), policy.Scope.ResidencyCellID(),
	); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if policy.RetentionProfile != model.RetentionLean &&
		policy.RetentionProfile != model.RetentionStandard &&
		policy.RetentionProfile != model.RetentionOverride {
		return nil, fmt.Errorf("reference-stack normalizer requires LEAN, STANDARD, or approved-override retention")
	}
	if policy.RetentionProfile == model.RetentionOverride {
		if policy.RetentionDuration <= 0 {
			return nil, fmt.Errorf("approved-override retention requires a positive duration")
		}
		if err := boundedRequired("override version", policy.OverrideVersion); err != nil {
			return nil, err
		}
	} else if policy.RetentionDuration != 0 || policy.OverrideVersion != "" {
		return nil, fmt.Errorf("default retention profiles cannot carry an override duration/version")
	}
	for label, value := range map[string]string{
		"policy version":               policy.PolicyVersion,
		"retention decision reference": policy.RetentionDecisionRef,
		"residency policy reference":   policy.ResidencyPolicyRef,
		"encryption key reference":     policy.EncryptionKeyRef,
		"operational policy reference": policy.OperationalPolicyRef,
	} {
		if err := boundedRequired(label, value); err != nil {
			return nil, err
		}
	}
	if _, err := model.NewStorageEstimate(policy.EstimatedBytes, policy.EstimatedBytesBasis); err != nil {
		return nil, err
	}
	if len(policy.PseudonymizationKey) < minimumKeyBytes {
		return nil, fmt.Errorf("pseudonymization key must contain at least %d bytes", minimumKeyBytes)
	}
	copyPolicy := policy
	copyPolicy.PseudonymizationKey = nil
	return &Normalizer{policy: copyPolicy, key: append([]byte(nil), policy.PseudonymizationKey...)}, nil
}

type partialReport struct {
	kind              SourceKind
	observationType   string
	sourceTimestamp   *time.Time
	subject           *model.EntityReference
	object            *model.EntityReference
	control           *model.ControlIdentity
	missing           []model.MissingEvidenceKind
	identityAssurance model.AssuranceLevel
}

func (n *Normalizer) normalize(ctx Context, report partialReport) (model.Observation, error) {
	if n == nil {
		return model.Observation{}, fmt.Errorf("normalizer is required")
	}
	if !report.kind.valid() {
		return model.Observation{}, fmt.Errorf("unsupported source kind %q", report.kind)
	}
	if err := boundedRequired("source instance", ctx.SourceInstance); err != nil {
		return model.Observation{}, err
	}
	if err := boundedRequired("source event key", ctx.EventKey); err != nil {
		return model.Observation{}, err
	}
	if ctx.ObservedAt.IsZero() || ctx.IngestedAt.IsZero() {
		return model.Observation{}, fmt.Errorf("collector-observed and ingest timestamps are required")
	}
	observedAt := ctx.ObservedAt.UTC()
	ingestedAt := ctx.IngestedAt.UTC()
	if ingestedAt.Before(observedAt) {
		return model.Observation{}, fmt.Errorf("ingest time cannot precede collector-observed time")
	}
	raw, evidence, lineage, err := evidenceReferences(ctx.Raw)
	if err != nil {
		return model.Observation{}, err
	}

	recordID := "observation:hmac-sha256:" + n.digest(
		"record", n.policy.Scope.TenantID(), n.policy.Scope.ScopeID(),
		string(report.kind), ctx.SourceInstance, ctx.EventKey, raw.Reference(),
	)
	lifecycle, err := n.lifecycle(observedAt)
	if err != nil {
		return model.Observation{}, err
	}
	envelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: recordID, SchemaVersion: model.CurrentSchemaVersion,
		Scope: n.policy.Scope, Lifecycle: lifecycle,
		DerivationLineage: []model.RecordReference{lineage}, Synthetic: ctx.Synthetic,
	})
	if err != nil {
		return model.Observation{}, fmt.Errorf("envelope: %w", err)
	}
	knowledge, err := n.knowledge(envelope, evidence, report.missing, report.identityAssurance, report.kind)
	if err != nil {
		return model.Observation{}, err
	}
	source, err := model.NewSourceIdentity(string(report.kind), ctx.SourceInstance)
	if err != nil {
		return model.Observation{}, err
	}
	collectorIdentity, err := model.NewCollectorIdentity("canaryview-dgxstack-"+string(report.kind), normalizerVersion)
	if err != nil {
		return model.Observation{}, err
	}
	return model.NewObservation(model.ObservationInput{
		Envelope: envelope, Basis: model.ObservationSourceReport, Knowledge: knowledge,
		ObservationType: report.observationType, Source: source, Collector: collectorIdentity,
		Control: report.control, SourceTimestamp: report.sourceTimestamp,
		ObservedTimestamp: observedAt, IngestedAt: ingestedAt,
		Subject: report.subject, Object: report.object, RawEvent: &raw,
		Evidence: []model.EvidenceReference{evidence},
	})
}

func evidenceReferences(in RawEvidence) (model.RawEventReference, model.EvidenceReference, model.RecordReference, error) {
	if err := lowercaseSHA256("raw reference", in.ReferenceSHA256); err != nil {
		return model.RawEventReference{}, model.EvidenceReference{}, model.RecordReference{}, err
	}
	if err := lowercaseSHA256("raw content", in.ContentSHA256); err != nil {
		return model.RawEventReference{}, model.EvidenceReference{}, model.RecordReference{}, err
	}
	raw, err := model.NewRawEventReference(
		"rawref:sha256:"+in.ReferenceSHA256, in.Availability, "sha256", in.ContentSHA256,
	)
	if err != nil {
		return model.RawEventReference{}, model.EvidenceReference{}, model.RecordReference{}, fmt.Errorf("raw evidence: %w", err)
	}
	evidenceID := "evidence:sha256:" + in.ReferenceSHA256
	evidence, err := model.NewEvidenceReference(evidenceID, model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		return model.RawEventReference{}, model.EvidenceReference{}, model.RecordReference{}, err
	}
	lineage, err := model.NewRecordReference(evidenceID, model.CurrentSchemaVersion)
	if err != nil {
		return model.RawEventReference{}, model.EvidenceReference{}, model.RecordReference{}, err
	}
	return raw, evidence, lineage, nil
}

func (n *Normalizer) lifecycle(observedAt time.Time) (model.Lifecycle, error) {
	expiresAt := observedAt
	switch n.policy.RetentionProfile {
	case model.RetentionLean:
		expiresAt = observedAt.AddDate(0, 6, 0)
	case model.RetentionStandard:
		expiresAt = observedAt.AddDate(0, 13, 0)
	case model.RetentionOverride:
		expiresAt = observedAt.Add(n.policy.RetentionDuration)
	}
	storage, err := model.NewStorageEstimate(n.policy.EstimatedBytes, n.policy.EstimatedBytesBasis)
	if err != nil {
		return model.Lifecycle{}, err
	}
	return model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassNormalizedObservation, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: n.policy.RetentionProfile, PolicyVersion: n.policy.PolicyVersion,
		RetentionDecisionRef: n.policy.RetentionDecisionRef, OverrideVersion: n.policy.OverrideVersion,
		RetentionClock: model.RetentionFromObserved, RetentionStart: observedAt, ExpiresAt: expiresAt,
		State: model.LifecycleActive, ResidencyPolicyRef: n.policy.ResidencyPolicyRef,
		EncryptionKeyRef: n.policy.EncryptionKeyRef, OperationalPolicyRef: n.policy.OperationalPolicyRef,
		EstimatedStorageImpact: storage,
	})
}

func (n *Normalizer) knowledge(envelope model.Envelope, evidence model.EvidenceReference, missing []model.MissingEvidenceKind, assurance model.AssuranceLevel, kind SourceKind) (model.Knowledge, error) {
	root, err := model.NewRecordReference(envelope.RecordID(), envelope.SchemaVersion())
	if err != nil {
		return model.Knowledge{}, err
	}
	inputs := envelope.DerivationLineage()
	link, err := model.NewLineageLink(root, inputs[0])
	if err != nil {
		return model.Knowledge{}, err
	}
	algorithm := "normalize.dgxstack." + string(kind)
	provenance, err := model.NewProvenance(root, algorithm, normalizerVersion, inputs, []model.LineageLink{link})
	if err != nil {
		return model.Knowledge{}, err
	}
	confidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: model.ConfidenceMedium, Method: model.ConfidenceDirectSource,
		SourceQuality: model.AssuranceDeclared, IdentityAssurance: assurance,
		Completeness: model.EvidencePartial, CandidateCount: 1,
		TimeUncertainty: model.TimeUnknown, AlgorithmID: algorithm, AlgorithmVersion: normalizerVersion,
		Calibration: model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
	if err != nil {
		return model.Knowledge{}, err
	}
	return model.NewKnowledge(model.KnowledgeInput{
		State: model.KnowledgeSourceObservation, AssertionMode: model.AssertionObserved,
		Producer: model.ProducerDeterministic, Confidence: confidence, Provenance: provenance,
		MissingEvidence: uniqueMissing(missing),
	})
}

func (n *Normalizer) entity(kind string, parts ...string) (model.EntityReference, error) {
	return model.NewEntityReferenceWithAssertion(
		kind+":hmac-sha256:"+n.digest(append([]string{"entity", kind}, parts...)...),
		kind, model.AssertionObserved, nil,
	)
}

func (n *Normalizer) control(kind string, parts ...string) (model.ControlIdentity, error) {
	return model.NewControlIdentity(
		kind+":hmac-sha256:"+n.digest(append([]string{"control", kind}, parts...)...), kind,
	)
}

func (n *Normalizer) bindEventKey(ctx Context, kind SourceKind, parts ...string) Context {
	components := []string{"source-event", string(kind), ctx.EventKey}
	components = append(components, parts...)
	ctx.EventKey = n.digest(components...)
	return ctx
}

func (n *Normalizer) digest(parts ...string) string {
	hash := hmac.New(sha256.New, n.key)
	for _, part := range parts {
		var length [8]byte
		value := uint64(len(part))
		for index := len(length) - 1; index >= 0; index-- {
			length[index] = byte(value)
			value >>= 8
		}
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func lowercaseSHA256(label, value string) error {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", label)
	}
	return nil
}

func boundedRequired(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is required and must not have surrounding whitespace", label)
	}
	if len(value) > maximumTextBytes {
		return fmt.Errorf("%s exceeds %d bytes", label, maximumTextBytes)
	}
	return nil
}

func uniqueMissing(values []model.MissingEvidenceKind) []model.MissingEvidenceKind {
	seen := make(map[model.MissingEvidenceKind]bool, len(values))
	result := make([]model.MissingEvidenceKind, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// SizeSummary reports canonical normalized-observation bytes. It is a bounded
// measurement input for later capacity/cost work; it does not persist records.
type SizeSummary struct {
	Records    int
	TotalBytes uint64
	MinBytes   uint64
	MaxBytes   uint64
}

func Measure(observations []model.Observation) (SizeSummary, error) {
	if len(observations) == 0 {
		return SizeSummary{}, fmt.Errorf("at least one observation is required")
	}
	result := SizeSummary{Records: len(observations)}
	for _, observation := range observations {
		blob, err := model.MarshalObservationV3(observation)
		if err != nil {
			return SizeSummary{}, err
		}
		size := uint64(len(blob))
		result.TotalBytes += size
		if result.MinBytes == 0 || size < result.MinBytes {
			result.MinBytes = size
		}
		if size > result.MaxBytes {
			result.MaxBytes = size
		}
	}
	return result, nil
}
