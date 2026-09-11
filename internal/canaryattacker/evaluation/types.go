package evaluation

import (
	"fmt"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	MaximumAssociations = 4096
	TraceRunNonceBytes  = 32

	// TraceRunEvidenceNamespace domain-separates the minimized exact-run
	// evidence emitted by an independent synthetic trace source.
	TraceRunEvidenceNamespace = "canaryattacker.evaluation.run.v1"
)

// SourceKind distinguishes the laboratory declaration stream from every
// vendor, kernel, proxy, and CanarySting observation source.
type SourceKind string

const SourceDeclaredGroundTruth SourceKind = "DECLARED_GROUND_TRUTH"

// TraceRunBinding names the independently observed trace hop and retained
// opaque evidence that supply the exact run and scenario identity used for
// evaluation. The evaluator never manufactures the binding from the corpus.
type TraceRunBinding struct {
	runID           string
	scenarioID      string
	scenarioVersion uint32
	hop             model.RecordReference
	evidence        model.EvidenceReference
}

// TraceRunNonce is 256 bits issued by the independent trace source. Its value
// is not retained by the binding or exposed in the evaluation report.
type TraceRunNonce struct {
	value [TraceRunNonceBytes]byte
}

// NewTraceRunNonce copies independently issued entropy into the opaque token
// used to bind one trace marker. Corpus fields alone cannot derive this token.
func NewTraceRunNonce(value []byte) (TraceRunNonce, error) {
	if len(value) != TraceRunNonceBytes {
		return TraceRunNonce{}, fmt.Errorf("trace run nonce must be exactly %d bytes", TraceRunNonceBytes)
	}
	var nonce TraceRunNonce
	copy(nonce.value[:], value)
	var nonzero byte
	for _, part := range nonce.value {
		nonzero |= part
	}
	if nonzero == 0 {
		return TraceRunNonce{}, fmt.Errorf("trace run nonce cannot be all zero")
	}
	return nonce, nil
}

// NewTraceRunEvidence returns the domain-separated opaque evidence reference
// that an independent trace source retains on its exact run-marker hop. The
// source-issued nonce prevents corpus-visible identity fields from being
// sufficient to manufacture the expected reference.
func NewTraceRunEvidence(runID, scenarioID string, scenarioVersion uint32, sourceNonce TraceRunNonce) (model.EvidenceReference, error) {
	if err := validateTraceRunIdentity(runID, scenarioID, scenarioVersion); err != nil {
		return model.EvidenceReference{}, err
	}
	if sourceNonce == (TraceRunNonce{}) {
		return model.EvidenceReference{}, fmt.Errorf("independent trace source nonce is required")
	}
	return model.NewEvidenceReference(
		"evidence:sha256:"+digestParts(TraceRunEvidenceNamespace, runID, scenarioID, fmt.Sprint(scenarioVersion), string(sourceNonce.value[:])),
		model.CurrentSchemaVersion, model.EvidenceSupporting, "", "",
	)
}

// NewTraceRunBinding validates a hop reference and its retained evidence as
// the exact run marker used by evaluation.
func NewTraceRunBinding(runID, scenarioID string, scenarioVersion uint32, hop model.RecordReference, evidence model.EvidenceReference, sourceNonce TraceRunNonce) (TraceRunBinding, error) {
	if err := validateTraceRunIdentity(runID, scenarioID, scenarioVersion); err != nil {
		return TraceRunBinding{}, err
	}
	canonicalHop, err := model.NewRecordReference(hop.ID(), hop.SchemaVersion())
	if err != nil {
		return TraceRunBinding{}, fmt.Errorf("trace run-binding hop: %w", err)
	}
	canonicalEvidence, err := model.NewEvidenceReference(
		evidence.ID(), evidence.SchemaVersion(), evidence.Role(), evidence.ExtensionNamespace(), evidence.ExtensionVersion(),
	)
	if err != nil {
		return TraceRunBinding{}, fmt.Errorf("trace run-binding evidence: %w", err)
	}
	wanted, err := NewTraceRunEvidence(runID, scenarioID, scenarioVersion, sourceNonce)
	if err != nil {
		return TraceRunBinding{}, err
	}
	if canonicalEvidence != wanted {
		return TraceRunBinding{}, fmt.Errorf("trace run-binding evidence is not the exact opaque run key")
	}
	return TraceRunBinding{
		runID: runID, scenarioID: scenarioID, scenarioVersion: scenarioVersion,
		hop: canonicalHop, evidence: canonicalEvidence,
	}, nil
}

func validateTraceRunIdentity(runID, scenarioID string, scenarioVersion uint32) error {
	for _, field := range []struct{ label, value string }{
		{"trace run id", runID}, {"trace scenario id", scenarioID},
	} {
		if field.value == "" || len(field.value) > 128 || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("%s must be non-empty, trimmed, and at most 128 bytes", field.label)
		}
	}
	if scenarioVersion == 0 {
		return fmt.Errorf("trace scenario version is required")
	}
	return nil
}

func (b TraceRunBinding) RunID() string              { return b.runID }
func (b TraceRunBinding) ScenarioID() string         { return b.scenarioID }
func (b TraceRunBinding) ScenarioVersion() uint32    { return b.scenarioVersion }
func (b TraceRunBinding) Hop() model.RecordReference { return b.hop }
func (b TraceRunBinding) Evidence() model.EvidenceReference {
	return b.evidence
}

func (b TraceRunBinding) validate() error {
	if err := validateTraceRunIdentity(b.runID, b.scenarioID, b.scenarioVersion); err != nil {
		return err
	}
	if _, err := model.NewRecordReference(b.hop.ID(), b.hop.SchemaVersion()); err != nil {
		return fmt.Errorf("trace run-binding hop: %w", err)
	}
	canonicalEvidence, err := model.NewEvidenceReference(
		b.evidence.ID(), b.evidence.SchemaVersion(), b.evidence.Role(), b.evidence.ExtensionNamespace(), b.evidence.ExtensionVersion(),
	)
	if err != nil {
		return fmt.Errorf("trace run-binding evidence: %w", err)
	}
	if canonicalEvidence.Role() != model.EvidenceSupporting || !strings.HasPrefix(canonicalEvidence.ID(), "evidence:sha256:") {
		return fmt.Errorf("trace run-binding evidence must be a supporting opaque digest reference")
	}
	return nil
}

// Source describes the existing corpus classification without projecting it
// into model.SourceIdentity. Ground truth is therefore not representable as a
// vendor or kernel observation source through this API.
type Source struct {
	kind                   SourceKind
	dataClass              string
	labDomain              string
	assertionMode          model.AssertionMode
	retentionPolicy        string
	reviewDue              time.Time
	lifecycleOwner         string
	lifecyclePolicyVersion string
	residencyPolicyRef     string
	encryptionKeyRef       string
	operationalPolicyRef   string
	perTenantModelUse      string
	crossTenantModelUse    string
	keyNamespace           string
	registryNamespace      string
	estimatedStorageBytes  uint64
	estimateBasis          groundtruth.EstimateBasis
	synthetic              bool
}

func (s Source) Kind() SourceKind                         { return s.kind }
func (s Source) DataClass() string                        { return s.dataClass }
func (s Source) LabDomain() string                        { return s.labDomain }
func (s Source) AssertionMode() model.AssertionMode       { return s.assertionMode }
func (s Source) RetentionPolicy() string                  { return s.retentionPolicy }
func (s Source) ReviewDue() time.Time                     { return s.reviewDue }
func (s Source) LifecycleOwner() string                   { return s.lifecycleOwner }
func (s Source) LifecyclePolicyVersion() string           { return s.lifecyclePolicyVersion }
func (s Source) ResidencyPolicyRef() string               { return s.residencyPolicyRef }
func (s Source) EncryptionKeyRef() string                 { return s.encryptionKeyRef }
func (s Source) OperationalPolicyRef() string             { return s.operationalPolicyRef }
func (s Source) PerTenantModelUse() string                { return s.perTenantModelUse }
func (s Source) CrossTenantModelUse() string              { return s.crossTenantModelUse }
func (s Source) KeyNamespace() string                     { return s.keyNamespace }
func (s Source) RegistryNamespace() string                { return s.registryNamespace }
func (s Source) EstimatedStorageBytes() uint64            { return s.estimatedStorageBytes }
func (s Source) EstimateBasis() groundtruth.EstimateBasis { return s.estimateBasis }
func (s Source) Synthetic() bool                          { return s.synthetic }
func (s Source) ExpiresAt() *time.Time                    { return nil }
func (s Source) LegalHoldSupported() bool                 { return false }

// Declaration is a payload-free view of one native ground-truth record.
type Declaration struct {
	kind       groundtruth.RecordKind
	reference  groundtruth.RecordReference
	lineage    []groundtruth.RecordReference
	recordedAt time.Time
}

func (d Declaration) Kind() groundtruth.RecordKind           { return d.kind }
func (d Declaration) Reference() groundtruth.RecordReference { return d.reference }
func (d Declaration) Lineage() []groundtruth.RecordReference {
	return append([]groundtruth.RecordReference(nil), d.lineage...)
}
func (d Declaration) RecordedAt() time.Time              { return d.recordedAt }
func (d Declaration) AssertionMode() model.AssertionMode { return model.AssertionDeclared }

// ScenarioHint is a bounded time and lineage hint for one executed step. It is
// metadata for evaluation only and cannot be inserted into a CanaryView trace.
type ScenarioHint struct {
	stepID      string
	sequence    uint32
	intent      groundtruth.RecordReference
	action      groundtruth.RecordReference
	windowStart time.Time
	windowEnd   time.Time
}

func (h ScenarioHint) StepID() string                      { return h.stepID }
func (h ScenarioHint) Sequence() uint32                    { return h.sequence }
func (h ScenarioHint) Intent() groundtruth.RecordReference { return h.intent }
func (h ScenarioHint) Action() groundtruth.RecordReference { return h.action }
func (h ScenarioHint) WindowStart() time.Time              { return h.windowStart }
func (h ScenarioHint) WindowEnd() time.Time                { return h.windowEnd }

func (h ScenarioHint) contains(reference groundtruth.RecordReference) bool {
	return sameGroundTruthReference(h.intent, reference) || sameGroundTruthReference(h.action, reference)
}

// Attempt keeps the one-to-one intent/action pair emitted by the corpus.
type Attempt struct {
	ordinal   uint32
	intent    Declaration
	action    Declaration
	status    groundtruth.ActionStatus
	attempted bool
	hint      ScenarioHint
}

func (a Attempt) Ordinal() uint32                  { return a.ordinal }
func (a Attempt) Intent() Declaration              { return a.intent }
func (a Attempt) Action() Declaration              { return a.action }
func (a Attempt) Status() groundtruth.ActionStatus { return a.status }
func (a Attempt) Attempted() bool                  { return a.attempted }
func (a Attempt) Hint() ScenarioHint               { return a.hint }

// Step is present for every reviewed scenario step, including steps for which
// the corpus emitted no intent/action pair.
type Step struct {
	id        string
	sequence  uint32
	objective string
	attempts  []Attempt
}

func (s Step) ID() string          { return s.id }
func (s Step) Sequence() uint32    { return s.sequence }
func (s Step) Objective() string   { return s.objective }
func (s Step) Attempts() []Attempt { return append([]Attempt(nil), s.attempts...) }

func (s Step) attemptForAction(reference groundtruth.RecordReference) (Attempt, bool) {
	for _, attempt := range s.attempts {
		if sameGroundTruthReference(attempt.action.reference, reference) {
			return attempt, true
		}
	}
	return Attempt{}, false
}

// Run is an immutable, in-memory evaluation view over one validated corpus.
// It is not a persistence backend or a canonical CanaryView source record.
type Run struct {
	corpusID          string
	schemaVersion     uint32
	scenarioReference groundtruth.RecordReference
	scenarioID        string
	scenarioVersion   uint32
	runID             string
	seed              uint64
	scope             model.Scope
	source            Source
	expectedTelemetry []string
	steps             []Step
}

func (r Run) CorpusID() string                               { return r.corpusID }
func (r Run) SchemaVersion() uint32                          { return r.schemaVersion }
func (r Run) ScenarioReference() groundtruth.RecordReference { return r.scenarioReference }
func (r Run) ScenarioID() string                             { return r.scenarioID }
func (r Run) ScenarioVersion() uint32                        { return r.scenarioVersion }
func (r Run) RunID() string                                  { return r.runID }
func (r Run) Seed() uint64                                   { return r.seed }
func (r Run) Scope() model.Scope                             { return r.scope }
func (r Run) Source() Source                                 { return r.source }
func (r Run) ExpectedTelemetry() []string                    { return append([]string(nil), r.expectedTelemetry...) }
func (r Run) Steps() []Step                                  { return copySteps(r.steps) }

func copySteps(values []Step) []Step {
	result := append([]Step(nil), values...)
	for index := range result {
		result[index].attempts = append([]Attempt(nil), result[index].attempts...)
		for attempt := range result[index].attempts {
			result[index].attempts[attempt].intent.lineage = append([]groundtruth.RecordReference(nil), result[index].attempts[attempt].intent.lineage...)
			result[index].attempts[attempt].action.lineage = append([]groundtruth.RecordReference(nil), result[index].attempts[attempt].action.lineage...)
		}
	}
	return result
}

func sameGroundTruthReference(left, right groundtruth.RecordReference) bool {
	return left.Kind() == right.Kind() && left.ID() == right.ID() && left.SchemaVersion() == right.SchemaVersion()
}
