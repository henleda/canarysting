package trace

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const maximumTextBytes = 256

// Status describes what the trace proves under its declared coverage.
type Status string

const (
	StatusPartial    Status = "PARTIAL"
	StatusComplete   Status = "COMPLETE_UNDER_DECLARED_COVERAGE"
	StatusConflicted Status = "CONFLICTED"
)

func (s Status) valid() bool {
	return s == StatusPartial || s == StatusComplete || s == StatusConflicted
}

// HopKind distinguishes source observations from source-reported policy
// decisions without turning either into a CanaryView action.
type HopKind string

const (
	HopObservation    HopKind = "OBSERVATION"
	HopPolicyDecision HopKind = "POLICY_DECISION"
)

func (k HopKind) valid() bool { return k == HopObservation || k == HopPolicyDecision }

// ExpectationKind is the closed version-1 declared-coverage vocabulary.
type ExpectationKind string

const (
	ExpectObservation    ExpectationKind = "OBSERVATION"
	ExpectPolicyDecision ExpectationKind = "POLICY_DECISION"
	ExpectSourceTime     ExpectationKind = "SOURCE_TIME"
	ExpectRawEvidence    ExpectationKind = "RAW_EVIDENCE"
	ExpectCorrelation    ExpectationKind = "CORRELATION"
)

func (k ExpectationKind) valid() bool {
	switch k {
	case ExpectObservation, ExpectPolicyDecision, ExpectSourceTime, ExpectRawEvidence, ExpectCorrelation:
		return true
	default:
		return false
	}
}

// ConflictKind is deliberately typed. Parser/model prose is evidence, not a
// canonical conflict category.
type ConflictKind string

const (
	ConflictAmbiguousCorrelation  ConflictKind = "AMBIGUOUS_CORRELATION"
	ConflictContradictoryEvidence ConflictKind = "CONTRADICTORY_EVIDENCE"
	ConflictOrderingUncertainty   ConflictKind = "ORDERING_UNCERTAINTY"
)

func (k ConflictKind) valid() bool {
	return k == ConflictAmbiguousCorrelation || k == ConflictContradictoryEvidence || k == ConflictOrderingUncertainty
}

// HopInput binds trace-only evidence availability to one immutable correlation
// record. RawEvent remains a reference and never embeds source payload.
type HopInput struct {
	Record   correlation.Record
	Kind     HopKind
	RawEvent *model.RawEventReference
	Evidence []model.EvidenceReference
}

// ExpectationInput declares coverage the builder can verify from its inputs.
// Record is required for source time and raw evidence, optional for correlation,
// and forbidden for whole-trace observation/policy-decision expectations.
type ExpectationInput struct {
	Kind   ExpectationKind
	Record *model.RecordReference
}

// ConflictInput records an explicit disagreement. Ambiguous candidate sets are
// added automatically and do not need to be repeated here.
type ConflictInput struct {
	Kind     ConflictKind
	Records  []model.RecordReference
	Evidence []model.EvidenceReference
}

// BuildInput contains no open payload or vendor-specific field map.
type BuildInput struct {
	Scope         model.Scope
	Hops          []HopInput
	Correlations  []correlation.Result
	Expectations  []ExpectationInput
	Conflicts     []ConflictInput
	ClosedAt      time.Time
	BuiltAt       time.Time
	HighWaterMark model.RecordReference
	Lifecycle     model.Lifecycle
	Synthetic     model.SyntheticContext
}

// Hop is an ordered reference to an immutable source record.
type Hop struct {
	reference  model.RecordReference
	kind       HopKind
	eventTime  *correlation.EventTime
	identities []model.EntityReference
	rawEvent   *model.RawEventReference
	evidence   []model.EvidenceReference
}

func (h Hop) Reference() model.RecordReference { return h.reference }
func (h Hop) Kind() HopKind                    { return h.kind }
func (h Hop) Time() (correlation.EventTime, bool) {
	return optionalValue(h.eventTime)
}
func (h Hop) Identities() []model.EntityReference {
	return append([]model.EntityReference(nil), h.identities...)
}
func (h Hop) RawEvent() (model.RawEventReference, bool) { return optionalValue(h.rawEvent) }
func (h Hop) Evidence() []model.EvidenceReference {
	return append([]model.EvidenceReference(nil), h.evidence...)
}

// TranslationStep retains both tuples and the translating control.
type TranslationStep struct {
	reference  model.RecordReference
	before     correlation.NetworkTuple
	after      correlation.NetworkTuple
	control    model.ControlIdentity
	observedAt correlation.EventTime
	direction  correlation.TraversalDirection
}

func (s TranslationStep) Reference() model.RecordReference          { return s.reference }
func (s TranslationStep) Before() correlation.NetworkTuple          { return s.before }
func (s TranslationStep) After() correlation.NetworkTuple           { return s.after }
func (s TranslationStep) Control() model.ControlIdentity            { return s.control }
func (s TranslationStep) ObservedAt() correlation.EventTime         { return s.observedAt }
func (s TranslationStep) Direction() correlation.TraversalDirection { return s.direction }

// JoinExplanation cites both joined records and every translation assertion.
type JoinExplanation struct {
	method         correlation.JoinMethod
	strength       correlation.Strength
	keyFingerprint string
	timeGap        time.Duration
	window         time.Duration
	citations      []model.RecordReference
	translations   []TranslationStep
}

func (e JoinExplanation) Method() correlation.JoinMethod { return e.method }
func (e JoinExplanation) Strength() correlation.Strength { return e.strength }
func (e JoinExplanation) KeyFingerprint() string         { return e.keyFingerprint }
func (e JoinExplanation) TimeGap() time.Duration         { return e.timeGap }
func (e JoinExplanation) Window() time.Duration          { return e.window }
func (e JoinExplanation) Citations() []model.RecordReference {
	return append([]model.RecordReference(nil), e.citations...)
}
func (e JoinExplanation) TranslationPath() []TranslationStep {
	return append([]TranslationStep(nil), e.translations...)
}

// Candidate preserves one qualifying alternative and all of its join methods.
type Candidate struct {
	reference     model.RecordReference
	strength      correlation.Strength
	confidence    model.Confidence
	missing       []correlation.MissingKey
	explanations  []JoinExplanation
	pathAmbiguous bool
}

func (c Candidate) Reference() model.RecordReference { return c.reference }
func (c Candidate) Strength() correlation.Strength   { return c.strength }
func (c Candidate) Confidence() model.Confidence     { return c.confidence }
func (c Candidate) MissingKeys() []correlation.MissingKey {
	return append([]correlation.MissingKey(nil), c.missing...)
}
func (c Candidate) Explanations() []JoinExplanation {
	return append([]JoinExplanation(nil), c.explanations...)
}
func (c Candidate) TranslationPathAmbiguous() bool { return c.pathAmbiguous }

type Rejection struct {
	reference model.RecordReference
	reasons   []correlation.RejectionReason
	missing   []correlation.MissingKey
}

func (r Rejection) Reference() model.RecordReference { return r.reference }
func (r Rejection) Reasons() []correlation.RejectionReason {
	return append([]correlation.RejectionReason(nil), r.reasons...)
}
func (r Rejection) MissingKeys() []correlation.MissingKey {
	return append([]correlation.MissingKey(nil), r.missing...)
}

// CorrelationSet is one anchor's complete candidate/rejection decision.
type CorrelationSet struct {
	anchor           model.RecordReference
	algorithmID      string
	algorithmVersion string
	anchorMissing    []correlation.MissingKey
	candidates       []Candidate
	rejections       []Rejection
	chosen           *model.RecordReference
	ambiguous        bool
}

func (s CorrelationSet) Anchor() model.RecordReference { return s.anchor }
func (s CorrelationSet) AlgorithmID() string           { return s.algorithmID }
func (s CorrelationSet) AlgorithmVersion() string      { return s.algorithmVersion }
func (s CorrelationSet) AnchorMissingKeys() []correlation.MissingKey {
	return append([]correlation.MissingKey(nil), s.anchorMissing...)
}
func (s CorrelationSet) Candidates() []Candidate               { return append([]Candidate(nil), s.candidates...) }
func (s CorrelationSet) Rejections() []Rejection               { return append([]Rejection(nil), s.rejections...) }
func (s CorrelationSet) Chosen() (model.RecordReference, bool) { return optionalValue(s.chosen) }
func (s CorrelationSet) Ambiguous() bool                       { return s.ambiguous }

type Expectation struct {
	kind      ExpectationKind
	reference *model.RecordReference
}

func (e Expectation) Kind() ExpectationKind                 { return e.kind }
func (e Expectation) Record() (model.RecordReference, bool) { return optionalValue(e.reference) }

type MissingTelemetry struct {
	expectation  Expectation
	availability *model.RawAvailability
}

func (m MissingTelemetry) Expectation() Expectation { return m.expectation }
func (m MissingTelemetry) RawAvailability() (model.RawAvailability, bool) {
	return optionalValue(m.availability)
}

type Conflict struct {
	kind     ConflictKind
	records  []model.RecordReference
	evidence []model.EvidenceReference
}

func (c Conflict) Kind() ConflictKind { return c.kind }
func (c Conflict) Records() []model.RecordReference {
	return append([]model.RecordReference(nil), c.records...)
}
func (c Conflict) Evidence() []model.EvidenceReference {
	return append([]model.EvidenceReference(nil), c.evidence...)
}

// Trace is an immutable CORRELATED_TRACE record and rebuildable projection.
type Trace struct {
	envelope         model.Envelope
	knowledge        model.Knowledge
	status           Status
	validFrom        time.Time
	validTo          time.Time
	closedAt         time.Time
	builtAt          time.Time
	highWaterMark    model.RecordReference
	hops             []Hop
	correlations     []CorrelationSet
	expectations     []Expectation
	missingTelemetry []MissingTelemetry
	conflicts        []Conflict
	integrityDigest  string
}

func (t Trace) Envelope() model.Envelope             { return t.envelope }
func (t Trace) Knowledge() model.Knowledge           { return t.knowledge }
func (t Trace) Status() Status                       { return t.status }
func (t Trace) ValidFrom() time.Time                 { return t.validFrom }
func (t Trace) ValidTo() time.Time                   { return t.validTo }
func (t Trace) ClosedAt() time.Time                  { return t.closedAt }
func (t Trace) BuiltAt() time.Time                   { return t.builtAt }
func (t Trace) HighWaterMark() model.RecordReference { return t.highWaterMark }
func (t Trace) Hops() []Hop                          { return append([]Hop(nil), t.hops...) }
func (t Trace) Correlations() []CorrelationSet {
	return append([]CorrelationSet(nil), t.correlations...)
}
func (t Trace) Expectations() []Expectation { return append([]Expectation(nil), t.expectations...) }
func (t Trace) MissingTelemetry() []MissingTelemetry {
	return append([]MissingTelemetry(nil), t.missingTelemetry...)
}
func (t Trace) Conflicts() []Conflict   { return append([]Conflict(nil), t.conflicts...) }
func (t Trace) IntegrityDigest() string { return t.integrityDigest }

func validateReference(ref model.RecordReference) error {
	_, err := model.NewRecordReference(ref.ID(), ref.SchemaVersion())
	return err
}

func validateScope(scope model.Scope) error {
	_, err := model.NewScope(scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID())
	return err
}

func sameScope(left, right model.Scope) bool {
	return left.TenantID() == right.TenantID() && left.ScopeID() == right.ScopeID() &&
		left.DeploymentBoundary() == right.DeploymentBoundary() && left.ResidencyCellID() == right.ResidencyCellID()
}

func referenceKey(ref model.RecordReference) string {
	return fmt.Sprintf("%s\x00%010d", ref.ID(), ref.SchemaVersion())
}

func sortedReferences(values []model.RecordReference) ([]model.RecordReference, error) {
	result := append([]model.RecordReference(nil), values...)
	sort.Slice(result, func(i, j int) bool { return referenceKey(result[i]) < referenceKey(result[j]) })
	for index, value := range result {
		if err := validateReference(value); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1] == value {
			return nil, fmt.Errorf("duplicate record reference %q", value.ID())
		}
	}
	return result, nil
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

func optionalValue[T any](value *T) (T, bool) {
	if value == nil {
		var zero T
		return zero, false
	}
	return *value, true
}
