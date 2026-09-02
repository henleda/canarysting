package model

import (
	"fmt"
	"sort"
	"time"
)

// ConfidenceInput records independently reviewable confidence components. It
// deliberately has no floating-point score: numeric confidence is not valid
// until its producer and calibration are defined and measured.
type ConfidenceInput struct {
	Level             ConfidenceLevel
	Method            ConfidenceMethod
	SourceQuality     AssuranceLevel
	IdentityAssurance AssuranceLevel
	Completeness      EvidenceCompleteness
	CandidateCount    uint32
	TimeUncertainty   TimeUncertainty
	TimeWindow        time.Duration
	AlgorithmID       string
	AlgorithmVersion  string
	Calibration       CalibrationState
	HumanReview       HumanReviewState
}

type Confidence struct {
	level             ConfidenceLevel
	method            ConfidenceMethod
	sourceQuality     AssuranceLevel
	identityAssurance AssuranceLevel
	completeness      EvidenceCompleteness
	candidateCount    uint32
	timeUncertainty   TimeUncertainty
	timeWindow        time.Duration
	algorithmID       string
	algorithmVersion  string
	calibration       CalibrationState
	humanReview       HumanReviewState
}

func NewConfidence(in ConfidenceInput) (Confidence, error) {
	if !in.Level.valid() {
		return Confidence{}, fmt.Errorf("unsupported confidence level %q", in.Level)
	}
	if !in.Method.valid() {
		return Confidence{}, fmt.Errorf("unsupported confidence method %q", in.Method)
	}
	if !in.SourceQuality.valid() {
		return Confidence{}, fmt.Errorf("unsupported source quality %q", in.SourceQuality)
	}
	if !in.IdentityAssurance.valid() {
		return Confidence{}, fmt.Errorf("unsupported identity assurance %q", in.IdentityAssurance)
	}
	if !in.Completeness.valid() {
		return Confidence{}, fmt.Errorf("unsupported evidence completeness %q", in.Completeness)
	}
	if in.CandidateCount == 0 {
		return Confidence{}, fmt.Errorf("confidence candidate count must be greater than zero")
	}
	if !in.TimeUncertainty.valid() {
		return Confidence{}, fmt.Errorf("unsupported time uncertainty %q", in.TimeUncertainty)
	}
	if in.TimeUncertainty == TimeBounded && in.TimeWindow <= 0 {
		return Confidence{}, fmt.Errorf("bounded time uncertainty requires a positive time window")
	}
	if in.TimeUncertainty != TimeBounded && in.TimeWindow != 0 {
		return Confidence{}, fmt.Errorf("only bounded time uncertainty may carry a time window")
	}
	if err := required("confidence algorithm id", in.AlgorithmID); err != nil {
		return Confidence{}, err
	}
	if err := required("confidence algorithm version", in.AlgorithmVersion); err != nil {
		return Confidence{}, err
	}
	if !in.Calibration.valid() {
		return Confidence{}, fmt.Errorf("unsupported calibration state %q", in.Calibration)
	}
	if !in.HumanReview.valid() {
		return Confidence{}, fmt.Errorf("unsupported human review state %q", in.HumanReview)
	}
	if in.Method == ConfidenceVerifiedIdentity && in.IdentityAssurance != AssuranceVerified {
		return Confidence{}, fmt.Errorf("verified-identity confidence requires verified identity assurance")
	}
	return Confidence{
		level: in.Level, method: in.Method, sourceQuality: in.SourceQuality,
		identityAssurance: in.IdentityAssurance, completeness: in.Completeness,
		candidateCount: in.CandidateCount, timeUncertainty: in.TimeUncertainty,
		timeWindow:  in.TimeWindow,
		algorithmID: in.AlgorithmID, algorithmVersion: in.AlgorithmVersion,
		calibration: in.Calibration, humanReview: in.HumanReview,
	}, nil
}

func (c Confidence) Level() ConfidenceLevel             { return c.level }
func (c Confidence) Method() ConfidenceMethod           { return c.method }
func (c Confidence) SourceQuality() AssuranceLevel      { return c.sourceQuality }
func (c Confidence) IdentityAssurance() AssuranceLevel  { return c.identityAssurance }
func (c Confidence) Completeness() EvidenceCompleteness { return c.completeness }
func (c Confidence) CandidateCount() uint32             { return c.candidateCount }
func (c Confidence) TimeUncertainty() TimeUncertainty   { return c.timeUncertainty }
func (c Confidence) TimeWindow() time.Duration          { return c.timeWindow }
func (c Confidence) AlgorithmID() string                { return c.algorithmID }
func (c Confidence) AlgorithmVersion() string           { return c.algorithmVersion }
func (c Confidence) Calibration() CalibrationState      { return c.calibration }
func (c Confidence) HumanReview() HumanReviewState      { return c.humanReview }

func (c Confidence) validate() error {
	_, err := NewConfidence(ConfidenceInput{
		Level: c.level, Method: c.method, SourceQuality: c.sourceQuality,
		IdentityAssurance: c.identityAssurance, Completeness: c.completeness,
		CandidateCount: c.candidateCount, TimeUncertainty: c.timeUncertainty,
		TimeWindow:  c.timeWindow,
		AlgorithmID: c.algorithmID, AlgorithmVersion: c.algorithmVersion,
		Calibration: c.calibration, HumanReview: c.humanReview,
	})
	return err
}

// Verification records a named, versioned procedure and its supporting
// evidence. Parsing an identifier is not a verification procedure.
type Verification struct {
	procedureID      string
	procedureVersion string
	producer         ProducerType
	evidence         []EvidenceReference
}

func NewVerification(procedureID, procedureVersion string, producer ProducerType, evidence []EvidenceReference) (Verification, error) {
	if err := required("verification procedure id", procedureID); err != nil {
		return Verification{}, err
	}
	if err := required("verification procedure version", procedureVersion); err != nil {
		return Verification{}, err
	}
	if producer != ProducerDeterministic && producer != ProducerOperator {
		return Verification{}, fmt.Errorf("verification producer must be deterministic or operator, got %q", producer)
	}
	refs, err := sortedEvidence(evidence, "verification evidence")
	if err != nil {
		return Verification{}, err
	}
	if len(refs) == 0 {
		return Verification{}, fmt.Errorf("verification requires supporting evidence")
	}
	for _, ref := range refs {
		if ref.role != EvidenceSupporting {
			return Verification{}, fmt.Errorf("verification evidence %q must have SUPPORTING role", ref.id)
		}
	}
	return Verification{procedureID: procedureID, procedureVersion: procedureVersion, producer: producer, evidence: refs}, nil
}

func (v Verification) ProcedureID() string      { return v.procedureID }
func (v Verification) ProcedureVersion() string { return v.procedureVersion }
func (v Verification) Producer() ProducerType   { return v.producer }
func (v Verification) Evidence() []EvidenceReference {
	return append([]EvidenceReference(nil), v.evidence...)
}

func (v Verification) validate() error {
	_, err := NewVerification(v.procedureID, v.procedureVersion, v.producer, v.evidence)
	return err
}

// LineageLink points from a derived child to one of its direct inputs.
type LineageLink struct {
	child  RecordReference
	parent RecordReference
}

func NewLineageLink(child, parent RecordReference) (LineageLink, error) {
	if err := child.validate(); err != nil {
		return LineageLink{}, fmt.Errorf("lineage child: %w", err)
	}
	if err := parent.validate(); err != nil {
		return LineageLink{}, fmt.Errorf("lineage parent: %w", err)
	}
	if child == parent {
		return LineageLink{}, fmt.Errorf("lineage cannot contain self-reference %q", child.id)
	}
	return LineageLink{child: child, parent: parent}, nil
}

func (l LineageLink) Child() RecordReference  { return l.child }
func (l LineageLink) Parent() RecordReference { return l.parent }

func (l LineageLink) validate() error {
	_, err := NewLineageLink(l.child, l.parent)
	return err
}

// Provenance is the serializable, acyclic transformation lineage for one
// canonical record. Inputs are the root's direct parents; Links may retain a
// larger ancestry closure so cycles and disconnected claims fail closed.
type Provenance struct {
	root                  RecordReference
	transformationID      string
	transformationVersion string
	inputs                []RecordReference
	links                 []LineageLink
}

func NewProvenance(root RecordReference, transformationID, transformationVersion string, inputs []RecordReference, links []LineageLink) (Provenance, error) {
	if err := root.validate(); err != nil {
		return Provenance{}, fmt.Errorf("provenance root: %w", err)
	}
	if err := required("transformation id", transformationID); err != nil {
		return Provenance{}, err
	}
	if err := required("transformation version", transformationVersion); err != nil {
		return Provenance{}, err
	}
	parents, err := sortedRecordReferences(inputs, "provenance input")
	if err != nil {
		return Provenance{}, err
	}
	for _, parent := range parents {
		if parent == root {
			return Provenance{}, fmt.Errorf("provenance root %q cannot be its own input", root.id)
		}
	}
	orderedLinks := append([]LineageLink(nil), links...)
	sort.Slice(orderedLinks, func(i, j int) bool {
		left, right := lineageLinkKey(orderedLinks[i]), lineageLinkKey(orderedLinks[j])
		return left < right
	})
	for i, link := range orderedLinks {
		if err := link.validate(); err != nil {
			return Provenance{}, err
		}
		if i > 0 && lineageLinkKey(orderedLinks[i-1]) == lineageLinkKey(link) {
			return Provenance{}, fmt.Errorf("duplicate lineage link %q", lineageLinkKey(link))
		}
	}
	if err := validateLineageGraph(root, parents, orderedLinks); err != nil {
		return Provenance{}, err
	}
	return Provenance{
		root: root, transformationID: transformationID,
		transformationVersion: transformationVersion, inputs: parents, links: orderedLinks,
	}, nil
}

func (p Provenance) Root() RecordReference         { return p.root }
func (p Provenance) TransformationID() string      { return p.transformationID }
func (p Provenance) TransformationVersion() string { return p.transformationVersion }
func (p Provenance) Inputs() []RecordReference {
	return append([]RecordReference(nil), p.inputs...)
}
func (p Provenance) Links() []LineageLink { return append([]LineageLink(nil), p.links...) }

func (p Provenance) validate() error {
	_, err := NewProvenance(p.root, p.transformationID, p.transformationVersion, p.inputs, p.links)
	return err
}

func validateLineageGraph(root RecordReference, inputs []RecordReference, links []LineageLink) error {
	children := make(map[string][]string)
	nodes := map[string]bool{recordReferenceKey(root): true}
	for _, link := range links {
		child, parent := recordReferenceKey(link.child), recordReferenceKey(link.parent)
		children[child] = append(children[child], parent)
		nodes[child], nodes[parent] = true, true
	}
	direct := make(map[string]bool, len(inputs))
	for _, input := range inputs {
		direct[recordReferenceKey(input)] = true
	}
	rootKey := recordReferenceKey(root)
	if len(children[rootKey]) != len(direct) {
		return fmt.Errorf("lineage root links do not match declared inputs")
	}
	for _, parent := range children[rootKey] {
		if !direct[parent] {
			return fmt.Errorf("lineage root contains undeclared input %q", parent)
		}
	}
	state := make(map[string]uint8)
	var visit func(string) error
	visit = func(node string) error {
		if state[node] == 1 {
			return fmt.Errorf("lineage cycle detected at %q", node)
		}
		if state[node] == 2 {
			return nil
		}
		state[node] = 1
		for _, parent := range children[node] {
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[node] = 2
		return nil
	}
	if err := visit(rootKey); err != nil {
		return err
	}
	for node := range nodes {
		if state[node] == 0 {
			return fmt.Errorf("lineage contains disconnected node %q", node)
		}
	}
	return nil
}

func recordReferenceKey(ref RecordReference) string {
	return fmt.Sprintf("%s@%d", ref.id, ref.schemaVersion)
}
func lineageLinkKey(link LineageLink) string {
	return recordReferenceKey(link.child) + "->" + recordReferenceKey(link.parent)
}

func sortedRecordReferences(values []RecordReference, label string) ([]RecordReference, error) {
	result := append([]RecordReference(nil), values...)
	sort.Slice(result, func(i, j int) bool { return recordReferenceKey(result[i]) < recordReferenceKey(result[j]) })
	for i, value := range result {
		if err := value.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if i > 0 && result[i-1] == value {
			return nil, fmt.Errorf("duplicate %s %q", label, value.id)
		}
	}
	return result, nil
}

func sortedEvidence(values []EvidenceReference, label string) ([]EvidenceReference, error) {
	result := append([]EvidenceReference(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].id == result[j].id {
			return result[i].schemaVersion < result[j].schemaVersion
		}
		return result[i].id < result[j].id
	})
	for i, value := range result {
		if err := value.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if i > 0 && result[i-1].id == value.id && result[i-1].schemaVersion == value.schemaVersion {
			return nil, fmt.Errorf("duplicate %s %q", label, value.id)
		}
	}
	return result, nil
}

// KnowledgeInput is copied into immutable Knowledge metadata.
type KnowledgeInput struct {
	State               KnowledgeState
	AssertionMode       AssertionMode
	Producer            ProducerType
	Confidence          Confidence
	Provenance          Provenance
	MissingEvidence     []MissingEvidenceKind
	ConflictingEvidence []EvidenceReference
	Verification        *Verification
}

type Knowledge struct {
	state               KnowledgeState
	assertionMode       AssertionMode
	producer            ProducerType
	confidence          Confidence
	provenance          Provenance
	missingEvidence     []MissingEvidenceKind
	conflictingEvidence []EvidenceReference
	verification        *Verification
}

func NewKnowledge(in KnowledgeInput) (Knowledge, error) {
	if !in.State.valid() {
		return Knowledge{}, fmt.Errorf("unsupported knowledge state %q", in.State)
	}
	if !in.AssertionMode.valid() {
		return Knowledge{}, fmt.Errorf("unsupported assertion mode %q", in.AssertionMode)
	}
	if !in.Producer.valid() {
		return Knowledge{}, fmt.Errorf("unsupported producer type %q", in.Producer)
	}
	if err := validateKnowledgeCombination(in.State, in.AssertionMode, in.Producer); err != nil {
		return Knowledge{}, err
	}
	if err := in.Confidence.validate(); err != nil {
		return Knowledge{}, fmt.Errorf("confidence: %w", err)
	}
	if err := in.Provenance.validate(); err != nil {
		return Knowledge{}, fmt.Errorf("provenance: %w", err)
	}
	verification, err := copyOptional(in.Verification, func(value Verification) error { return value.validate() })
	if err != nil {
		return Knowledge{}, fmt.Errorf("verification: %w", err)
	}
	if in.AssertionMode == AssertionVerified && verification == nil {
		return Knowledge{}, fmt.Errorf("VERIFIED assertion requires verification evidence")
	}
	if in.AssertionMode != AssertionVerified && verification != nil {
		return Knowledge{}, fmt.Errorf("verification evidence requires VERIFIED assertion mode")
	}
	if (in.Confidence.SourceQuality() == AssuranceVerified || in.Confidence.IdentityAssurance() == AssuranceVerified) && verification == nil {
		return Knowledge{}, fmt.Errorf("verified source or identity assurance requires verification evidence")
	}
	missing := append([]MissingEvidenceKind(nil), in.MissingEvidence...)
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
	for i, value := range missing {
		if !value.valid() {
			return Knowledge{}, fmt.Errorf("unsupported missing evidence kind %q", value)
		}
		if i > 0 && missing[i-1] == value {
			return Knowledge{}, fmt.Errorf("duplicate missing evidence kind %q", value)
		}
	}
	conflicts, err := sortedEvidence(in.ConflictingEvidence, "conflicting evidence")
	if err != nil {
		return Knowledge{}, err
	}
	for _, ref := range conflicts {
		if ref.role != EvidenceContradicting {
			return Knowledge{}, fmt.Errorf("conflicting evidence %q must have CONTRADICTING role", ref.id)
		}
	}
	return Knowledge{
		state: in.State, assertionMode: in.AssertionMode, producer: in.Producer,
		confidence: in.Confidence, provenance: in.Provenance,
		missingEvidence: missing, conflictingEvidence: conflicts, verification: verification,
	}, nil
}

func validateKnowledgeCombination(state KnowledgeState, mode AssertionMode, producer ProducerType) error {
	valid := false
	switch state {
	case KnowledgeSourceObservation:
		valid = (producer == ProducerDeterministic || producer == ProducerOperator) && mode != AssertionInferred
	case KnowledgeCorrelation:
		valid = producer == ProducerCorrelation && mode == AssertionInferred
	case KnowledgeInference:
		valid = (producer == ProducerInference || producer == ProducerModelGenerated) && mode == AssertionInferred
	case KnowledgeRecommendation:
		valid = (producer == ProducerDeterministic || producer == ProducerInference ||
			producer == ProducerModelGenerated || producer == ProducerOperator) &&
			(mode == AssertionDeclared || mode == AssertionInferred)
	case KnowledgeAction:
		valid = (producer == ProducerDeterministic || producer == ProducerOperator) && (mode == AssertionDeclared || mode == AssertionVerified)
	}
	if !valid {
		return fmt.Errorf("knowledge state %s cannot use assertion mode %s with producer %s", state, mode, producer)
	}
	return nil
}

func (k Knowledge) State() KnowledgeState        { return k.state }
func (k Knowledge) AssertionMode() AssertionMode { return k.assertionMode }
func (k Knowledge) Producer() ProducerType       { return k.producer }
func (k Knowledge) Confidence() Confidence       { return k.confidence }
func (k Knowledge) Provenance() Provenance       { return k.provenance }
func (k Knowledge) MissingEvidence() []MissingEvidenceKind {
	return append([]MissingEvidenceKind(nil), k.missingEvidence...)
}
func (k Knowledge) ConflictingEvidence() []EvidenceReference {
	return append([]EvidenceReference(nil), k.conflictingEvidence...)
}
func (k Knowledge) Verification() (Verification, bool) { return valueOptional(k.verification) }

func (k Knowledge) validate() error {
	_, err := NewKnowledge(KnowledgeInput{
		State: k.state, AssertionMode: k.assertionMode, Producer: k.producer,
		Confidence: k.confidence, Provenance: k.provenance,
		MissingEvidence: k.missingEvidence, ConflictingEvidence: k.conflictingEvidence,
		Verification: k.verification,
	})
	return err
}

func (k Knowledge) validateForEnvelope(envelope Envelope) error {
	if err := k.validate(); err != nil {
		return err
	}
	root := k.provenance.root
	if root.id != envelope.recordID || root.schemaVersion != envelope.schemaVersion {
		return fmt.Errorf("provenance root must match envelope record and schema version")
	}
	want, err := sortedRecordReferences(envelope.derivationLineage, "envelope lineage")
	if err != nil {
		return err
	}
	if len(want) != len(k.provenance.inputs) {
		return fmt.Errorf("provenance inputs must match envelope derivation lineage")
	}
	for i := range want {
		if want[i] != k.provenance.inputs[i] {
			return fmt.Errorf("provenance inputs must match envelope derivation lineage")
		}
	}
	return nil
}
