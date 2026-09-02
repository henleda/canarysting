package model

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestKnowledgeStatesCannotBeConfused(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	base := mustSourceKnowledge(t, envelope, nil, nil)
	tests := []struct {
		name     string
		state    KnowledgeState
		mode     AssertionMode
		producer ProducerType
		wantOK   bool
	}{
		{name: "source observation", state: KnowledgeSourceObservation, mode: AssertionObserved, producer: ProducerDeterministic, wantOK: true},
		{name: "declared source", state: KnowledgeSourceObservation, mode: AssertionDeclared, producer: ProducerOperator, wantOK: true},
		{name: "source cannot infer", state: KnowledgeSourceObservation, mode: AssertionInferred, producer: ProducerInference},
		{name: "correlation", state: KnowledgeCorrelation, mode: AssertionInferred, producer: ProducerCorrelation, wantOK: true},
		{name: "correlation is not observation", state: KnowledgeCorrelation, mode: AssertionObserved, producer: ProducerDeterministic},
		{name: "inference", state: KnowledgeInference, mode: AssertionInferred, producer: ProducerInference, wantOK: true},
		{name: "model inference", state: KnowledgeInference, mode: AssertionInferred, producer: ProducerModelGenerated, wantOK: true},
		{name: "model cannot observe", state: KnowledgeInference, mode: AssertionObserved, producer: ProducerModelGenerated},
		{name: "recommendation", state: KnowledgeRecommendation, mode: AssertionInferred, producer: ProducerModelGenerated, wantOK: true},
		{name: "recommendation cannot verify", state: KnowledgeRecommendation, mode: AssertionVerified, producer: ProducerOperator},
		{name: "action declaration", state: KnowledgeAction, mode: AssertionDeclared, producer: ProducerOperator, wantOK: true},
		{name: "action cannot be model generated", state: KnowledgeAction, mode: AssertionDeclared, producer: ProducerModelGenerated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewKnowledge(KnowledgeInput{
				State: test.state, AssertionMode: test.mode, Producer: test.producer,
				Confidence: base.confidence, Provenance: base.provenance,
			})
			if (err == nil) != test.wantOK {
				t.Fatalf("NewKnowledge() error=%v wantOK=%t", err, test.wantOK)
			}
		})
	}
}

func TestObservationCannotCarryCorrelationKnowledge(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	base := mustSourceKnowledge(t, envelope, nil, nil)
	correlation, err := NewKnowledge(KnowledgeInput{
		State: KnowledgeCorrelation, AssertionMode: AssertionInferred,
		Producer: ProducerCorrelation, Confidence: base.confidence, Provenance: base.provenance,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport, Knowledge: correlation,
		ObservationType: "network.flow", Source: mustSource(t), Collector: mustCollector(t),
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
	})
	if err == nil || !strings.Contains(err.Error(), "SOURCE_OBSERVATION") {
		t.Fatalf("correlation metadata was accepted as an Observation: %v", err)
	}
}

func TestParsedOrForgedIdentityCannotClaimVerified(t *testing.T) {
	parsed, err := NewEntityReference("spiffe://example.test/ns/default/sa/api", "WORKLOAD")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AssertionMode() != AssertionDeclared {
		t.Fatalf("syntactic identifier assertion=%s want=%s", parsed.AssertionMode(), AssertionDeclared)
	}
	if _, ok := parsed.Verification(); ok {
		t.Fatal("syntactic identifier invented verification evidence")
	}
	if _, err := NewEntityReferenceWithAssertion(parsed.ID(), parsed.Kind(), AssertionVerified, nil); err == nil {
		t.Fatal("parse-only identifier was accepted as VERIFIED")
	}
	if _, err := NewVerification("spiffe.parse", "1", ProducerDeterministic, nil); err == nil {
		t.Fatal("verification without evidence was accepted")
	}
	evidence := []EvidenceReference{mustEvidenceRef(t, "mesh-trust-chain-1", EvidenceSupporting, "", "")}
	if _, err := NewVerification("mesh.trust-chain", "1", ProducerModelGenerated, evidence); err == nil {
		t.Fatal("model-generated verification was accepted")
	}
	verification, err := NewVerification("mesh.trust-chain", "1", ProducerDeterministic, evidence)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := NewEntityReferenceWithAssertion(parsed.ID(), parsed.Kind(), AssertionVerified, &verification)
	if err != nil {
		t.Fatal(err)
	}
	if proof, ok := verified.Verification(); !ok || proof.ProcedureID() != "mesh.trust-chain" {
		t.Fatal("verified identity lost its verification procedure")
	}
}

func TestVerifiedKnowledgeRequiresProcedureEvidence(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	base := mustSourceKnowledge(t, envelope, nil, nil)
	input := KnowledgeInput{
		State: KnowledgeSourceObservation, AssertionMode: AssertionVerified,
		Producer: ProducerDeterministic, Confidence: base.confidence, Provenance: base.provenance,
	}
	if _, err := NewKnowledge(input); err == nil || !strings.Contains(err.Error(), "verification evidence") {
		t.Fatalf("VERIFIED without evidence was accepted: %v", err)
	}
	verification, err := NewVerification(
		"source.signature", "2", ProducerDeterministic,
		[]EvidenceReference{mustEvidenceRef(t, "signature-1", EvidenceSupporting, "", "")},
	)
	if err != nil {
		t.Fatal(err)
	}
	input.Verification = &verification
	if _, err := NewKnowledge(input); err != nil {
		t.Fatalf("evidence-backed VERIFIED knowledge was rejected: %v", err)
	}
}

func TestVerifiedKnowledgeAndEntityV3RoundTrip(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	base := mustSourceKnowledge(t, envelope, nil, nil)
	verification, err := NewVerification(
		"mesh.trust-chain", "1", ProducerDeterministic,
		[]EvidenceReference{mustEvidenceRef(t, "mesh-proof-1", EvidenceSupporting, "", "")},
	)
	if err != nil {
		t.Fatal(err)
	}
	confidence, err := NewConfidence(ConfidenceInput{
		Level: ConfidenceHigh, Method: ConfidenceVerifiedIdentity,
		SourceQuality: AssuranceDeclared, IdentityAssurance: AssuranceVerified,
		Completeness: EvidenceComplete, CandidateCount: 1, TimeUncertainty: TimeExact,
		AlgorithmID: "mesh.verify", AlgorithmVersion: "1",
		Calibration: CalibrationNotApplicable, HumanReview: HumanUnreviewed,
	})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := NewKnowledge(KnowledgeInput{
		State: KnowledgeSourceObservation, AssertionMode: AssertionVerified,
		Producer: ProducerDeterministic, Confidence: confidence,
		Provenance: base.provenance, Verification: &verification,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := NewEntityReferenceWithAssertion(
		"spiffe://example.test/ns/default/sa/api", "WORKLOAD", AssertionVerified, &verification,
	)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport, Knowledge: knowledge,
		ObservationType: "identity.authenticated", Source: mustSource(t), Collector: mustCollector(t),
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested, Subject: &subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := MarshalObservationV3(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"assertion_mode":"VERIFIED"`, `"method":"VERIFIED_IDENTITY"`,
		`"procedure_id":"mesh.trust-chain"`, `"id":"mesh-proof-1"`,
	} {
		if !bytes.Contains(blob, []byte(expected)) {
			t.Errorf("verified fixture missing %s: %s", expected, blob)
		}
	}
	if bytes.Contains(blob, []byte(`"score"`)) || bytes.Contains(blob, []byte(`"probability"`)) {
		t.Fatalf("uncalibrated schema emitted false numeric precision: %s", blob)
	}
	decoded, err := UnmarshalObservationV3(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, observation) {
		t.Fatalf("verified round trip changed observation:\n got: %#v\nwant: %#v", decoded, observation)
	}
}

func TestConfidenceTimeBoundsAndVerifiedAssuranceFailClosed(t *testing.T) {
	base := ConfidenceInput{
		Level: ConfidenceHigh, Method: ConfidenceDirectSource,
		SourceQuality: AssuranceDeclared, IdentityAssurance: AssuranceDeclared,
		Completeness: EvidencePartial, CandidateCount: 1, TimeUncertainty: TimeBounded,
		AlgorithmID: "normalize", AlgorithmVersion: "1",
		Calibration: CalibrationNotApplicable, HumanReview: HumanUnreviewed,
	}
	if _, err := NewConfidence(base); err == nil {
		t.Fatal("bounded uncertainty without a window was accepted")
	}
	base.TimeUncertainty = TimeExact
	base.TimeWindow = 1
	if _, err := NewConfidence(base); err == nil {
		t.Fatal("exact time carried a nonzero uncertainty window")
	}
	base.TimeWindow = 0
	base.SourceQuality = AssuranceVerified
	confidence, err := NewConfidence(base)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	knowledge := mustSourceKnowledge(t, envelope, nil, nil)
	if _, err := NewKnowledge(KnowledgeInput{
		State: KnowledgeSourceObservation, AssertionMode: AssertionObserved,
		Producer: ProducerDeterministic, Confidence: confidence, Provenance: knowledge.provenance,
	}); err == nil {
		t.Fatal("verified source assurance without verification evidence was accepted")
	}
}

func TestProvenanceRejectsCyclesAndDisconnectedClaims(t *testing.T) {
	root := mustRecordRef(t, "root")
	a := mustRecordRef(t, "a")
	b := mustRecordRef(t, "b")
	rootA := mustLineageLink(t, root, a)
	aB := mustLineageLink(t, a, b)
	bA := mustLineageLink(t, b, a)
	if _, err := NewProvenance(root, "correlate", "1", []RecordReference{a}, []LineageLink{rootA, aB, bA}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cyclic lineage was accepted: %v", err)
	}
	disconnected := mustLineageLink(t, b, mustRecordRef(t, "c"))
	if _, err := NewProvenance(root, "correlate", "1", []RecordReference{a}, []LineageLink{rootA, disconnected}); err == nil || !strings.Contains(err.Error(), "disconnected") {
		t.Fatalf("disconnected lineage was accepted: %v", err)
	}
	if _, err := NewProvenance(root, "correlate", "1", []RecordReference{a}, nil); err == nil || !strings.Contains(err.Error(), "root links") {
		t.Fatalf("undeclared direct lineage was accepted: %v", err)
	}
}

func TestProvenanceRejectsEveryBackEdgeInAChain(t *testing.T) {
	for length := 2; length <= 12; length++ {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			nodes := make([]RecordReference, length)
			for i := range nodes {
				nodes[i] = mustRecordRef(t, fmt.Sprintf("node-%02d", i))
			}
			links := []LineageLink{mustLineageLink(t, nodes[0], nodes[1])}
			for i := 1; i < length-1; i++ {
				links = append(links, mustLineageLink(t, nodes[i], nodes[i+1]))
			}
			for ancestor := 0; ancestor < length-1; ancestor++ {
				cyclic := append([]LineageLink(nil), links...)
				cyclic = append(cyclic, mustLineageLink(t, nodes[length-1], nodes[ancestor]))
				if _, err := NewProvenance(nodes[0], "property.chain", "1", []RecordReference{nodes[1]}, cyclic); err == nil {
					t.Fatalf("back edge to node %d was accepted", ancestor)
				}
			}
		})
	}
}

func TestKnowledgeDiagnosticsAreTypedAndRoleChecked(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	base := mustSourceKnowledge(t, envelope, nil, nil)
	if _, err := NewKnowledge(KnowledgeInput{
		State: base.state, AssertionMode: base.assertionMode, Producer: base.producer,
		Confidence: base.confidence, Provenance: base.provenance,
		MissingEvidence: []MissingEvidenceKind{"free-form warning: token=secret"},
	}); err == nil {
		t.Fatal("free-form missing-evidence diagnostic was accepted")
	}
	if _, err := NewKnowledge(KnowledgeInput{
		State: base.state, AssertionMode: base.assertionMode, Producer: base.producer,
		Confidence: base.confidence, Provenance: base.provenance,
		ConflictingEvidence: []EvidenceReference{mustEvidenceRef(t, "support-1", EvidenceSupporting, "", "")},
	}); err == nil {
		t.Fatal("supporting evidence was mislabeled as a conflict")
	}
}

func TestObservationRejectsKnowledgeForAnotherRecord(t *testing.T) {
	envelope := mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext())
	otherEnvelope, err := NewEnvelope(EnvelopeInput{
		RecordID: "observation-other", SchemaVersion: CurrentSchemaVersion,
		Scope: envelope.Scope(), Lifecycle: envelope.Lifecycle(), Synthetic: ProductionContext(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport,
		Knowledge:       mustSourceKnowledge(t, otherEnvelope, nil, nil),
		ObservationType: "network.flow", Source: mustSource(t), Collector: mustCollector(t),
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
	})
	if err == nil || !strings.Contains(err.Error(), "root must match") {
		t.Fatalf("foreign provenance root was accepted: %v", err)
	}
}

func mustLineageLink(t *testing.T, child, parent RecordReference) LineageLink {
	t.Helper()
	link, err := NewLineageLink(child, parent)
	if err != nil {
		t.Fatal(err)
	}
	return link
}
