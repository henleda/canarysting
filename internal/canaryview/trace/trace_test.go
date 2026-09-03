package trace_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

var fixtureTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

type fixtureCase struct {
	Name              string                `json:"name"`
	CandidateCount    int                   `json:"candidate_count"`
	RawAvailability   model.RawAvailability `json:"raw_availability"`
	ExpectedStatus    trace.Status          `json:"expected_status"`
	ExpectedMissing   int                   `json:"expected_missing"`
	ExpectedConflicts int                   `json:"expected_conflicts"`
}

func TestRedactedPartialAndConflictFixtures(t *testing.T) {
	blob, err := os.ReadFile("testdata/partial_conflict_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	lower := bytes.ToLower(blob)
	for _, prohibited := range []string{
		"authorization", "bearer ", "password", "request_body", "credential",
		"canary_secret", "customer.example", "10.0.", "192.168.", `"payload"`,
	} {
		if bytes.Contains(lower, []byte(prohibited)) {
			t.Errorf("fixture contains prohibited raw or secret-like marker %q", prohibited)
		}
	}
	var cases []fixtureCase
	if err := json.Unmarshal(blob, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("fixture cases=%d want=2", len(cases))
	}
	for index, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			scope := mustScope(t, "tenant-fixture", "scope-fixture")
			anchor := mustRecord(t, scope, "fixture-anchor-"+test.Name, fixtureTime, opaqueDigest(index+1))
			hops := []trace.HopInput{{Record: anchor, Kind: trace.HopObservation}}
			results := []correlation.Result(nil)
			if test.RawAvailability != "" {
				raw := mustRaw(t, index+1, test.RawAvailability)
				hops[0].RawEvent = &raw
			}
			if test.CandidateCount > 0 {
				candidates := make([]correlation.Record, 0, test.CandidateCount)
				for candidateIndex := 0; candidateIndex < test.CandidateCount; candidateIndex++ {
					candidate := mustRecord(
						t, scope, fmt.Sprintf("fixture-candidate-%s-%d", test.Name, candidateIndex),
						fixtureTime.Add(time.Duration(candidateIndex+1)*time.Second), opaqueDigest(index+1),
					)
					candidates = append(candidates, candidate)
					hops = append(hops, trace.HopInput{Record: candidate, Kind: trace.HopPolicyDecision})
				}
				results = []correlation.Result{mustCorrelate(t, anchor, candidates)}
			}
			expectations := []trace.ExpectationInput{{Kind: trace.ExpectObservation}}
			if test.RawAvailability != "" {
				ref := anchor.Reference()
				expectations = append(expectations, trace.ExpectationInput{Kind: trace.ExpectRawEvidence, Record: &ref})
			}
			if test.CandidateCount > 0 {
				expectations = append(expectations, trace.ExpectationInput{Kind: trace.ExpectCorrelation})
			}
			value := mustBuild(t, trace.BuildInput{
				Scope: scope, Hops: hops, Correlations: results, Expectations: expectations,
				ClosedAt: fixtureTime.Add(time.Minute), BuiltAt: fixtureTime.Add(2 * time.Minute),
				HighWaterMark: mustReference(t, "fixture-high-water-"+test.Name),
				Lifecycle:     mustLifecycle(t, fixtureTime.Add(time.Minute), model.RetentionLean, model.LifecycleActive),
				Synthetic:     model.ProductionContext(),
			})
			if value.Status() != test.ExpectedStatus || len(value.MissingTelemetry()) != test.ExpectedMissing || len(value.Conflicts()) != test.ExpectedConflicts {
				t.Fatalf("status=%s missing=%d conflicts=%d", value.Status(), len(value.MissingTelemetry()), len(value.Conflicts()))
			}
		})
	}
}

func TestBuildIsDeterministicAndRetainsAmbiguousCandidatesWithCitations(t *testing.T) {
	scope := mustScope(t, "tenant-a", "scope-a")
	shared := opaqueDigest(41)
	anchor := mustRecord(t, scope, "anchor", fixtureTime, shared)
	left := mustRecord(t, scope, "candidate-left", fixtureTime.Add(time.Second), shared)
	right := mustRecord(t, scope, "candidate-right", fixtureTime.Add(2*time.Second), shared)
	result := mustCorrelate(t, anchor, []correlation.Record{right, left})
	if !result.Ambiguous() {
		t.Fatal("fixture did not produce an ambiguous correlation")
	}
	raw := mustRaw(t, 41, model.RawAvailable)
	closedAt := fixtureTime.Add(time.Minute)
	base := trace.BuildInput{
		Scope: scope,
		Hops: []trace.HopInput{
			{Record: right, Kind: trace.HopPolicyDecision},
			{Record: anchor, Kind: trace.HopObservation, RawEvent: &raw},
			{Record: left, Kind: trace.HopPolicyDecision},
		},
		Correlations: []correlation.Result{result},
		Expectations: []trace.ExpectationInput{
			{Kind: trace.ExpectObservation}, {Kind: trace.ExpectPolicyDecision}, {Kind: trace.ExpectCorrelation},
		},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute),
		HighWaterMark: mustReference(t, "high-water-ambiguous"),
		Lifecycle:     mustLifecycle(t, closedAt, model.RetentionLean, model.LifecycleActive),
		Synthetic:     model.ProductionContext(),
	}
	first := mustBuild(t, base)
	base.Hops[0], base.Hops[2] = base.Hops[2], base.Hops[0]
	second := mustBuild(t, base)
	if first.Envelope().RecordID() != second.Envelope().RecordID() || first.IntegrityDigest() != second.IntegrityDigest() {
		t.Fatalf("input permutation changed deterministic identity: %s %s", first.Envelope().RecordID(), second.Envelope().RecordID())
	}
	if first.Status() != trace.StatusConflicted || len(first.Conflicts()) != 1 {
		t.Fatalf("ambiguous trace status=%s conflicts=%d", first.Status(), len(first.Conflicts()))
	}
	if got := first.Knowledge().Confidence().CandidateCount(); got != 2 {
		t.Fatalf("aggregate candidate count=%d want=2", got)
	}
	sets := first.Correlations()
	if len(sets) != 1 || !sets[0].Ambiguous() {
		t.Fatalf("correlation sets=%d ambiguous=%v", len(sets), len(sets) == 1 && sets[0].Ambiguous())
	}
	if _, chosen := sets[0].Chosen(); chosen {
		t.Fatal("ambiguous trace invented a chosen candidate")
	}
	candidates := sets[0].Candidates()
	if len(candidates) != 2 {
		t.Fatalf("retained candidates=%d want=2", len(candidates))
	}
	for _, candidate := range candidates {
		explanations := candidate.Explanations()
		if len(explanations) != 1 || explanations[0].Method() != correlation.JoinRequestID {
			t.Fatalf("candidate %s explanations=%v", candidate.Reference().ID(), explanations)
		}
		got := referenceIDs(explanations[0].Citations())
		want := []string{"anchor", candidate.Reference().ID()}
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("join citations=%v want=%v", got, want)
		}
	}
	if got := hopIDs(first.Hops()); !reflect.DeepEqual(got, []string{"anchor", "candidate-left", "candidate-right"}) {
		t.Fatalf("ordered hops=%v", got)
	}
}

func TestPassiveTraceCanRemainPartialWithoutCanaryInteraction(t *testing.T) {
	scope := mustScope(t, "tenant-passive", "scope-passive")
	record := mustRecord(t, scope, "passive-observation", fixtureTime, "")
	raw := mustRaw(t, 51, model.RawIntegrityMismatch)
	ref := record.Reference()
	closedAt := fixtureTime.Add(time.Minute)
	value := mustBuild(t, trace.BuildInput{
		Scope: scope,
		Hops:  []trace.HopInput{{Record: record, Kind: trace.HopObservation, RawEvent: &raw}},
		Expectations: []trace.ExpectationInput{
			{Kind: trace.ExpectObservation}, {Kind: trace.ExpectRawEvidence, Record: &ref},
		},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute),
		HighWaterMark: mustReference(t, "high-water-passive"),
		Lifecycle:     mustLifecycle(t, closedAt, model.RetentionLean, model.LifecycleActive),
		Synthetic:     model.ProductionContext(),
	})
	if value.Status() != trace.StatusPartial || len(value.Correlations()) != 0 {
		t.Fatalf("passive trace status=%s correlations=%d", value.Status(), len(value.Correlations()))
	}
	missing := value.MissingTelemetry()
	if len(missing) != 1 {
		t.Fatalf("missing telemetry=%d want=1", len(missing))
	}
	availability, ok := missing[0].RawAvailability()
	if !ok || availability != model.RawIntegrityMismatch {
		t.Fatalf("broken raw availability=%s ok=%v", availability, ok)
	}
	retained, ok := value.Hops()[0].RawEvent()
	if !ok || retained.Reference() != raw.Reference() || retained.Availability() != model.RawIntegrityMismatch {
		t.Fatal("broken raw reference was discarded")
	}
	if got := value.Knowledge().MissingEvidence(); !reflect.DeepEqual(got, []model.MissingEvidenceKind{model.MissingRawEvent}) {
		t.Fatalf("knowledge missing evidence=%v", got)
	}
}

func TestTranslationAndIdentityVerificationRemainEvidenceLinked(t *testing.T) {
	scope := mustScope(t, "tenant-evidence", "scope-evidence")
	verificationEvidence, err := model.NewEvidenceReference(
		"mesh-verification", model.CurrentSchemaVersion, model.EvidenceSupporting, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := model.NewVerification(
		"mesh-chain.verify", "1", model.ProducerDeterministic, []model.EvidenceReference{verificationEvidence},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := model.NewEntityReferenceWithAssertion(
		"workload-a", "WORKLOAD", model.AssertionVerified, &verification,
	)
	if err != nil {
		t.Fatal(err)
	}
	before := mustTuple(t, 61)
	after := mustTuple(t, 71)
	control, err := model.NewControlIdentity("nat-control-a", "NAT_GATEWAY")
	if err != nil {
		t.Fatal(err)
	}
	eventTime, err := correlation.NewEventTime(fixtureTime, 0)
	if err != nil {
		t.Fatal(err)
	}
	translationRef := mustReference(t, "translation-a")
	translation, err := correlation.NewTranslation(correlation.TranslationInput{
		Reference: translationRef, Scope: scope, Before: before, After: after,
		Control: control, ObservedAt: eventTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := correlation.NewRecord(correlation.RecordInput{
		Reference: mustReference(t, "translated-anchor"), Scope: scope,
		Vantage: correlation.SourceVantageGeneral, Time: &eventTime, Tuple: &before,
		Identities: []model.EntityReference{identity},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidateTime, err := correlation.NewEventTime(fixtureTime.Add(time.Second), 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := correlation.NewRecord(correlation.RecordInput{
		Reference: mustReference(t, "translated-candidate"), Scope: scope,
		Vantage: correlation.SourceVantageGeneral, Time: &candidateTime, Tuple: &after,
		Identities: []model.EntityReference{identity},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := correlation.NewEngine(correlation.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	correlated, err := engine.Correlate(anchor, []correlation.Record{candidate}, []correlation.Translation{translation})
	if err != nil {
		t.Fatal(err)
	}
	closedAt := fixtureTime.Add(time.Minute)
	value := mustBuild(t, trace.BuildInput{
		Scope: scope,
		Hops: []trace.HopInput{
			{Record: anchor, Kind: trace.HopObservation},
			{Record: candidate, Kind: trace.HopPolicyDecision},
		},
		Correlations: []correlation.Result{correlated},
		Expectations: []trace.ExpectationInput{
			{Kind: trace.ExpectObservation}, {Kind: trace.ExpectPolicyDecision}, {Kind: trace.ExpectCorrelation},
		},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute),
		HighWaterMark: mustReference(t, "high-water-translation"),
		Lifecycle:     mustLifecycle(t, closedAt, model.RetentionLean, model.LifecycleActive),
		Synthetic:     model.ProductionContext(),
	})
	wantLineage := map[string]bool{"translation-a": false, "mesh-verification": false}
	for _, reference := range value.Envelope().DerivationLineage() {
		if _, wanted := wantLineage[reference.ID()]; wanted {
			wantLineage[reference.ID()] = true
		}
	}
	for reference, found := range wantLineage {
		if !found {
			t.Errorf("lineage omitted %s", reference)
		}
	}
	explanations := value.Correlations()[0].Candidates()[0].Explanations()
	translated := false
	for _, explanation := range explanations {
		if explanation.Method() != correlation.JoinTranslatedTuple {
			continue
		}
		translated = true
		path := explanation.TranslationPath()
		if len(path) != 1 || path[0].Reference() != translationRef || path[0].Before() != before || path[0].After() != after || path[0].Control() != control {
			t.Fatalf("translation path lost evidence: %#v", path)
		}
		if !reflect.DeepEqual(referenceIDs(explanation.Citations()), []string{"translated-anchor", "translated-candidate", "translation-a"}) {
			t.Fatalf("translation citations=%v", referenceIDs(explanation.Citations()))
		}
	}
	if !translated {
		t.Fatal("translated-tuple explanation was not retained")
	}
}

func TestExplicitContradictoryEvidenceIsRetained(t *testing.T) {
	scope := mustScope(t, "tenant-conflict", "scope-conflict")
	left := mustRecord(t, scope, "conflict-left", fixtureTime, "")
	right := mustRecord(t, scope, "conflict-right", fixtureTime.Add(time.Second), "")
	evidence, err := model.NewEvidenceReference(
		"conflict-evidence", model.CurrentSchemaVersion, model.EvidenceContradicting, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	closedAt := fixtureTime.Add(time.Minute)
	value := mustBuild(t, trace.BuildInput{
		Scope: scope,
		Hops: []trace.HopInput{
			{Record: left, Kind: trace.HopObservation},
			{Record: right, Kind: trace.HopPolicyDecision},
		},
		Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}, {Kind: trace.ExpectPolicyDecision}},
		Conflicts: []trace.ConflictInput{{
			Kind:     trace.ConflictContradictoryEvidence,
			Records:  []model.RecordReference{right.Reference(), left.Reference()},
			Evidence: []model.EvidenceReference{evidence},
		}},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute),
		HighWaterMark: mustReference(t, "high-water-conflict"),
		Lifecycle:     mustLifecycle(t, closedAt, model.RetentionLean, model.LifecycleActive),
		Synthetic:     model.ProductionContext(),
	})
	if value.Status() != trace.StatusConflicted || len(value.Conflicts()) != 1 {
		t.Fatalf("explicit conflict status=%s count=%d", value.Status(), len(value.Conflicts()))
	}
	if got := value.Conflicts()[0].Evidence(); len(got) != 1 || got[0].ID() != evidence.ID() {
		t.Fatalf("conflict evidence=%v", got)
	}
	if got := value.Knowledge().ConflictingEvidence(); len(got) != 1 || got[0].ID() != evidence.ID() {
		t.Fatalf("knowledge conflict evidence=%v", got)
	}
	if !containsID(value.Envelope().DerivationLineage(), evidence.ID()) {
		t.Fatal("conflicting evidence is missing from trace lineage")
	}
}

func TestBuilderRejectsBoundsAndCrossScopeHops(t *testing.T) {
	config := trace.DefaultBuilderConfig()
	config.MaxHops = 1
	builder, err := trace.NewBuilder(config)
	if err != nil {
		t.Fatal(err)
	}
	scopeA := mustScope(t, "tenant-a", "scope-a")
	scopeB := mustScope(t, "tenant-b", "scope-b")
	closedAt := fixtureTime.Add(time.Minute)
	base := trace.BuildInput{
		Scope:        scopeA,
		Hops:         []trace.HopInput{{Record: mustRecord(t, scopeA, "a", fixtureTime, ""), Kind: trace.HopObservation}},
		Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}},
		ClosedAt:     closedAt, BuiltAt: closedAt.Add(time.Minute),
		HighWaterMark: mustReference(t, "high-water-bounds"),
		Lifecycle:     mustLifecycle(t, closedAt, model.RetentionLean, model.LifecycleActive),
		Synthetic:     model.ProductionContext(),
	}
	base.Hops = append(base.Hops, trace.HopInput{Record: mustRecord(t, scopeA, "b", fixtureTime, ""), Kind: trace.HopObservation})
	if _, err := builder.Build(base); err == nil {
		t.Fatal("builder accepted input over configured hop bound")
	}
	base.Hops = []trace.HopInput{{Record: mustRecord(t, scopeB, "outside", fixtureTime, ""), Kind: trace.HopObservation}}
	if _, err := builder.Build(base); err == nil {
		t.Fatal("builder accepted a cross-scope hop")
	}
}

func TestStoreScopeLifecycleAndParentDeletionInvalidation(t *testing.T) {
	now := fixtureTime.Add(2 * time.Minute)
	production := mustStore(t, 8, func() time.Time { return now })
	scopeA := mustScope(t, "tenant-a", "scope-a")
	scopeB := mustScope(t, "tenant-b", "scope-b")
	parent := mustReference(t, "source-parent")
	activeA := simpleTrace(t, scopeA, "active-a", parent, model.LifecycleActive, model.ProductionContext())
	heldA := simpleTrace(t, scopeA, "held-a", parent, model.LifecycleHeld, model.ProductionContext())
	activeB := simpleTrace(t, scopeB, "active-b", parent, model.LifecycleActive, model.ProductionContext())
	for _, value := range []trace.Trace{activeA, heldA, activeB} {
		if err := production.Put(value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := production.Get(scopeB, activeA.Envelope().RecordID()); !errors.Is(err, trace.ErrNotFound) {
		t.Fatalf("cross-scope record became visible: %v", err)
	}
	affected, err := production.AffectedBy(scopeA, parent)
	if err != nil || len(affected) != 2 {
		t.Fatalf("scope A affected=%d err=%v", len(affected), err)
	}
	invalidations, err := production.InvalidateBy(scopeA, parent, trace.InvalidationParentDeleted, now)
	if err != nil || len(invalidations) != 2 {
		t.Fatalf("scope A invalidations=%d err=%v", len(invalidations), err)
	}
	if invalidations[0].Trace().ID() > invalidations[1].Trace().ID() {
		t.Fatal("invalidation results are not deterministic")
	}
	for _, value := range []trace.Trace{activeA, heldA} {
		if _, err := production.Get(scopeA, value.Envelope().RecordID()); !errors.Is(err, trace.ErrNotFound) {
			t.Fatalf("invalidated trace %s remained visible: %v", value.Envelope().RecordID(), err)
		}
	}
	if _, err := production.Get(scopeB, activeB.Envelope().RecordID()); err != nil {
		t.Fatalf("scope B was invalidated by scope A operation: %v", err)
	}
	if repeated, err := production.InvalidateBy(scopeA, parent, trace.InvalidationParentDeleted, now); err != nil || len(repeated) != 0 {
		t.Fatalf("repeat invalidation=%d err=%v", len(repeated), err)
	}

	heldDisposition, err := trace.EvaluateLifecycle(heldA, fixtureTime.Add(200*24*time.Hour))
	if err != nil || !heldDisposition.Queryable || heldDisposition.EffectiveState != model.LifecycleHeld {
		t.Fatalf("held lifecycle disposition=%+v err=%v", heldDisposition, err)
	}
	expiring := simpleTrace(t, scopeA, "expiring", mustReference(t, "expiry-parent"), model.LifecycleActive, model.ProductionContext())
	secondStore := mustStore(t, 4, func() time.Time { return now })
	if err := secondStore.Put(expiring); err != nil {
		t.Fatal(err)
	}
	now = expiring.Envelope().Lifecycle().ExpiresAt()
	if _, err := secondStore.Get(scopeA, expiring.Envelope().RecordID()); !errors.Is(err, trace.ErrNotFound) {
		t.Fatalf("expired trace remained visible: %v", err)
	}
	disposition, err := trace.EvaluateLifecycle(expiring, now)
	if err != nil || disposition.Queryable || !disposition.RequiresInvalidation || disposition.EffectiveState != model.LifecycleExpiryDue {
		t.Fatalf("expiry disposition=%+v err=%v", disposition, err)
	}
	synthetic, err := model.NewSyntheticContext("trace-fixture-v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := secondStore.Put(simpleTrace(t, scopeA, "synthetic", mustReference(t, "synthetic-parent"), model.LifecycleActive, synthetic)); !errors.Is(err, trace.ErrSynthetic) {
		t.Fatalf("synthetic trace entered production store: %v", err)
	}
}

func TestStoreBoundsAndConcurrentScopeIsolation(t *testing.T) {
	production := mustStore(t, 64, func() time.Time { return fixtureTime.Add(3 * time.Minute) })
	const count = 32
	values := make([]trace.Trace, 0, count*2)
	for index := 0; index < count; index++ {
		for _, scopeID := range []string{"scope-a", "scope-b"} {
			scope := mustScope(t, "tenant-concurrent", scopeID)
			values = append(values, simpleTrace(
				t, scope, fmt.Sprintf("%s-%03d", scopeID, index), mustReference(t, fmt.Sprintf("parent-%s-%03d", scopeID, index)),
				model.LifecycleActive, model.ProductionContext(),
			))
		}
	}
	var wait sync.WaitGroup
	for _, value := range values {
		value := value
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := production.Put(value); err != nil {
				t.Errorf("put %s: %v", value.Envelope().RecordID(), err)
			}
		}()
	}
	wait.Wait()
	for _, scopeID := range []string{"scope-a", "scope-b"} {
		got, err := production.Query(mustScope(t, "tenant-concurrent", scopeID), 64)
		if err != nil || len(got) != count {
			t.Fatalf("scope %s traces=%d err=%v", scopeID, len(got), err)
		}
		for _, value := range got {
			if value.Envelope().Scope().ScopeID() != scopeID {
				t.Fatalf("scope %s query leaked %s", scopeID, value.Envelope().Scope().ScopeID())
			}
		}
	}
	if got, err := production.Query(mustScope(t, "tenant-concurrent", "scope-a"), 65); !errors.Is(err, trace.ErrBound) || got != nil {
		t.Fatalf("oversize query returned records: %d %v", len(got), err)
	}

	bounded := mustStore(t, 1, func() time.Time { return fixtureTime.Add(3 * time.Minute) })
	scope := mustScope(t, "tenant-bounded", "scope-bounded")
	first := simpleTrace(t, scope, "bounded-first", mustReference(t, "bounded-parent-first"), model.LifecycleActive, model.ProductionContext())
	if err := bounded.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := bounded.Put(first); !errors.Is(err, trace.ErrDuplicate) {
		t.Fatalf("duplicate immutable trace was accepted: %v", err)
	}
	second := simpleTrace(t, scope, "bounded-second", mustReference(t, "bounded-parent-second"), model.LifecycleActive, model.ProductionContext())
	if err := bounded.Put(second); !errors.Is(err, trace.ErrCapacity) {
		t.Fatalf("per-scope trace capacity was not enforced: %v", err)
	}
}

func simpleTrace(t *testing.T, scope model.Scope, suffix string, parent model.RecordReference, state model.LifecycleState, synthetic model.SyntheticContext) trace.Trace {
	t.Helper()
	seed := len(suffix) + int(suffix[0])
	eventAt := fixtureTime.Add(time.Duration(seed) * time.Second)
	closedAt := eventAt.Add(time.Minute)
	record := mustRecord(t, scope, "observation-"+suffix, eventAt, "")
	return mustBuild(t, trace.BuildInput{
		Scope: scope, Hops: []trace.HopInput{{Record: record, Kind: trace.HopObservation}},
		Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}},
		ClosedAt:     closedAt, BuiltAt: closedAt.Add(time.Minute), HighWaterMark: parent,
		Lifecycle: mustLifecycle(t, closedAt, model.RetentionLean, state), Synthetic: synthetic,
	})
}

func mustBuild(t *testing.T, input trace.BuildInput) trace.Trace {
	t.Helper()
	builder, err := trace.NewBuilder(trace.DefaultBuilderConfig())
	if err != nil {
		t.Fatal(err)
	}
	value, err := builder.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustStore(t *testing.T, capacity int, now func() time.Time) *trace.ProductionStore {
	t.Helper()
	value, err := trace.NewProductionStore(trace.StoreLimits{
		TracesPerScope: capacity, QueryResults: capacity, InvalidationResults: capacity,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustCorrelate(t *testing.T, anchor correlation.Record, candidates []correlation.Record) correlation.Result {
	t.Helper()
	engine, err := correlation.NewEngine(correlation.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Correlate(anchor, candidates, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustRecord(t *testing.T, scope model.Scope, id string, at time.Time, requestDigest string) correlation.Record {
	t.Helper()
	reference := mustReference(t, id)
	eventTime, err := correlation.NewEventTime(at, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := correlation.RecordInput{
		Reference: reference, Scope: scope, Vantage: correlation.SourceVantageGeneral, Time: &eventTime,
	}
	if requestDigest != "" {
		requestID, requestErr := correlation.NewOpaqueID("fixture-request", requestDigest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		input.RequestIDs = []correlation.OpaqueID{requestID}
	}
	record, err := correlation.NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func mustLifecycle(t *testing.T, closedAt time.Time, profile model.RetentionProfile, state model.LifecycleState) model.Lifecycle {
	t.Helper()
	expiresAt := closedAt.Add(90 * 24 * time.Hour)
	if profile == model.RetentionStandard {
		expiresAt = closedAt.AddDate(0, 13, 0)
	}
	estimate, err := model.NewStorageEstimate(4096, model.EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	holds := []string(nil)
	if state == model.LifecycleHeld {
		holds = []string{"hold-trace-fixture-v1"}
	}
	lifecycle, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassCorrelatedTrace, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: profile, PolicyVersion: "trace-policy-v1", RetentionDecisionRef: "retention/trace-v1",
		RetentionClock: model.RetentionFromTraceClose, RetentionStart: closedAt, ExpiresAt: expiresAt,
		State: state, LegalHoldIDs: holds, ResidencyPolicyRef: "residency/us-test-v1",
		EncryptionKeyRef: "key://test/trace", OperationalPolicyRef: "operational/trace-v1",
		PerTenantModelUse: model.ModelUseGrant{}, CrossTenantModelUse: model.ModelUseGrant{},
		EstimatedStorageImpact: estimate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func mustScope(t *testing.T, tenantID, scopeID string) model.Scope {
	t.Helper()
	scope, err := model.NewScope(tenantID, scopeID, "deployment-test", "residency-test")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustReference(t *testing.T, id string) model.RecordReference {
	t.Helper()
	reference, err := model.NewRecordReference(id, model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func mustRaw(t *testing.T, seed int, availability model.RawAvailability) model.RawEventReference {
	t.Helper()
	value, err := model.NewRawEventReference("rawref:sha256:"+opaqueDigest(seed+1000), availability, "sha256", opaqueDigest(seed+2000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustTuple(t *testing.T, seed int) correlation.NetworkTuple {
	t.Helper()
	value, err := correlation.NewNetworkTuple(
		correlation.ProtocolTCP, opaqueDigest(seed), uint16(1000+seed),
		opaqueDigest(seed+1), uint16(2000+seed),
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func opaqueDigest(seed int) string { return fmt.Sprintf("%064x", seed+1) }

func referenceIDs(values []model.RecordReference) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ID())
	}
	sort.Strings(result)
	return result
}

func containsID(values []model.RecordReference, wanted string) bool {
	for _, value := range values {
		if value.ID() == wanted {
			return true
		}
	}
	return false
}

func hopIDs(values []trace.Hop) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Reference().ID())
	}
	return result
}
