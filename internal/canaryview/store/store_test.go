package store_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/store"
)

var (
	fixtureObserved = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	fixtureNow      = time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
)

type fixtureCase struct {
	Name            string               `json:"name"`
	RecordID        string               `json:"record_id"`
	TenantID        string               `json:"tenant_id"`
	ScopeID         string               `json:"scope_id"`
	State           model.LifecycleState `json:"state"`
	ExpiresAt       time.Time            `json:"expires_at"`
	ModelUseAllowed bool                 `json:"model_use_allowed"`
	Synthetic       bool                 `json:"synthetic"`
	ExpectedPut     string               `json:"expected_put"`
}

func TestLifecycleFixturesAreRedactedAndExecutable(t *testing.T) {
	blob, err := os.ReadFile("testdata/lifecycle_cases.json")
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
	if len(cases) < 6 {
		t.Fatalf("lifecycle fixture coverage shrank to %d cases", len(cases))
	}

	production := newStore(t, 16, func() time.Time { return fixtureNow })
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			observation := observationFixture(t, observationOptions{
				recordID: test.RecordID, tenantID: test.TenantID, scopeID: test.ScopeID,
				state: test.State, expiresAt: test.ExpiresAt,
				perTenantModelUse: test.ModelUseAllowed, synthetic: test.Synthetic,
			})
			disposition, err := store.EvaluateLifecycle(observation, fixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			err = production.Put(observation)
			switch test.ExpectedPut {
			case "accepted":
				if err != nil || !disposition.Queryable {
					t.Fatalf("accepted fixture: disposition=%+v err=%v", disposition, err)
				}
			case "lifecycle-unavailable":
				if !errors.Is(err, store.ErrLifecycleUnavailable) || disposition.Queryable {
					t.Fatalf("lifecycle fixture: disposition=%+v err=%v", disposition, err)
				}
			case "synthetic-rejected":
				if !errors.Is(err, store.ErrSynthetic) {
					t.Fatalf("synthetic fixture was not rejected: %v", err)
				}
			default:
				t.Fatalf("unsupported expected_put %q", test.ExpectedPut)
			}
		})
	}

	scope := mustScope(t, "tenant-fixture", "scope-blue")
	visible, err := production.Query(scope, 16)
	if err != nil {
		t.Fatal(err)
	}
	got := recordIDs(visible)
	if want := []string{"fixture-active", "fixture-held"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("visible lifecycle fixtures=%v want=%v", got, want)
	}
}

func TestStoreScopeIsolationAndFailClosedJoin(t *testing.T) {
	production := newStore(t, 16, func() time.Time { return fixtureNow })
	scopeA := mustScope(t, "tenant-a", "scope-a")
	scopeB := mustScope(t, "tenant-b", "scope-b")
	parent := mustReference(t, "raw-parent")

	for _, observation := range []model.Observation{
		observationFixture(t, observationOptions{recordID: "same-id", tenantID: "tenant-a", scopeID: "scope-a"}),
		observationFixture(t, observationOptions{recordID: "same-id", tenantID: "tenant-b", scopeID: "scope-b"}),
		observationFixture(t, observationOptions{recordID: "only-b", tenantID: "tenant-b", scopeID: "scope-b"}),
		observationFixture(t, observationOptions{recordID: "child-a", tenantID: "tenant-a", scopeID: "scope-a", lineage: []model.RecordReference{parent}}),
		observationFixture(t, observationOptions{recordID: "child-b", tenantID: "tenant-b", scopeID: "scope-b", lineage: []model.RecordReference{parent}}),
	} {
		if err := production.Put(observation); err != nil {
			t.Fatal(err)
		}
	}

	gotA, err := production.Get(scopeA, "same-id")
	if err != nil || gotA.Envelope().Scope().TenantID() != "tenant-a" {
		t.Fatalf("scope A get crossed boundary: tenant=%q err=%v", gotA.Envelope().Scope().TenantID(), err)
	}
	gotB, err := production.Get(scopeB, "same-id")
	if err != nil || gotB.Envelope().Scope().TenantID() != "tenant-b" {
		t.Fatalf("scope B get crossed boundary: tenant=%q err=%v", gotB.Envelope().Scope().TenantID(), err)
	}
	joined, err := production.Join(scopeA, []string{"same-id", "only-b"})
	if !errors.Is(err, store.ErrNotFound) || joined != nil {
		t.Fatalf("cross-scope join returned partial/existence data: joined=%v err=%v", recordIDs(joined), err)
	}
	affected, err := production.AffectedBy(scopeA, parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordIDs(affected); !reflect.DeepEqual(got, []string{"child-a"}) {
		t.Fatalf("scope A invalidation set crossed boundary: %v", got)
	}
	if _, err := production.Get(scopeA, "only-b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-scope get did not fail closed: %v", err)
	}
}

func TestStoreBoundsAndDeterministicQuery(t *testing.T) {
	production := newStore(t, 3, func() time.Time { return fixtureNow })
	scope := mustScope(t, "tenant-a", "scope-a")
	for _, id := range []string{"z", "a", "m"} {
		if err := production.Put(observationFixture(t, observationOptions{recordID: id, tenantID: "tenant-a", scopeID: "scope-a"})); err != nil {
			t.Fatal(err)
		}
	}
	if err := production.Put(observationFixture(t, observationOptions{recordID: "overflow", tenantID: "tenant-a", scopeID: "scope-a"})); !errors.Is(err, store.ErrCapacity) {
		t.Fatalf("per-scope capacity was not enforced: %v", err)
	}
	if err := production.Put(observationFixture(t, observationOptions{recordID: "a", tenantID: "tenant-a", scopeID: "scope-a"})); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("duplicate immutable record was not rejected: %v", err)
	}
	if _, err := production.Query(scope, 0); !errors.Is(err, store.ErrBound) {
		t.Fatalf("zero query bound accepted: %v", err)
	}
	if _, err := production.Query(scope, 4); !errors.Is(err, store.ErrBound) {
		t.Fatalf("oversize query bound accepted: %v", err)
	}
	if joined, err := production.Join(scope, []string{"a", "m", "z", "overflow"}); !errors.Is(err, store.ErrBound) || joined != nil {
		t.Fatalf("oversize join returned data: %v %v", recordIDs(joined), err)
	}
	first, err := production.Query(scope, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := production.Query(scope, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordIDs(first), []string{"a", "m", "z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("query order=%v want=%v", got, want)
	}
	for i := range first {
		left, err := model.MarshalObservationV3(first[i])
		if err != nil {
			t.Fatal(err)
		}
		right, err := model.MarshalObservationV3(second[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("deterministic serialization changed for %q", first[i].Envelope().RecordID())
		}
	}
}

func TestOperationalRetentionDoesNotGrantModelUse(t *testing.T) {
	production := newStore(t, 8, func() time.Time { return fixtureNow })
	scope := mustScope(t, "tenant-a", "scope-a")
	for _, options := range []observationOptions{
		{recordID: "operational-only", tenantID: "tenant-a", scopeID: "scope-a"},
		{recordID: "per-tenant-authorized", tenantID: "tenant-a", scopeID: "scope-a", perTenantModelUse: true},
		{recordID: "cross-only", tenantID: "tenant-a", scopeID: "scope-a", crossTenantModelUse: true},
	} {
		if err := production.Put(observationFixture(t, options)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := production.PerTenantBaselineInputs(scope, []string{"per-tenant-authorized"}, "model-use/per-tenant-v1"); err != nil || len(got) != 1 {
		t.Fatalf("authorized per-tenant input rejected: len=%d err=%v", len(got), err)
	}
	for _, id := range []string{"operational-only", "cross-only"} {
		if got, err := production.PerTenantBaselineInputs(scope, []string{id}, "model-use/per-tenant-v1"); !errors.Is(err, store.ErrModelUseDenied) || got != nil {
			t.Fatalf("%s entered baseline without exact grant: got=%v err=%v", id, recordIDs(got), err)
		}
	}
	if got, err := production.PerTenantBaselineInputs(scope, []string{"per-tenant-authorized"}, "model-use/other"); !errors.Is(err, store.ErrModelUseDenied) || got != nil {
		t.Fatalf("mismatched policy entered baseline: got=%v err=%v", recordIDs(got), err)
	}
}

func TestExpiryRemovesOrdinaryVisibilityAndInvalidationInputs(t *testing.T) {
	now := fixtureNow
	production := newStore(t, 8, func() time.Time { return now })
	scope := mustScope(t, "tenant-a", "scope-a")
	parent := mustReference(t, "raw-parent")
	observation := observationFixture(t, observationOptions{
		recordID: "expires", tenantID: "tenant-a", scopeID: "scope-a",
		expiresAt: fixtureNow.Add(time.Hour), lineage: []model.RecordReference{parent},
	})
	if err := production.Put(observation); err != nil {
		t.Fatal(err)
	}
	now = fixtureNow.Add(2 * time.Hour)
	if _, err := production.Get(scope, "expires"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired record remained queryable: %v", err)
	}
	if got, err := production.Query(scope, 8); err != nil || len(got) != 0 {
		t.Fatalf("expired query result=%v err=%v", recordIDs(got), err)
	}
	if got, err := production.AffectedBy(scope, parent); err != nil || len(got) != 0 {
		t.Fatalf("expired invalidation input remained active: %v err=%v", recordIDs(got), err)
	}
	disposition, err := store.EvaluateLifecycle(observation, now)
	if err != nil || disposition.Queryable || !disposition.RequiresInvalidation || disposition.EffectiveState != model.LifecycleExpiryDue {
		t.Fatalf("expiry disposition=%+v err=%v", disposition, err)
	}
}

func TestConcurrentScopeOperations(t *testing.T) {
	production := newStore(t, 128, func() time.Time { return fixtureNow })
	const records = 64
	observations := make([]model.Observation, 0, records*2)
	for i := 0; i < records; i++ {
		for _, scopeID := range []string{"scope-a", "scope-b"} {
			observations = append(observations, observationFixture(t, observationOptions{
				recordID: fmt.Sprintf("record-%03d", i), tenantID: "tenant-a", scopeID: scopeID,
			}))
		}
	}
	var wait sync.WaitGroup
	for _, observation := range observations {
		observation := observation
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := production.Put(observation); err != nil {
				t.Errorf("put %s/%s: %v", observation.Envelope().Scope().ScopeID(), observation.Envelope().RecordID(), err)
			}
		}()
	}
	wait.Wait()
	for _, scopeID := range []string{"scope-a", "scope-b"} {
		got, err := production.Query(mustScope(t, "tenant-a", scopeID), 128)
		if err != nil || len(got) != records {
			t.Fatalf("query %s count=%d err=%v", scopeID, len(got), err)
		}
	}
}

type observationOptions struct {
	recordID, tenantID, scopeID string
	state                       model.LifecycleState
	expiresAt                   time.Time
	lineage                     []model.RecordReference
	perTenantModelUse           bool
	crossTenantModelUse         bool
	synthetic                   bool
}

func observationFixture(t *testing.T, options observationOptions) model.Observation {
	t.Helper()
	if options.state == "" {
		options.state = model.LifecycleActive
	}
	if options.expiresAt.IsZero() {
		options.expiresAt = fixtureNow.Add(24 * time.Hour)
	}
	perTenant := mustGrant(t, options.perTenantModelUse, "model-use/per-tenant-v1")
	crossTenant := mustGrant(t, options.crossTenantModelUse, "model-use/cross-tenant-v1")
	estimate, err := model.NewStorageEstimate(2048, model.EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	holds := []string(nil)
	if options.state == model.LifecycleHeld {
		holds = []string{"hold-fixture-1"}
	}
	lifecycle, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassNormalizedObservation, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionOverride, PolicyVersion: "fixture-policy-v1",
		RetentionDecisionRef: "retention/" + options.recordID, OverrideVersion: "fixture-override-v1",
		RetentionClock: model.RetentionFromObserved, RetentionStart: fixtureObserved,
		ExpiresAt: options.expiresAt, State: options.state, LegalHoldIDs: holds,
		ResidencyPolicyRef: "residency/us-fixture-v1", EncryptionKeyRef: "key://fixture/evidence",
		OperationalPolicyRef: "operational/fixture-v1", PerTenantModelUse: perTenant,
		CrossTenantModelUse: crossTenant, EstimatedStorageImpact: estimate,
	})
	if err != nil {
		t.Fatal(err)
	}
	synthetic := model.ProductionContext()
	if options.synthetic {
		synthetic, err = model.NewSyntheticContext("scenario-fixture-v1")
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: options.recordID, SchemaVersion: model.CurrentSchemaVersion,
		Scope: mustScope(t, options.tenantID, options.scopeID), Lifecycle: lifecycle,
		DerivationLineage: options.lineage, Synthetic: synthetic,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := mustReference(t, options.recordID)
	links := make([]model.LineageLink, 0, len(options.lineage))
	for _, parent := range options.lineage {
		link, err := model.NewLineageLink(root, parent)
		if err != nil {
			t.Fatal(err)
		}
		links = append(links, link)
	}
	provenance, err := model.NewProvenance(root, "normalize.fixture", "v1", options.lineage, links)
	if err != nil {
		t.Fatal(err)
	}
	confidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: model.ConfidenceHigh, Method: model.ConfidenceDirectSource,
		SourceQuality: model.AssuranceDeclared, IdentityAssurance: model.AssuranceUnverified,
		Completeness: model.EvidencePartial, CandidateCount: 1, TimeUncertainty: model.TimeExact,
		AlgorithmID: "normalize.fixture", AlgorithmVersion: "v1",
		Calibration: model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := model.NewKnowledge(model.KnowledgeInput{
		State: model.KnowledgeSourceObservation, AssertionMode: model.AssertionObserved,
		Producer: model.ProducerDeterministic, Confidence: confidence, Provenance: provenance,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := model.NewSourceIdentity("fixture-source", options.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := model.NewCollectorIdentity("fixture-collector", "v1")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := model.NewObservation(model.ObservationInput{
		Envelope: envelope, Basis: model.ObservationSourceReport, Knowledge: knowledge,
		ObservationType: "fixture.network.flow", Source: source, Collector: collector,
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureObserved.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func newStore(t *testing.T, bound int, now func() time.Time) *store.ProductionObservationStore {
	t.Helper()
	production, err := store.NewProductionObservationStore(store.Limits{
		ObservationsPerScope: bound, QueryResults: bound, JoinRecords: bound,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return production
}

func mustScope(t *testing.T, tenantID, scopeID string) model.Scope {
	t.Helper()
	scope, err := model.NewScope(tenantID, scopeID, "saas-fixture", "us-fixture-1")
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

func mustGrant(t *testing.T, allowed bool, policyRef string) model.ModelUseGrant {
	t.Helper()
	if !allowed {
		policyRef = ""
	}
	grant, err := model.NewModelUseGrant(allowed, policyRef)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func recordIDs(observations []model.Observation) []string {
	ids := make([]string, 0, len(observations))
	for _, observation := range observations {
		ids = append(ids, observation.Envelope().RecordID())
	}
	return ids
}

func TestFixtureVocabularyIsStable(t *testing.T) {
	// Guard accidental introduction of unbounded/free-form fixture fields.
	contents, err := os.ReadFile("testdata/lifecycle_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(contents, &raw); err != nil {
		t.Fatal(err)
	}
	want := []string{"expected_put", "expires_at", "model_use_allowed", "name", "record_id", "scope_id", "state", "synthetic", "tenant_id"}
	for _, item := range raw {
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if !reflect.DeepEqual(keys, want) {
			t.Fatalf("fixture fields=%s want=%s", strings.Join(keys, ","), strings.Join(want, ","))
		}
	}
}
