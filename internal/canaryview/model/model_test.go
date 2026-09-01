package model

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	fixtureObserved       = time.Date(2026, 9, 1, 17, 1, 2, 300, time.UTC)
	fixtureRetentionStart = fixtureObserved
	fixtureExpiry         = fixtureRetentionStart.AddDate(0, 13, 0)
	fixtureIngested       = fixtureObserved.Add(2 * time.Second)
)

func TestObservationV2CompleteRoundTrip(t *testing.T) {
	observation := completeObservationFixture(t)
	blob, err := MarshalObservationV2(observation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalObservationV2(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, observation) {
		t.Fatalf("round trip changed observation:\n got: %#v\nwant: %#v\njson: %s", decoded, observation, blob)
	}

	for _, field := range []string{
		`"schema_version":2`, `"tenant_id":"tenant-a"`,
		`"basis":"SOURCE_REPORT"`,
		`"source_timestamp":"2026-09-01T17:01:01.0000003Z"`,
		`"data_class":"NORMALIZED_OBSERVATION"`, `"retention_profile":"STANDARD"`,
		`"retention_decision_ref":"retention/observation-1"`,
		`"retention_clock":"OBSERVED_TIME"`,
		`"legal_hold_ids":["hold-1"]`, `"residency_cell_id":"us-central-1"`,
		`"encryption_key_ref":"key://tenant-a/evidence"`,
		`"per_tenant_model_use":{"allowed":true,"policy_ref":"model-use/per-tenant-v1"}`,
		`"cross_tenant_model_use":{"allowed":false}`,
		`"derivation_lineage":[{"id":"raw-42","schema_version":2}]`,
		`"synthetic":true`, `"scenario_id":"scenario-7"`,
		`"role":"VENDOR_EXTENSION"`, `"extension_namespace":"hubble.io/v1"`,
	} {
		if !bytes.Contains(blob, []byte(field)) {
			t.Errorf("serialized observation missing %s: %s", field, blob)
		}
	}
	for _, prohibited := range []string{"payload", "request_body", "credential_value", "canary_secret"} {
		if bytes.Contains(bytes.ToLower(blob), []byte(prohibited)) {
			t.Errorf("serialized observation contains prohibited payload carrier %q: %s", prohibited, blob)
		}
	}
}

func TestObservationV2SupportsPartialSourceReports(t *testing.T) {
	observation := partialObservationFixture(t)
	blob, err := MarshalObservationV2(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"source_timestamp", "control", "subject", "object", "raw_event", "evidence", "scenario_id"} {
		if bytes.Contains(blob, []byte(`"`+absent+`":`)) {
			t.Errorf("optional field %q should be absent: %s", absent, blob)
		}
	}
	decoded, err := UnmarshalObservationV2(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, observation) {
		t.Fatalf("partial round trip changed observation:\n got: %#v\nwant: %#v", decoded, observation)
	}
	if _, ok := decoded.SourceTimestamp(); ok {
		t.Fatal("missing source timestamp was invented")
	}
	if _, ok := decoded.RawEvent(); ok {
		t.Fatal("missing raw reference was invented")
	}
}

func TestObservationV2AdditiveFieldsAndVersionGate(t *testing.T) {
	blob, err := MarshalObservationV2(partialObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	withFutureField := append(append([]byte(nil), blob[:len(blob)-1]...), []byte(`,"future_additive_field":{"value":1}}`)...)
	if _, err := UnmarshalObservationV2(withFutureField); err != nil {
		t.Fatalf("additive v2 field should be ignored: %v", err)
	}
	withoutBasis := bytes.Replace(blob, []byte(`"basis":"SOURCE_REPORT",`), nil, 1)
	if len(withoutBasis) == len(blob) {
		t.Fatalf("source-report basis not found in fixture: %s", blob)
	}
	if _, err := UnmarshalObservationV2(withoutBasis); err == nil || !strings.Contains(err.Error(), "source-report basis") {
		t.Fatalf("wire record without source-report basis was accepted: %v", err)
	}
	unsupported := bytes.Replace(blob, []byte(`"schema_version":2`), []byte(`"schema_version":3`), 1)
	if _, err := UnmarshalObservationV2(unsupported); err == nil || !strings.Contains(err.Error(), "unsupported schema version 3") {
		t.Fatalf("unsupported version was not rejected: %v", err)
	}
}

func TestObservationV1RequiresTrustedSourceReingestion(t *testing.T) {
	if _, err := MarshalObservationV1(partialObservationFixture(t)); !errors.Is(err, errObservationV1RequiresReingestion) {
		t.Fatalf("schema v1 marshal did not require re-ingestion: %v", err)
	}
	if _, err := UnmarshalObservationV1([]byte(`{"envelope":{"schema_version":1}}`)); !errors.Is(err, errObservationV1RequiresReingestion) {
		t.Fatalf("schema v1 unmarshal did not require re-ingestion: %v", err)
	}
}

func TestNormalizedObservationDefaultRetentionPeriods(t *testing.T) {
	lean := lifecycleInputFixture(t)
	lean.RetentionProfile = RetentionLean
	lean.PolicyVersion = "lean-v1"
	lean.RetentionDecisionRef = "retention/lean-observation-1"
	lean.ExpiresAt = lean.RetentionStart.AddDate(0, 6, 0)
	if _, err := NewLifecycle(lean); err != nil {
		t.Fatalf("Lean normalized-observation default was rejected: %v", err)
	}

	standard := lifecycleInputFixture(t)
	if _, err := NewLifecycle(standard); err != nil {
		t.Fatalf("Standard normalized-observation default was rejected: %v", err)
	}
}

func TestRequiredScopeSourceAndLifecycleFailClosed(t *testing.T) {
	if _, err := NewScope("", "scope-a", "saas", "us-central-1"); err == nil {
		t.Fatal("empty tenant was accepted")
	}
	if _, err := NewScope("tenant-a", "", "saas", "us-central-1"); err == nil {
		t.Fatal("empty scope was accepted")
	}
	if _, err := NewSourceIdentity("", "source-1"); err == nil {
		t.Fatal("empty source system was accepted")
	}
	if _, err := NewCollectorIdentity("collector", ""); err == nil {
		t.Fatal("empty collector version was accepted")
	}

	base := lifecycleInputFixture(t)
	tests := []struct {
		name   string
		mutate func(*LifecycleInput)
	}{
		{name: "missing expiry", mutate: func(in *LifecycleInput) { in.ExpiresAt = time.Time{} }},
		{name: "expiry before start", mutate: func(in *LifecycleInput) { in.ExpiresAt = in.RetentionStart.Add(-time.Second) }},
		{name: "missing key", mutate: func(in *LifecycleInput) { in.EncryptionKeyRef = "" }},
		{name: "missing residency policy", mutate: func(in *LifecycleInput) { in.ResidencyPolicyRef = "" }},
		{name: "missing operational policy", mutate: func(in *LifecycleInput) { in.OperationalPolicyRef = "" }},
		{name: "missing retention decision", mutate: func(in *LifecycleInput) { in.RetentionDecisionRef = "" }},
		{name: "missing retention clock", mutate: func(in *LifecycleInput) { in.RetentionClock = "" }},
		{name: "wrong standard period", mutate: func(in *LifecycleInput) { in.ExpiresAt = in.RetentionStart.Add(time.Second) }},
		{name: "missing estimate", mutate: func(in *LifecycleInput) { in.EstimatedStorageImpact = StorageEstimate{} }},
		{name: "override version without override profile", mutate: func(in *LifecycleInput) { in.OverrideVersion = "override-v1" }},
		{name: "held without hold", mutate: func(in *LifecycleInput) { in.State = LifecycleHeld }},
		{name: "hold without held state", mutate: func(in *LifecycleInput) { in.LegalHoldIDs = []string{"hold-1"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			if _, err := NewLifecycle(input); err == nil {
				t.Fatal("invalid lifecycle was accepted")
			}
		})
	}
}

func TestHoldDoesNotGrantModelUse(t *testing.T) {
	input := lifecycleInputFixture(t)
	input.State = LifecycleHeld
	input.LegalHoldIDs = []string{"hold-z", "hold-a"}
	lifecycle, err := NewLifecycle(input)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.PerTenantModelUse().Allowed() || lifecycle.CrossTenantModelUse().Allowed() {
		t.Fatal("legal hold changed model-use authorization")
	}
	wantHolds := []string{"hold-a", "hold-z"}
	if got := lifecycle.LegalHoldIDs(); !reflect.DeepEqual(got, wantHolds) {
		t.Fatalf("holds=%v want=%v", got, wantHolds)
	}
	if !lifecycle.ExpiresAt().Equal(fixtureExpiry.UTC()) {
		t.Fatal("hold rewrote original expiry")
	}
	if _, err := NewModelUseGrant(true, ""); err == nil {
		t.Fatal("model use was authorized without a policy reference")
	}
}

func TestSyntheticContextRequiresScenario(t *testing.T) {
	if _, err := NewSyntheticContext(""); err == nil {
		t.Fatal("synthetic context without scenario was accepted")
	}
	production := ProductionContext()
	if production.Synthetic() || production.ScenarioID() != "" {
		t.Fatal("explicit production context changed")
	}
	if _, err := NewEnvelope(EnvelopeInput{
		RecordID: "unclassified", SchemaVersion: CurrentSchemaVersion,
		Scope: mustScope(t), Lifecycle: mustLifecycle(t, lifecycleInputFixture(t)),
	}); err == nil {
		t.Fatal("unclassified envelope silently became production")
	}

	blob, err := MarshalObservationV2(partialObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	withoutClassification := bytes.Replace(blob, []byte(`,"synthetic":false`), nil, 1)
	if len(withoutClassification) == len(blob) {
		t.Fatalf("synthetic classification not found in fixture: %s", blob)
	}
	if _, err := UnmarshalObservationV2(withoutClassification); err == nil || !strings.Contains(err.Error(), "classification is required") {
		t.Fatalf("wire record without synthetic classification was accepted: %v", err)
	}
}

func TestVendorExtensionsRemainEvidenceReferences(t *testing.T) {
	if _, err := NewEvidenceReference("evidence-1", CurrentSchemaVersion, EvidenceVendorExtension, "", "v1"); err == nil {
		t.Fatal("vendor extension without namespace was accepted")
	}
	if _, err := NewEvidenceReference("evidence-1", CurrentSchemaVersion, EvidenceSupporting, "vendor", "v1"); err == nil {
		t.Fatal("canonical supporting evidence accepted vendor-extension metadata")
	}
	if _, err := NewEvidenceReference("evidence-1", 0, EvidenceSupporting, "", ""); err == nil {
		t.Fatal("unversioned evidence reference was accepted")
	}
	ref, err := NewEvidenceReference("evidence-1", CurrentSchemaVersion, EvidenceVendorExtension, "vendor.example/v1", "1.2")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Role() != EvidenceVendorExtension || ref.ExtensionNamespace() != "vendor.example/v1" {
		t.Fatalf("vendor evidence reference changed: %+v", ref)
	}
}

func TestObservationContractHasNoPayloadCarrier(t *testing.T) {
	prohibitedNames := []string{"payload", "body", "secret", "credential", "token", "authorization"}
	for _, value := range []any{RawEventReference{}, EvidenceReference{}, rawEventReferenceV2{}, evidenceReferenceV2{}, ObservationInput{}, observationV2{}} {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			field := typeOf.Field(i)
			lowerName := strings.ToLower(field.Name)
			for _, prohibited := range prohibitedNames {
				if strings.Contains(lowerName, prohibited) {
					t.Errorf("%s.%s is a prohibited raw-data carrier", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Map ||
				(field.Type.Kind() == reflect.Slice && (field.Type.Elem().Kind() == reflect.Uint8 || field.Type.Elem().Kind() == reflect.String)) {
				t.Errorf("%s.%s can carry unbounded raw content", typeOf.Name(), field.Name)
			}
		}
	}

	for _, reference := range []string{
		"data:text/plain,Authorization:Bearer-SECRET",
		"https://user:secret@example.test/events/42",
		"https://example.test/events/42?token=secret",
		"source://events/Authorization: Bearer SECRET",
		"source:AuthorizationBearerTOPSECRET",
		"source://events/Authorization%3A%20Bearer%20TOPSECRET",
	} {
		if _, err := NewRawEventReference(reference, RawAvailable, "", ""); err == nil {
			t.Errorf("unsafe raw event reference was accepted: %q", reference)
		}
	}
	if _, err := NewRawEventReference("rawref:sha256:"+strings.Repeat("1", 64), RawAvailable, "sha256", "TOPSECRET"); err == nil {
		t.Fatal("non-digest raw event hash value was accepted")
	}

	blob, err := MarshalObservationV2(partialObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	legacyDiagnostic := append(append([]byte(nil), blob[:len(blob)-1]...), []byte(`,"parser_warnings":["Authorization: Bearer TOPSECRET"]}`)...)
	decoded, err := UnmarshalObservationV2(legacyDiagnostic)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalObservationV2(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(reencoded, []byte("TOPSECRET")) || bytes.Contains(reencoded, []byte("parser_warnings")) {
		t.Fatalf("ignored free-form diagnostic survived canonical serialization: %s", reencoded)
	}
}

func TestObservationRequiresSourceReportAndTrustedRetentionClock(t *testing.T) {
	base := ObservationInput{
		Envelope: mustEnvelope(t, mustLifecycle(t, lifecycleInputFixture(t)), nil, ProductionContext()),
		Basis:    ObservationSourceReport, ObservationType: "network.flow",
		Source: mustSource(t), Collector: mustCollector(t),
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
	}

	invalidBasis := base
	invalidBasis.Basis = ObservationBasis("DERIVED")
	if _, err := NewObservation(invalidBasis); err == nil {
		t.Fatal("derived basis was accepted as an Observation")
	}

	beforeObserved := base
	beforeObserved.IngestedAt = fixtureObserved.Add(-time.Second)
	if _, err := NewObservation(beforeObserved); err == nil {
		t.Fatal("ingest time before observed time was accepted")
	}

	wrongClock := lifecycleInputFixture(t)
	wrongClock.RetentionProfile = RetentionOverride
	wrongClock.OverrideVersion = "override-v1"
	wrongClock.RetentionDecisionRef = "retention/override-1"
	wrongClock.RetentionStart = fixtureObserved.Add(time.Hour)
	wrongClock.ExpiresAt = wrongClock.RetentionStart.Add(24 * time.Hour)
	wrongClockObservation := base
	wrongClockObservation.Envelope = mustEnvelope(t, mustLifecycle(t, wrongClock), nil, ProductionContext())
	if _, err := NewObservation(wrongClockObservation); err == nil {
		t.Fatal("retention start unrelated to trusted observation clock was accepted")
	}

	ingestFallback := lifecycleInputFixture(t)
	ingestFallback.RetentionClock = RetentionFromIngest
	ingestFallback.RetentionStart = fixtureIngested
	ingestFallback.ExpiresAt = fixtureIngested.AddDate(0, 13, 0)
	fallbackObservation := base
	fallbackObservation.Envelope = mustEnvelope(t, mustLifecycle(t, ingestFallback), nil, ProductionContext())
	if _, err := NewObservation(fallbackObservation); err != nil {
		t.Fatalf("recorded ingest fallback was rejected: %v", err)
	}
}

func TestObservationIsImmutableFromCallerValues(t *testing.T) {
	lineage := []RecordReference{mustRecordRef(t, "raw-1")}
	holds := []string{"hold-1"}
	evidence := []EvidenceReference{mustEvidenceRef(t, "evidence-1", EvidenceSupporting, "", "")}
	control := mustControl(t)
	sourceTimestamp := fixtureObserved.Add(-time.Second)

	lifecycleInput := lifecycleInputFixture(t)
	lifecycleInput.State = LifecycleHeld
	lifecycleInput.LegalHoldIDs = holds
	lifecycle := mustLifecycle(t, lifecycleInput)
	envelope := mustEnvelope(t, lifecycle, lineage, ProductionContext())
	observation, err := NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport,
		ObservationType: "network.flow", Source: mustSource(t),
		Collector: mustCollector(t), Control: &control, SourceTimestamp: &sourceTimestamp,
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
		Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}

	lineage[0] = mustRecordRef(t, "changed")
	holds[0] = "changed"
	evidence[0] = mustEvidenceRef(t, "changed", EvidenceSupporting, "", "")
	control.id = "changed"
	sourceTimestamp = time.Time{}

	gotEvidence := observation.Evidence()
	gotEvidence[0] = mustEvidenceRef(t, "changed-again", EvidenceSupporting, "", "")
	gotLineage := observation.Envelope().DerivationLineage()
	gotLineage[0] = mustRecordRef(t, "changed-again")
	gotHolds := observation.Envelope().Lifecycle().LegalHoldIDs()
	gotHolds[0] = "changed-again"

	if got := observation.Evidence()[0].ID(); got != "evidence-1" {
		t.Fatalf("evidence mutated through caller/getter: %q", got)
	}
	if got := observation.Envelope().DerivationLineage()[0].ID(); got != "raw-1" {
		t.Fatalf("lineage mutated through caller/getter: %q", got)
	}
	if got := observation.Envelope().Lifecycle().LegalHoldIDs()[0]; got != "hold-1" {
		t.Fatalf("hold mutated through caller/getter: %q", got)
	}
	if got, _ := observation.Control(); got.ID() != "control-1" {
		t.Fatalf("control mutated through caller pointer: %q", got.ID())
	}
	if got, _ := observation.SourceTimestamp(); !got.Equal(fixtureObserved.Add(-time.Second).UTC()) {
		t.Fatalf("source timestamp mutated through caller pointer: %v", got)
	}
}

func completeObservationFixture(t *testing.T) Observation {
	t.Helper()
	perTenant, err := NewModelUseGrant(true, "model-use/per-tenant-v1")
	if err != nil {
		t.Fatal(err)
	}
	lifecycleInput := lifecycleInputFixture(t)
	lifecycleInput.State = LifecycleHeld
	lifecycleInput.LegalHoldIDs = []string{"hold-1"}
	lifecycleInput.PerTenantModelUse = perTenant
	lifecycle := mustLifecycle(t, lifecycleInput)
	synthetic, err := NewSyntheticContext("scenario-7")
	if err != nil {
		t.Fatal(err)
	}
	envelope := mustEnvelope(t, lifecycle, []RecordReference{mustRecordRef(t, "raw-42")}, synthetic)
	control := mustControl(t)
	subject := mustEntity(t, "workload-a", "WORKLOAD")
	object := mustEntity(t, "service-b", "SERVICE")
	raw, err := NewRawEventReference("rawref:sha256:"+strings.Repeat("1", 64), RawAvailable, "sha256", strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	sourceTimestamp := time.Date(2026, 9, 1, 17, 1, 1, 300, time.UTC)
	observation, err := NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport,
		ObservationType: "network.flow", Source: mustSource(t),
		Collector: mustCollector(t), Control: &control, SourceTimestamp: &sourceTimestamp,
		ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
		Subject: &subject, Object: &object, RawEvent: &raw,
		Evidence: []EvidenceReference{
			mustEvidenceRef(t, "evidence-1", EvidenceSupporting, "", ""),
			mustEvidenceRef(t, "evidence-vendor", EvidenceVendorExtension, "hubble.io/v1", "1.0"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func partialObservationFixture(t *testing.T) Observation {
	t.Helper()
	lifecycle := mustLifecycle(t, lifecycleInputFixture(t))
	envelope := mustEnvelope(t, lifecycle, nil, ProductionContext())
	observation, err := NewObservation(ObservationInput{
		Envelope: envelope, Basis: ObservationSourceReport,
		ObservationType: "policy.decision", Source: mustSource(t),
		Collector: mustCollector(t), ObservedTimestamp: fixtureObserved, IngestedAt: fixtureIngested,
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func lifecycleInputFixture(t *testing.T) LifecycleInput {
	t.Helper()
	estimate, err := NewStorageEstimate(768, EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	return LifecycleInput{
		DataClass: DataClassNormalizedObservation, Sensitivity: SensitivityConfidential,
		RetentionProfile: RetentionStandard, PolicyVersion: "standard-v1",
		RetentionDecisionRef: "retention/observation-1", RetentionClock: RetentionFromObserved,
		RetentionStart: fixtureRetentionStart, ExpiresAt: fixtureExpiry, State: LifecycleActive,
		ResidencyPolicyRef: "residency/us-central-v1", EncryptionKeyRef: "key://tenant-a/evidence",
		OperationalPolicyRef:   "processing/normalize-v1",
		EstimatedStorageImpact: estimate,
	}
}

func mustLifecycle(t *testing.T, input LifecycleInput) Lifecycle {
	t.Helper()
	lifecycle, err := NewLifecycle(input)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func mustEnvelope(t *testing.T, lifecycle Lifecycle, lineage []RecordReference, synthetic SyntheticContext) Envelope {
	t.Helper()
	scope := mustScope(t)
	envelope, err := NewEnvelope(EnvelopeInput{
		RecordID: "observation-1", SchemaVersion: CurrentSchemaVersion,
		Scope: scope, Lifecycle: lifecycle, DerivationLineage: lineage, Synthetic: synthetic,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func mustScope(t *testing.T) Scope {
	t.Helper()
	scope, err := NewScope("tenant-a", "scope-a", "saas", "us-central-1")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustRecordRef(t *testing.T, id string) RecordReference {
	t.Helper()
	ref, err := NewRecordReference(id, CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func mustEvidenceRef(t *testing.T, id string, role EvidenceRole, namespace, version string) EvidenceReference {
	t.Helper()
	ref, err := NewEvidenceReference(id, CurrentSchemaVersion, role, namespace, version)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func mustSource(t *testing.T) SourceIdentity {
	t.Helper()
	source, err := NewSourceIdentity("cilium-hubble", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func mustCollector(t *testing.T) CollectorIdentity {
	t.Helper()
	collector, err := NewCollectorIdentity("hubble-reader", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func mustControl(t *testing.T) ControlIdentity {
	t.Helper()
	control, err := NewControlIdentity("control-1", "NETWORK_POLICY")
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func mustEntity(t *testing.T, id, kind string) EntityReference {
	t.Helper()
	entity, err := NewEntityReference(id, kind)
	if err != nil {
		t.Fatal(err)
	}
	return entity
}
