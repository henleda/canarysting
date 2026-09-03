package dgxstack_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/adapters/envoy"
	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/canaryview/collector/dgxstack"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	canaryviewstore "github.com/canarysting/canarysting/internal/canaryview/store"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
)

func TestEveryReferenceStackSourceEmitsScopedLifecycleObservation(t *testing.T) {
	normalizer, scope := newNormalizer(t, "scope-a", byte(0x41))
	observedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	sourceTime := observedAt.Add(-time.Second)

	var src4, dst4 [16]byte
	copy(src4[:], []byte{10, 42, 0, 9})
	copy(dst4[:], []byte{10, 42, 0, 10})
	kubernetesObject := metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID("customer-pod-uid"), Name: "customer-api", Namespace: "customer-prod",
			Labels:            map[string]string{"secret-label": "do-not-retain"},
			CreationTimestamp: metav1.NewTime(sourceTime),
		},
	}

	builders := []struct {
		kind dgxstack.SourceKind
		make func(dgxstack.Context) (model.Observation, error)
	}{
		{dgxstack.SourceCanarySting, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeCanaryStingInteraction(ctx, intelligence.AdversaryInteractionEvent{
				ScopeKey: "scope-a", FlowID: 777, CanaryType: "fake-secret", Timestamp: sourceTime,
				Tier: 3, Verdict: "jail", Features: map[string]float64{"private-feature": 1.2},
			})
		}},
		{dgxstack.SourceEngine, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeObservedTopologyEdge(ctx, observebaseline.TopoEdgeView{
				SrcIP: src4[:4], DstIP: dst4[:4], DstPort: 8443, Family: observe.AFInet,
				FlowCount: 4, TotalBytes: 1000, TotalPkts: 10, FirstSeen: sourceTime.Add(-time.Minute), LastSeen: sourceTime,
			})
		}},
		{dgxstack.SourceKernel, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeKernelFlow(ctx, 777, observe.FlowStats{
				IngressPackets: 2, IngressBytes: 50, EgressPackets: 3, EgressBytes: 75,
				FirstSeenNs: 100, LastSeenNs: 200, Family: observe.AFInet,
				SrcPort: 40000, DstPort: 8443, Closed: 1, SrcIP: src4, DstIP: dst4,
			})
		}},
		{dgxstack.SourceEnvoy, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeEnvoyRequest(ctx, 777, envoy.RequestObservation{
				Method: "POST", Path: "/private?token=super-secret",
				Headers: map[string]string{"authorization": "Bearer do-not-retain", "user-agent": "private-agent"},
			}, &sourceTime)
		}},
		{dgxstack.SourceKubernetes, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeKubernetesObject(ctx, kubernetesObject)
		}},
		{dgxstack.SourceCilium, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeCiliumEndpoint(ctx, dgxstack.CiliumEndpointReport{
				EndpointID: 321, IdentityID: 456, ObservedAt: sourceTime,
			})
		}},
		{dgxstack.SourceHubble, func(ctx dgxstack.Context) (model.Observation, error) {
			return normalizer.NormalizeHubbleFlow(ctx, dgxstack.HubbleFlowReport{
				FlowID: "flow-1", SourceIdentity: 456, DestinationIdentity: 789,
				Verdict: "FORWARDED", Timestamp: sourceTime,
			})
		}},
	}

	if got := dgxstack.SourceKinds(); !reflect.DeepEqual(got, []dgxstack.SourceKind{
		dgxstack.SourceCanarySting, dgxstack.SourceEngine, dgxstack.SourceKernel,
		dgxstack.SourceEnvoy, dgxstack.SourceKubernetes, dgxstack.SourceCilium, dgxstack.SourceHubble,
	}) {
		t.Fatalf("source catalog = %v", got)
	}

	observations := make([]model.Observation, 0, len(builders))
	for index, builder := range builders {
		ctx := eventContext(observedAt, "event-"+string(builder.kind))
		observation, err := builder.make(ctx)
		if err != nil {
			t.Fatalf("normalize %s: %v", builder.kind, err)
		}
		observations = append(observations, observation)
		if observation.Source().System() != string(builder.kind) {
			t.Errorf("source %d system = %q", index, observation.Source().System())
		}
		if got := observation.Envelope().Scope(); got.TenantID() != scope.TenantID() ||
			got.ScopeID() != scope.ScopeID() || got.DeploymentBoundary() != scope.DeploymentBoundary() ||
			got.ResidencyCellID() != scope.ResidencyCellID() {
			t.Errorf("source %s scope changed: %+v", builder.kind, got)
		}
		lifecycle := observation.Envelope().Lifecycle()
		if lifecycle.DataClass() != model.DataClassNormalizedObservation ||
			lifecycle.RetentionProfile() != model.RetentionOverride ||
			!lifecycle.RetentionStart().Equal(observedAt) ||
			!lifecycle.ExpiresAt().Equal(observedAt.Add(24*time.Hour)) ||
			lifecycle.PerTenantModelUse().Allowed() || lifecycle.CrossTenantModelUse().Allowed() {
			t.Errorf("source %s lifecycle is not the explicit 24h/default-off policy", builder.kind)
		}
		if !observation.Envelope().Synthetic().Synthetic() || observation.Envelope().Synthetic().ScenarioID() != "scenario-m2b2" {
			t.Errorf("source %s lost synthetic classification", builder.kind)
		}
		raw, ok := observation.RawEvent()
		if !ok || raw.Availability() != model.RawDeleted || raw.HashAlgorithm() != "sha256" || raw.HashValue() != digest("raw-content") {
			t.Errorf("source %s raw reference/checksum = %+v, %v", builder.kind, raw, ok)
		}
		if len(observation.Envelope().DerivationLineage()) != 1 || len(observation.Evidence()) != 1 ||
			len(observation.Knowledge().Provenance().Inputs()) != 1 {
			t.Errorf("source %s lacks single-source provenance", builder.kind)
		}
		if observation.Knowledge().State() != model.KnowledgeSourceObservation ||
			observation.Knowledge().Confidence().Completeness() != model.EvidencePartial {
			t.Errorf("source %s is not an explicit partial source observation", builder.kind)
		}
		blob, err := model.MarshalObservationV3(observation)
		if err != nil {
			t.Fatalf("marshal %s: %v", builder.kind, err)
		}
		for _, prohibited := range []string{
			"super-secret", "Bearer do-not-retain", "private-agent", "customer-api",
			"customer-prod", "secret-label", "do-not-retain", "customer-pod-uid",
			"10.42.0.9", "10.42.0.10", "private-feature", "fake-secret",
		} {
			if strings.Contains(string(blob), prohibited) {
				t.Errorf("source %s retained prohibited raw value %q", builder.kind, prohibited)
			}
		}
	}

	summary, err := dgxstack.Measure(observations)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Records != len(builders) || summary.TotalBytes == 0 || summary.MinBytes == 0 || summary.MaxBytes < summary.MinBytes {
		t.Fatalf("invalid size summary: %+v", summary)
	}
}

func TestSocketCookieIsTheOnlyCrossLayerJoin(t *testing.T) {
	normalizer, _ := newNormalizer(t, "scope-a", byte(0x52))
	now := time.Date(2026, 9, 2, 14, 0, 0, 0, time.UTC)
	ctx := eventContext(now, "cookie-join")
	canary, err := normalizer.NormalizeCanaryStingInteraction(ctx, intelligence.AdversaryInteractionEvent{
		ScopeKey: "scope-a", FlowID: 0xC0FFEE, CanaryType: "route", Timestamp: now, Verdict: "observe",
	})
	if err != nil {
		t.Fatal(err)
	}
	var src, dst [16]byte
	copy(src[:], []byte{192, 0, 2, 1})
	copy(dst[:], []byte{192, 0, 2, 2})
	kernel, err := normalizer.NormalizeKernelFlow(ctx, 0xC0FFEE, observe.FlowStats{
		Family: observe.AFInet, SrcIP: src, DstIP: dst, DstPort: 443, FirstSeenNs: 1, LastSeenNs: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	envoyObservation, err := normalizer.NormalizeEnvoyRequest(ctx, 0xC0FFEE, envoy.RequestObservation{Path: "/x"}, &now)
	if err != nil {
		t.Fatal(err)
	}

	canarySubject, _ := canary.Subject()
	kernelSubject, _ := kernel.Subject()
	envoySubject, _ := envoyObservation.Subject()
	if canarySubject.ID() != kernelSubject.ID() || canarySubject.ID() != envoySubject.ID() {
		t.Fatalf("same socket cookie did not produce one join: %q %q %q", canarySubject.ID(), kernelSubject.ID(), envoySubject.ID())
	}
	if !strings.HasPrefix(canarySubject.ID(), "SOCKET_COOKIE:hmac-sha256:") {
		t.Fatalf("socket join is not a pseudonymized cookie identity: %q", canarySubject.ID())
	}

	partial, err := normalizer.NormalizeEnvoyRequest(ctx, 0, envoy.RequestObservation{Path: "/x"}, &now)
	if err != nil {
		t.Fatalf("unattributed Envoy request should remain a partial observation: %v", err)
	}
	if _, ok := partial.Subject(); ok {
		t.Fatal("unattributed Envoy request invented a join subject")
	}
	if !containsMissing(partial, model.MissingSubjectIdentity) {
		t.Fatal("unattributed Envoy request did not name missing subject identity")
	}
}

func TestScopeAndPseudonymizationFailClosed(t *testing.T) {
	normalizerA, _ := newNormalizer(t, "scope-a", byte(0x61))
	normalizerB, _ := newNormalizer(t, "scope-b", byte(0x62))
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	ctx := eventContext(now, "scope-test")

	if _, err := normalizerA.NormalizeCanaryStingInteraction(ctx, intelligence.AdversaryInteractionEvent{
		ScopeKey: "scope-b", FlowID: 99, CanaryType: "route", Timestamp: now,
	}); err == nil {
		t.Fatal("cross-scope CanarySting event was accepted")
	}
	left, err := normalizerA.NormalizeEnvoyRequest(ctx, 99, envoy.RequestObservation{Path: "/same"}, &now)
	if err != nil {
		t.Fatal(err)
	}
	right, err := normalizerB.NormalizeEnvoyRequest(ctx, 99, envoy.RequestObservation{Path: "/same"}, &now)
	if err != nil {
		t.Fatal(err)
	}
	leftSubject, _ := left.Subject()
	rightSubject, _ := right.Subject()
	if leftSubject.ID() == rightSubject.ID() {
		t.Fatal("scope-specific pseudonymization produced a cross-scope join")
	}
}

func TestSourceIdentityIsIdempotentAndBindsImmutableAttributes(t *testing.T) {
	normalizer, _ := newNormalizer(t, "scope-a", byte(0x68))
	now := time.Date(2026, 9, 2, 15, 30, 0, 0, time.UTC)
	ctx := eventContext(now, "native-event-id")
	first, err := normalizer.NormalizeEnvoyRequest(ctx, 55, envoy.RequestObservation{Method: "GET", Path: "/one"}, &now)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := normalizer.NormalizeEnvoyRequest(ctx, 55, envoy.RequestObservation{Method: "GET", Path: "/one"}, &now)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := normalizer.NormalizeEnvoyRequest(ctx, 55, envoy.RequestObservation{Method: "GET", Path: "/two"}, &now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Envelope().RecordID() != repeated.Envelope().RecordID() {
		t.Fatal("identical source report did not produce an idempotent record ID")
	}
	if first.Envelope().RecordID() == changed.Envelope().RecordID() {
		t.Fatal("changed immutable source attributes reused a record ID")
	}
	firstSubject, _ := first.Subject()
	changedSubject, _ := changed.Subject()
	if firstSubject.ID() != changedSubject.ID() {
		t.Fatal("same socket cookie did not retain the same join identity across requests")
	}
}

func TestNormalizerRejectsUnsafePolicyAndEvidence(t *testing.T) {
	scope, err := model.NewScope("tenant", "scope", "deployment", "residency")
	if err != nil {
		t.Fatal(err)
	}
	base := dgxstack.Policy{
		Scope: scope, RetentionProfile: model.RetentionStandard,
		PolicyVersion: "policy-v1", RetentionDecisionRef: "decision-v1",
		ResidencyPolicyRef: "residency-v1", EncryptionKeyRef: "key-v1",
		OperationalPolicyRef: "operations-v1", EstimatedBytes: 4096,
		EstimatedBytesBasis: model.EstimateAssumed, PseudonymizationKey: make([]byte, 32),
	}
	for name, mutate := range map[string]func(*dgxstack.Policy){
		"short key":      func(p *dgxstack.Policy) { p.PseudonymizationKey = []byte("short") },
		"unbounded text": func(p *dgxstack.Policy) { p.EncryptionKeyRef = strings.Repeat("x", 513) },
		"implicit override": func(p *dgxstack.Policy) {
			p.RetentionProfile = model.RetentionOverride
			p.RetentionDuration = time.Hour
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := base
			mutate(&policy)
			if _, err := dgxstack.NewNormalizer(policy); err == nil {
				t.Fatal("unsafe policy was accepted")
			}
		})
	}

	normalizer, _ := newNormalizer(t, "scope-a", byte(0x73))
	ctx := eventContext(time.Now().UTC(), "bad-digest")
	ctx.Raw.ContentSHA256 = "ABC"
	if _, err := normalizer.NormalizeInventory(ctx, dgxstack.SourceKernel, ctx.ObservedAt); err == nil {
		t.Fatal("malformed content digest was accepted")
	}
	if _, err := normalizer.NormalizeInventory(eventContext(ctx.ObservedAt, "unknown"), dgxstack.SourceKind("unknown"), ctx.ObservedAt); err == nil {
		t.Fatal("unknown source kind was accepted")
	}
}

func TestHubbleProofDTOCannotCarryPayloadOrSocketCookie(t *testing.T) {
	typeOf := reflect.TypeOf(dgxstack.HubbleFlowReport{})
	for _, name := range []string{"Payload", "Body", "Headers", "Token", "SocketCookie"} {
		if _, found := typeOf.FieldByName(name); found {
			t.Fatalf("Hubble proof DTO unexpectedly carries %s", name)
		}
	}
}

func TestSyntheticDGXObservationIsRejectedFromProductionStore(t *testing.T) {
	normalizer, _ := newNormalizer(t, "scope-a", byte(0x7a))
	now := time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC)
	observation, err := normalizer.NormalizeInventory(eventContext(now, "lab-inventory"), dgxstack.SourceKubernetes, now)
	if err != nil {
		t.Fatal(err)
	}
	production, err := canaryviewstore.NewProductionObservationStore(canaryviewstore.Limits{
		ObservationsPerScope: 10, QueryResults: 10, JoinRecords: 10,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := production.Put(observation); !errors.Is(err, canaryviewstore.ErrSynthetic) {
		t.Fatalf("production store accepted synthetic DGX evidence: %v", err)
	}
}

func newNormalizer(t *testing.T, scopeID string, keyByte byte) (*dgxstack.Normalizer, model.Scope) {
	t.Helper()
	scope, err := model.NewScope("internal-lab", scopeID, "dgx-spark", "dgx-local")
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := dgxstack.NewNormalizer(dgxstack.Policy{
		Scope: scope, RetentionProfile: model.RetentionOverride, RetentionDuration: 24 * time.Hour,
		PolicyVersion: "dgx-validation-v1", RetentionDecisionRef: "dgx-validation-24h",
		OverrideVersion: "dgx-validation-24h-v1", ResidencyPolicyRef: "dgx-local-only",
		EncryptionKeyRef: "operator-managed-dgx-filesystem", OperationalPolicyRef: "m2b2-read-only-proof",
		EstimatedBytes: 4096, EstimatedBytesBasis: model.EstimateAssumed,
		PseudonymizationKey: bytesOf(keyByte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return normalizer, scope
}

func eventContext(observedAt time.Time, eventKey string) dgxstack.Context {
	synthetic, err := model.NewSyntheticContext("scenario-m2b2")
	if err != nil {
		panic(err)
	}
	return dgxstack.Context{
		SourceInstance: "dgx-lab", EventKey: eventKey,
		ObservedAt: observedAt, IngestedAt: observedAt.Add(time.Second), Synthetic: synthetic,
		Raw: dgxstack.RawEvidence{
			ReferenceSHA256: digest("raw-reference"), ContentSHA256: digest("raw-content"),
			Availability: model.RawDeleted,
		},
	}
}

func containsMissing(observation model.Observation, value model.MissingEvidenceKind) bool {
	for _, candidate := range observation.Knowledge().MissingEvidence() {
		if candidate == value {
			return true
		}
	}
	return false
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
