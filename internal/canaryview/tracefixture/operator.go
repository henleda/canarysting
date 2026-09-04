// Package tracefixture builds minimized, synthetic correlated traces for
// operator-experience and DGX validation. It is laboratory-only: callers must
// opt into the synthetic scenario, and no customer identifiers or payloads are
// accepted or retained.
package tracefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

const ScenarioID = "m2b5-operator-conflict"

var fixtureTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// OperatorConflict returns the fixed M2B.5 partial/conflicted fixture. The
// trace is synthetic, immutable, scope-bound, and contains references only.
func OperatorConflict() (trace.Trace, error) {
	scope, err := model.NewScope("internal-lab", "operator-workspace", "fixture", "lab-local")
	if err != nil {
		return trace.Trace{}, err
	}
	synthetic, err := model.NewSyntheticContext(ScenarioID)
	if err != nil {
		return trace.Trace{}, err
	}

	checkout, err := model.NewEntityReference("checkout-api", "APPLICATION")
	if err != nil {
		return trace.Trace{}, err
	}
	payments, err := model.NewEntityReference("payments", "SERVICE")
	if err != nil {
		return trace.Trace{}, err
	}
	requestID, err := correlation.NewOpaqueID("fixture.gateway.request", digest("request"))
	if err != nil {
		return trace.Trace{}, err
	}

	anchor, err := record("gateway-request", scope, synthetic, fixtureTime, 250*time.Millisecond, []model.EntityReference{checkout}, requestID)
	if err != nil {
		return trace.Trace{}, err
	}
	allow, err := record("cilium-policy-allow", scope, synthetic, fixtureTime.Add(time.Second), 0, []model.EntityReference{payments}, requestID)
	if err != nil {
		return trace.Trace{}, err
	}
	deny, err := record("mesh-policy-deny", scope, synthetic, fixtureTime.Add(2*time.Second), 0, []model.EntityReference{payments}, requestID)
	if err != nil {
		return trace.Trace{}, err
	}

	engine, err := correlation.NewEngine(correlation.DefaultConfig())
	if err != nil {
		return trace.Trace{}, err
	}
	result, err := engine.Correlate(anchor, []correlation.Record{deny, allow}, nil)
	if err != nil {
		return trace.Trace{}, err
	}

	raw, err := model.NewRawEventReference(
		"rawref:sha256:"+digest("gateway-raw-reference"),
		model.RawIntegrityMismatch,
		"sha256",
		digest("gateway-raw-integrity"),
	)
	if err != nil {
		return trace.Trace{}, err
	}
	gatewayEvidence, err := model.NewEvidenceReference("evidence-gateway-summary", model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		return trace.Trace{}, err
	}
	// Reuse the same canonical evidence ID in supporting and contradicting
	// contexts. The projection must preserve both roles rather than deduplicating
	// by ID and hiding the contradiction from the operator.
	allowEvidence, err := model.NewEvidenceReference("evidence-policy-conflict", model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		return trace.Trace{}, err
	}
	denyEvidence, err := model.NewEvidenceReference("evidence-mesh-policy", model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		return trace.Trace{}, err
	}
	conflictEvidence, err := model.NewEvidenceReference("evidence-policy-conflict", model.CurrentSchemaVersion, model.EvidenceContradicting, "", "")
	if err != nil {
		return trace.Trace{}, err
	}

	closedAt := fixtureTime.Add(time.Minute)
	lifecycle, err := lifecycle(closedAt)
	if err != nil {
		return trace.Trace{}, err
	}
	highWater, err := reference("operator-fixture-high-water")
	if err != nil {
		return trace.Trace{}, err
	}
	anchorRef := anchor.Reference()
	builder, err := trace.NewBuilder(trace.DefaultBuilderConfig())
	if err != nil {
		return trace.Trace{}, err
	}
	return builder.Build(trace.BuildInput{
		Scope: scope,
		Hops: []trace.HopInput{
			{Record: deny, Kind: trace.HopPolicyDecision, Evidence: []model.EvidenceReference{denyEvidence}},
			{Record: anchor, Kind: trace.HopObservation, RawEvent: &raw, Evidence: []model.EvidenceReference{gatewayEvidence}},
			{Record: allow, Kind: trace.HopPolicyDecision, Evidence: []model.EvidenceReference{allowEvidence}},
		},
		Correlations: []correlation.Result{result},
		Expectations: []trace.ExpectationInput{
			{Kind: trace.ExpectObservation},
			{Kind: trace.ExpectPolicyDecision},
			{Kind: trace.ExpectCorrelation},
			{Kind: trace.ExpectRawEvidence, Record: &anchorRef},
		},
		Conflicts: []trace.ConflictInput{{
			Kind:     trace.ConflictContradictoryEvidence,
			Records:  []model.RecordReference{allow.Reference(), deny.Reference()},
			Evidence: []model.EvidenceReference{conflictEvidence},
		}},
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute), HighWaterMark: highWater,
		Lifecycle: lifecycle, Synthetic: synthetic,
	})
}

func record(id string, scope model.Scope, synthetic model.SyntheticContext, at time.Time, uncertainty time.Duration, identities []model.EntityReference, requestID correlation.OpaqueID) (correlation.Record, error) {
	ref, err := reference(id)
	if err != nil {
		return correlation.Record{}, err
	}
	eventTime, err := correlation.NewEventTime(at, uncertainty)
	if err != nil {
		return correlation.Record{}, err
	}
	return correlation.NewRecord(correlation.RecordInput{
		Reference: ref, Scope: scope, Vantage: correlation.SourceVantageGeneral,
		Time: &eventTime, Identities: identities, RequestIDs: []correlation.OpaqueID{requestID},
		Synthetic: synthetic,
	})
}

func lifecycle(closedAt time.Time) (model.Lifecycle, error) {
	estimate, err := model.NewStorageEstimate(4096, model.EstimateAssumed)
	if err != nil {
		return model.Lifecycle{}, err
	}
	return model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassCorrelatedTrace, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionLean, PolicyVersion: "operator-fixture-v1",
		RetentionDecisionRef: "retention/operator-fixture-v1", RetentionClock: model.RetentionFromTraceClose,
		RetentionStart: closedAt, ExpiresAt: closedAt.Add(90 * 24 * time.Hour), State: model.LifecycleActive,
		ResidencyPolicyRef: "residency/lab-local-v1", EncryptionKeyRef: "key://lab-local/operator-fixture",
		OperationalPolicyRef: "operational/operator-fixture-v1",
		PerTenantModelUse:    model.ModelUseGrant{}, CrossTenantModelUse: model.ModelUseGrant{},
		EstimatedStorageImpact: estimate,
	})
}

func reference(id string) (model.RecordReference, error) {
	return model.NewRecordReference(id, model.CurrentSchemaVersion)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte("canarysting-m2b5-fixture\x00" + value))
	return hex.EncodeToString(sum[:])
}
