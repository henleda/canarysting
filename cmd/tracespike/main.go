// tracespike is the bounded M2B.4/M2B.5 DGX proof. It uses only minimized
// synthetic records and emits fixed assertions; no customer payload or raw
// identifier is accepted or written.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
	"github.com/canarysting/canarysting/internal/canaryview/tracefixture"
	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
)

var safeID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,94}[a-z0-9])?$`)

const (
	operatorScenarioID    = "m2b5-operator-conflict"
	operatorMissingCount  = 2
	operatorConflictCount = 3
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tracespike: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("tracespike", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runID := flags.String("run-id", "", "bounded DGX run ID")
	scenarioID := flags.String("scenario-id", "", "synthetic scenario ID")
	selfcheck := flags.Bool("selfcheck", false, "run the fixed proof")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if !*selfcheck {
		return fmt.Errorf("-selfcheck is required")
	}
	if !safeID.MatchString(*runID) || len(*runID) > 48 {
		return fmt.Errorf("run ID must be 1-48 lowercase alphanumeric/hyphen characters")
	}
	if !safeID.MatchString(*scenarioID) || len(*scenarioID) > 96 {
		return fmt.Errorf("scenario ID must be 1-96 lowercase alphanumeric/hyphen characters")
	}
	if *scenarioID != operatorScenarioID {
		return fmt.Errorf("scenario ID must be %q", operatorScenarioID)
	}
	if output == nil {
		return fmt.Errorf("proof output is required")
	}
	if err := executeProof(*runID, *scenarioID); err != nil {
		return err
	}
	for _, line := range []string{
		"PROOF passive_partial=PASS canary_touch_required=false",
		"PROOF deterministic_id=PASS input_order_independent=true",
		"PROOF ambiguity=PASS candidates=2 chosen=false",
		"PROOF join_citations=PASS all_links_evidence_backed=true",
		"PROOF broken_raw=PASS availability=INTEGRITY_MISMATCH",
		"PROOF lifecycle=PASS held_visible=true expired_hidden=true",
		"PROOF invalidation=PASS exact_scope=true",
		"PROOF bounds=PASS truncation=false",
		fmt.Sprintf("PROOF operator_projection=PASS scenario_id=m2b5-operator-conflict explanation_present=true raw_reference_metadata_present=true raw_availability=INTEGRITY_MISMATCH status=CONFLICTED missing=%d conflicts=%d", operatorMissingCount, operatorConflictCount),
		"PROOF ground_truth_ingest=PASS declared_only=true assisted=1 unassisted=1 unmatched_steps=1",
	} {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	return nil
}

func executeProof(runID, scenarioID string) error {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	scope, err := model.NewScope("internal-lab", "m2b4-"+runID, "dgx-spark", "dgx-local")
	if err != nil {
		return err
	}
	otherScope, err := model.NewScope("internal-lab", "m2b4-other-"+runID, "dgx-spark", "dgx-local")
	if err != nil {
		return err
	}
	synthetic, err := model.NewSyntheticContext(scenarioID)
	if err != nil {
		return err
	}
	shared := digest("request", scenarioID)
	anchor, err := proofRecord("trace-anchor", scope, synthetic, now, shared)
	if err != nil {
		return err
	}
	left, err := proofRecord("trace-left", scope, synthetic, now.Add(time.Second), shared)
	if err != nil {
		return err
	}
	right, err := proofRecord("trace-right", scope, synthetic, now.Add(2*time.Second), shared)
	if err != nil {
		return err
	}
	engine, err := correlation.NewEngine(correlation.DefaultConfig())
	if err != nil {
		return err
	}
	result, err := engine.Correlate(anchor, []correlation.Record{right, left}, nil)
	if err != nil {
		return err
	}
	if !result.Ambiguous() || len(result.Candidates()) != 2 {
		return fmt.Errorf("ambiguous candidates were not retained")
	}
	if _, selected := result.Chosen(); selected {
		return fmt.Errorf("ambiguous correlation selected a candidate")
	}

	closedAt := now.Add(time.Minute)
	raw, err := model.NewRawEventReference("rawref:sha256:"+digest("raw-reference", scenarioID), model.RawAvailable, "sha256", digest("raw-integrity", scenarioID))
	if err != nil {
		return err
	}
	parent, err := recordReference("trace-high-water")
	if err != nil {
		return err
	}
	activeLifecycle, err := proofLifecycle(closedAt, model.LifecycleActive)
	if err != nil {
		return err
	}
	input := trace.BuildInput{
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
		ClosedAt: closedAt, BuiltAt: closedAt.Add(time.Minute), HighWaterMark: parent,
		Lifecycle: activeLifecycle, Synthetic: synthetic,
	}
	first, err := build(input)
	if err != nil {
		return err
	}
	input.Hops[0], input.Hops[2] = input.Hops[2], input.Hops[0]
	second, err := build(input)
	if err != nil {
		return err
	}
	if first.Envelope().RecordID() != second.Envelope().RecordID() || first.IntegrityDigest() != second.IntegrityDigest() {
		return fmt.Errorf("trace identity changed with input order")
	}
	if first.Status() != trace.StatusConflicted || len(first.Conflicts()) != 1 {
		return fmt.Errorf("ambiguous trace did not become conflicted")
	}
	if err := evaluateGroundTruthProof(runID, first); err != nil {
		return fmt.Errorf("ground-truth separation proof: %w", err)
	}
	for _, candidate := range first.Correlations()[0].Candidates() {
		for _, explanation := range candidate.Explanations() {
			if !hasReference(explanation.Citations(), anchor.Reference()) || !hasReference(explanation.Citations(), candidate.Reference()) {
				return fmt.Errorf("join explanation omitted a joined record")
			}
		}
	}

	passive, err := proofRecord("passive-observation", scope, synthetic, now, "")
	if err != nil {
		return err
	}
	broken, err := model.NewRawEventReference("rawref:sha256:"+digest("broken-reference", scenarioID), model.RawIntegrityMismatch, "sha256", digest("broken-integrity", scenarioID))
	if err != nil {
		return err
	}
	passiveRef := passive.Reference()
	passiveParent, err := recordReference("passive-high-water")
	if err != nil {
		return err
	}
	partial, err := build(trace.BuildInput{
		Scope: scope, Hops: []trace.HopInput{{Record: passive, Kind: trace.HopObservation, RawEvent: &broken}},
		Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}, {Kind: trace.ExpectRawEvidence, Record: &passiveRef}},
		ClosedAt:     closedAt, BuiltAt: closedAt.Add(time.Minute), HighWaterMark: passiveParent,
		Lifecycle: activeLifecycle, Synthetic: synthetic,
	})
	if err != nil {
		return err
	}
	if partial.Status() != trace.StatusPartial || len(partial.Correlations()) != 0 || len(partial.MissingTelemetry()) != 1 {
		return fmt.Errorf("passive partial trace was not explicit")
	}
	availability, ok := partial.MissingTelemetry()[0].RawAvailability()
	if !ok || availability != model.RawIntegrityMismatch {
		return fmt.Errorf("broken raw availability was lost")
	}

	trustedNow := closedAt.Add(time.Minute)
	store, err := trace.NewSyntheticStore(trace.StoreLimits{TracesPerScope: 8, QueryResults: 8, InvalidationResults: 8}, scenarioID, func() time.Time { return trustedNow })
	if err != nil {
		return err
	}
	heldInput := input
	heldInput.Correlations = nil
	heldInput.Hops = []trace.HopInput{{Record: anchor, Kind: trace.HopObservation}}
	heldInput.Expectations = []trace.ExpectationInput{{Kind: trace.ExpectObservation}}
	heldInput.HighWaterMark, err = recordReference("held-parent")
	if err != nil {
		return err
	}
	heldInput.Lifecycle, err = proofLifecycle(closedAt, model.LifecycleHeld)
	if err != nil {
		return err
	}
	held, err := build(heldInput)
	if err != nil {
		return err
	}
	if err := store.Put(held); err != nil {
		return err
	}
	trustedNow = held.Envelope().Lifecycle().ExpiresAt().Add(time.Hour)
	if _, err := store.Get(scope, held.Envelope().RecordID()); err != nil {
		return fmt.Errorf("held trace was hidden after nominal expiry: %w", err)
	}

	expiryStore, err := trace.NewSyntheticStore(trace.StoreLimits{TracesPerScope: 8, QueryResults: 8, InvalidationResults: 8}, scenarioID, func() time.Time { return trustedNow })
	if err != nil {
		return err
	}
	trustedNow = closedAt.Add(time.Minute)
	if err := expiryStore.Put(partial); err != nil {
		return err
	}
	trustedNow = partial.Envelope().Lifecycle().ExpiresAt()
	if _, err := expiryStore.Get(scope, partial.Envelope().RecordID()); !errors.Is(err, trace.ErrNotFound) {
		return fmt.Errorf("expired trace remained queryable")
	}

	trustedNow = closedAt.Add(time.Minute)
	invalidationStore, err := trace.NewSyntheticStore(trace.StoreLimits{TracesPerScope: 8, QueryResults: 8, InvalidationResults: 8}, scenarioID, func() time.Time { return trustedNow })
	if err != nil {
		return err
	}
	otherRecord, err := proofRecord("other-observation", otherScope, synthetic, now, "")
	if err != nil {
		return err
	}
	other, err := build(trace.BuildInput{
		Scope: otherScope, Hops: []trace.HopInput{{Record: otherRecord, Kind: trace.HopObservation}},
		Expectations: []trace.ExpectationInput{{Kind: trace.ExpectObservation}}, ClosedAt: closedAt,
		BuiltAt: closedAt.Add(time.Minute), HighWaterMark: parent,
		Lifecycle: activeLifecycle, Synthetic: synthetic,
	})
	if err != nil {
		return err
	}
	if err := invalidationStore.Put(partial); err != nil {
		return err
	}
	if err := invalidationStore.Put(other); err != nil {
		return err
	}
	invalidated, err := invalidationStore.InvalidateBy(scope, passiveParent, trace.InvalidationParentDeleted, trustedNow)
	if err != nil || len(invalidated) != 1 {
		return fmt.Errorf("exact-scope invalidation failed: %w", err)
	}
	if _, err := invalidationStore.Get(otherScope, other.Envelope().RecordID()); err != nil {
		return fmt.Errorf("invalidation crossed scope: %w", err)
	}

	bounded := trace.DefaultBuilderConfig()
	bounded.MaxHops = 1
	boundedBuilder, err := trace.NewBuilder(bounded)
	if err != nil {
		return err
	}
	overBound := input
	overBound.Correlations = nil
	overBound.Expectations = []trace.ExpectationInput{{Kind: trace.ExpectObservation}}
	if _, err := boundedBuilder.Build(overBound); err == nil {
		return fmt.Errorf("over-bound trace input was truncated or accepted")
	}

	operatorTrace, err := tracefixture.OperatorConflict()
	if err != nil {
		return fmt.Errorf("build operator trace fixture: %w", err)
	}
	workspace := views.ProjectTrace(operatorTrace)
	if workspace.TraceID != operatorTrace.Envelope().RecordID() || workspace.WhatHappened == "" || workspace.Explanation.Claim == "" || workspace.Explanation.Reason == "" {
		return fmt.Errorf("operator trace explanation is incomplete")
	}
	if workspace.Status.Code != string(trace.StatusConflicted) || len(workspace.Missing) != operatorMissingCount || len(workspace.Conflicts) != operatorConflictCount {
		return fmt.Errorf("operator trace partial/conflicting state is not explicit")
	}
	joinIdentities := make(map[string]bool)
	translatedPathPresent := false
	for _, join := range workspace.Explanation.Joins {
		pathIdentity := ""
		for _, step := range join.TranslationPath {
			pathIdentity += fmt.Sprintf(":%s:v%d:%s", step.Record.ID, step.Record.SchemaVersion, step.Direction)
		}
		identity := fmt.Sprintf("%s:v%d:%s:v%d:%s:%s:%s:%s%s", join.Anchor.ID, join.Anchor.SchemaVersion, join.Candidate.ID, join.Candidate.SchemaVersion, join.Method, join.Strength, join.KeyFingerprint, join.TimeGap+":"+join.Window, pathIdentity)
		if join.KeyFingerprint == "" || joinIdentities[identity] {
			return fmt.Errorf("operator trace collapsed a canonical join explanation")
		}
		if join.Method == "Request ID" && (join.TimeGap != "" || join.Window != "" || len(join.TranslationPath) != 0) {
			return fmt.Errorf("operator trace invented context for an exact identifier join")
		}
		if join.Method == "Translated tuple and time window" {
			if join.TimeGap == "" || join.Window == "" || len(join.TranslationPath) == 0 {
				return fmt.Errorf("operator trace omitted translated join context")
			}
			translatedPathPresent = true
		}
		joinIdentities[identity] = true
	}
	if len(joinIdentities) != 8 || !translatedPathPresent {
		return fmt.Errorf("operator trace join explanations = %d translated_path=%t, want 8/true", len(joinIdentities), translatedPathPresent)
	}
	rawReferenceMetadataPresent := false
	supportingContext, versionedSupportingContext, contradictingContext := false, false, false
	for _, evidence := range workspace.Evidence {
		if evidence.Raw && evidence.SourceOwned && evidence.Reference != "" && evidence.Role == "" && evidence.Availability == "Integrity mismatch" && evidence.HashAlgorithm != "" && evidence.HashValue != "" {
			rawReferenceMetadataPresent = true
		}
		if evidence.ID == "evidence-policy-conflict" {
			supportingContext = supportingContext || evidence.Role == "Supporting" && evidence.SchemaVersion == 3 && evidence.HopRecord != nil && evidence.HopRecord.ID == "cilium-policy-allow" && evidence.HopRecord.SchemaVersion == 3
			versionedSupportingContext = versionedSupportingContext || evidence.Role == "Supporting" && evidence.SchemaVersion == 4 && evidence.HopRecord != nil && evidence.HopRecord.ID == "cilium-policy-allow" && evidence.HopRecord.SchemaVersion == 4
			contradictingContext = contradictingContext || evidence.Role == "Contradicting" && evidence.SchemaVersion == 3 && evidence.HopRecord == nil
		}
	}
	if !rawReferenceMetadataPresent || !supportingContext || !versionedSupportingContext || !contradictingContext {
		return fmt.Errorf("operator trace omitted raw-reference metadata or evidence-role context")
	}
	recordVersions := make(map[uint32]bool)
	for _, hop := range workspace.Hops {
		if hop.Record.ID == "cilium-policy-allow" {
			recordVersions[hop.Record.SchemaVersion] = true
		}
	}
	if !recordVersions[3] || !recordVersions[4] || len(recordVersions) != 2 {
		return fmt.Errorf("operator trace collapsed versioned record identity")
	}
	if workspace.Confidence.TimeUncertainty != "Bounded" || workspace.Confidence.TimeWindow == "" || len(workspace.Hops) == 0 || workspace.Hops[0].TimeWindow == "" {
		return fmt.Errorf("operator trace omitted time uncertainty")
	}
	conflictEvidencePresent, secondaryConflictEvidencePresent := false, false
	for _, conflict := range workspace.Conflicts {
		conflictEvidencePresent = conflictEvidencePresent || len(conflict.Evidence) == 1 && conflict.Evidence[0].ID == "evidence-policy-conflict" && conflict.Evidence[0].SchemaVersion == 3
		secondaryConflictEvidencePresent = secondaryConflictEvidencePresent || len(conflict.Evidence) == 1 && conflict.Evidence[0].ID == "evidence-policy-conflict-secondary" && conflict.Evidence[0].SchemaVersion == 3
	}
	if !conflictEvidencePresent || !secondaryConflictEvidencePresent {
		return fmt.Errorf("operator trace conflict omitted its evidence reference")
	}
	if tracefixture.ScenarioID != operatorScenarioID || !workspace.Synthetic || workspace.ScenarioID != scenarioID || workspace.SafetyNote != "This workspace is read-only and cannot trigger or change a response." {
		return fmt.Errorf("operator trace safety or synthetic provenance is incomplete")
	}
	return nil
}

func proofRecord(id string, scope model.Scope, synthetic model.SyntheticContext, at time.Time, requestDigest string) (correlation.Record, error) {
	reference, err := recordReference(id)
	if err != nil {
		return correlation.Record{}, err
	}
	eventTime, err := correlation.NewEventTime(at, 0)
	if err != nil {
		return correlation.Record{}, err
	}
	input := correlation.RecordInput{Reference: reference, Scope: scope, Vantage: correlation.SourceVantageGeneral, Time: &eventTime, Synthetic: synthetic}
	if requestDigest != "" {
		requestID, requestErr := correlation.NewOpaqueID("dgx.trace.request", requestDigest)
		if requestErr != nil {
			return correlation.Record{}, requestErr
		}
		input.RequestIDs = []correlation.OpaqueID{requestID}
	}
	return correlation.NewRecord(input)
}

func build(input trace.BuildInput) (trace.Trace, error) {
	builder, err := trace.NewBuilder(trace.DefaultBuilderConfig())
	if err != nil {
		return trace.Trace{}, err
	}
	return builder.Build(input)
}

func proofLifecycle(closedAt time.Time, state model.LifecycleState) (model.Lifecycle, error) {
	estimate, err := model.NewStorageEstimate(4096, model.EstimateAssumed)
	if err != nil {
		return model.Lifecycle{}, err
	}
	holds := []string(nil)
	if state == model.LifecycleHeld {
		holds = []string{"hold-m2b4-proof"}
	}
	return model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassCorrelatedTrace, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionLean, PolicyVersion: "m2b4-proof-v1",
		RetentionDecisionRef: "retention/m2b4-proof", RetentionClock: model.RetentionFromTraceClose,
		RetentionStart: closedAt, ExpiresAt: closedAt.Add(90 * 24 * time.Hour), State: state,
		LegalHoldIDs: holds, ResidencyPolicyRef: "residency/dgx-local-v1",
		EncryptionKeyRef: "key://dgx-local/proof", OperationalPolicyRef: "operational/m2b4-proof-v1",
		EstimatedStorageImpact: estimate,
	})
}

func recordReference(id string) (model.RecordReference, error) {
	return model.NewRecordReference(id, model.CurrentSchemaVersion)
}

func hasReference(values []model.RecordReference, wanted model.RecordReference) bool {
	sort.Slice(values, func(i, j int) bool { return values[i].ID() < values[j].ID() })
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
