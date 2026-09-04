package views

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/canaryview/trace"
)

// TraceWorkspace is the bounded, read-only operator projection of one immutable
// canonical trace. It contains references and safe summaries only; raw source
// payloads remain in their owning systems.
type TraceWorkspace struct {
	TraceID      string               `json:"trace_id"`
	Title        string               `json:"title"`
	Summary      string               `json:"summary"`
	WhatHappened string               `json:"what_happened"`
	Status       TraceStatusView      `json:"status"`
	Confidence   TraceConfidenceView  `json:"confidence"`
	Scope        TraceScopeView       `json:"scope"`
	Affected     []TraceIdentityView  `json:"affected"`
	Hops         []TraceHopView       `json:"hops"`
	Explanation  TraceExplanationView `json:"explanation"`
	Missing      []TraceGapView       `json:"missing"`
	Conflicts    []TraceConflictView  `json:"conflicts"`
	Evidence     []TraceEvidenceView  `json:"evidence"`
	Lifecycle    TraceLifecycleView   `json:"lifecycle"`
	Synthetic    bool                 `json:"synthetic"`
	ScenarioID   string               `json:"scenario_id,omitempty"`
	SafetyNote   string               `json:"safety_note"`
}

type TraceStatusView struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

type TraceConfidenceView struct {
	Level             string `json:"level"`
	Method            string `json:"method"`
	Completeness      string `json:"completeness"`
	SourceQuality     string `json:"source_quality"`
	IdentityAssurance string `json:"identity_assurance"`
	CandidateCount    uint32 `json:"candidate_count"`
	TimeUncertainty   string `json:"time_uncertainty"`
	TimeWindow        string `json:"time_window,omitempty"`
	HumanReview       string `json:"human_review"`
}

type TraceScopeView struct {
	TenantID           string `json:"tenant_id"`
	ScopeID            string `json:"scope_id"`
	DisplayName        string `json:"display_name"`
	DeploymentBoundary string `json:"deployment_boundary"`
	ResidencyCellID    string `json:"residency_cell_id"`
}

type TraceIdentityView struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	AssertionMode string `json:"assertion_mode"`
	Verified      bool   `json:"verified"`
}

type TraceReferenceView struct {
	ID            string `json:"id"`
	SchemaVersion uint32 `json:"schema_version"`
}

type TraceHopView struct {
	Record          TraceReferenceView  `json:"record"`
	Kind            string              `json:"kind"`
	Label           string              `json:"label"`
	At              string              `json:"at,omitempty"`
	TimeStatus      string              `json:"time_status"`
	TimeUncertainty string              `json:"time_uncertainty"`
	TimeWindow      string              `json:"time_window,omitempty"`
	Identities      []TraceIdentityView `json:"identities"`
	EvidenceCount   int                 `json:"evidence_count"`
}

type TraceExplanationView struct {
	Claim   string          `json:"claim"`
	Reason  string          `json:"reason"`
	Methods []string        `json:"methods"`
	Joins   []TraceJoinView `json:"joins"`
}

type TraceJoinView struct {
	Anchor          TraceReferenceView         `json:"anchor"`
	Candidate       TraceReferenceView         `json:"candidate"`
	Method          string                     `json:"method"`
	Strength        string                     `json:"strength"`
	KeyFingerprint  string                     `json:"key_fingerprint"`
	TimeGap         string                     `json:"time_gap"`
	Window          string                     `json:"window"`
	TranslationPath []TraceTranslationStepView `json:"translation_path"`
	Citations       []TraceReferenceView       `json:"citations"`
	Selected        bool                       `json:"selected"`
	Ambiguous       bool                       `json:"ambiguous"`
}

type TraceTranslationStepView struct {
	Record    TraceReferenceView `json:"record"`
	Direction string             `json:"direction"`
}

type TraceGapView struct {
	Kind         string              `json:"kind"`
	Label        string              `json:"label"`
	Record       *TraceReferenceView `json:"record,omitempty"`
	Availability string              `json:"availability,omitempty"`
	NextStep     string              `json:"next_step"`
}

type TraceConflictView struct {
	Kind     string               `json:"kind"`
	Label    string               `json:"label"`
	Records  []TraceReferenceView `json:"records"`
	Evidence []TraceReferenceView `json:"evidence"`
}

type TraceEvidenceView struct {
	ID            string              `json:"id"`
	SchemaVersion uint32              `json:"schema_version,omitempty"`
	Label         string              `json:"label"`
	Summary       string              `json:"summary"`
	Role          string              `json:"role,omitempty"`
	HopRecord     *TraceReferenceView `json:"hop_record,omitempty"`
	Raw           bool                `json:"raw"`
	SourceOwned   bool                `json:"source_owned"`
	Reference     string              `json:"reference"`
	Availability  string              `json:"availability"`
	HashAlgorithm string              `json:"hash_algorithm,omitempty"`
	HashValue     string              `json:"hash_value,omitempty"`
}

type TraceLifecycleView struct {
	DataClass           string   `json:"data_class"`
	Sensitivity         string   `json:"sensitivity"`
	RetentionProfile    string   `json:"retention_profile"`
	State               string   `json:"state"`
	ExpiresAt           string   `json:"expires_at"`
	LegalHoldIDs        []string `json:"legal_hold_ids"`
	ResidencyPolicyRef  string   `json:"residency_policy_ref"`
	EncryptionBoundary  string   `json:"encryption_boundary"`
	PerTenantModelUse   bool     `json:"per_tenant_model_use"`
	CrossTenantModelUse bool     `json:"cross_tenant_model_use"`
}

// ProjectTrace turns a validated canonical trace into the display contract. It
// does not query, mutate, score, infer an action, or reveal source payloads.
func ProjectTrace(value trace.Trace) TraceWorkspace {
	envelope := value.Envelope()
	scope := envelope.Scope()
	knowledge := value.Knowledge()
	confidence := knowledge.Confidence()
	hops := projectTraceHops(value.Hops())
	affected := affectedIdentities(hops)
	missing := projectTraceMissing(value.MissingTelemetry())
	conflicts := projectTraceConflicts(value.Conflicts())
	joins, methods := projectTraceJoins(value.Correlations())
	evidence := projectTraceEvidence(value.Hops(), value.Conflicts())

	observations, policyDecisions := 0, 0
	for _, hop := range value.Hops() {
		if hop.Kind() == trace.HopObservation {
			observations++
		} else if hop.Kind() == trace.HopPolicyDecision {
			policyDecisions++
		}
	}
	status := traceStatus(value.Status(), len(missing), len(conflicts))
	scopeName := humanizeIdentifier(scope.ScopeID())
	title := traceTitle(value.Status(), affected)
	whatHappened := fmt.Sprintf(
		"CanaryView ordered %d source records—%s and %s—within %s.",
		len(hops), countLabel(observations, "observation"), countLabel(policyDecisions, "policy decision"), scopeName,
	)
	claim := "The available records may describe one security journey."
	reason := fmt.Sprintf("CanaryView retained %s across %s; every displayed join cites the records that support it.", countLabel(len(joins), "candidate join"), countLabel(len(value.Correlations()), "correlation set"))
	if value.Status() == trace.StatusConflicted {
		claim = "The available records may describe one security journey, but the outcome is not resolved."
		reason = fmt.Sprintf("CanaryView retained %s and %s rather than selecting an unsupported path.", countLabel(len(joins), "candidate join"), countLabel(len(conflicts), "conflict"))
	}

	lifecycle := envelope.Lifecycle()
	return TraceWorkspace{
		TraceID: envelope.RecordID(), Title: title,
		Summary:      traceSummary(len(hops), len(missing), len(conflicts)),
		WhatHappened: whatHappened, Status: status,
		Confidence: TraceConfidenceView{
			Level: displayEnum(string(confidence.Level())), Method: displayEnum(string(confidence.Method())),
			Completeness: displayEnum(string(confidence.Completeness())), SourceQuality: displayEnum(string(confidence.SourceQuality())),
			IdentityAssurance: displayEnum(string(confidence.IdentityAssurance())), CandidateCount: confidence.CandidateCount(),
			TimeUncertainty: displayEnum(string(confidence.TimeUncertainty())), TimeWindow: durationIfPositive(confidence.TimeWindow()),
			HumanReview: displayEnum(string(confidence.HumanReview())),
		},
		Scope: TraceScopeView{
			TenantID: scope.TenantID(), ScopeID: scope.ScopeID(), DisplayName: scopeName,
			DeploymentBoundary: scope.DeploymentBoundary(), ResidencyCellID: scope.ResidencyCellID(),
		},
		Affected: affected, Hops: hops,
		Explanation: TraceExplanationView{Claim: claim, Reason: reason, Methods: methods, Joins: joins},
		Missing:     missing, Conflicts: conflicts, Evidence: evidence,
		Lifecycle: TraceLifecycleView{
			DataClass: displayEnum(string(lifecycle.DataClass())), Sensitivity: displayEnum(string(lifecycle.Sensitivity())),
			RetentionProfile: displayEnum(string(lifecycle.RetentionProfile())), State: displayEnum(string(lifecycle.State())),
			ExpiresAt: lifecycle.ExpiresAt().Format(time.RFC3339), LegalHoldIDs: nonNilStrings(lifecycle.LegalHoldIDs()),
			ResidencyPolicyRef: lifecycle.ResidencyPolicyRef(), EncryptionBoundary: lifecycle.EncryptionKeyRef(),
			PerTenantModelUse: lifecycle.PerTenantModelUse().Allowed(), CrossTenantModelUse: lifecycle.CrossTenantModelUse().Allowed(),
		},
		Synthetic: envelope.Synthetic().Synthetic(), ScenarioID: envelope.Synthetic().ScenarioID(),
		SafetyNote: "This workspace is read-only and cannot trigger or change a response.",
	}
}

func projectTraceHops(values []trace.Hop) []TraceHopView {
	result := make([]TraceHopView, 0, len(values))
	for _, value := range values {
		record := traceReferenceView(value.Reference())
		identities := make([]TraceIdentityView, 0, len(value.Identities()))
		for _, identity := range value.Identities() {
			_, verified := identity.Verification()
			identities = append(identities, TraceIdentityView{
				ID: identity.ID(), Kind: displayEnum(identity.Kind()), Name: humanizeIdentifier(identity.ID()),
				AssertionMode: displayEnum(string(identity.AssertionMode())), Verified: verified,
			})
		}
		at, timeStatus, timeUncertainty, timeWindow := "", "Source time missing", "Unknown", ""
		if eventTime, ok := value.Time(); ok {
			at = eventTime.At().Format(time.RFC3339Nano)
			if eventTime.Uncertainty() == 0 {
				timeStatus, timeUncertainty = "Exact source time", "Exact"
			} else {
				timeStatus, timeUncertainty, timeWindow = "Bounded source time", "Bounded", eventTime.Uncertainty().String()
			}
		}
		_, hasRaw := value.RawEvent()
		result = append(result, TraceHopView{
			Record: record, Kind: displayEnum(string(value.Kind())), Label: humanizeIdentifier(value.Reference().ID()),
			At: at, TimeStatus: timeStatus, TimeUncertainty: timeUncertainty, TimeWindow: timeWindow,
			Identities: identities, EvidenceCount: len(value.Evidence()) + boolInt(hasRaw),
		})
	}
	return result
}

func affectedIdentities(hops []TraceHopView) []TraceIdentityView {
	byKey := make(map[string]TraceIdentityView)
	for _, hop := range hops {
		for _, identity := range hop.Identities {
			byKey[identity.Kind+"\x00"+identity.ID] = identity
		}
	}
	result := make([]TraceIdentityView, 0, len(byKey))
	for _, identity := range byKey {
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func projectTraceJoins(values []trace.CorrelationSet) ([]TraceJoinView, []string) {
	joins := make([]TraceJoinView, 0)
	methodSet := make(map[string]bool)
	for _, set := range values {
		chosen, hasChosen := set.Chosen()
		for _, candidate := range set.Candidates() {
			for _, explanation := range candidate.Explanations() {
				method := joinMethodLabel(explanation.Method())
				methodSet[method] = true
				citations := make([]TraceReferenceView, 0, len(explanation.Citations()))
				for _, citation := range explanation.Citations() {
					citations = append(citations, traceReferenceView(citation))
				}
				translationPath := make([]TraceTranslationStepView, 0, len(explanation.TranslationPath()))
				for _, step := range explanation.TranslationPath() {
					translationPath = append(translationPath, TraceTranslationStepView{
						Record: traceReferenceView(step.Reference()), Direction: displayEnum(string(step.Direction())),
					})
				}
				joins = append(joins, TraceJoinView{
					Anchor: traceReferenceView(set.Anchor()), Candidate: traceReferenceView(candidate.Reference()), Method: method,
					Strength: displayEnum(string(explanation.Strength())), KeyFingerprint: explanation.KeyFingerprint(),
					TimeGap: explanation.TimeGap().String(), Window: explanation.Window().String(),
					TranslationPath: translationPath, Citations: citations,
					Selected: hasChosen && chosen == candidate.Reference(), Ambiguous: set.Ambiguous() || candidate.TranslationPathAmbiguous(),
				})
			}
		}
	}
	methods := make([]string, 0, len(methodSet))
	for method := range methodSet {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return joins, methods
}

func projectTraceMissing(values []trace.MissingTelemetry) []TraceGapView {
	result := make([]TraceGapView, 0, len(values))
	for _, value := range values {
		expectation := value.Expectation()
		var recordView *TraceReferenceView
		if record, ok := expectation.Record(); ok {
			projected := traceReferenceView(record)
			recordView = &projected
		}
		availability := ""
		if rawAvailability, ok := value.RawAvailability(); ok {
			availability = displayEnum(string(rawAvailability))
		}
		result = append(result, TraceGapView{
			Kind: string(expectation.Kind()), Label: expectationLabel(expectation.Kind()), Record: recordView,
			Availability: availability, NextStep: expectationNextStep(expectation.Kind()),
		})
	}
	return result
}

func projectTraceConflicts(values []trace.Conflict) []TraceConflictView {
	result := make([]TraceConflictView, 0, len(values))
	for _, value := range values {
		records := make([]TraceReferenceView, 0, len(value.Records()))
		for _, record := range value.Records() {
			records = append(records, traceReferenceView(record))
		}
		evidence := make([]TraceReferenceView, 0, len(value.Evidence()))
		for _, reference := range value.Evidence() {
			evidence = append(evidence, evidenceReferenceView(reference))
		}
		result = append(result, TraceConflictView{
			Kind: string(value.Kind()), Label: conflictLabel(value.Kind()), Records: records, Evidence: evidence,
		})
	}
	return result
}

func projectTraceEvidence(hops []trace.Hop, conflicts []trace.Conflict) []TraceEvidenceView {
	result := make([]TraceEvidenceView, 0)
	for _, hop := range hops {
		label := humanizeIdentifier(hop.Reference().ID())
		hopRecord := traceReferenceView(hop.Reference())
		if raw, ok := hop.RawEvent(); ok {
			result = append(result, TraceEvidenceView{
				ID: raw.Reference(), Label: label, Summary: "Source-owned raw evidence reference for " + label + ".",
				HopRecord: &hopRecord, Raw: true, SourceOwned: true,
				Reference: raw.Reference(), Availability: displayEnum(string(raw.Availability())),
				HashAlgorithm: raw.HashAlgorithm(), HashValue: raw.HashValue(),
			})
		}
		for _, evidence := range hop.Evidence() {
			result = append(result, TraceEvidenceView{
				ID: evidence.ID(), Label: label, Summary: "Evidence reference attached to " + label + ".",
				SchemaVersion: evidence.SchemaVersion(), Role: displayEnum(string(evidence.Role())), HopRecord: &hopRecord,
				Reference: evidence.ID(), Availability: "Reference only",
			})
		}
	}
	for _, conflict := range conflicts {
		for _, evidence := range conflict.Evidence() {
			result = append(result, TraceEvidenceView{
				ID: evidence.ID(), Label: conflictLabel(conflict.Kind()), Summary: "Evidence reference attached to " + strings.ToLower(conflictLabel(conflict.Kind())) + ".",
				SchemaVersion: evidence.SchemaVersion(), Role: displayEnum(string(evidence.Role())), Reference: evidence.ID(), Availability: "Reference only",
			})
		}
	}
	return result
}

func traceReferenceView(value model.RecordReference) TraceReferenceView {
	return TraceReferenceView{ID: value.ID(), SchemaVersion: value.SchemaVersion()}
}

func evidenceReferenceView(value model.EvidenceReference) TraceReferenceView {
	return TraceReferenceView{ID: value.ID(), SchemaVersion: value.SchemaVersion()}
}

func durationIfPositive(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	return value.String()
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func traceStatus(status trace.Status, missing, conflicts int) TraceStatusView {
	label := "Partial"
	switch status {
	case trace.StatusComplete:
		label = "Complete under declared coverage"
	case trace.StatusConflicted:
		label = "Conflicted"
	}
	return TraceStatusView{
		Code: string(status), Label: label,
		Detail: fmt.Sprintf("%s; %s.", countLabel(missing, "expected item")+" missing", countLabel(conflicts, "conflict")+" unresolved"),
	}
}

func traceTitle(status trace.Status, affected []TraceIdentityView) string {
	state := "Correlated evidence"
	if status == trace.StatusPartial {
		state = "Partial evidence"
	} else if status == trace.StatusConflicted {
		state = "Conflicting evidence"
	}
	if len(affected) >= 2 {
		return fmt.Sprintf("%s across %s and %s", state, affected[0].Name, affected[1].Name)
	}
	if len(affected) == 1 {
		return fmt.Sprintf("%s for %s", state, affected[0].Name)
	}
	return state + " in the selected scope"
}

func traceSummary(hops, missing, conflicts int) string {
	return fmt.Sprintf("CanaryView correlated %s. Coverage remains explicit: %s and %s.", countLabel(hops, "source record"), countLabel(missing, "expected item")+" missing", countLabel(conflicts, "conflict")+" unresolved")
}

func conflictLabel(kind trace.ConflictKind) string {
	switch kind {
	case trace.ConflictAmbiguousCorrelation:
		return "Equally strong correlation candidates"
	case trace.ConflictContradictoryEvidence:
		return "Contradictory policy evidence"
	case trace.ConflictOrderingUncertainty:
		return "Uncertain event ordering"
	default:
		return displayEnum(string(kind))
	}
}

func expectationLabel(kind trace.ExpectationKind) string {
	switch kind {
	case trace.ExpectRawEvidence:
		return "Raw evidence could not be verified"
	case trace.ExpectSourceTime:
		return "Source timestamp is missing"
	case trace.ExpectCorrelation:
		return "Expected correlation is missing"
	case trace.ExpectPolicyDecision:
		return "Expected policy decision is missing"
	default:
		return "Expected observation is missing"
	}
}

func expectationNextStep(kind trace.ExpectationKind) string {
	if kind == trace.ExpectRawEvidence {
		return "Verify the source-owned reference and integrity digest; do not infer the missing content."
	}
	return "Acquire the named missing evidence from its source before raising confidence."
}

func joinMethodLabel(method correlation.JoinMethod) string {
	switch method {
	case correlation.JoinRequestID:
		return "Request ID"
	case correlation.JoinVendorID:
		return "Vendor transaction ID"
	case correlation.JoinSocketCookie:
		return "Socket cookie"
	case correlation.JoinOTelSpanID:
		return "OpenTelemetry trace and span ID"
	case correlation.JoinOTelTraceID:
		return "OpenTelemetry trace ID"
	case correlation.JoinVerifiedIdentity:
		return "Verified identity"
	case correlation.JoinDeclaredIdentity:
		return "Declared identity and time window"
	case correlation.JoinTranslatedTuple:
		return "Translated tuple and time window"
	case correlation.JoinTupleTime:
		return "Network tuple and time window"
	default:
		return displayEnum(string(method))
	}
}

func humanizeIdentifier(value string) string {
	if index := strings.LastIndex(value, ":"); index >= 0 {
		value = value[index+1:]
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == '_' || r == '/' })
	for index, part := range parts {
		upper := strings.ToUpper(part)
		if upper == "API" || upper == "HTTP" || upper == "OTEL" {
			parts[index] = upper
			continue
		}
		if part != "" {
			parts[index] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, " ")
}

func displayEnum(value string) string {
	label := strings.ToLower(strings.ReplaceAll(value, "_", " "))
	if label == "" {
		return ""
	}
	return strings.ToUpper(label[:1]) + label[1:]
}

func countLabel(count int, noun string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", count, noun)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
