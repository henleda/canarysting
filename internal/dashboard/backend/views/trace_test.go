package views_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/canarysting/canarysting/internal/canaryview/tracefixture"
	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
)

func TestProjectTraceExplainsPartialConflictedJourney(t *testing.T) {
	value, err := tracefixture.OperatorConflict()
	if err != nil {
		t.Fatal(err)
	}

	got := views.ProjectTrace(value)
	if got.TraceID != value.Envelope().RecordID() {
		t.Fatalf("trace id = %q, want %q", got.TraceID, value.Envelope().RecordID())
	}
	if got.Title != "Conflicting evidence across Checkout API and Payments" {
		t.Fatalf("title = %q", got.Title)
	}
	if got.Status.Label != "Conflicted" || got.Status.Code != "CONFLICTED" {
		t.Fatalf("status = %#v", got.Status)
	}
	if got.Confidence.Level != "Low" || got.Confidence.Completeness != "Partial" {
		t.Fatalf("confidence = %#v", got.Confidence)
	}
	if got.Confidence.TimeUncertainty != "Bounded" || got.Confidence.TimeWindow != "2.25s" {
		t.Fatalf("trace time confidence = %#v", got.Confidence)
	}
	boundedHop := false
	for _, hop := range got.Hops {
		if hop.RecordID == "gateway-request" {
			boundedHop = hop.TimeStatus == "Bounded source time" && hop.TimeUncertainty == "Bounded" && hop.TimeWindow == "250ms"
		}
	}
	if !boundedHop {
		t.Fatalf("bounded source-time projection missing: %#v", got.Hops)
	}
	if !strings.Contains(got.WhatHappened, "3 source records") || !strings.Contains(got.WhatHappened, "1 observation") || !strings.Contains(got.WhatHappened, "2 policy decisions") {
		t.Fatalf("what happened = %q", got.WhatHappened)
	}
	if got.Explanation.Claim == "" || got.Explanation.Reason == "" || len(got.Explanation.Joins) != 2 {
		t.Fatalf("explanation = %#v", got.Explanation)
	}
	for _, join := range got.Explanation.Joins {
		if join.Method != "Request ID" || join.Strength != "Exact" || len(join.Citations) != 2 {
			t.Fatalf("join = %#v", join)
		}
	}
	if len(got.Affected) != 2 || got.Affected[0].Name != "Checkout API" || got.Affected[1].Name != "Payments" {
		t.Fatalf("affected = %#v", got.Affected)
	}
	if len(got.Missing) != 2 {
		t.Fatalf("missing = %#v", got.Missing)
	}
	foundBrokenRaw := false
	for _, gap := range got.Missing {
		foundBrokenRaw = foundBrokenRaw || gap.Kind == "RAW_EVIDENCE" && gap.Availability == "Integrity mismatch"
	}
	if !foundBrokenRaw {
		t.Fatalf("broken raw gap missing: %#v", got.Missing)
	}
	if len(got.Conflicts) != 2 {
		t.Fatalf("conflicts = %#v", got.Conflicts)
	}
	if len(got.Evidence) < 1 || !got.Evidence[0].Raw || got.Evidence[0].Availability != "Integrity mismatch" {
		t.Fatalf("evidence = %#v", got.Evidence)
	}
	if got.Evidence[0].Role != "" {
		t.Fatalf("raw reference invented claim role: %#v", got.Evidence[0])
	}
	supporting, contradicting := false, false
	for _, evidence := range got.Evidence {
		if evidence.ID != "evidence-policy-conflict" {
			continue
		}
		supporting = supporting || evidence.Role == "Supporting" && evidence.HopRecordID == "cilium-policy-allow"
		contradicting = contradicting || evidence.Role == "Contradicting" && evidence.HopRecordID == ""
	}
	if !supporting || !contradicting {
		t.Fatalf("same-ID evidence contexts were not preserved: %#v", got.Evidence)
	}
	foundConflictEvidence := false
	for _, conflict := range got.Conflicts {
		foundConflictEvidence = foundConflictEvidence || len(conflict.EvidenceIDs) == 1 && conflict.EvidenceIDs[0] == "evidence-policy-conflict"
	}
	if !foundConflictEvidence {
		t.Fatalf("conflict evidence IDs = %#v", got.Conflicts)
	}
	rawBlob, err := json.Marshal(got.Evidence[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{`"role"`, `"expires_at"`, `"legal_hold_ids"`, `"residency"`, `"model_use"`} {
		if strings.Contains(string(rawBlob), prohibited) {
			t.Fatalf("raw-reference projection contains trace-owned field %q: %s", prohibited, rawBlob)
		}
	}
	if !got.Synthetic || got.ScenarioID != "m2b5-operator-conflict" {
		t.Fatalf("synthetic=%t scenario=%q", got.Synthetic, got.ScenarioID)
	}
	if got.SafetyNote != "This workspace is read-only and cannot trigger or change a response." {
		t.Fatalf("safety note = %q", got.SafetyNote)
	}

	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(blob))
	for _, prohibited := range []string{"request_body", "authorization", "bearer ", "password", "canary_secret", `"payload"`} {
		if strings.Contains(lower, prohibited) {
			t.Fatalf("projection contains prohibited marker %q: %s", prohibited, blob)
		}
	}
}
