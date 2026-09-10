package main

import (
	"testing"
	"time"
)

func TestFixedScenarioV1HasStableReviewedLifecycleAndIdentity(t *testing.T) {
	first, err := buildFixture(31001)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildFixture(31002)
	if err != nil {
		t.Fatal(err)
	}
	wantRecordedAt := time.Date(2026, time.September, 7, 0, 0, 0, 0, time.UTC)
	wantReviewDue := time.Date(2027, time.September, 7, 0, 0, 0, 0, time.UTC)
	firstEnvelope := first.scenario.Envelope()
	secondEnvelope := second.scenario.Envelope()
	if !firstEnvelope.RecordedAt().Equal(wantRecordedAt) || !firstEnvelope.CorpusReviewDue().Equal(wantReviewDue) {
		t.Fatalf("scenario v1 lifecycle = %s/%s, want %s/%s", firstEnvelope.RecordedAt(), firstEnvelope.CorpusReviewDue(), wantRecordedAt, wantReviewDue)
	}
	if !secondEnvelope.RecordedAt().Equal(wantRecordedAt) || !secondEnvelope.CorpusReviewDue().Equal(wantReviewDue) {
		t.Fatal("scenario v1 lifecycle changed between fixture constructions")
	}
	if first.scenario.SemanticSHA256() != second.scenario.SemanticSHA256() {
		t.Fatal("scenario v1 semantic identity changed with runtime fixture construction")
	}
}
