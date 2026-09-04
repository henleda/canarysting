// tracebackend is a loopback-only, test-only server for the dashboard
// Playwright suite. It exercises the production read-only trace handler and
// projection with the canonical synthetic fixture; it is not runtime wiring.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/trace"
	"github.com/canarysting/canarysting/internal/canaryview/tracefixture"
	"github.com/canarysting/canarysting/internal/dashboard/backend"
	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
)

const (
	listenAddress             = "127.0.0.1:3102"
	notFoundTraceID           = "trace:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	unavailableTraceID        = "trace:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	malformedTraceID          = "trace:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	invalidEvidenceID         = "trace:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	invalidJSONID             = "trace:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	zeroCandidateID           = "trace:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	zeroDurationID            = "trace:sha256:1111111111111111111111111111111111111111111111111111111111111111"
	heldWithoutHoldID         = "trace:sha256:2222222222222222222222222222222222222222222222222222222222222222"
	duplicateHoldID           = "trace:sha256:3333333333333333333333333333333333333333333333333333333333333333"
	invalidJoinID             = "trace:sha256:4444444444444444444444444444444444444444444444444444444444444444"
	invalidJoinTimeID         = "trace:sha256:5555555555555555555555555555555555555555555555555555555555555555"
	duplicateJoinID           = "trace:sha256:6666666666666666666666666666666666666666666666666666666666666666"
	duplicateConflictID       = "trace:sha256:7777777777777777777777777777777777777777777777777777777777777777"
	invalidConflictRecordsID  = "trace:sha256:8888888888888888888888888888888888888888888888888888888888888888"
	invalidConflictEvidenceID = "trace:sha256:9999999999999999999999999999999999999999999999999999999999999999"
	emptyConflictEvidenceID   = "trace:sha256:abababababababababababababababababababababababababababababababab"
)

type fixtureSource struct {
	value trace.Trace
}

func (s fixtureSource) GetTrace(_ context.Context, id string) (trace.Trace, error) {
	if id == s.value.Envelope().RecordID() {
		return s.value, nil
	}
	if id == unavailableTraceID {
		return trace.Trace{}, errors.New("synthetic source unavailable")
	}
	return trace.Trace{}, trace.ErrNotFound
}

func main() {
	value, err := tracefixture.OperatorConflict()
	if err != nil {
		log.Fatal(err)
	}
	productionHandler := backend.New(backend.Config{TraceSource: fixtureSource{value: value}}).Handler()
	malformedProjection := views.ProjectTrace(value)
	malformedProjection.TraceID = malformedTraceID
	malformedProjection.Lifecycle.ExpiresAt = "2026-02-29T12:00:00Z"
	invalidEvidenceProjection := views.ProjectTrace(value)
	invalidEvidenceProjection.TraceID = invalidEvidenceID
	invalidEvidenceProjection.Evidence[0].Role = "Supporting"
	zeroCandidateProjection := views.ProjectTrace(value)
	zeroCandidateProjection.TraceID = zeroCandidateID
	zeroCandidateProjection.Confidence.CandidateCount = 0
	zeroDurationProjection := views.ProjectTrace(value)
	zeroDurationProjection.TraceID = zeroDurationID
	zeroDurationProjection.Confidence.TimeWindow = "0s0ms"
	heldWithoutHoldProjection := views.ProjectTrace(value)
	heldWithoutHoldProjection.TraceID = heldWithoutHoldID
	heldWithoutHoldProjection.Lifecycle.State = "Held"
	duplicateHoldProjection := views.ProjectTrace(value)
	duplicateHoldProjection.TraceID = duplicateHoldID
	duplicateHoldProjection.Lifecycle.State = "Held"
	duplicateHoldProjection.Lifecycle.LegalHoldIDs = []string{"hold-fixture", "hold-fixture"}
	invalidJoinProjection := views.ProjectTrace(value)
	invalidJoinProjection.TraceID = invalidJoinID
	invalidJoinProjection.Explanation.Joins[0].KeyFingerprint = ""
	invalidJoinTimeProjection := views.ProjectTrace(value)
	invalidJoinTimeProjection.TraceID = invalidJoinTimeID
	for index := range invalidJoinTimeProjection.Explanation.Joins {
		if invalidJoinTimeProjection.Explanation.Joins[index].Method == "Request ID" {
			invalidJoinTimeProjection.Explanation.Joins[index].TimeGap = "0s"
			invalidJoinTimeProjection.Explanation.Joins[index].Window = "0s"
			break
		}
	}
	duplicateJoinProjection := views.ProjectTrace(value)
	duplicateJoinProjection.TraceID = duplicateJoinID
	duplicateJoinProjection.Explanation.Joins = append(duplicateJoinProjection.Explanation.Joins, duplicateJoinProjection.Explanation.Joins[0])
	duplicateConflictProjection := views.ProjectTrace(value)
	duplicateConflictProjection.TraceID = duplicateConflictID
	duplicateConflict := duplicateConflictProjection.Conflicts[0]
	duplicateConflict.Records = reversedReferences(duplicateConflict.Records)
	duplicateConflict.Evidence = reversedReferences(duplicateConflict.Evidence)
	duplicateConflictProjection.Conflicts = append(duplicateConflictProjection.Conflicts, duplicateConflict)
	invalidConflictRecordsProjection := views.ProjectTrace(value)
	invalidConflictRecordsProjection.TraceID = invalidConflictRecordsID
	invalidConflictRecordsProjection.Conflicts[0].Records = append(invalidConflictRecordsProjection.Conflicts[0].Records, invalidConflictRecordsProjection.Conflicts[0].Records[0])
	invalidConflictEvidenceProjection := views.ProjectTrace(value)
	invalidConflictEvidenceProjection.TraceID = invalidConflictEvidenceID
	for index := range invalidConflictEvidenceProjection.Conflicts {
		if len(invalidConflictEvidenceProjection.Conflicts[index].Evidence) > 0 {
			invalidConflictEvidenceProjection.Conflicts[index].Evidence = append(invalidConflictEvidenceProjection.Conflicts[index].Evidence, invalidConflictEvidenceProjection.Conflicts[index].Evidence[0])
			break
		}
	}
	emptyConflictEvidenceProjection := views.ProjectTrace(value)
	emptyConflictEvidenceProjection.TraceID = emptyConflictEvidenceID
	for index := range emptyConflictEvidenceProjection.Conflicts {
		if emptyConflictEvidenceProjection.Conflicts[index].Kind == "CONTRADICTORY_EVIDENCE" {
			emptyConflictEvidenceProjection.Conflicts[index].Evidence = nil
			break
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/test/trace-fixture", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"trace_id":                     value.Envelope().RecordID(),
			"not_found_trace_id":           notFoundTraceID,
			"unavailable_trace_id":         unavailableTraceID,
			"malformed_trace_id":           malformedTraceID,
			"invalid_evidence_id":          invalidEvidenceID,
			"invalid_json_id":              invalidJSONID,
			"zero_candidate_id":            zeroCandidateID,
			"zero_duration_id":             zeroDurationID,
			"held_without_hold_id":         heldWithoutHoldID,
			"duplicate_hold_id":            duplicateHoldID,
			"invalid_join_id":              invalidJoinID,
			"invalid_join_time_id":         invalidJoinTimeID,
			"duplicate_join_id":            duplicateJoinID,
			"duplicate_conflict_id":        duplicateConflictID,
			"invalid_conflict_records_id":  invalidConflictRecordsID,
			"invalid_conflict_evidence_id": invalidConflictEvidenceID,
			"empty_conflict_evidence_id":   emptyConflictEvidenceID,
		})
	})
	mux.HandleFunc("GET /api/traces/"+malformedTraceID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(malformedProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidEvidenceID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invalidEvidenceProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidJSONID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{malformed"))
	})
	mux.HandleFunc("GET /api/traces/"+zeroCandidateID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(zeroCandidateProjection)
	})
	mux.HandleFunc("GET /api/traces/"+zeroDurationID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(zeroDurationProjection)
	})
	mux.HandleFunc("GET /api/traces/"+heldWithoutHoldID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(heldWithoutHoldProjection)
	})
	mux.HandleFunc("GET /api/traces/"+duplicateHoldID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(duplicateHoldProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidJoinID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invalidJoinProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidJoinTimeID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invalidJoinTimeProjection)
	})
	mux.HandleFunc("GET /api/traces/"+duplicateJoinID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(duplicateJoinProjection)
	})
	mux.HandleFunc("GET /api/traces/"+duplicateConflictID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(duplicateConflictProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidConflictRecordsID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invalidConflictRecordsProjection)
	})
	mux.HandleFunc("GET /api/traces/"+invalidConflictEvidenceID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invalidConflictEvidenceProjection)
	})
	mux.HandleFunc("GET /api/traces/"+emptyConflictEvidenceID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(emptyConflictEvidenceProjection)
	})
	mux.Handle("/", productionHandler)

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	fmt.Printf("trace E2E backend listening on http://%s\n", listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func reversedReferences(values []views.TraceReferenceView) []views.TraceReferenceView {
	result := append([]views.TraceReferenceView(nil), values...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}
