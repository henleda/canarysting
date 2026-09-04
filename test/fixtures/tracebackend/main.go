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
	listenAddress      = "127.0.0.1:3102"
	notFoundTraceID    = "trace:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	unavailableTraceID = "trace:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	malformedTraceID   = "trace:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	invalidEvidenceID  = "trace:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	invalidJSONID      = "trace:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	zeroCandidateID    = "trace:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	zeroDurationID     = "trace:sha256:1111111111111111111111111111111111111111111111111111111111111111"
	heldWithoutHoldID  = "trace:sha256:2222222222222222222222222222222222222222222222222222222222222222"
	duplicateHoldID    = "trace:sha256:3333333333333333333333333333333333333333333333333333333333333333"
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/test/trace-fixture", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"trace_id":             value.Envelope().RecordID(),
			"not_found_trace_id":   notFoundTraceID,
			"unavailable_trace_id": unavailableTraceID,
			"malformed_trace_id":   malformedTraceID,
			"invalid_evidence_id":  invalidEvidenceID,
			"invalid_json_id":      invalidJSONID,
			"zero_candidate_id":    zeroCandidateID,
			"zero_duration_id":     zeroDurationID,
			"held_without_hold_id": heldWithoutHoldID,
			"duplicate_hold_id":    duplicateHoldID,
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
