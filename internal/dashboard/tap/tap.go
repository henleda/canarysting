// Package tap is the engine's MINIMAL, read-only data tap for the M8 dashboard.
// It runs inside the engine process (which owns the live calibration/baseline
// state and the durable EventStore — and holds the bbolt write lock, so a second
// process can't open it read-only). It exposes only RAW state + the scope's
// interaction events as JSON; all dashboard presentation/aggregation lives in the
// SEPARATE dashboard-backend, which consumes this tap. It never writes anything
// and never crosses a scope boundary (rule 5); the events it serves are already
// anonymized (rule 9 — only derived features, tier, canary type, and the socket
// cookie, no raw addresses/payloads).
package tap

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/boltevents"
)

// Source holds the read-only handles the tap surfaces. Any may be nil (the tap
// degrades gracefully — a nil store just yields empty/zero sections).
type Source struct {
	Scope      contract.ScopeKey
	Calib      *calibration.Store
	Baseline   *baseline.Store
	Events     *boltevents.Store
	Aggregator *observebaseline.Aggregator
	Now        func() time.Time // injectable clock (nil => time.Now)
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// State is the live scalar state of a scope (calibration + baseline gates + the
// observe-path fold counters). Small; safe to poll frequently.
type State struct {
	Scope       string                   `json:"scope"`
	Calibration calibration.State        `json:"calibration"`
	Baseline    baseline.GateState       `json:"baseline"`
	Observe     observebaseline.AggStats `json:"observe"`
	At          time.Time                `json:"at"`
}

// Handler returns the tap's HTTP mux. Endpoints:
//
//	GET /raw/state                 — the live scalar state (above)
//	GET /raw/events?since_sec=N    — the scope's interaction events in the last N
//	                                 seconds (default 3600); the backend rolls
//	                                 these into tier/cost/recon views
//	GET /healthz                   — liveness
func (s *Source) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/raw/state", s.handleState)
	mux.HandleFunc("/raw/events", s.handleEvents)
	return mux
}

func (s *Source) handleState(w http.ResponseWriter, _ *http.Request) {
	now := s.now()
	st := State{Scope: string(s.Scope), At: now}
	if s.Calib != nil {
		st.Calibration = s.Calib.State(s.Scope)
	}
	if s.Baseline != nil {
		st.Baseline = s.Baseline.State(s.Scope, now)
	}
	if s.Aggregator != nil {
		st.Observe = s.Aggregator.Stats()
	}
	writeJSON(w, st)
}

func (s *Source) handleEvents(w http.ResponseWriter, r *http.Request) {
	sinceSec := 3600
	if v := r.URL.Query().Get("since_sec"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sinceSec = n
		}
	}
	now := s.now()
	var events []intelligence.AdversaryInteractionEvent
	if s.Events != nil {
		events, _ = s.Events.Query(string(s.Scope), now.Add(-time.Duration(sinceSec)*time.Second), now)
	}
	if events == nil {
		events = []intelligence.AdversaryInteractionEvent{}
	}
	writeJSON(w, events)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
