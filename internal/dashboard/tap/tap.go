// Package tap is the engine's MINIMAL data tap for the M8/M9 dashboard. It runs
// inside the engine process (which owns the live calibration/baseline state and
// the durable EventStore — and holds the bbolt write lock, so a second process
// can't open it read-only). It exposes RAW state + the scope's interaction
// events as JSON; all dashboard presentation/aggregation lives in the SEPARATE
// dashboard-backend, which consumes this tap.
//
// It never touches the engine's durable stores and never crosses a scope
// boundary (rule 5); the events it serves are already anonymized (rule 9 — only
// derived features, tier, canary type, and the socket cookie, no raw
// addresses/payloads). The ONE exception to read-only is the M9 live cost meter
// (D5): PUT /raw/attack-ledger accepts the attacker's OWN in-memory token ledger
// (see ledger.go) — no scope state, never persisted, never folded into the
// EventStore, kept strictly separate from the defender-derived proxy estimate.
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
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/sharedset"
)

// crossMatchThreshold is the similarity at/above which the current adversary flow is
// called a cross-customer "match" for the dashboard (the matcher feeds M continuously
// below this too; this is only the legible on-screen yes/no). Demo-tuned.
const crossMatchThreshold = 0.5

// Source holds the read-only handles the tap surfaces. Any may be nil (the tap
// degrades gracefully — a nil store just yields empty/zero sections).
type Source struct {
	Scope      contract.ScopeKey
	Calib      *calibration.Store
	Baseline   *baseline.Store
	Events     *boltevents.Store
	Aggregator *observebaseline.Aggregator
	SharedSet  *sharedset.Store // D6 cross-customer consumer (nil if not consuming)
	Now        func() time.Time // injectable clock (nil => time.Now)

	// ledger holds the M9 attacker's live real-cost meter — the one (small,
	// in-memory) write surface on the tap (D5). Lazily initialized in Handler.
	ledger *ledgerStore
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
	Scope         string                   `json:"scope"`
	Calibration   calibration.State        `json:"calibration"`
	Baseline      baseline.GateState       `json:"baseline"`
	Observe       observebaseline.AggStats `json:"observe"`
	CrossCustomer CrossCustomerState       `json:"cross_customer"`
	At            time.Time                `json:"at"`
}

// CrossCustomerState surfaces the D6 cross-customer network from the CONSUMER side:
// how many network-confirmed patterns this deployment has loaded, the k-of-distinct-
// enrolled-scopes provenance, and whether the CURRENT adversary flow matches one of
// those patterns (the engine's real sharedset.Match — the same similarity that feeds
// M). All zero when this deployment is not consuming the network.
type CrossCustomerState struct {
	Consuming  int     `json:"consuming"`   // # network-confirmed patterns loaded into detection
	Threshold  int     `json:"threshold"`   // k distinct ENROLLED scopes a pattern needed to cross
	FlowID     uint64  `json:"flow_id"`     // current adversary flow evaluated (0 = none)
	FlowIDHex  string  `json:"flow_id_hex"` // hex form for the dashboard
	Similarity float64 `json:"similarity"`  // best similarity of that flow to a consumed pattern [0,1]
	Matched    bool    `json:"matched"`     // similarity >= crossMatchThreshold
}

// Handler returns the tap's HTTP mux. Endpoints:
//
//	GET /raw/state                 — the live scalar state (above)
//	GET /raw/events?since_sec=N    — the scope's interaction events in the last N
//	                                 seconds (default 3600); the backend rolls
//	                                 these into tier/cost/recon views
//	GET /healthz                   — liveness
//	PUT /raw/attack-ledger         — M9 attacker posts its live real-cost meter
//	GET /raw/attack-ledger         — read the live meter (backend polls this)
func (s *Source) Handler() http.Handler {
	if s.ledger == nil {
		s.ledger = &ledgerStore{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/raw/state", s.handleState)
	mux.HandleFunc("/raw/events", s.handleEvents)
	mux.HandleFunc("/raw/attack-ledger", s.handleAttackLedger)
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
	if s.SharedSet != nil {
		cc := CrossCustomerState{Consuming: s.SharedSet.Len(), Threshold: network.AggregationThreshold}
		// Evaluate the CURRENT adversary flow against the consumed patterns with the
		// engine's real matcher (same similarity that feeds M). Only when consuming.
		if cc.Consuming > 0 && s.Events != nil {
			if cookie, ok := s.currentAdversaryFlow(now); ok {
				sim := s.SharedSet.Match(s.Scope, contract.FlowIdentity{SocketCookie: cookie}, now)
				cc.FlowID = cookie
				cc.FlowIDHex = "0x" + strconv.FormatUint(cookie, 16)
				cc.Similarity = sim
				cc.Matched = sim >= crossMatchThreshold
			}
		}
		st.CrossCustomer = cc
	}
	writeJSON(w, st)
}

// currentAdversaryFlow picks the flow to evaluate for a cross-customer match: the
// most-escalated recent flow (highest max tier, tie-broken by most recent), mirroring
// the dashboard's selectCurrentFlow. Considers only flows that reached Tier>=Contain
// (a real adversary), within the last 30 minutes. Returns its socket cookie.
func (s *Source) currentAdversaryFlow(now time.Time) (uint64, bool) {
	if s.Events == nil {
		return 0, false
	}
	evs, err := s.Events.Query(string(s.Scope), now.Add(-30*time.Minute), now)
	if err != nil || len(evs) == 0 {
		return 0, false
	}
	var bestCookie uint64
	var bestTier int
	var bestAt time.Time
	found := false
	for _, e := range evs {
		if e.Tier < 2 { // below Tier 2 (Contain) is not a committed adversary
			continue
		}
		if !found || e.Tier > bestTier || (e.Tier == bestTier && e.Timestamp.After(bestAt)) {
			bestCookie, bestTier, bestAt, found = e.FlowID, e.Tier, e.Timestamp, true
		}
	}
	return bestCookie, found
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
