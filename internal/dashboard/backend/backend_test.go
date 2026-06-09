package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
)

// fakeTap serves /raw/state and /raw/events like the real tap. failFirst forces
// the first /raw/state call to 500 to exercise graceful degradation.
func fakeTap(t *testing.T, scope string, events []intelligence.AdversaryInteractionEvent, failFirst bool) *httptest.Server {
	t.Helper()
	var calls int32
	state := views.TapState{
		Scope:       scope,
		Calibration: calibration.State{Calibrated: true, EvidenceSeen: 50, EvidenceFloor: 50},
		Baseline:    baseline.GateState{Live: true, BucketSufficient: true, Calibrated: true},
		Observe:     observebaseline.AggStats{CompletedFolds: 312},
		At:          time.Now(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/raw/state", func(w http.ResponseWriter, _ *http.Request) {
		if failFirst && atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/raw/events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if events == nil {
			events = []intelligence.AdversaryInteractionEvent{}
		}
		_ = json.NewEncoder(w).Encode(events)
	})
	return httptest.NewServer(mux)
}

func sampleEvents() []intelligence.AdversaryInteractionEvent {
	now := time.Now()
	return []intelligence.AdversaryInteractionEvent{
		{FlowID: 0x10, Tier: 1, Verdict: "tag", CanaryType: ".env", Timestamp: now.Add(-30 * time.Second)},
		{FlowID: 0x30, Tier: 3, Verdict: "jail", CanaryType: ".aws/credentials", Timestamp: now.Add(-5 * time.Second), Sting: intelligence.StingOutcome{TimeHeldSec: 40, TokenCostProxy: 400}},
	}
}

func TestBackendPollAndServe(t *testing.T) {
	tap := fakeTap(t, "test-scope", sampleEvents(), false)
	defer tap.Close()

	b := New(Config{TapBaseURL: tap.URL, PollInterval: time.Second, EventsWindow: time.Hour, Env: "staged-range"})
	if err := b.poll(time.Now()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	ov, ok := b.snapshot()
	if !ok {
		t.Fatal("snapshot not present after poll")
	}
	if ov.Scope != "test-scope" {
		t.Fatalf("scope = %q, want test-scope", ov.Scope)
	}
	if !ov.TapReachable {
		t.Fatal("TapReachable = false after successful poll")
	}
	if ov.Env != "staged-range" {
		t.Fatalf("Env = %q, want staged-range", ov.Env)
	}
	if ov.Escalation.TierLadder[0].Count != 312 {
		t.Fatalf("T0 count = %d, want 312 (CompletedFolds passthrough)", ov.Escalation.TierLadder[0].Count)
	}
	if ov.Escalation.Flow == nil || ov.Escalation.Flow.FlowID != 0x30 {
		t.Fatalf("current flow not the T3 jail flow: %+v", ov.Escalation.Flow)
	}

	// Serve via the handler and confirm valid JSON + scope passthrough.
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/overview")
	if err != nil {
		t.Fatalf("GET /api/overview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got views.Overview
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if got.Scope != "test-scope" {
		t.Fatalf("served scope = %q, want test-scope", got.Scope)
	}
}

func TestBackendTapUnreachable(t *testing.T) {
	tap := fakeTap(t, "test-scope", sampleEvents(), true) // first /raw/state -> 500
	defer tap.Close()

	b := New(Config{TapBaseURL: tap.URL, PollInterval: 10 * time.Millisecond, EventsWindow: time.Hour})

	// First poll fails (tap 500). No snapshot yet.
	if err := b.poll(time.Now()); err == nil {
		t.Fatal("expected poll error on tap 500")
	}
	ov, ok := b.snapshot()
	if ok {
		t.Fatal("snapshot should not exist after the only (failed) poll")
	}
	if ov.TapReachable {
		t.Fatal("TapReachable = true with no successful poll")
	}

	// healthz must be 503 (no good poll, stale).
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()
	hz, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	hz.Body.Close()
	if hz.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("healthz status = %d, want 503", hz.StatusCode)
	}

	// Second poll succeeds (tap now 200).
	if err := b.poll(time.Now()); err != nil {
		t.Fatalf("second poll should succeed: %v", err)
	}
	ov2, ok2 := b.snapshot()
	if !ok2 || !ov2.TapReachable {
		t.Fatalf("after recovery: ok=%v reachable=%v", ok2, ov2.TapReachable)
	}
	hz2, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz #2: %v", err)
	}
	hz2.Body.Close()
	if hz2.StatusCode != http.StatusOK {
		t.Fatalf("healthz after recovery = %d, want 200", hz2.StatusCode)
	}
}

func TestBackendTapDownAfterGoodPollStale(t *testing.T) {
	// A good poll then a failed poll: tapOK=false and lastAt is older than 2*interval.
	tap := fakeTap(t, "test-scope", sampleEvents(), false)
	b := New(Config{TapBaseURL: tap.URL, PollInterval: 10 * time.Millisecond, EventsWindow: time.Hour})
	if err := b.poll(time.Now().Add(-time.Second)); err != nil { // good poll, but timestamped 1s in the past => stale
		t.Fatalf("poll: %v", err)
	}
	tap.Close() // now the tap is gone
	if err := b.poll(time.Now()); err == nil {
		t.Fatal("expected poll error with tap closed")
	}

	srv := httptest.NewServer(b.Handler())
	defer srv.Close()
	hz, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	hz.Body.Close()
	if hz.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("healthz = %d, want 503 (tap down + stale)", hz.StatusCode)
	}

	// /api/overview still serves the last-good snapshot, marked unreachable.
	resp, err := http.Get(srv.URL + "/api/overview")
	if err != nil {
		t.Fatalf("GET /api/overview: %v", err)
	}
	defer resp.Body.Close()
	var ov views.Overview
	if err := json.NewDecoder(resp.Body).Decode(&ov); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ov.TapReachable {
		t.Fatal("TapReachable = true, want false (last-good snapshot, tap down)")
	}
	if ov.Scope != "test-scope" {
		t.Fatalf("last-good scope = %q, want test-scope", ov.Scope)
	}
}

func TestBackendHealthzOK(t *testing.T) {
	tap := fakeTap(t, "test-scope", nil, false)
	defer tap.Close()
	b := New(Config{TapBaseURL: tap.URL, PollInterval: time.Second, EventsWindow: time.Hour})
	if err := b.poll(time.Now()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", resp.StatusCode)
	}
}

// eventsFailingTap serves /raw/state with 200 (valid state) but always 500s on
// /raw/events, to exercise the events-degradation path.
func eventsFailingTap(t *testing.T, scope string) *httptest.Server {
	t.Helper()
	state := views.TapState{
		Scope:       scope,
		Calibration: calibration.State{Calibrated: true, EvidenceSeen: 50, EvidenceFloor: 50},
		Baseline:    baseline.GateState{Live: true, BucketSufficient: true, Calibrated: true},
		Observe:     observebaseline.AggStats{CompletedFolds: 312},
		At:          time.Now(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/raw/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/raw/events", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "events boom", http.StatusInternalServerError)
	})
	return httptest.NewServer(mux)
}

func TestBackendEventsDegradation(t *testing.T) {
	// /raw/state 200 but /raw/events 500: poll() returns a non-nil error, yet the
	// snapshot exists (ok=true) with TapReachable=true and all event-derived fields
	// at honest zeros.
	tap := eventsFailingTap(t, "test-scope")
	defer tap.Close()

	b := New(Config{TapBaseURL: tap.URL, PollInterval: time.Second, EventsWindow: time.Hour})
	err := b.poll(time.Now())
	if err == nil {
		t.Fatal("poll() = nil, want non-nil error (events 500)")
	}

	ov, ok := b.snapshot()
	if !ok {
		t.Fatal("snapshot not present (state poll succeeded, should have a snapshot)")
	}
	if !ov.TapReachable {
		t.Fatal("TapReachable = false, want true (state reached the tap)")
	}
	// state-derived fields present (CompletedFolds passthrough)...
	if ov.Escalation.TierLadder[0].Count != 312 {
		t.Fatalf("T0 count = %d, want 312 (state-derived, survives events failure)", ov.Escalation.TierLadder[0].Count)
	}
	// ...event-derived fields at honest zeros.
	if ov.Escalation.TierLadder[1].Count != 0 {
		t.Fatalf("ladder[1].Count = %d, want 0 (no events)", ov.Escalation.TierLadder[1].Count)
	}
	if ov.AttackerCost.TokensBurned != 0 {
		t.Fatalf("TokensBurned = %v, want 0 (no events)", ov.AttackerCost.TokensBurned)
	}
	if ov.Escalation.Flow != nil {
		t.Fatalf("Flow = %+v, want nil (no events)", ov.Escalation.Flow)
	}
}

func TestBackendHealthzFreshButTapDown(t *testing.T) {
	// One good poll (fresh: lastAt = now), then the tap goes down. poll() fails
	// (tapOK=false) but the last good poll is within 2*PollInterval, so /healthz
	// must still return 200 (fresh, not stale).
	tap := fakeTap(t, "test-scope", sampleEvents(), false)
	b := New(Config{TapBaseURL: tap.URL, PollInterval: time.Hour, EventsWindow: time.Hour})
	if err := b.poll(time.Now()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	tap.Close() // tap is now gone
	if err := b.poll(time.Now()); err == nil {
		t.Fatal("expected poll error with tap closed")
	}

	srv := httptest.NewServer(b.Handler())
	defer srv.Close()
	hz, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer hz.Body.Close()
	if hz.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d, want 200 (tap down but last good poll is fresh)", hz.StatusCode)
	}
}

func TestBackendSSE(t *testing.T) {
	tap := fakeTap(t, "test-scope", sampleEvents(), false)
	defer tap.Close()

	b := New(Config{TapBaseURL: tap.URL, PollInterval: 50 * time.Millisecond, EventsWindow: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	srv := httptest.NewServer(b.Handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stream: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	reader := bufio.NewReader(resp.Body)
	frames := 0
	deadline := time.After(5 * time.Second)
	for frames < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out after %d overview frames", frames)
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE line: %v", err)
		}
		if strings.HasPrefix(line, "event: overview") {
			data, err := reader.ReadString('\n') // the data: line
			if err != nil {
				t.Fatalf("read SSE data line: %v", err)
			}
			payload := strings.TrimPrefix(strings.TrimSpace(data), "data: ")
			var ov views.Overview
			if err := json.Unmarshal([]byte(payload), &ov); err != nil {
				t.Fatalf("SSE frame not valid Overview JSON: %v (%q)", err, payload)
			}
			if ov.Scope != "test-scope" {
				t.Fatalf("SSE overview scope = %q, want test-scope", ov.Scope)
			}
			// The frame must terminate with the blank separator line: after the
			// data: line, the next read returns exactly "\n" (the \n\n terminator).
			sep, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read SSE separator line: %v", err)
			}
			if sep != "\n" {
				t.Fatalf("SSE frame separator = %q, want %q (\\n\\n terminator)", sep, "\n")
			}
			frames++
		}
	}
	cancel()
}
