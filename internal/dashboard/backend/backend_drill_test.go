package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
	"github.com/canarysting/canarysting/internal/intelligence"
)

func drillEvents() []intelligence.AdversaryInteractionEvent {
	now := time.Now()
	return []intelligence.AdversaryInteractionEvent{
		{FlowID: 0x10, Tier: 1, Verdict: "tag", CanaryType: ".env", Timestamp: now.Add(-90 * time.Second), Score: 1},
		{FlowID: 0x10, Tier: 2, Verdict: "contain", CanaryType: ".aws/credentials", Timestamp: now.Add(-60 * time.Second), Score: 2,
			Sting: intelligence.StingOutcome{Mechanism: "fake_tree", TimeHeldSec: 8, BytesServed: 8000, RequestsAbsrb: 2, TokenCostProxy: 2000}},
		{FlowID: 0x30, Tier: 3, Verdict: "jail", CanaryType: ".env", Timestamp: now.Add(-30 * time.Second), Score: 5},
	}
}

// drillTap serves /raw/state + /raw/events; failEvents flips /raw/events to 500.
func drillTap(t *testing.T, evs []intelligence.AdversaryInteractionEvent, failEvents *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/raw/state", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(views.TapState{Scope: "m7-window", At: time.Now()})
	})
	mux.HandleFunc("/raw/events", func(w http.ResponseWriter, _ *http.Request) {
		if failEvents != nil && atomic.LoadInt32(failEvents) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(evs)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func getJSON(t *testing.T, srv *Backend, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func TestServeFlowDetail(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	var d views.FlowDetail
	if code := getJSON(t, b, "/api/flow/0x10?since=1h", &d); code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if d.FlowIDHex != "0x10" || d.PeakTier != 2 || len(d.Timeline) != 2 {
		t.Fatalf("flow detail wrong: %+v", d)
	}
}

func TestServeFlowDetailInvalidCookie(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	if code := getJSON(t, b, "/api/flow/zzz?since=1h", nil); code != 400 {
		t.Fatalf("want 400 for bad cookie, got %d", code)
	}
}

func TestServeFlowDetailNotFound(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	if code := getJSON(t, b, "/api/flow/0x999?since=1h", nil); code != 404 {
		t.Fatalf("want 404 for unknown cookie, got %d", code)
	}
}

func TestServeFlowsListAndTierFilter(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	var fl views.FlowsList
	getJSON(t, b, "/api/flows?since=1h", &fl)
	if fl.TotalCount != 2 || len(fl.Flows) != 2 {
		t.Fatalf("want 2 sessions, got %+v", fl)
	}
	var t3 views.FlowsList
	getJSON(t, b, "/api/flows?since=1h&tier=3", &t3)
	if t3.Filtered != 1 || t3.Flows[0].PeakTier != 3 {
		t.Fatalf("tier filter wrong: %+v", t3)
	}
}

func TestServeCostBreakdown(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	var cb views.CostBreakdown
	getJSON(t, b, "/api/cost?since=1h", &cb)
	if cb.Total.TimeHeldSec != 8 || cb.Total.TokenCost != 2000 {
		t.Fatalf("cost total wrong: %+v", cb.Total)
	}
	if len(cb.ByMechanism) != 1 || cb.ByMechanism[0].Mechanism != "fake_tree" {
		t.Fatalf("by-mechanism wrong: %+v", cb.ByMechanism)
	}
}

func TestServeReconTimeline(t *testing.T) {
	tap := drillTap(t, drillEvents(), nil)
	b := New(Config{TapBaseURL: tap.URL})
	var rt views.ReconTimeline
	getJSON(t, b, "/api/recon?since=1h", &rt)
	if rt.TotalRecon != 1 { // one T1 event (0x10's first touch)
		t.Fatalf("want 1 recon row, got %+v", rt)
	}
	if !rt.Rows[0].Escalated || rt.Rows[0].EscalatedTier != 2 {
		t.Fatalf("0x10 recon should be escalated to T2: %+v", rt.Rows[0])
	}
}

func TestServeDrillDownFallsBackToCacheOnTapError(t *testing.T) {
	var fail int32
	tap := drillTap(t, drillEvents(), &fail)
	b := New(Config{TapBaseURL: tap.URL})
	// one successful poll populates the cache
	if err := b.poll(time.Now()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	// now make the tap fail; the handler should fall back to the cache
	atomic.StoreInt32(&fail, 1)
	var fl views.FlowsList
	if code := getJSON(t, b, "/api/flows?since=1h", &fl); code != 200 {
		t.Fatalf("want 200 via cache fallback, got %d", code)
	}
	if fl.TotalCount != 2 {
		t.Fatalf("cache fallback events wrong: %+v", fl)
	}
}

func TestServeDrillDownNoTapNoCache503(t *testing.T) {
	var fail int32 = 1
	tap := drillTap(t, drillEvents(), &fail) // events always 500, never polled
	b := New(Config{TapBaseURL: tap.URL})
	if code := getJSON(t, b, "/api/flows?since=1h", nil); code != 503 {
		t.Fatalf("want 503 with no tap and no cache, got %d", code)
	}
}

func TestParseSince(t *testing.T) {
	mk := func(q string) *http.Request {
		u, _ := url.Parse("/x?" + q)
		return &http.Request{URL: u}
	}
	def := time.Hour
	cases := []struct {
		q    string
		want int
	}{
		{"since=30m", 1800},
		{"since=2h", 7200},
		{"since=900", 900},
		{"", 3600},
		{"since=garbage", 3600},
		{"since=-5m", 3600},
		{"since=24h", 86400},       // exactly the cap (decision E)
		{"since=48h", 86400},       // over-range duration clamped to 24h
		{"since=999999999", 86400}, // over-range integer seconds clamped too
	}
	for _, c := range cases {
		if got := parseSince(mk(c.q), def); got != c.want {
			t.Errorf("parseSince(%q) = %d, want %d", c.q, got, c.want)
		}
	}
}
