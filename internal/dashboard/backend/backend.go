// Package backend is the read-only dashboard-backend service. It polls the
// engine tap (internal/dashboard/tap) over HTTP, derives the Overview view tree
// (internal/dashboard/backend/views), caches the last-good snapshot, and serves
// it to the Next.js frontend over JSON + SSE. It NEVER writes anything and never
// imports a store/persist/contract/adapter/bpf package — it talks to the engine
// only via HTTP GETs to the tap, so read-only is enforced by construction.
package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
	"github.com/canarysting/canarysting/internal/intelligence"
)

const (
	defaultPollInterval = 5 * time.Second
	defaultEventsWindow = time.Hour
	httpClientTimeout   = 4 * time.Second // < poll interval so a slow tap can't stall the loop
	sseHeartbeat        = 15 * time.Second
)

// Config configures a Backend.
type Config struct {
	TapBaseURL   string        // e.g. "http://127.0.0.1:8088"
	PollInterval time.Duration // default 5s
	EventsWindow time.Duration // default 1h; passed as since_sec to the tap
	HTTPClient   *http.Client  // nil => default with a 4s timeout
	Env          string        // free-form environment label surfaced in the topbar
}

// Backend polls the tap and serves the dashboard API.
type Backend struct {
	cfg    Config
	client *http.Client

	mu     sync.RWMutex
	last   *views.Overview // last successfully derived snapshot; nil until first poll
	lastAt time.Time       // wall time of the last SUCCESSFUL poll
	tapOK  bool            // whether the most recent poll reached the tap
	// lastEvents is the raw event slice from the most recent successful poll —
	// the fallback for drill-down handlers when a per-request tap fetch fails.
	lastEvents []intelligence.AdversaryInteractionEvent

	subsMu sync.Mutex
	subs   map[chan struct{}]struct{} // SSE subscriber notification channels
}

// New constructs a Backend from cfg, applying defaults. It does not start polling.
func New(cfg Config) *Backend {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.EventsWindow <= 0 {
		cfg.EventsWindow = defaultEventsWindow
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: httpClientTimeout}
	}
	return &Backend{
		cfg:    cfg,
		client: client,
		subs:   make(map[chan struct{}]struct{}),
	}
}

// Run starts the poll loop. It polls once immediately, then on each tick, and
// blocks until ctx is cancelled.
func (b *Backend) Run(ctx context.Context) {
	if err := b.poll(time.Now()); err != nil {
		log.Printf("dashboard-backend: initial poll failed: %v", err)
	}
	t := time.NewTicker(b.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := b.poll(now); err != nil {
				log.Printf("dashboard-backend: poll failed: %v", err)
			}
		}
	}
}

// poll fetches /raw/state + /raw/events from the tap, derives the Overview, and
// atomically swaps the cached snapshot, then notifies SSE subscribers. On tap
// failure it keeps the last-good snapshot, marks TapReachable=false on a degraded
// copy, and does NOT notify subscribers (no fresh data to push).
func (b *Backend) poll(now time.Time) error {
	state, errState := b.fetchState()
	if errState != nil {
		b.markTapDown()
		return fmt.Errorf("fetch state: %w", errState)
	}
	events, errEvents := b.fetchEvents()
	if errEvents != nil {
		// State succeeded; degrade gracefully with empty events (honest zeros).
		events = nil
	}

	ov := views.Derive(state, events, now)
	ov.Env = b.cfg.Env
	// The M9 live cost meter comes from a SEPARATE tap endpoint (not state/events),
	// so it's merged in after Derive. Best-effort: a missing/failed ledger just
	// leaves Present=false (honest "attack not running").
	ov.RealAttackCost = b.fetchLedger()

	b.mu.Lock()
	b.last = &ov
	b.lastAt = now
	b.tapOK = true
	b.lastEvents = events // shallow copy is safe: events are value types, read-only downstream
	b.mu.Unlock()

	b.notify()

	if errEvents != nil {
		return fmt.Errorf("fetch events: %w", errEvents)
	}
	return nil
}

func (b *Backend) markTapDown() {
	b.mu.Lock()
	b.tapOK = false
	b.mu.Unlock()
}

func (b *Backend) fetchState() (views.TapState, error) {
	var st views.TapState
	body, err := b.get(b.cfg.TapBaseURL + "/raw/state")
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return st, fmt.Errorf("decode state: %w", err)
	}
	return st, nil
}

// fetchEvents fetches the configured default window (used by poll()).
func (b *Backend) fetchEvents() ([]intelligence.AdversaryInteractionEvent, error) {
	return b.fetchEventsWindow(int(b.cfg.EventsWindow.Seconds()))
}

// fetchEventsWindow fetches the scope's events over the last sinceSec seconds.
// Drill-down handlers call this per request with the ?since= window.
func (b *Backend) fetchEventsWindow(sinceSec int) ([]intelligence.AdversaryInteractionEvent, error) {
	if sinceSec < 1 {
		sinceSec = 1
	}
	u := b.cfg.TapBaseURL + "/raw/events?since_sec=" + strconv.Itoa(sinceSec)
	body, err := b.get(u)
	if err != nil {
		return nil, err
	}
	var events []intelligence.AdversaryInteractionEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}
	return events, nil
}

// cachedEvents returns the last poll's events as a fallback when a per-request
// tap fetch fails. ok=false if no successful poll has happened yet.
func (b *Backend) cachedEvents() ([]intelligence.AdversaryInteractionEvent, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.lastEvents == nil {
		return nil, false
	}
	out := make([]intelligence.AdversaryInteractionEvent, len(b.lastEvents))
	copy(out, b.lastEvents)
	return out, true
}

// fetchLedger polls the tap's attack-ledger for the M9 live cost meter. It is
// best-effort and never fails the poll: any error (endpoint absent on an older
// tap, transport failure, "not present" body) yields a zero view with
// Present=false. The decode struct is local — the backend reaches the tap only
// over HTTP and does not import the tap package.
func (b *Backend) fetchLedger() views.RealAttackCostView {
	body, err := b.get(b.cfg.TapBaseURL + "/raw/attack-ledger")
	if err != nil {
		return views.RealAttackCostView{}
	}
	var led struct {
		Present             *bool   `json:"present"` // set to false by the tap when no run yet
		InputTokens         int64   `json:"input_tokens"`
		OutputTokens        int64   `json:"output_tokens"`
		CacheReadTokens     int64   `json:"cache_read_tokens"`
		CacheCreationTokens int64   `json:"cache_creation_tokens"`
		USD                 float64 `json:"usd"`
		HardCapUSD          float64 `json:"hard_cap_usd"`
		Model               string  `json:"model"`
		Active              bool    `json:"active"`
	}
	if err := json.Unmarshal(body, &led); err != nil {
		return views.RealAttackCostView{}
	}
	if led.Present != nil && !*led.Present {
		return views.RealAttackCostView{} // tap explicitly reports no run yet
	}
	capFrac := 0.0
	if led.HardCapUSD > 0 {
		capFrac = led.USD / led.HardCapUSD
		if capFrac > 1 {
			capFrac = 1
		}
		if capFrac < 0 {
			capFrac = 0
		}
	}
	return views.RealAttackCostView{
		Present:             true,
		Active:              led.Active,
		Model:               led.Model,
		InputTokens:         led.InputTokens,
		OutputTokens:        led.OutputTokens,
		CacheReadTokens:     led.CacheReadTokens,
		CacheCreationTokens: led.CacheCreationTokens,
		TotalTokens:         led.InputTokens + led.OutputTokens + led.CacheReadTokens + led.CacheCreationTokens,
		USD:                 led.USD,
		HardCapUSD:          led.HardCapUSD,
		CapFraction:         capFrac,
	}
}

func (b *Backend) get(rawURL string) ([]byte, error) {
	if _, err := url.Parse(rawURL); err != nil {
		return nil, fmt.Errorf("bad url %q: %w", rawURL, err)
	}
	resp, err := b.client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tap returned status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// snapshot returns a copy of the last-good Overview with TapReachable reflecting
// the current tap health, plus whether any snapshot exists yet.
func (b *Backend) snapshot() (views.Overview, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.last == nil {
		return views.Overview{Env: b.cfg.Env, TapReachable: false}, false
	}
	ov := *b.last
	ov.TapReachable = b.tapOK
	return ov, true
}

// Handler returns the dashboard API mux: GET /api/overview, GET /api/stream,
// GET /healthz.
func (b *Backend) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", b.serveOverview)
	mux.HandleFunc("/api/stream", b.serveStream)
	mux.HandleFunc("/healthz", b.serveHealthz)
	// Interactive console drill-downs (Go 1.22+ method+pattern routing).
	mux.HandleFunc("GET /api/flow/{cookie}", b.serveFlowDetail)
	mux.HandleFunc("GET /api/flows", b.serveFlowsList)
	mux.HandleFunc("GET /api/cost", b.serveCostBreakdown)
	mux.HandleFunc("GET /api/recon", b.serveReconTimeline)
	return mux
}

// drillEvents resolves the events for a drill-down request: a per-request tap
// fetch over the ?since= window, falling back to the last poll's cache if the tap
// is unreachable. Returns ok=false (caller writes 503) only when both fail.
//
// effectiveSec is the window the returned events ACTUALLY cover. It equals
// sinceSec on the normal path, but on a cache fallback it drops to the poll
// window (cfg.EventsWindow) when that is narrower than the request — so the
// handler can signal the UI that the view is degraded rather than silently
// render a 1h slice under a "24h" label. The data itself is never fabricated.
func (b *Backend) drillEvents(sinceSec int) (events []intelligence.AdversaryInteractionEvent, ok bool, effectiveSec int) {
	if ev, err := b.fetchEventsWindow(sinceSec); err == nil {
		return ev, true, sinceSec
	}
	ev, ok := b.cachedEvents()
	if !ok {
		return nil, false, 0
	}
	effectiveSec = sinceSec
	if cacheSec := int(b.cfg.EventsWindow.Seconds()); cacheSec < sinceSec {
		effectiveSec = cacheSec
		log.Printf("dashboard-backend: tap unreachable; drill served from %s poll cache (requested %ds)",
			b.cfg.EventsWindow, sinceSec)
	}
	return ev, true, effectiveSec
}

// setWindowHeader tells the client the data covers a narrower window than asked
// (cache fallback). The drill pages render this as a faint "showing cached Nh"
// note so the time-range label never overstates the data.
func setWindowHeader(w http.ResponseWriter, requested, effective int) {
	if effective < requested {
		w.Header().Set("X-CS-Effective-Window-Sec", strconv.Itoa(effective))
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (b *Backend) serveFlowDetail(w http.ResponseWriter, r *http.Request) {
	cookie := r.PathValue("cookie")
	id, err := strconv.ParseUint(strings.TrimPrefix(cookie, "0x"), 16, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid cookie")
		return
	}
	var sessionSel int64
	if s := r.URL.Query().Get("session"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			sessionSel = n
		}
	}
	sinceSec := parseSince(r, b.cfg.EventsWindow)
	events, ok, effSec := b.drillEvents(sinceSec)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tap unreachable and no cached events")
		return
	}
	d := views.DeriveFlowDetail(id, events, time.Now(), sessionSel)
	if d == nil {
		writeErr(w, http.StatusNotFound, "flow not found")
		return
	}
	setWindowHeader(w, sinceSec, effSec)
	writeJSON(w, d)
}

func (b *Backend) serveFlowsList(w http.ResponseWriter, r *http.Request) {
	tier := -1
	if t := r.URL.Query().Get("tier"); t != "" {
		if n, err := strconv.Atoi(t); err == nil {
			tier = n
		}
	}
	sinceSec := parseSince(r, b.cfg.EventsWindow)
	events, ok, effSec := b.drillEvents(sinceSec)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tap unreachable and no cached events")
		return
	}
	setWindowHeader(w, sinceSec, effSec)
	writeJSON(w, views.DeriveFlowsList(events, tier))
}

func (b *Backend) serveCostBreakdown(w http.ResponseWriter, r *http.Request) {
	sinceSec := parseSince(r, b.cfg.EventsWindow)
	events, ok, effSec := b.drillEvents(sinceSec)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tap unreachable and no cached events")
		return
	}
	setWindowHeader(w, sinceSec, effSec)
	writeJSON(w, views.DeriveCostBreakdown(events, time.Now(), views.BucketDurFor(sinceSec)))
}

func (b *Backend) serveReconTimeline(w http.ResponseWriter, r *http.Request) {
	sinceSec := parseSince(r, b.cfg.EventsWindow)
	events, ok, effSec := b.drillEvents(sinceSec)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tap unreachable and no cached events")
		return
	}
	setWindowHeader(w, sinceSec, effSec)
	writeJSON(w, views.DeriveReconTimeline(events, time.Now()))
}

// maxSinceSec is the cookie-reuse-safe upper bound on the drill-down window
// (decision E: max selectable 24h). The frontend pills only offer up to 24h, but
// the endpoints are hand-craftable / deep-linkable, so the cap is enforced here
// too — over-range is clamped (not silently honored) so the window the UI labels
// always matches the data, and the cost-bucket count can't blow past its cap.
const maxSinceSec = 24 * 60 * 60

// parseSince resolves the ?since= window (Go duration string OR integer seconds,
// relative — decision C) to seconds, defaulting to def, clamped to [1, maxSinceSec].
func parseSince(r *http.Request, def time.Duration) int {
	secs := int(def.Seconds())
	v := r.URL.Query().Get("since")
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		secs = int(d.Seconds())
	} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
		secs = n
	}
	return clampSince(secs)
}

func clampSince(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxSinceSec {
		return maxSinceSec
	}
	return n
}

func (b *Backend) serveOverview(w http.ResponseWriter, _ *http.Request) {
	ov, _ := b.snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(ov)
}

func (b *Backend) serveHealthz(w http.ResponseWriter, _ *http.Request) {
	b.mu.RLock()
	tapOK := b.tapOK
	lastAt := b.lastAt
	hadPoll := b.last != nil
	b.mu.RUnlock()

	stale := !hadPoll || time.Since(lastAt) > 2*b.cfg.PollInterval
	if !tapOK && stale {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("tap unreachable\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

// serveStream streams the cached Overview as SSE: one `event: overview` frame on
// each poll tick, plus a `: keep-alive` heartbeat every 15s. One-way push.
func (b *Backend) serveStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := b.subscribe()
	defer b.unsubscribe(ch)

	// Send the current snapshot immediately if we have one.
	if _, ok := b.snapshot(); ok {
		if err := b.writeOverviewEvent(w, flusher); err != nil {
			return
		}
		// Drain one pending notify (non-blocking): if a poll signalled this
		// subscriber between subscribe() and the initial frame, the buffered tick
		// would otherwise immediately re-send the same Overview. Dropping exactly
		// one tick here avoids that back-to-back duplicate without a data race.
		select {
		case <-ch:
		default:
		}
	}

	hb := time.NewTicker(sseHeartbeat)
	defer hb.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := b.writeOverviewEvent(w, flusher); err != nil {
				return
			}
		case <-hb.C:
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (b *Backend) writeOverviewEvent(w http.ResponseWriter, flusher http.Flusher) error {
	ov, _ := b.snapshot()
	payload, err := json.Marshal(ov) // single line: json.Marshal has no embedded newlines
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: overview\ndata: %s\n\n", payload); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func (b *Backend) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	b.subsMu.Lock()
	b.subs[ch] = struct{}{}
	b.subsMu.Unlock()
	return ch
}

func (b *Backend) unsubscribe(ch chan struct{}) {
	b.subsMu.Lock()
	delete(b.subs, ch)
	b.subsMu.Unlock()
}

// notify does a non-blocking signal to each subscriber; a slow subscriber simply
// misses a tick (channel buffered(1)) but never blocks the poll loop.
func (b *Backend) notify() {
	b.subsMu.Lock()
	defer b.subsMu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
