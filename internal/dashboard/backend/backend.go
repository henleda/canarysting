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

	b.mu.Lock()
	b.last = &ov
	b.lastAt = now
	b.tapOK = true
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

func (b *Backend) fetchEvents() ([]intelligence.AdversaryInteractionEvent, error) {
	sinceSec := int(b.cfg.EventsWindow.Seconds())
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
	return mux
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
