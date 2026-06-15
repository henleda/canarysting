// Command siem-sink is a MOCK local SIEM receiver for the M7 demo. It accepts the
// engine's ONE-WAY SIEM webhook POSTs (internal/intelligence/siem WebhookEmitter),
// appends each event as NDJSON to a file, and serves a tiny human summary at GET / so
// the demo can SHOW the rich, ATT&CK-tagged events landing in "a SIEM".
//
// It is a DEMO AID — a stand-in for the customer's OWN SIEM/SOAR — NOT product code.
// It is deliberately one-way: it 204s the POST and never sends anything the engine
// could act on (the engine's emitter ignores the response anyway). View it via the
// dashboard SSH tunnel (add -L 9600:127.0.0.1:9600) at http://localhost:9600/, or tail
// the NDJSON file on the box.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type sink struct {
	mu       sync.Mutex
	f        *os.File
	received uint64
	first    time.Time
	lastN    []json.RawMessage // most-recent events, newest last (bounded)
}

const keepLast = 25

func (s *sink) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB/event guard
	if err != nil || len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.received == 0 {
		s.first = time.Now().UTC()
	}
	s.received++
	if _, err := s.f.Write(append(body, '\n')); err == nil {
		_ = s.f.Sync()
	}
	cp := make(json.RawMessage, len(body))
	copy(cp, body)
	s.lastN = append(s.lastN, cp)
	if len(s.lastN) > keepLast {
		s.lastN = s.lastN[len(s.lastN)-keepLast:]
	}
	s.mu.Unlock()
	// ONE-WAY: acknowledge with no actionable content.
	w.WriteHeader(http.StatusNoContent)
}

func (s *sink) handleGet(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := map[string]any{
		"sink":        "canarysting mock SIEM receiver (demo)",
		"received":    s.received,
		"first_seen":  s.first,
		"last_events": s.lastN,
		"note":        "one-way ingest; events are the engine's rich local SIEM stream (NOT the anonymized cross-customer feed)",
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func main() {
	addr := env("SIEM_SINK_ADDR", "127.0.0.1:9600")
	path := env("SIEM_SINK_FILE", "/var/lib/canarysting/siem-sink.ndjson")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("siem-sink: open %s: %v", path, err)
	}
	defer f.Close()

	s := &sink{f: f}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			s.handlePost(w, r)
		case http.MethodGet:
			s.handleGet(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	log.Printf("siem-sink: mock SIEM receiver on %s, appending NDJSON to %s", addr, path)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
