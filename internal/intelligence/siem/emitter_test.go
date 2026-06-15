package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNewSink_OffByDefault(t *testing.T) {
	// The zero/empty format and explicit "off" are inert (NopEmitter).
	for _, f := range []string{"", "off"} {
		e, _ := NewSink(SinkConfig{Format: f})
		if _, ok := e.(NopEmitter); !ok {
			t.Fatalf("format %q should be NopEmitter (off by default), got %T", f, e)
		}
	}
}

func TestNewSink_JSONWithoutEndpointFailsSafeToOff(t *testing.T) {
	// A network format with no endpoint must NOT guess a destination — fail safe to off.
	e, note := NewSink(SinkConfig{Format: "json", Endpoint: ""})
	if _, ok := e.(NopEmitter); !ok {
		t.Fatalf("json with no endpoint should fall back to NopEmitter, got %T (%s)", e, note)
	}
}

func TestNewSink_Selects(t *testing.T) {
	if e, _ := NewSink(SinkConfig{Format: "stdout"}); !isType[*StdoutEmitter](e) {
		t.Errorf("stdout -> %T", e)
	}
	if e, _ := NewSink(SinkConfig{Format: "cef"}); !isType[*CEFEmitter](e) {
		t.Errorf("cef -> %T", e)
	}
	if e, _ := NewSink(SinkConfig{Format: "webhook", Endpoint: "http://x"}); !isType[*WebhookEmitter](e) {
		t.Errorf("webhook -> %T", e)
	}
	// unknown format -> off (never a guess).
	if e, _ := NewSink(SinkConfig{Format: "bogus"}); !isType[NopEmitter](e) {
		t.Errorf("bogus -> %T, want NopEmitter", e)
	}
}

func isType[T any](v any) bool { _, ok := v.(T); return ok }

func TestStdoutEmitter_WritesNDJSON(t *testing.T) {
	var buf bytes.Buffer
	e := NewStdoutEmitter(&buf)
	if err := e.Emit(context.Background(), FromRecord(sampleRecord())); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(buf.String(), "\n")
	if strings.Contains(line, "\n") {
		t.Fatal("NDJSON line contains an embedded newline")
	}
	var ev SiemEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("stdout line is not valid JSON: %v", err)
	}
	if ev.EventID != "m7-window:abc123" {
		t.Fatalf("round-trip event_id = %q", ev.EventID)
	}
}

// TestWebhookEmitter_OneWayPost asserts the webhook POSTs the JSON event and that the
// receiver's RESPONSE BODY is ignored — there is no path by which the response steers
// the engine (one-way). We make the server return a body that, if parsed as control,
// would be observable; the emitter must succeed on 2xx and discard the body.
func TestWebhookEmitter_OneWayPost(t *testing.T) {
	var (
		mu       sync.Mutex
		gotBody  []byte
		gotCT    string
		gotAuth  string
		gotPath  string
		reqCount int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody, gotCT, gotAuth, gotPath = b, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), r.URL.Path
		reqCount++
		mu.Unlock()
		// A response that would matter ONLY if the emitter parsed it for control.
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"action":"DISABLE_ENGINE"}`)
	}))
	defer srv.Close()

	e := NewWebhookEmitter(srv.URL, "hectoken")
	if err := e.Emit(context.Background(), FromRecord(sampleRecord())); err != nil {
		t.Fatalf("emit: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reqCount != 1 {
		t.Fatalf("expected exactly one POST, got %d", reqCount)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotAuth != "Splunk hectoken" {
		t.Errorf("auth header = %q, want Splunk hectoken", gotAuth)
	}
	if gotPath != "/" {
		t.Errorf("path = %q", gotPath)
	}
	var ev SiemEvent
	if err := json.Unmarshal(gotBody, &ev); err != nil {
		t.Fatalf("posted body is not the JSON event: %v", err)
	}
	if ev.EventID != "m7-window:abc123" {
		t.Errorf("posted event_id = %q", ev.EventID)
	}
	// The Emitter interface itself has no return channel beyond error — structurally
	// one-way. (The {"action":"DISABLE_ENGINE"} body was discarded by construction.)
}

func TestWebhookEmitter_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	e := NewWebhookEmitter(srv.URL, "")
	if err := e.Emit(context.Background(), FromRecord(sampleRecord())); err == nil {
		t.Fatal("expected error on 5xx (so the drain's bounded retry/drop kicks in)")
	}
}

func TestNopEmitter_Inert(t *testing.T) {
	if err := (NopEmitter{}).Emit(context.Background(), FromRecord(sampleRecord())); err != nil {
		t.Fatalf("NopEmitter.Emit returned error: %v", err)
	}
}

// TestEmitterInterface_IsOneWay is a compile-time-ish assertion that the Emitter
// contract returns only (error) — no inbound control type. If someone adds a method
// returning a command/response, this documents the intent to keep it one-way.
func TestEmitterInterface_IsOneWay(t *testing.T) {
	var _ Emitter = (*StdoutEmitter)(nil)
	var _ Emitter = (*WebhookEmitter)(nil)
	var _ Emitter = (*CEFEmitter)(nil)
	var _ Emitter = NopEmitter{}
}
