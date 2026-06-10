package attacker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestExecuteReusesOneConnection is the load-bearing keepalive proof: two
// consecutive Execute calls must travel over a SINGLE TCP connection. A new
// connection per request would mean a new socket cookie and lost escalation.
func TestExecuteReusesOneConnection(t *testing.T) {
	var newConns int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok %s", r.URL.Path)
	}))
	// Count distinct TCP connections the server accepts via the ConnState hook.
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt64(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	client, err := BuildKeepAliveClient("") // no src-ip bind in unit test
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	tool := NewHTTPTool(client, srv.URL)

	for _, p := range []string{"/.env", "/.aws/credentials"} {
		res, isErr, probe := tool.Execute(context.Background(), fmt.Sprintf(`{"method":"GET","path":%q}`, p))
		if isErr {
			t.Fatalf("unexpected tool error for %s: %s", p, res)
		}
		if probe.StatusCode != 200 {
			t.Fatalf("want 200 for %s, got %d", p, probe.StatusCode)
		}
		if !strings.Contains(res, "ok "+p) {
			t.Fatalf("body not echoed for %s: %s", p, res)
		}
	}

	if got := atomic.LoadInt64(&newConns); got != 1 {
		t.Fatalf("keepalive broken: want 1 TCP connection across two requests, got %d", got)
	}
}

// TestExecuteRejectsBadPath confirms a path without a leading slash is a
// non-fatal tool error.
func TestExecuteRejectsBadPath(t *testing.T) {
	client, _ := BuildKeepAliveClient("")
	tool := NewHTTPTool(client, "http://127.0.0.1:1")
	res, isErr, _ := tool.Execute(context.Background(), `{"method":"GET","path":"no-slash"}`)
	if !isErr {
		t.Fatalf("want isError for bad path, got ok: %s", res)
	}
}

// TestExecuteBadJSON confirms malformed tool input is a non-fatal tool error.
func TestExecuteBadJSON(t *testing.T) {
	client, _ := BuildKeepAliveClient("")
	tool := NewHTTPTool(client, "http://127.0.0.1:1")
	res, isErr, _ := tool.Execute(context.Background(), `{not json`)
	if !isErr {
		t.Fatalf("want isError for bad JSON, got ok: %s", res)
	}
}

// TestExecuteReadsFullBodyOverCap verifies the body is read to completion even
// past the preview cap (required for connection reuse) and the byte count
// reflects the full read up to bodyReadCap.
func TestExecuteReadsLargeBody(t *testing.T) {
	const n = 50 << 10 // 50 KiB, under bodyReadCap but well over the preview cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", n)))
	}))
	defer srv.Close()

	client, _ := BuildKeepAliveClient("")
	tool := NewHTTPTool(client, srv.URL)
	res, isErr, probe := tool.Execute(context.Background(), `{"method":"GET","path":"/big"}`)
	if isErr {
		t.Fatalf("unexpected error: %s", res)
	}
	if probe.Bytes != n {
		t.Fatalf("want %d bytes read, got %d", n, probe.Bytes)
	}
	if len(res) > resultPreviewCap+128 { // preview + the "HTTP 200 | N bytes | " prefix
		t.Fatalf("result string not bounded by preview cap: len=%d", len(res))
	}
}
