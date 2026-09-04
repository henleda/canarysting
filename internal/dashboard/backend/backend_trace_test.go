package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canarysting/canarysting/internal/canaryview/trace"
	"github.com/canarysting/canarysting/internal/canaryview/tracefixture"
	"github.com/canarysting/canarysting/internal/dashboard/backend/views"
)

type staticTraceSource struct {
	value trace.Trace
	err   error
}

func (s staticTraceSource) GetTrace(context.Context, string) (trace.Trace, error) {
	return s.value, s.err
}

func TestTraceWorkspaceAPIProjectsCanonicalTrace(t *testing.T) {
	value, err := tracefixture.OperatorConflict()
	if err != nil {
		t.Fatal(err)
	}
	b := New(Config{TraceSource: staticTraceSource{value: value}})
	req := httptest.NewRequest(http.MethodGet, "/api/traces/"+value.Envelope().RecordID(), nil)
	rec := httptest.NewRecorder()

	b.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	var got views.TraceWorkspace
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TraceID != value.Envelope().RecordID() || got.Explanation.Claim == "" || len(got.Evidence) == 0 {
		t.Fatalf("workspace = %#v", got)
	}
}

func TestTraceWorkspaceAPIRejectsInvalidAndUnavailableRequests(t *testing.T) {
	value, err := tracefixture.OperatorConflict()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		path   string
		source TraceSource
		want   int
	}{
		{name: "invalid id", path: "/api/traces/not-a-trace", source: staticTraceSource{}, want: http.StatusBadRequest},
		{name: "scope selector", path: "/api/traces/trace:sha256:" + repeatHex("a") + "?scope=other", source: staticTraceSource{value: value}, want: http.StatusBadRequest},
		{name: "tenant selector", path: "/api/traces/trace:sha256:" + repeatHex("a") + "?tenant=other", source: staticTraceSource{value: value}, want: http.StatusBadRequest},
		{name: "source absent", path: "/api/traces/trace:sha256:" + repeatHex("a"), want: http.StatusServiceUnavailable},
		{name: "not found", path: "/api/traces/trace:sha256:" + repeatHex("b"), source: staticTraceSource{err: trace.ErrNotFound}, want: http.StatusNotFound},
		{name: "source failed", path: "/api/traces/trace:sha256:" + repeatHex("c"), source: staticTraceSource{err: errors.New("query failed")}, want: http.StatusServiceUnavailable},
		{name: "mismatched record", path: "/api/traces/trace:sha256:" + repeatHex("d"), source: staticTraceSource{value: value}, want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := New(Config{TraceSource: test.source})
			rec := httptest.NewRecorder()
			b.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, test.path, nil))
			if rec.Code != test.want {
				t.Fatalf("status = %d want %d body=%s", rec.Code, test.want, rec.Body.String())
			}
		})
	}
}

func repeatHex(value string) string {
	const digestLength = 64
	result := ""
	for len(result) < digestLength {
		result += value
	}
	return result
}
