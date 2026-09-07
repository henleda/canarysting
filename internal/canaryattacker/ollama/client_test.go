package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/planner"
)

func TestClientUsesOnlyPinnedLoopbackChatContract(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://203.0.113.1:9999")
	t.Setenv("HTTPS_PROXY", "http://203.0.113.1:9999")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/chat" || request.URL.RawQuery != "" {
			t.Errorf("unexpected request target: %s %s", request.Method, request.URL.String())
		}
		var payload apiRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.Model != "qwen3-coder:30b-a3b-q8_0" || payload.Stream || payload.Think || payload.KeepAlive != 0 ||
			payload.Options.Temperature != 0 || payload.Options.Seed != 7 || payload.Options.NumPredict != 128 || payload.Options.NumContext != 1024 {
			t.Errorf("unbounded request: %+v", payload)
		}
		if len(payload.Tools) != 1 || payload.Tools[0].Function.Name != "action_001" ||
			payload.Tools[0].Function.Parameters.Type != "object" || payload.Tools[0].Function.Parameters.AdditionalProperties ||
			len(payload.Tools[0].Function.Parameters.Properties) != 0 {
			t.Errorf("tool schema is not closed: %+v", payload.Tools)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(validAPIResponse("qwen3-coder:30b-a3b-q8_0", "action_001", `{}`)))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Complete(context.Background(), turnRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.Model != "qwen3-coder:30b-a3b-q8_0" || len(response.Proposals) != 1 ||
		response.Proposals[0].Name != "action_001" || string(response.Proposals[0].Arguments) != `{}` || len(response.OutputSHA256) != 64 {
		t.Fatalf("unexpected parsed response: %+v", response)
	}
}

func TestRequestAcceptsEveryPlannerActionHandle(t *testing.T) {
	request := turnRequest()
	for ordinal := 1; ordinal <= planner.AbsoluteMaxCatalogActions; ordinal++ {
		request.Tools[0].Name = fmt.Sprintf("action_%03d", ordinal)
		if _, err := buildRequest(request); err != nil {
			t.Fatalf("valid planner handle %q was rejected: %v", request.Tools[0].Name, err)
		}
	}
	for _, handle := range []string{"action_000", "action_0001", "action_1025", "action_01", "action_ab1"} {
		request.Tools[0].Name = handle
		if _, err := buildRequest(request); err == nil {
			t.Fatalf("invalid planner handle %q was accepted", handle)
		}
	}
}

func TestClientRejectsNonLoopbackAndAmbiguousEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434",
		"http://127.0.0.2:11434", "http://user@127.0.0.1:11434", "http://127.0.0.1",
		"http://127.0.0.1:11434/api", "http://127.0.0.1:11434?x=1",
	} {
		if _, err := New(endpoint); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestClientRejectsRedirects(t *testing.T) {
	marker := "response-controlled-location-marker"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/"+marker, http.StatusFound)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(context.Background(), turnRequest()); err == nil || !strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), marker) {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestClientSanitizesTransportErrors(t *testing.T) {
	client, err := New("http://127.0.0.1:11434")
	if err != nil {
		t.Fatal(err)
	}
	errMarker := "response-controlled-transport-marker"
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("%s", errMarker)
	})
	_, err = client.Complete(context.Background(), turnRequest())
	if err == nil || strings.Contains(err.Error(), errMarker) || err.Error() != "call fixed-loopback Ollama failed" {
		t.Fatalf("transport error = %v", err)
	}
}

func TestClientSanitizesResponseBodyReadErrors(t *testing.T) {
	marker := "response-controlled-body-read-marker"
	tests := map[string]struct {
		call      func(*Client) error
		wantError string
	}{
		"complete": {
			call: func(client *Client) error {
				_, err := client.Complete(context.Background(), turnRequest())
				return err
			},
			wantError: "read Ollama response failed",
		},
		"unload": {
			call: func(client *Client) error {
				return client.Unload(context.Background(), "qwen3-coder:30b-a3b-q8_0")
			},
			wantError: "read Ollama unload response failed",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := New("http://127.0.0.1:11434")
			if err != nil {
				t.Fatal(err)
			}
			client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       errorReadCloser{err: fmt.Errorf("%s", marker)},
					Request:    request,
				}, nil
			})
			err = test.call(client)
			if err == nil || strings.Contains(err.Error(), marker) || err.Error() != test.wantError {
				t.Fatalf("body read error = %v", err)
			}
		})
	}
}

func TestResponseParserFailsClosed(t *testing.T) {
	request := turnRequest()
	valid := validAPIResponse(request.Model, "action_001", `{}`)
	tests := map[string]string{
		"duplicate key": strings.Replace(valid, `"done":true`, `"done":true,"done":true`, 1),
		"unknown field": strings.Replace(valid, `"done":true`, `"unexpected":1,"done":true`, 1),
		"wrong model":   strings.Replace(valid, request.Model, "other-model", 1),
		"bad arguments": strings.Replace(valid, `"arguments":{}`, `"arguments":[]`, 1),
		"thinking":      strings.Replace(valid, `"content":""`, `"content":"","thinking":"hidden"`, 1),
		"trailing":      valid + `{}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResponse([]byte(body), request); err == nil {
				t.Fatalf("unsafe response accepted: %s", body)
			}
		})
	}
}

func TestResponseParserPreservesSurplusCallsWithinAuditBudget(t *testing.T) {
	request := turnRequest()
	request.MaxProposals = 2
	body := strings.Replace(
		validAPIResponse(request.Model, "action_001", `{}`),
		`"tool_calls":[`,
		`"tool_calls":[{"id":"call_surplus","function":{"name":"action_001","arguments":{}}},`,
		1,
	)
	response, err := parseResponse([]byte(body), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Proposals) != 2 {
		t.Fatalf("parsed proposals = %d, want 2", len(response.Proposals))
	}
	request.MaxProposals = 1
	if _, err := parseResponse([]byte(body), request); err == nil {
		t.Fatal("response beyond the remaining audit budget was accepted")
	}
}

func TestResponseParserDoesNotEchoUntrustedFieldNames(t *testing.T) {
	request := turnRequest()
	marker := "attacker-controlled-secret-marker"
	body := strings.Replace(validAPIResponse(request.Model, "action_001", `{}`), `"done":true`, `"`+marker+`":1,"done":true`, 1)
	if _, err := parseResponse([]byte(body), request); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("untrusted-field diagnostic = %v", err)
	}
}

func TestResponseParserRejectsCaseAliasedFields(t *testing.T) {
	request := turnRequest()
	valid := validAPIResponse(request.Model, "action_001", "{}")
	for name, body := range map[string]string{
		"case-fold collision": strings.Replace(valid, "\"arguments\":{}", "\"arguments\":{\"target\":\"elsewhere\"},\"Arguments\":{}", 1),
		"noncanonical alias":  strings.Replace(valid, "\"arguments\":{}", "\"Arguments\":{}", 1),
		"root alias":          strings.Replace(valid, "\"model\":\"", "\"Model\":\"", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResponse([]byte(body), request); err == nil {
				t.Fatalf("case-aliased response accepted: %s", body)
			}
		})
	}

	argumentsRemainOpaque := strings.Replace(valid, "\"arguments\":{}", "\"arguments\":{\"Target\":\"elsewhere\"}", 1)
	response, err := parseResponse([]byte(argumentsRemainOpaque), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Proposals) != 1 || string(response.Proposals[0].Arguments) != "{\"Target\":\"elsewhere\"}" {
		t.Fatalf("nonempty opaque arguments = %s", response.Proposals[0].Arguments)
	}
}

func TestCancelledRequestStopsPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Complete(ctx, turnRequest())
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
}

func TestUnloadUsesFixedGenerateEndpointWithoutPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/generate" {
			t.Errorf("unexpected unload request: %s %s", request.Method, request.URL.Path)
		}
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode unload request: %v", err)
		}
		if len(payload) != 2 || string(payload["model"]) != `"qwen3-coder:30b-a3b-q8_0"` || string(payload["keep_alive"]) != "0" {
			t.Errorf("unload request was not exact: %s", payload)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"model":"qwen3-coder:30b-a3b-q8_0","created_at":"` +
			time.Now().UTC().Format(time.RFC3339Nano) + `","response":"","done":true,"done_reason":"unload"}`))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Unload(context.Background(), "qwen3-coder:30b-a3b-q8_0"); err != nil {
		t.Fatal(err)
	}
}

func TestUnloadRejectsNonJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte(`{"model":"qwen3-coder:30b-a3b-q8_0","created_at":"` +
			time.Now().UTC().Format(time.RFC3339Nano) + `","response":"","done":true,"done_reason":"unload"}`))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Unload(context.Background(), "qwen3-coder:30b-a3b-q8_0"); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Fatalf("non-JSON unload response error = %v", err)
	}
}

func TestUnloadRejectsCaseAliasedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte("{\"model\":\"qwen3-coder:30b-a3b-q8_0\",\"created_at\":\"" +
			time.Now().UTC().Format(time.RFC3339Nano) + "\",\"response\":\"\",\"done\":false,\"Done\":true,\"done_reason\":\"unload\"}"))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Unload(context.Background(), "qwen3-coder:30b-a3b-q8_0"); err == nil {
		t.Fatal("case-aliased unload response was accepted")
	}
}

func turnRequest() planner.TurnRequest {
	return planner.TurnRequest{
		Model: "qwen3-coder:30b-a3b-q8_0", Instruction: "Use one reviewed function only.",
		Tools:           []planner.Tool{{Name: "action_001", Description: "Execute one reviewed synthetic action."}},
		MaxOutputTokens: 128, ContextTokens: 1024, MaxProposals: 1, Seed: 7,
	}
}

func validAPIResponse(model, toolName, arguments string) string {
	return `{"model":"` + model + `","created_at":"` + time.Now().UTC().Format(time.RFC3339Nano) +
		`","message":{"role":"assistant","content":"","tool_calls":[{"id":"call_fixture","function":{"name":"` + toolName +
		`","arguments":` + arguments + `}}]},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,` +
		`"prompt_eval_count":10,"prompt_eval_duration":1,"eval_count":5,"eval_duration":1}`
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type errorReadCloser struct {
	err error
}

func (reader errorReadCloser) Read([]byte) (int, error) {
	return 0, reader.err
}

func (errorReadCloser) Close() error {
	return nil
}
