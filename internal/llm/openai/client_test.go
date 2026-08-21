package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/attacker"
)

// fakeOpenAI is an in-process OpenAI-compatible server: it records each request
// body and returns queued raw JSON responses in order (mirrors the anthropic
// FakeClient/httptest style). Path is ignored so /v1/chat/completions matches.
type fakeOpenAI struct {
	mu        sync.Mutex
	requests  []openAIRequest
	responses []string
	i         int
}

func newFakeOpenAI(t *testing.T, responses ...string) (*httptest.Server, *fakeOpenAI) {
	t.Helper()
	f := &fakeOpenAI{responses: responses}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req openAIRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.requests = append(f.requests, req)
		var resp string
		if f.i < len(f.responses) {
			resp = f.responses[f.i]
			f.i++
		} else {
			resp = `{"id":"end","choices":[{"index":0,"message":{"role":"assistant","content":"(no more)"},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0}}`
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeOpenAI) req(i int) openAIRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[i]
}

// toolParam mirrors the agent's single http_request tool for building params.
func toolParam() sdk.ToolParam {
	return sdk.ToolParam{
		Name:        "http_request",
		Description: sdk.String("probe the target"),
		InputSchema: sdk.ToolInputSchemaParam{
			Properties: map[string]any{
				"method": map[string]any{"type": "string"},
				"path":   map[string]any{"type": "string"},
			},
			Required: []string{"method", "path"},
		},
	}
}

// TestClientNew_ToolCallResponse drives one New() against the fake server and
// asserts (a) the OUTBOUND request is OpenAI-shaped (system+user messages, the
// http_request tool, tool_choice auto) and (b) the tool_call + usage translate
// back into an *sdk.Message the agent reads.
func TestClientNew_ToolCallResponse(t *testing.T) {
	toolResp := `{
		"id":"chatcmpl-1","object":"chat.completion","model":"llama3.1",
		"choices":[{"index":0,"message":{"role":"assistant","content":null,
			"tool_calls":[{"id":"call_abc","type":"function","function":{"name":"http_request","arguments":"{\"method\":\"GET\",\"path\":\"/.env\"}"}}]},
			"finish_reason":"tool_calls"}],
		"usage":{"prompt_tokens":123,"completion_tokens":45,"total_tokens":168}
	}`
	srv, fake := newFakeOpenAI(t, toolResp)
	client := NewWithHTTPClient(srv.URL+"/v1", "", srv.Client())

	tp := toolParam()
	params := sdk.MessageNewParams{
		Model:     sdk.Model("llama3.1"),
		MaxTokens: 16000,
		System:    []sdk.TextBlockParam{{Text: "SYSTEM", CacheControl: sdk.NewCacheControlEphemeralParam()}},
		Messages:  []sdk.MessageParam{sdk.NewUserMessage(sdk.NewTextBlock("begin"))},
		Tools:     []sdk.ToolUnionParam{{OfTool: &tp}},
	}

	msg, err := client.New(context.Background(), params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) outbound request shape
	req := fake.req(0)
	if len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[1].Role != "user" {
		t.Fatalf("outbound messages not system+user: %+v", req.Messages)
	}
	if req.Messages[0].Content != "SYSTEM" || req.Messages[1].Content != "begin" {
		t.Fatalf("outbound message content wrong: %+v", req.Messages)
	}
	if len(req.Tools) != 1 || req.Tools[0].Function.Name != "http_request" {
		t.Fatalf("outbound tools wrong: %+v", req.Tools)
	}
	if req.ToolChoice != "auto" {
		t.Fatalf("tool_choice: want auto, got %q", req.ToolChoice)
	}
	if req.Model != "llama3.1" || req.MaxTokens != 16000 {
		t.Fatalf("model/max_tokens wrong: %q %d", req.Model, req.MaxTokens)
	}

	// (b) translated response
	if string(msg.StopReason) != "tool_use" {
		t.Fatalf("stop_reason: want tool_use, got %q", msg.StopReason)
	}
	if msg.Usage.InputTokens != 123 || msg.Usage.OutputTokens != 45 {
		t.Fatalf("usage: %+v", msg.Usage)
	}
	tu, ok := msg.Content[0].AsAny().(sdk.ToolUseBlock)
	if !ok {
		t.Fatalf("want ToolUseBlock, got %T", msg.Content[0].AsAny())
	}
	if tu.Name != "http_request" || tu.ID != "call_abc" {
		t.Fatalf("tool_use fields: name=%q id=%q", tu.Name, tu.ID)
	}
}

// TestClientNew_HTTPError: a non-2xx from the server is a transport error.
func TestClientNew_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := NewWithHTTPClient(srv.URL+"/v1", "", srv.Client())
	_, err := client.New(context.Background(), sdk.MessageNewParams{
		Model:    sdk.Model("nope"),
		Messages: []sdk.MessageParam{sdk.NewUserMessage(sdk.NewTextBlock("hi"))},
	})
	if err == nil {
		t.Fatal("want error on HTTP 500, got nil")
	}
}

// TestClientNew_APIError: a 200 body carrying an OpenAI error object surfaces it.
func TestClientNew_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"error":{"message":"context length exceeded","type":"invalid_request_error"}}`)
	}))
	defer srv.Close()
	client := NewWithHTTPClient(srv.URL+"/v1", "", srv.Client())
	_, err := client.New(context.Background(), sdk.MessageNewParams{
		Model:    sdk.Model("m"),
		Messages: []sdk.MessageParam{sdk.NewUserMessage(sdk.NewTextBlock("hi"))},
	})
	if err == nil {
		t.Fatal("want error on api error body, got nil")
	}
}

// TestOpenAIBackendDrivesAgentLoop is the seam-level integration test: the OpenAI
// client, plugged into the REAL attacker agent, must drive one tool_call against
// a live (in-process) target and then finish — proving the OpenAI backend is a
// drop-in for the Anthropic Messager. Mirrors attacker.TestAgentLoopOneToolThenEndTurn.
func TestOpenAIBackendDrivesAgentLoop(t *testing.T) {
	// Fake target records the paths the agent probes.
	var targetPaths []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetPaths = append(targetPaths, r.URL.Path)
		_, _ = io.WriteString(w, "body for "+r.URL.Path)
	}))
	defer target.Close()

	// Turn 1: tool_call GET /.env ; Turn 2: final text, end_turn.
	turn1 := `{
		"id":"c1","model":"llama3.1",
		"choices":[{"index":0,"message":{"role":"assistant","content":null,
			"tool_calls":[{"id":"call_1","type":"function","function":{"name":"http_request","arguments":"{\"method\":\"GET\",\"path\":\"/.env\"}"}}]},
			"finish_reason":"tool_calls"}],
		"usage":{"prompt_tokens":100,"completion_tokens":50}
	}`
	turn2 := `{
		"id":"c2","model":"llama3.1",
		"choices":[{"index":0,"message":{"role":"assistant","content":"Found /.env with credentials."},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":200,"completion_tokens":20}
	}`
	oai, fake := newFakeOpenAI(t, turn1, turn2)
	client := NewWithHTTPClient(oai.URL+"/v1", "", oai.Client())

	hc, err := attacker.BuildKeepAliveClient("")
	if err != nil {
		t.Fatalf("keepalive client: %v", err)
	}
	tool := attacker.NewHTTPTool(hc, target.URL)
	budget := attacker.NewBudget(5, 5, 25, 0.5)
	agent := attacker.NewAgent(client, tool, budget, attacker.Config{Model: sdk.Model("llama3.1")})

	res, err := agent.RunAttack(context.Background())
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if res.StopReason != "end_turn" {
		t.Fatalf("stop_reason: want end_turn, got %q", res.StopReason)
	}
	if res.TurnsCompleted != 2 {
		t.Fatalf("want 2 turns, got %d", res.TurnsCompleted)
	}
	if len(targetPaths) != 1 || targetPaths[0] != "/.env" {
		t.Fatalf("want one probe of /.env, got %v", targetPaths)
	}
	// (100+200) input @ $5/1M + (50+20) output @ $25/1M
	wantUSD := 300.0/1e6*5 + 70.0/1e6*25
	if res.TotalUSD < wantUSD-1e-9 || res.TotalUSD > wantUSD+1e-9 {
		t.Fatalf("usd: want %.8f got %.8f", wantUSD, res.TotalUSD)
	}

	// The turn-2 request must carry the tool_result round trip: an assistant
	// message with the tool_calls and a role:"tool" message keyed by call_1.
	req2 := fake.req(1)
	var sawAssistantCall, sawToolResult bool
	for _, m := range req2.Messages {
		if m.Role == "assistant" && len(m.ToolCalls) == 1 && m.ToolCalls[0].ID == "call_1" {
			sawAssistantCall = true
		}
		if m.Role == "tool" && m.ToolCallID == "call_1" {
			sawToolResult = true
		}
	}
	if !sawAssistantCall {
		t.Fatalf("turn-2 request missing assistant tool_calls round trip: %+v", req2.Messages)
	}
	if !sawToolResult {
		t.Fatalf("turn-2 request missing role:tool result keyed by call_1: %+v", req2.Messages)
	}
}
