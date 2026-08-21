package openai

import (
	"encoding/json"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
)

// TestBuildOpenAIRequest is the core request-translation check: an Anthropic
// Messages body (system + user + assistant-with-tool_use + tool_result + one
// http_request tool) becomes a well-formed OpenAI Chat Completions request with
// the tool_result mapped to a role:"tool" message keyed by tool_call_id.
func TestBuildOpenAIRequest(t *testing.T) {
	wire := `{
		"model":"claude-opus-4-8",
		"max_tokens":16000,
		"system":[{"type":"text","text":"SYS PROMPT","cache_control":{"type":"ephemeral"}}],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"begin the engagement"}]},
			{"role":"assistant","content":[
				{"type":"text","text":"probing /.env"},
				{"type":"tool_use","id":"tu1","name":"http_request","input":{"method":"GET","path":"/.env"}}
			]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"tu1","content":"HTTP 200 | 42 bytes | secret","is_error":false}
			]}
		],
		"tools":[{"name":"http_request","description":"probe","input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}]
	}`
	var areq anthropicRequest
	if err := json.Unmarshal([]byte(wire), &areq); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}

	got := buildOpenAIRequest(areq, "llama3.1")

	if got.Model != "llama3.1" {
		t.Fatalf("model: want llama3.1, got %q", got.Model)
	}
	if got.MaxTokens != 16000 {
		t.Fatalf("max_tokens: want 16000, got %d", got.MaxTokens)
	}
	if got.ToolChoice != "auto" {
		t.Fatalf("tool_choice: want auto, got %q", got.ToolChoice)
	}
	if len(got.Tools) != 1 || got.Tools[0].Function.Name != "http_request" || got.Tools[0].Type != "function" {
		t.Fatalf("tools not translated: %+v", got.Tools)
	}

	// system, user, assistant(tool_calls), tool — in that order.
	if len(got.Messages) != 4 {
		t.Fatalf("want 4 messages, got %d: %+v", len(got.Messages), got.Messages)
	}
	if got.Messages[0].Role != "system" || got.Messages[0].Content != "SYS PROMPT" {
		t.Fatalf("system msg wrong: %+v", got.Messages[0])
	}
	if got.Messages[1].Role != "user" || got.Messages[1].Content != "begin the engagement" {
		t.Fatalf("user msg wrong: %+v", got.Messages[1])
	}
	asst := got.Messages[2]
	if asst.Role != "assistant" || asst.Content != "probing /.env" {
		t.Fatalf("assistant msg wrong: %+v", asst)
	}
	if len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ID != "tu1" ||
		asst.ToolCalls[0].Function.Name != "http_request" {
		t.Fatalf("assistant tool_calls wrong: %+v", asst.ToolCalls)
	}
	if asst.ToolCalls[0].Function.Arguments != `{"method":"GET","path":"/.env"}` {
		t.Fatalf("arguments not compacted string: %q", asst.ToolCalls[0].Function.Arguments)
	}
	tool := got.Messages[3]
	if tool.Role != "tool" || tool.ToolCallID != "tu1" || tool.Content != "HTTP 200 | 42 bytes | secret" {
		t.Fatalf("tool msg wrong: %+v", tool)
	}
}

// TestBuildOpenAIRequest_StringSystem covers a system field delivered as a plain
// string rather than a text-block array.
func TestBuildOpenAIRequest_StringSystem(t *testing.T) {
	var areq anthropicRequest
	if err := json.Unmarshal([]byte(`{"model":"m","system":"just a string","messages":[]}`), &areq); err != nil {
		t.Fatal(err)
	}
	got := buildOpenAIRequest(areq, "")
	if got.Model != "m" {
		t.Fatalf("model fallback: %q", got.Model)
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != "system" || got.Messages[0].Content != "just a string" {
		t.Fatalf("string system not handled: %+v", got.Messages)
	}
}

// TestBuildAnthropicMessage_ToolCall verifies an OpenAI tool_call response
// round-trips into an *sdk.Message the agent loop can read (populated ToolUseBlock)
// with mapped usage and stop_reason tool_use.
func TestBuildAnthropicMessage_ToolCall(t *testing.T) {
	oresp := openAIResponse{
		ID:    "chatcmpl-x",
		Model: "llama3.1",
		Choices: []openAIChoice{{
			Message: openAIRespMsg{
				Role: "assistant",
				ToolCalls: []openAIRespToolCall{{
					ID:   "call_1",
					Type: "function",
					Function: struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					}{Name: "http_request", Arguments: json.RawMessage(`"{\"method\":\"GET\",\"path\":\"/.env\"}"`)},
				}},
			},
			FinishReason: "tool_calls",
		}},
		Usage: &openAIUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
	}

	doc, err := buildAnthropicMessage(oresp, "llama3.1")
	if err != nil {
		t.Fatalf("build doc: %v", err)
	}
	msg, err := anthropic.MessageFromJSON(doc)
	if err != nil {
		t.Fatalf("MessageFromJSON(%s): %v", doc, err)
	}
	if string(msg.StopReason) != "tool_use" {
		t.Fatalf("stop_reason: want tool_use, got %q", msg.StopReason)
	}
	if msg.Usage.InputTokens != 100 || msg.Usage.OutputTokens != 50 {
		t.Fatalf("usage mapping wrong: %+v", msg.Usage)
	}
	if len(msg.Content) != 1 {
		t.Fatalf("want 1 content block, got %d", len(msg.Content))
	}
	// Read the tool_use block via the SDK accessor the agent loop uses.
	tu, ok := msg.Content[0].AsAny().(sdk.ToolUseBlock)
	if !ok {
		t.Fatalf("want ToolUseBlock, got %T", msg.Content[0].AsAny())
	}
	if tu.Name != "http_request" || tu.ID != "call_1" {
		t.Fatalf("tool block fields wrong: name=%q id=%q", tu.Name, tu.ID)
	}
	var in struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(tu.Input, &in); err != nil {
		t.Fatalf("tool input not JSON (double-encoded string not unwrapped): %q: %v", string(tu.Input), err)
	}
	if in.Method != "GET" || in.Path != "/.env" {
		t.Fatalf("tool input not normalized: %+v", in)
	}
}

// TestBuildAnthropicMessage_FinalTextNoUsage covers the terminal turn: a plain
// text completion with NO usage block degrades to zero tokens (no crash) and
// stop_reason end_turn.
func TestBuildAnthropicMessage_FinalTextNoUsage(t *testing.T) {
	oresp := openAIResponse{
		Choices: []openAIChoice{{
			Message:      openAIRespMsg{Role: "assistant", Content: json.RawMessage(`"all done"`)},
			FinishReason: "stop",
		}},
		// Usage intentionally nil.
	}
	doc, err := buildAnthropicMessage(oresp, "llama3.1")
	if err != nil {
		t.Fatalf("build doc: %v", err)
	}
	msg, err := anthropic.MessageFromJSON(doc)
	if err != nil {
		t.Fatalf("MessageFromJSON: %v", err)
	}
	if string(msg.StopReason) != "end_turn" {
		t.Fatalf("stop_reason: want end_turn, got %q", msg.StopReason)
	}
	if msg.Usage.InputTokens != 0 || msg.Usage.OutputTokens != 0 {
		t.Fatalf("missing usage should be zero, got %+v", msg.Usage)
	}
}

// TestBuildAnthropicMessage_ToolCallsDespiteStopFinish covers the local-model
// quirk where a model emits tool_calls but reports finish_reason "stop": the
// presence of tool calls must win → stop_reason tool_use.
func TestBuildAnthropicMessage_ToolCallsDespiteStopFinish(t *testing.T) {
	oresp := openAIResponse{
		Choices: []openAIChoice{{
			Message: openAIRespMsg{
				Role: "assistant",
				ToolCalls: []openAIRespToolCall{{
					ID: "c1",
					Function: struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					}{Name: "http_request", Arguments: json.RawMessage(`{"method":"GET","path":"/x"}`)},
				}},
			},
			FinishReason: "stop",
		}},
	}
	doc, _ := buildAnthropicMessage(oresp, "m")
	msg, err := anthropic.MessageFromJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.StopReason) != "tool_use" {
		t.Fatalf("tool_calls present must force tool_use, got %q", msg.StopReason)
	}
}

func TestArgsRawToInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"object", `{"method":"GET","path":"/x"}`, `{"method":"GET","path":"/x"}`},
		{"double-encoded string", `"{\"path\":\"/y\"}"`, `{"path":"/y"}`},
		{"empty string", `""`, `{}`},
		{"empty bytes", ``, `{}`},
		{"null", `null`, `{}`},
		{"plain string value", `"hello"`, `{}`},
		{"garbage", `not json`, `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := string(argsRawToInput(json.RawMessage(c.in)))
			if got != c.want {
				t.Fatalf("argsRawToInput(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSalvageTextToolCall(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		wantOK   bool
		wantPath string
	}{
		{"wrapper form", `I'll call {"name":"http_request","arguments":{"method":"GET","path":"/.env"}} now`, true, "/.env"},
		{"wrapper parameters", `{"name":"http_request","parameters":{"path":"/admin"}}`, true, "/admin"},
		{"bare args", `Let me try {"method":"GET","path":"/backup/db.sql"}`, true, "/backup/db.sql"},
		{"prose only", `I think I should look at the environment file.`, false, ""},
		{"path without slash", `{"method":"GET","path":"relative"}`, false, ""},
		{"no json", `just text`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, in, ok := salvageTextToolCall(c.text)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (in=%s)", ok, c.wantOK, string(in))
			}
			if !ok {
				return
			}
			if name != "http_request" {
				t.Fatalf("name=%q", name)
			}
			var probe struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(in, &probe); err != nil {
				t.Fatalf("salvaged input not JSON: %v", err)
			}
			if probe.Path != c.wantPath {
				t.Fatalf("path=%q want %q", probe.Path, c.wantPath)
			}
		})
	}
}

func TestMapFinishReason(t *testing.T) {
	cases := map[string]string{
		"stop":           "end_turn",
		"":               "end_turn",
		"length":         "max_tokens",
		"content_filter": "refusal",
		"tool_calls":     "tool_use",
		"weird":          "end_turn",
	}
	for in, want := range cases {
		if got := mapFinishReason(in); got != want {
			t.Fatalf("mapFinishReason(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCoerceContentString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"plain"`, "plain"},
		{`null`, ""},
		{``, ""},
		{`[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "ab"},
	}
	for _, c := range cases {
		if got := coerceContentString(json.RawMessage(c.in)); got != c.want {
			t.Fatalf("coerceContentString(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
