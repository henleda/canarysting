package openai

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// This file is the pure (network-free) translation layer between the Anthropic
// Messages shape the attacker agent speaks and the OpenAI Chat Completions shape
// a local server (Ollama / DGX Spark) speaks. Everything here operates on the
// Anthropic *wire* JSON — the exact bytes the SDK's request params marshal to —
// so it never depends on the SDK's internal union representation and stays fully
// unit-testable offline. client.go does the transport and hands the wire JSON in
// and the translated response doc out.

// ---- Anthropic wire structs (what sdk.MessageNewParams marshals to) ----

// anthropicRequest is the subset of the Anthropic Messages request body the
// translation needs. Fields we ignore (thinking, output_config, metadata, …) are
// simply not decoded.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int64              `json:"max_tokens"`
	System    json.RawMessage    `json:"system"` // string OR []text-block
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string OR []block
}

// anthropicBlock is a lenient superset of the content-block variants the agent
// produces: text, tool_use, tool_result (thinking/redacted_thinking are decoded
// but dropped in translation — a local OpenAI model has no use for them).
type anthropicBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text,omitempty"`
	// tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// tool_result
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ---- OpenAI Chat Completions structs ----

type openAIRequest struct {
	Model      string          `json:"model"`
	Messages   []openAIMessage `json:"messages"`
	Tools      []openAITool    `json:"tools,omitempty"`
	ToolChoice string          `json:"tool_choice,omitempty"`
	MaxTokens  int64           `json:"max_tokens,omitempty"`
	Stream     bool            `json:"stream"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // OpenAI arguments are a JSON *string*
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIToolFunc `json:"function"`
}

type openAIToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ---- OpenAI response structs ----

type openAIResponse struct {
	ID      string         `json:"id"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   *openAIUsage   `json:"usage"`
	Error   *openAIError   `json:"error"`
}

type openAIChoice struct {
	Index        int           `json:"index"`
	Message      openAIRespMsg `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIRespMsg struct {
	Role      string               `json:"role"`
	Content   json.RawMessage      `json:"content"` // string, null, or content-part array
	ToolCalls []openAIRespToolCall `json:"tool_calls"`
}

// openAIRespToolCall tolerates arguments as either a JSON string (spec) or a raw
// JSON object (some Ollama builds), via json.RawMessage.
type openAIRespToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type openAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// ---- Anthropic response doc (fed to anthropic.MessageFromJSON) ----

type respDoc struct {
	ID         string      `json:"id"`
	Type       string      `json:"type"`
	Role       string      `json:"role"`
	Model      string      `json:"model"`
	StopReason string      `json:"stop_reason"`
	Content    []respBlock `json:"content"`
	Usage      respUsage   `json:"usage"`
}

type respBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type respUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
}

// buildOpenAIRequest translates an Anthropic Messages request into an OpenAI
// Chat Completions request. model overrides the request model (the agent passes
// the -openai-model through sdk params, but the caller may substitute).
func buildOpenAIRequest(areq anthropicRequest, model string) openAIRequest {
	out := openAIRequest{Model: model, Stream: false}
	if out.Model == "" {
		out.Model = areq.Model
	}
	if areq.MaxTokens > 0 {
		out.MaxTokens = areq.MaxTokens
	}

	if sys := systemText(areq.System); sys != "" {
		out.Messages = append(out.Messages, openAIMessage{Role: "system", Content: sys})
	}

	for _, m := range areq.Messages {
		text, blocks := parseContent(m.Content)
		if len(blocks) == 0 {
			// A plain-string content message (rare; the agent uses block arrays).
			if text != "" {
				out.Messages = append(out.Messages, openAIMessage{Role: mapRole(m.Role), Content: text})
			}
			continue
		}
		switch m.Role {
		case "assistant":
			var textParts []string
			var calls []openAIToolCall
			for _, b := range blocks {
				switch b.Type {
				case "text":
					if b.Text != "" {
						textParts = append(textParts, b.Text)
					}
				case "tool_use":
					calls = append(calls, openAIToolCall{
						ID:   b.ID,
						Type: "function",
						Function: openAIFunctionCall{
							Name:      b.Name,
							Arguments: compactJSON(b.Input),
						},
					})
					// thinking / redacted_thinking: intentionally dropped.
				}
			}
			content := strings.Join(textParts, "\n")
			// Skip an assistant turn that carries neither text nor a tool call —
			// some servers reject a bodiless assistant message. (In practice the
			// OpenAI backend never emits thinking-only assistant turns.)
			if content != "" || len(calls) > 0 {
				out.Messages = append(out.Messages, openAIMessage{
					Role:      "assistant",
					Content:   content,
					ToolCalls: calls,
				})
			}
		default: // "user"
			var textParts []string
			for _, b := range blocks {
				switch b.Type {
				case "text":
					if b.Text != "" {
						textParts = append(textParts, b.Text)
					}
				case "tool_result":
					content := coerceContentString(b.Content)
					if content == "" && b.IsError {
						content = "error"
					}
					// Each tool_result becomes an OpenAI "tool" message keyed by
					// the tool_call id it answers.
					out.Messages = append(out.Messages, openAIMessage{
						Role:       "tool",
						ToolCallID: b.ToolUseID,
						Content:    content,
					})
				}
			}
			if len(textParts) > 0 {
				out.Messages = append(out.Messages, openAIMessage{
					Role:    "user",
					Content: strings.Join(textParts, "\n"),
				})
			}
		}
	}

	for _, t := range areq.Tools {
		params := t.InputSchema
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object"}`)
		}
		out.Tools = append(out.Tools, openAITool{
			Type: "function",
			Function: openAIToolFunc{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  params,
			},
		})
	}
	if len(out.Tools) > 0 {
		out.ToolChoice = "auto"
	}
	return out
}

// buildAnthropicMessage translates an OpenAI Chat Completions response into an
// Anthropic Message JSON document (the form anthropic.MessageFromJSON decodes).
// model backfills the message model when the server omits it.
func buildAnthropicMessage(oresp openAIResponse, model string) (string, error) {
	doc := respDoc{
		ID:      firstNonEmpty(oresp.ID, "openai-response"),
		Type:    "message",
		Role:    "assistant",
		Model:   firstNonEmpty(oresp.Model, model, "openai"),
		Content: []respBlock{},
	}

	var text string
	var toolCalls []openAIRespToolCall
	finish := ""
	if len(oresp.Choices) > 0 {
		ch := oresp.Choices[0]
		text = coerceContentString(ch.Message.Content)
		toolCalls = ch.Message.ToolCalls
		finish = ch.FinishReason
	}

	if strings.TrimSpace(text) != "" {
		doc.Content = append(doc.Content, respBlock{Type: "text", Text: text})
	}
	for i, tc := range toolCalls {
		id := tc.ID
		if id == "" {
			id = "call_" + strconv.Itoa(i)
		}
		name := tc.Function.Name
		if name == "" {
			name = "http_request"
		}
		doc.Content = append(doc.Content, respBlock{
			Type:  "tool_use",
			ID:    id,
			Name:  name,
			Input: argsRawToInput(tc.Function.Arguments),
		})
	}

	// Graceful degradation: some local models emit the tool call as plain text
	// instead of a structured tool_calls array. When we got none structured, try
	// to salvage one from the text so the run still escalates.
	if len(toolCalls) == 0 {
		if name, args, ok := salvageTextToolCall(text); ok {
			doc.Content = append(doc.Content, respBlock{
				Type:  "tool_use",
				ID:    "call_text_0",
				Name:  name,
				Input: args,
			})
		}
	}

	if hasToolUse(doc.Content) {
		doc.StopReason = "tool_use"
	} else {
		doc.StopReason = mapFinishReason(finish)
	}

	if oresp.Usage != nil {
		// Map what the server gives us; a missing usage block leaves these at 0
		// (the budget simply doesn't advance for that turn — never a crash).
		doc.Usage.InputTokens = oresp.Usage.PromptTokens
		doc.Usage.OutputTokens = oresp.Usage.CompletionTokens
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- helpers ----

// parseContent returns (text, nil) when content is a JSON string, or ("", blocks)
// when it is a block array. Anything else yields ("", nil).
func parseContent(raw json.RawMessage) (string, []anthropicBlock) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var bs []anthropicBlock
	if err := json.Unmarshal(raw, &bs); err == nil {
		return "", bs
	}
	return "", nil
}

// systemText flattens an Anthropic system field (string or []text-block) to a
// single string.
func systemText(raw json.RawMessage) string {
	text, blocks := parseContent(raw)
	if text != "" {
		return text
	}
	var parts []string
	for _, b := range blocks {
		if b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// coerceContentString flattens an OpenAI/Anthropic content value that may be a
// JSON string, null, or an array of {type,text} parts.
func coerceContentString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// compactJSON returns raw as a compact JSON string, defaulting to "{}" for empty
// or unparseable input (so an OpenAI arguments string is always valid JSON).
func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "{}"
	}
	return buf.String()
}

// argsRawToInput normalizes an OpenAI tool-call arguments value into a valid
// Anthropic tool_use input object. It accepts a JSON object, a JSON string that
// wraps a JSON object (double-encoded, common with local models), or anything
// else (which degrades to "{}").
func argsRawToInput(raw json.RawMessage) json.RawMessage {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return json.RawMessage("{}")
	}
	if strings.HasPrefix(s, "{") && json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	var unq string
	if err := json.Unmarshal(raw, &unq); err == nil {
		u := strings.TrimSpace(unq)
		if strings.HasPrefix(u, "{") && json.Valid([]byte(u)) {
			return json.RawMessage(u)
		}
	}
	return json.RawMessage("{}")
}

// salvageTextToolCall makes a conservative attempt to recover an http_request
// tool call embedded as text (some local models narrate the call instead of
// emitting a structured tool_calls array). It only fires when it finds a JSON
// object carrying a path that starts with "/", so it never manufactures a call
// out of prose.
func salvageTextToolCall(text string) (name string, input json.RawMessage, ok bool) {
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return "", nil, false
	}
	candidate := text[start : end+1]
	if !json.Valid([]byte(candidate)) {
		return "", nil, false
	}
	// Wrapper form: {"name":"http_request","arguments"|"parameters":{...}}
	var wrap struct {
		Name       string          `json:"name"`
		Arguments  json.RawMessage `json:"arguments"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(candidate), &wrap); err == nil && wrap.Name != "" {
		args := wrap.Arguments
		if len(args) == 0 {
			args = wrap.Parameters
		}
		if in := argsRawToInput(args); looksLikeHTTPArgs(in) {
			return wrap.Name, in, true
		}
	}
	// Bare-args form: {"method":"GET","path":"/..."}
	if in := json.RawMessage(candidate); looksLikeHTTPArgs(in) {
		return "http_request", in, true
	}
	return "", nil, false
}

// looksLikeHTTPArgs reports whether raw parses as an object with a path that
// begins with "/", the minimum evidence that it is an http_request argument set.
func looksLikeHTTPArgs(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var probe struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(probe.Path, "/")
}

func hasToolUse(blocks []respBlock) bool {
	for _, b := range blocks {
		if b.Type == "tool_use" {
			return true
		}
	}
	return false
}

// mapFinishReason maps an OpenAI finish_reason to an Anthropic stop_reason. Tool
// use is decided by the presence of tool_use blocks (not this map), so
// "tool_calls" only reaches here when no calls survived.
func mapFinishReason(fr string) string {
	switch fr {
	case "length":
		return "max_tokens"
	case "content_filter":
		return "refusal"
	case "tool_calls":
		return "tool_use"
	default: // "stop", "", anything else
		return "end_turn"
	}
}

func mapRole(role string) string {
	if role == "assistant" {
		return "assistant"
	}
	return "user"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
