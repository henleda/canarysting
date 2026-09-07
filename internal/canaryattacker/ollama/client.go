package ollama

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/canarysting/canarysting/internal/canaryattacker/planner"
)

const (
	DefaultEndpoint          = "http://127.0.0.1:11434"
	AbsoluteMaxRequestBytes  = 256 << 10
	AbsoluteMaxResponseBytes = 1 << 20
	requestTimeout           = 5 * time.Minute
)

type Client struct {
	endpoint string
	http     *http.Client
}

func New(endpoint string) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("Ollama endpoint is invalid")
	}
	if parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("Ollama endpoint must be an exact HTTP IPv4 loopback origin")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("Ollama endpoint must include a valid explicit port")
	}
	address := net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if (network != "tcp" && network != "tcp4") || requested != address {
				return nil, fmt.Errorf("refusing non-pinned Ollama dial")
			}
			return dialer.DialContext(ctx, "tcp4", address)
		},
	}
	return &Client{
		endpoint: "http://" + address,
		http: &http.Client{
			Transport: transport, Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Returning ErrUseLastResponse refuses the redirect without
				// allowing net/http to copy a response-controlled Location into
				// the returned transport error.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type apiRequest struct {
	Model     string       `json:"model"`
	Messages  []apiMessage `json:"messages"`
	Tools     []apiTool    `json:"tools"`
	Stream    bool         `json:"stream"`
	Think     bool         `json:"think"`
	KeepAlive int          `json:"keep_alive"`
	Options   apiOptions   `json:"options"`
}

type apiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiTool struct {
	Type     string      `json:"type"`
	Function apiFunction `json:"function"`
}

type apiFunction struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Parameters  apiParameters `json:"parameters"`
}

type apiParameters struct {
	Type                 string         `json:"type"`
	Properties           map[string]any `json:"properties"`
	AdditionalProperties bool           `json:"additionalProperties"`
}

type apiOptions struct {
	Temperature float64 `json:"temperature"`
	Seed        int64   `json:"seed"`
	NumPredict  uint64  `json:"num_predict"`
	NumContext  uint64  `json:"num_ctx"`
}

type apiResponse struct {
	Model              string             `json:"model"`
	CreatedAt          string             `json:"created_at"`
	Message            apiResponseMessage `json:"message"`
	Done               bool               `json:"done"`
	DoneReason         string             `json:"done_reason"`
	TotalDuration      uint64             `json:"total_duration"`
	LoadDuration       uint64             `json:"load_duration"`
	PromptEvalCount    uint64             `json:"prompt_eval_count"`
	PromptEvalDuration uint64             `json:"prompt_eval_duration"`
	EvalCount          uint64             `json:"eval_count"`
	EvalDuration       uint64             `json:"eval_duration"`
}

type unloadRequest struct {
	Model     string `json:"model"`
	KeepAlive int    `json:"keep_alive"`
}

type unloadResponse struct {
	Model      string `json:"model"`
	CreatedAt  string `json:"created_at"`
	Response   string `json:"response"`
	Done       bool   `json:"done"`
	DoneReason string `json:"done_reason"`
}

type apiResponseMessage struct {
	Role      string        `json:"role"`
	Content   string        `json:"content"`
	Thinking  string        `json:"thinking,omitempty"`
	Images    []string      `json:"images,omitempty"`
	ToolCalls []apiToolCall `json:"tool_calls,omitempty"`
}

type apiToolCall struct {
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Function apiCalledFunction `json:"function"`
}

type apiCalledFunction struct {
	Index     int             `json:"index,omitempty"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (c *Client) Complete(ctx context.Context, request planner.TurnRequest) (planner.TurnResponse, error) {
	payload, err := buildRequest(request)
	if err != nil {
		return planner.TurnResponse{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return planner.TurnResponse{}, fmt.Errorf("encode Ollama request: %w", err)
	}
	if len(body) > AbsoluteMaxRequestBytes {
		return planner.TurnResponse{}, fmt.Errorf("Ollama request exceeds %d bytes", AbsoluteMaxRequestBytes)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return planner.TurnResponse{}, fmt.Errorf("construct Ollama request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "canarysting-bounded-planner/1")
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return planner.TurnResponse{}, sanitizedTransportError(ctx, "call fixed-loopback Ollama")
	}
	defer httpResponse.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(httpResponse.Body, AbsoluteMaxResponseBytes+1))
	if err != nil {
		return planner.TurnResponse{}, sanitizedTransportError(ctx, "read Ollama response")
	}
	if len(limited) > AbsoluteMaxResponseBytes {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response exceeds %d bytes", AbsoluteMaxResponseBytes)
	}
	if httpResponse.StatusCode >= http.StatusMultipleChoices && httpResponse.StatusCode < http.StatusBadRequest {
		return planner.TurnResponse{}, fmt.Errorf("Ollama redirect response is forbidden")
	}
	if httpResponse.StatusCode != http.StatusOK {
		return planner.TurnResponse{}, fmt.Errorf("Ollama returned status %d", httpResponse.StatusCode)
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(httpResponse.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response content type is not application/json")
	}
	return parseResponse(limited, request)
}

// Unload releases only the exact named model through Ollama's fixed-loopback
// generate endpoint. It sends no prompt and grants no additional network
// authority; callers use it as a bounded cleanup fallback after cancellation.
func (c *Client) Unload(ctx context.Context, model string) error {
	if model == "" || len(model) > 128 {
		return fmt.Errorf("Ollama unload model identity is invalid")
	}
	body, err := json.Marshal(unloadRequest{Model: model, KeepAlive: 0})
	if err != nil {
		return fmt.Errorf("encode Ollama unload request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("construct Ollama unload request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "canarysting-bounded-planner/1")
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return sanitizedTransportError(ctx, "call fixed-loopback Ollama unload")
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, AbsoluteMaxResponseBytes+1))
	if err != nil {
		return sanitizedTransportError(ctx, "read Ollama unload response")
	}
	if httpResponse.StatusCode >= http.StatusMultipleChoices && httpResponse.StatusCode < http.StatusBadRequest {
		return fmt.Errorf("Ollama unload redirect response is forbidden")
	}
	if len(responseBody) > AbsoluteMaxResponseBytes || httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama unload response is oversized or returned status %d", httpResponse.StatusCode)
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(httpResponse.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return fmt.Errorf("Ollama unload response content type is not application/json")
	}
	if err := rejectDuplicateKeys(responseBody); err != nil {
		return fmt.Errorf("Ollama unload response JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var response unloadResponse
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("Ollama unload response schema is invalid")
	}
	if err := requireEOF(decoder); err != nil {
		return fmt.Errorf("Ollama unload response contains trailing data")
	}
	if response.Model != model || !response.Done || response.Response != "" || response.DoneReason != "unload" {
		return fmt.Errorf("Ollama did not confirm exact model unload")
	}
	if _, err := time.Parse(time.RFC3339Nano, response.CreatedAt); err != nil {
		return fmt.Errorf("Ollama unload response timestamp is invalid")
	}
	return nil
}

func sanitizedTransportError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s failed", operation)
}

func buildRequest(request planner.TurnRequest) (apiRequest, error) {
	if request.Model == "" || request.Instruction == "" || len(request.Instruction) > 1024 ||
		request.MaxOutputTokens == 0 || request.MaxOutputTokens > planner.AbsoluteMaxOutputTokens ||
		request.ContextTokens == 0 || request.ContextTokens > planner.AbsoluteMaxContextTokens || request.MaxProposals == 0 {
		return apiRequest{}, fmt.Errorf("Ollama turn request is incomplete or exceeds planner bounds")
	}
	if len(request.Tools) == 0 || len(request.Tools) > 256 || len(request.Observations) > 256 {
		return apiRequest{}, fmt.Errorf("Ollama tool or observation count is outside bounds")
	}
	tools := make([]apiTool, 0, len(request.Tools))
	for _, tool := range request.Tools {
		if !validActionName(tool.Name) || tool.Description == "" || len(tool.Description) > 256 {
			return apiRequest{}, fmt.Errorf("Ollama tool definition is invalid")
		}
		tools = append(tools, apiTool{Type: "function", Function: apiFunction{
			Name: tool.Name, Description: tool.Description,
			Parameters: apiParameters{Type: "object", Properties: map[string]any{}, AdditionalProperties: false},
		}})
	}
	observationJSON, err := json.Marshal(struct {
		Task         string                `json:"task"`
		Observations []planner.Observation `json:"reviewed_action_results"`
	}{Task: "Select one available reviewed action function, or stop.", Observations: request.Observations})
	if err != nil {
		return apiRequest{}, fmt.Errorf("encode bounded observations: %w", err)
	}
	return apiRequest{
		Model:    request.Model,
		Messages: []apiMessage{{Role: "system", Content: request.Instruction}, {Role: "user", Content: string(observationJSON)}},
		Tools:    tools, Stream: false, Think: false, KeepAlive: 0,
		Options: apiOptions{Temperature: 0, Seed: request.Seed, NumPredict: request.MaxOutputTokens, NumContext: request.ContextTokens},
	}, nil
}

func parseResponse(body []byte, request planner.TurnRequest) (planner.TurnResponse, error) {
	if err := rejectDuplicateKeys(body); err != nil {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response apiResponse
	if err := decoder.Decode(&response); err != nil {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response schema is invalid")
	}
	if err := requireEOF(decoder); err != nil {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response contains trailing data")
	}
	if response.Model != request.Model || response.Message.Role != "assistant" || !response.Done ||
		response.PromptEvalCount == 0 || response.EvalCount == 0 || response.EvalCount > request.MaxOutputTokens {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response identity, role, completion, or usage is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, response.CreatedAt); err != nil {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response timestamp is invalid")
	}
	if !utf8.ValidString(response.Message.Content) || len(response.Message.Content) > 64<<10 || response.Message.Thinking != "" || len(response.Message.Images) != 0 {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response contains unsupported or oversized message content")
	}
	if len(response.Message.ToolCalls) > int(request.MaxProposals) {
		return planner.TurnResponse{}, fmt.Errorf("Ollama response exceeds remaining proposal capacity")
	}
	proposals := make([]planner.Proposal, 0, len(response.Message.ToolCalls))
	for _, call := range response.Message.ToolCalls {
		if len(call.ID) > 256 || (call.Type != "" && call.Type != "function") || call.Function.Index < 0 ||
			call.Function.Name == "" || len(call.Function.Name) > 128 || len(call.Function.Arguments) > planner.AbsoluteMaxProposalBytes ||
			!json.Valid(call.Function.Arguments) || !isJSONObject(call.Function.Arguments) {
			return planner.TurnResponse{}, fmt.Errorf("Ollama response contains an invalid tool call")
		}
		proposals = append(proposals, planner.Proposal{Name: call.Function.Name, Arguments: append(json.RawMessage(nil), call.Function.Arguments...)})
	}
	digest := sha256.Sum256(body)
	return planner.TurnResponse{
		Model: response.Model, Done: response.Done, DoneReason: response.DoneReason,
		PromptTokens: response.PromptEvalCount, OutputTokens: response.EvalCount,
		OutputSHA256: hex.EncodeToString(digest[:]), Proposals: proposals,
	}, nil
}

func validActionName(value string) bool {
	if len(value) != len("action_000") || !strings.HasPrefix(value, "action_") {
		return false
	}
	for _, character := range value[len("action_"):] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}
