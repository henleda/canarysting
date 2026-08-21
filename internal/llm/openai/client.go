// Package openai is a second backend for the attacker agent (internal/llm/attacker):
// it satisfies the SAME anthropic.Messager seam but speaks the OpenAI Chat
// Completions API shape, so the loop can be driven by a LOCALLY-hosted open model
// (e.g. an NVIDIA DGX Spark running Ollama, which exposes an OpenAI-compatible API
// at http://<host>:11434/v1/chat/completions with tool/function calling) with no
// hosted-LLM ToS or per-token cost.
//
// The whole client is a translator: it accepts the Anthropic-shaped
// sdk.MessageNewParams the agent already builds, converts the system/user/
// assistant/tool messages and the single http_request tool into the OpenAI
// tools/tool_calls shape, POSTs to {base}/chat/completions, then translates the
// assistant tool_calls + usage back into an *sdk.Message the agent reads exactly
// as it reads a real Anthropic response. Translation runs on the Anthropic *wire*
// JSON (see translate.go), so it depends only on the stable request/response
// shapes, never on the SDK's internal union types.
//
// Import-graph rule (same as the anthropic seam): nothing here may import
// internal/engine, internal/intelligence, internal/sting, or any adapter/proxy
// package. It reuses internal/llm/anthropic only for the Messager interface and
// MessageFromJSON (the one correct way to build an *sdk.Message the loop can read).
//
// Stdlib only — no module dependency is added by this backend.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
)

// DefaultBaseURL is the Ollama OpenAI-compatible base (includes the /v1 prefix;
// the client appends /chat/completions). Matches the DGX Spark default.
const DefaultBaseURL = "http://localhost:11434/v1"

// defaultTimeout is generous: local models on first load can be slow, and the
// engagement's rules of engagement tell the agent to wait for slow responses.
const defaultTimeout = 300 * time.Second

// respReadCap bounds how much of the completion response we read (the model's
// own output, already bounded by max_tokens; this is a hard safety ceiling).
const respReadCap = 8 << 20 // 8 MiB

// Client is a Messager backed by an OpenAI-compatible Chat Completions endpoint.
type Client struct {
	baseURL string
	apiKey  string // optional; sent as a Bearer header when non-empty (ignored by Ollama)
	http    *http.Client
}

// New builds a Client. An empty baseURL falls back to DefaultBaseURL. apiKey is
// optional (Ollama ignores it); when set it is sent as "Authorization: Bearer".
func New(baseURL, apiKey string) *Client {
	return NewWithHTTPClient(baseURL, apiKey, &http.Client{Timeout: defaultTimeout})
}

// NewWithHTTPClient is New with a caller-supplied *http.Client (used by tests to
// point at an in-process fake server). A nil hc gets the default.
func NewWithHTTPClient(baseURL, apiKey string, hc *http.Client) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    hc,
	}
}

func (c *Client) endpoint() string { return c.baseURL + "/chat/completions" }

// New issues one Chat Completions request and returns the translated response as
// an *sdk.Message. It satisfies anthropic.Messager.
func (c *Client) New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error) {
	// Bridge through the Anthropic wire JSON the SDK params marshal to. This is
	// exactly the request body the real SDK would POST, so it is a faithful and
	// version-robust source for the translation. Marshal a pointer so a
	// pointer-receiver MarshalJSON on the SDK params is always honored.
	wire, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request params: %w", err)
	}
	var areq anthropicRequest
	if err := json.Unmarshal(wire, &areq); err != nil {
		return nil, fmt.Errorf("openai: parse request params: %w", err)
	}

	oreq := buildOpenAIRequest(areq, string(p.Model))
	body, err := json.Marshal(oreq)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal chat request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: build http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai: POST %s: %w", c.endpoint(), err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, respReadCap))
	if err != nil {
		return nil, fmt.Errorf("openai: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai: chat completions HTTP %d: %s", resp.StatusCode, snippet(raw))
	}

	var oresp openAIResponse
	if err := json.Unmarshal(raw, &oresp); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	if oresp.Error != nil && oresp.Error.Message != "" {
		return nil, fmt.Errorf("openai: api error: %s", oresp.Error.Message)
	}

	doc, err := buildAnthropicMessage(oresp, string(p.Model))
	if err != nil {
		return nil, fmt.Errorf("openai: translate response: %w", err)
	}
	// MessageFromJSON is the one correct constructor: it populates the SDK's
	// internal raw buffers so the agent's AsAny()/AsToolUse() reads work.
	return anthropic.MessageFromJSON(doc)
}

// snippet truncates a body for inclusion in an error message.
func snippet(b []byte) string {
	const max = 500
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// compile-time check that the OpenAI client satisfies the same seam the agent
// loop depends on.
var _ anthropic.Messager = (*Client)(nil)
