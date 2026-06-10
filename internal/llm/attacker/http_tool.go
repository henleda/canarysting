package attacker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// bodyReadCap bounds how much of a response body we read into the tool result.
// The deception body is capped at 64 KiB on the defender side (verified
// attrition-body-cap=64<<10); 128 KiB here covers it with headroom while
// bounding the tool-result string the model re-encodes each turn.
const bodyReadCap = 128 << 10

// resultPreviewCap bounds the body slice echoed back into the tool result text.
// The whole body is still read to completion (that is the deception-burn
// mechanism and is required for keepalive connection reuse); this only limits
// how much we hand back to the model as a single tool_result.
const resultPreviewCap = 4096

// BuildKeepAliveClient builds the single HTTP client shared across every tool
// call in a run. The load-bearing constraint across the whole M9 design: ONE
// TCP connection for the whole run = ONE socket cookie = ONE flow that
// escalates T0->T3. The always-on prober deliberately sets DisableKeepAlives
// to get DISTINCT flows; the attacker inverts that.
//
// srcIP binds the local address to the declared-attacker IP so the staged
// labeler attributes the flow correctly.
func BuildKeepAliveClient(srcIP string) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if srcIP != "" {
		local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
		if err != nil {
			return nil, fmt.Errorf("bad src-ip %q: %w", srcIP, err)
		}
		dialer.LocalAddr = local
	}
	return &http.Client{
		// Must exceed the adapter's max inline hold (verified maxHold=8s) so a
		// full tarpit completes instead of the client cancelling it.
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			DisableKeepAlives:   false, // REQUIRED — single socket cookie across the run
			MaxIdleConnsPerHost: 1,     // force reuse of the one connection
			MaxConnsPerHost:     1,
			IdleConnTimeout:     120 * time.Second,
		},
	}, nil
}

// httpRequestInput is the shape of the http_request tool's arguments. Always
// parsed with json.Unmarshal — never raw string-matched — because 4.x models
// vary JSON escaping in tool inputs (skill pitfall).
type httpRequestInput struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
}

// HTTPTool executes the agent's one tool against a fixed target base URL over
// the shared keepalive client. The base URL is fixed in the executor (not
// model-controlled) so the agent can never redirect off-target.
type HTTPTool struct {
	client  *http.Client
	baseURL string // e.g. http://10.20.1.24:8080 (no trailing slash)
}

// NewHTTPTool builds the tool executor. baseURL has any trailing slash trimmed.
func NewHTTPTool(client *http.Client, baseURL string) *HTTPTool {
	return &HTTPTool{client: client, baseURL: strings.TrimRight(baseURL, "/")}
}

// ProbeResult is the structured outcome of one tool call, recorded for the run
// ledger (CanaryPathsHit, byte counts) independent of the string handed back to
// the model.
type ProbeResult struct {
	Method     string
	Path       string
	StatusCode int
	Bytes      int
	Err        string
}

// Execute runs one http_request. It returns the tool-result string to feed back
// to the model and an isError flag. A tool error is NEVER fatal to the loop —
// the model is expected to adapt to a new path; the agent loop keeps going.
func (t *HTTPTool) Execute(ctx context.Context, rawInput string) (result string, isError bool, probe ProbeResult) {
	var in httpRequestInput
	if err := json.Unmarshal([]byte(rawInput), &in); err != nil {
		return fmt.Sprintf("error: invalid tool input JSON: %v", err), true, ProbeResult{Err: "bad-input"}
	}
	if in.Method == "" {
		in.Method = http.MethodGet
	}
	in.Method = strings.ToUpper(in.Method)
	if !strings.HasPrefix(in.Path, "/") {
		return fmt.Sprintf("error: path must start with \"/\", got %q", in.Path), true,
			ProbeResult{Method: in.Method, Path: in.Path, Err: "bad-path"}
	}
	probe = ProbeResult{Method: in.Method, Path: in.Path}

	var bodyReader io.Reader
	if in.Body != "" {
		bodyReader = strings.NewReader(in.Body)
	}
	req, err := http.NewRequestWithContext(ctx, in.Method, t.baseURL+in.Path, bodyReader)
	if err != nil {
		probe.Err = "build-request"
		return fmt.Sprintf("error: %v", err), true, probe
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Connection error (e.g. the kernel jail dropped the socket) is reported
		// as a tool error; the model retries per its rules of engagement.
		probe.Err = err.Error()
		return fmt.Sprintf("error: request failed: %v", err), true, probe
	}
	defer resp.Body.Close()

	// Read the body to completion (bounded). This is mandatory for connection
	// reuse — an abandoned body marks the connection dirty and the next request
	// opens a NEW socket (new cookie, escalation lost). It is also the
	// deception-burn mechanism: the body becomes a tool_result and is re-encoded
	// as input tokens on every subsequent turn.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, bodyReadCap))
	// Drain any remainder past the cap so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	probe.StatusCode = resp.StatusCode
	probe.Bytes = len(bodyBytes)

	preview := bodyBytes
	if len(preview) > resultPreviewCap {
		preview = preview[:resultPreviewCap]
	}
	return fmt.Sprintf("HTTP %d | %d bytes | %s", resp.StatusCode, len(bodyBytes), string(preview)), false, probe
}
