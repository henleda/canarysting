// Package attacker is the M9 LLM/scripted adversary that drives the live
// CanarySting deception range from the declared-attacker source IP. It runs an
// Anthropic agentic loop with exactly one tool (http_request) over a keepalive
// connection, so a single socket cookie escalates T0->T3 and the deception
// bodies it pulls back burn real tokens — capped by a hard dollar ceiling.
//
// Import-graph rule (hard): nothing in this package may import internal/engine,
// internal/intelligence, internal/sting, or any adapter/proxy package. The
// attacker is conceptually the adversary; it does its own cost accounting and
// reaches the proxy number only over HTTP (the dashboard tap), never by import.
package attacker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
)

// Config controls one attack run.
type Config struct {
	Model     sdk.Model
	MaxTokens int64
	Effort    sdk.OutputConfigEffort
	MaxTurns  int

	// Scripted selects the deterministic zero-API variant (no Messager used).
	Scripted    bool
	CanaryPaths []string // scripted probe set
	MazeDepth   int      // scripted: child links to follow from the first deception body
}

// RunResult is the run ledger. The token/USD totals are the attacker's
// ground-truth real cost (distinct from the defender's proxy estimate).
type RunResult struct {
	TurnsCompleted           int           `json:"turns_completed"`
	TotalInputTokens         int64         `json:"total_input_tokens"`
	TotalOutputTokens        int64         `json:"total_output_tokens"`
	TotalCacheReadTokens     int64         `json:"total_cache_read_tokens"`
	TotalCacheCreationTokens int64         `json:"total_cache_creation_tokens"`
	TotalUSD                 float64       `json:"total_usd"`
	InputUSD                 float64       `json:"input_usd"`
	OutputUSD                float64       `json:"output_usd"`
	CacheReadUSD             float64       `json:"cache_read_usd"`
	CacheCreationUSD         float64       `json:"cache_creation_usd"`
	StopReason               string        `json:"stop_reason"`
	CanaryPathsHit           []string      `json:"canary_paths_hit"`
	Probes                   []ProbeResult `json:"-"`
}

// Agent runs one attack. Build it with NewAgent.
type Agent struct {
	client anthropic.Messager // nil in scripted mode
	tool   *HTTPTool
	budget *Budget
	cfg    Config

	// onProgress, if set, is called after each turn/probe with the running
	// budget snapshot. The binary uses it to POST the live cost meter to the
	// dashboard tap. Keeping it a callback keeps the import-graph rule intact.
	onProgress func(Snapshot)

	// sleep is injectable so the rate-limit retry path is testable without a
	// real wall-clock wait. Defaults to time.Sleep.
	sleep func(time.Duration)

	result RunResult
	hits   map[string]bool
}

// NewAgent wires an attack run. client may be nil only when cfg.Scripted.
func NewAgent(client anthropic.Messager, tool *HTTPTool, budget *Budget, cfg Config) *Agent {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 16000
	}
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 30
	}
	if cfg.Effort == "" {
		cfg.Effort = sdk.OutputConfigEffortHigh
	}
	return &Agent{
		client: client,
		tool:   tool,
		budget: budget,
		cfg:    cfg,
		sleep:  time.Sleep,
		hits:   map[string]bool{},
	}
}

// SetProgressHook registers a per-turn callback (used for the live cost meter).
func (a *Agent) SetProgressHook(f func(Snapshot)) { a.onProgress = f }

// RunAttack runs the agentic loop (or the scripted sequence if cfg.Scripted).
func (a *Agent) RunAttack(ctx context.Context) (RunResult, error) {
	if a.cfg.Scripted {
		return a.runScripted(ctx)
	}
	return a.runLLM(ctx)
}

func (a *Agent) runLLM(ctx context.Context) (RunResult, error) {
	if a.client == nil {
		return a.result, errors.New("attacker: nil client in LLM mode")
	}
	adaptive := sdk.ThinkingConfigAdaptiveParam{
		// Show reasoning in the response (default on 4.8 omits it). The demo
		// wants the attacker's chain-of-attack visible in the run log.
		Display: sdk.ThinkingConfigAdaptiveDisplaySummarized,
	}
	httpTool := a.httpRequestTool()
	tools := []sdk.ToolUnionParam{{OfTool: &httpTool}}

	messages := []sdk.MessageParam{
		sdk.NewUserMessage(sdk.NewTextBlock(InitialUserMessage)),
	}

	for turn := 0; turn < a.cfg.MaxTurns; turn++ {
		if a.budget.Exceeded() { // pre-turn hard cap — no API call once tripped
			a.result.StopReason = "budget_exceeded"
			break
		}
		if err := ctx.Err(); err != nil { // kill switch (signal/cancel)
			a.result.StopReason = "cancelled"
			break
		}

		params := sdk.MessageNewParams{
			Model:        a.cfg.Model,
			MaxTokens:    a.cfg.MaxTokens,
			Thinking:     sdk.ThinkingConfigParamUnion{OfAdaptive: &adaptive},
			OutputConfig: sdk.OutputConfigParam{Effort: a.cfg.Effort},
			System: []sdk.TextBlockParam{{
				Text:         SystemPrompt,
				CacheControl: sdk.NewCacheControlEphemeralParam(),
			}},
			Messages: messages,
			Tools:    tools,
		}

		resp, err := a.callWithRetry(ctx, params)
		if err != nil {
			if ctx.Err() != nil {
				a.result.StopReason = "cancelled"
				break
			}
			return a.result, fmt.Errorf("turn %d: %w", turn, err)
		}

		a.result.TurnsCompleted = turn + 1
		running := a.budget.Accumulate(resp.Usage)
		log.Printf("[cost] turn=%d in=%d out=%d cacheRead=%d running=$%.4f",
			turn, resp.Usage.InputTokens, resp.Usage.OutputTokens,
			resp.Usage.CacheReadInputTokens, running)
		a.emitProgress()

		messages = append(messages, resp.ToParam()) // history BEFORE tool dispatch

		var toolResults []sdk.ContentBlockParamUnion
		for _, block := range resp.Content {
			switch v := block.AsAny().(type) {
			case sdk.ThinkingBlock:
				if v.Thinking != "" {
					log.Printf("[think] %s", truncate(v.Thinking, 500))
				}
			case sdk.TextBlock:
				log.Printf("[agent] %s", v.Text)
			case sdk.ToolUseBlock:
				raw := string(v.Input) // populated json.RawMessage; parse, never string-match
				out, isErr, probe := a.tool.Execute(ctx, raw)
				a.record(probe)
				toolResults = append(toolResults, sdk.NewToolResultBlock(v.ID, out, isErr))
			}
		}

		if resp.StopReason == sdk.StopReasonRefusal {
			log.Printf("[agent] refusal category=%s expl=%s",
				resp.StopDetails.Category, resp.StopDetails.Explanation)
			a.result.StopReason = "refusal"
			break
		}
		if resp.StopReason != sdk.StopReasonToolUse { // end_turn / max_tokens → done
			a.result.StopReason = string(resp.StopReason)
			break
		}
		if len(toolResults) == 0 {
			// tool_use stop but no tool block we executed — avoid an empty user
			// turn that would loop forever.
			a.result.StopReason = "no_tool_calls"
			break
		}
		messages = append(messages, sdk.NewUserMessage(toolResults...))
	}
	if a.result.StopReason == "" {
		a.result.StopReason = "max_turns"
	}
	a.finalize()
	return a.result, nil
}

// callWithRetry issues one Messages request, retrying once on a rate-limit /
// overloaded response (429 / 529) after a short backoff.
func (a *Agent) callWithRetry(ctx context.Context, params sdk.MessageNewParams) (*sdk.Message, error) {
	resp, err := a.client.New(ctx, params)
	if err == nil {
		return resp, nil
	}
	var apiErr *sdk.Error
	if errors.As(err, &apiErr) && (apiErr.StatusCode == 429 || apiErr.StatusCode == 529) {
		log.Printf("[retry] %d from API; one retry after backoff", apiErr.StatusCode)
		a.sleep(60 * time.Second)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Re-check the cap after the backoff before spending again (invariant:
		// no API call once the budget is tripped).
		if a.budget.Exceeded() {
			return nil, fmt.Errorf("budget exceeded during rate-limit backoff")
		}
		return a.client.New(ctx, params)
	}
	return nil, err
}

func (a *Agent) record(p ProbeResult) {
	a.result.Probes = append(a.result.Probes, p)
	if p.Err == "" && isCanary(p.Path, a.cfg.CanaryPaths) && !a.hits[p.Path] {
		a.hits[p.Path] = true
		a.result.CanaryPathsHit = append(a.result.CanaryPathsHit, p.Path)
	}
}

func (a *Agent) finalize() {
	s := a.budget.Snapshot()
	a.result.TotalInputTokens = s.InputTokens
	a.result.TotalOutputTokens = s.OutputTokens
	a.result.TotalCacheReadTokens = s.CacheReadTokens
	a.result.TotalCacheCreationTokens = s.CacheCreationTokens
	a.result.TotalUSD = s.USD
	a.result.InputUSD = s.InputUSD
	a.result.OutputUSD = s.OutputUSD
	a.result.CacheReadUSD = s.CacheReadUSD
	a.result.CacheCreationUSD = s.CacheCreationUSD
}

func (a *Agent) emitProgress() {
	if a.onProgress != nil {
		a.onProgress(a.budget.Snapshot())
	}
}

// httpRequestTool is the one tool. Required is set per the verified
// ToolInputSchemaParam.Required field.
func (a *Agent) httpRequestTool() sdk.ToolParam {
	return sdk.ToolParam{
		Name: "http_request",
		Description: sdk.String(`Make an HTTP request to the target server to probe for ` +
			`files, credentials, configuration endpoints, or admin interfaces. The server may ` +
			`delay responses for suspicious paths — wait for the full response. Escalate from ` +
			`reconnaissance paths to credential and secret paths as you learn.`),
		InputSchema: sdk.ToolInputSchemaParam{
			Properties: map[string]any{
				"method": map[string]any{"type": "string", "enum": []string{"GET", "POST", "HEAD"}},
				"path":   map[string]any{"type": "string", "description": `URL path, must start with "/"`},
				"body":   map[string]any{"type": "string", "description": "optional POST body"},
			},
			Required: []string{"method", "path"},
		},
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isCanary reports whether path matches one of the known canary paths. If the
// caller supplied no path list, every successful touch counts as a hit (the LLM
// run leaves CanaryPaths empty, so its summary lists everything it reached).
func isCanary(path string, canaries []string) bool {
	if len(canaries) == 0 {
		return true
	}
	for _, c := range canaries {
		if path == c {
			return true
		}
	}
	return false
}
