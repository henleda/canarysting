# M9 Implementation Plan — Scenario + LLM Attacker

**Status:** PLAN — awaiting founder signoff on the decisions below.
**Author context:** Synthesized from three M9 design specs (SDK/agent-loop, attacker-scenario, integration/deploy). All disagreements between the specs are reconciled here against the **live Anthropic Go SDK source** (`anthropic-sdk-go/main/message.go`) and the **actual repo code** — no field name, price, or call shape in this plan is a guess.
**Repo:** `github.com/canarysting/canarysting` @ `43102ab`. Go toolchain on both boxes: `go1.25.3`. `go.mod` directive: `go 1.22`.
**M9 goal (exit criterion):** the demo runs end-to-end with a *real* Claude agent burning *real* tokens against the live attrition, with a hard dollar cap, and the real cost shown side-by-side with the system's `TokenCostProxy` estimate.

---

## 0. DECISIONS NEEDING SIGNOFF (read first)

Six decisions gate the build. Recommendations are mine; the founder confirms or overrides.

| # | Decision | Recommendation | Why it matters |
|---|---|---|---|
| **D1** | **Anthropic Go SDK vs raw `net/http`.** The two specs disagreed (SDK/agent spec said SDK; integration spec said raw HTTP). | **Use the official SDK** (`github.com/anthropics/anthropic-sdk-go`). | The `claude-api` skill mandates the official SDK whenever one exists for the language ("Never fall back to raw HTTP… just because it feels lighter"). The SDK gives verified typed access to `resp.Usage`, `resp.StopReason`, adaptive thinking, and `OutputConfig.Effort` — all of which this loop needs and all of which I verified exist (see §2). The integration spec's raw-HTTP rationale rested on a **factual error** (it claimed the SDK works at go 1.22 — it does not; see D2), so its premise is void. The dependency is scoped to one command tree. |
| **D2** | **`go.mod` directive bump `go 1.22` → `go 1.24`.** Required by the SDK's own `go.mod` minimum. | **Do it.** One-line change. | The toolchain on both boxes is already `go1.25.3`, so this is metadata only — no compiled artifact changes, no other source file touched. Without it, `go mod tidy` will refuse to add the SDK cleanly. The integration spec's "no go.mod change" claim is incorrect and is overridden. |
| **D3** | **Client-box egress to `api.anthropic.com:443`.** | **No Terraform change needed.** | Verified: the client-box SG already has `egress { protocol="-1" cidr_blocks=["0.0.0.0/0"] }`. The box can reach the API today. (Optional: tighten the SG comment string — not load-bearing.) |
| **D4** | **API-key provisioning.** Where the key lives and how it's read. | **`/etc/canarysting/anthropic.key` (mode 0600), systemd `EnvironmentFile` pattern**, falling back to `ANTHROPIC_API_KEY` env for dev runs. Never a CLI arg (so it never shows in `ps aux`), never committed. | Mirrors the existing `/etc/canarysting/m7.env` `EnvironmentFile` convention. The SDK's `anthropic.NewClient()` reads `ANTHROPIC_API_KEY` automatically; we set it from the file. |
| **D5** | **Real-cost on the dashboard.** Run-end JSON only, or a live "tokens burning" meter on the CISO screen. | **Run-end JSON for the MVP** (zero new write paths). Treat the live meter as a *fast-follow* once the founder confirms they want it on-screen for the demo. | The dashboard tap (`internal/dashboard/tap/tap.go`) is **read-only by construction** — it only serves `/raw/state`, `/raw/events`, `/healthz`. A live meter requires adding a *write* endpoint to the tap (`PUT /raw/attack-ledger`, in-memory, mutex-guarded) plus a new `views.Overview` field. That's a clean, in-scope extension (the attacker posts only its own token count, no scope data), but it breaks the tap's read-only invariant, so it needs explicit signoff. The `AttackerCostView.TokensBurned` field (verified present) continues to carry the **proxy** estimate; the real count is a *separate* number shown alongside, never merged. |
| **D6** | **Demo posture + sting floor.** Two sub-decisions, both runtime flags on the *adapter* (no code change): tier thresholds and attrition floor. | **Live demo:** `-sting-floor 2` (token_bait, aggressive) for visible token burn (~$5 cap reached in ~7 deception turns). Tier thresholds: use the engine's existing default posture for a realistic 3-5-touch escalation, or `-aggressive` (all thresholds 0.01 → single touch trips Tier 2) for the fastest, most dramatic run. **M7 window stays at its current posture — M9 does not change it.** | Floor 2 + aggressive thresholds is the "money shot" (meter climbs in 30-60s of wall time). Default thresholds are more faithful to the GTG-1002 narrative. The founder picks the demo flavor. |

**Two further sub-decisions folded into the build (recommendations baked in, flag if you disagree):**

- **D6a — Source IP collision with the prober.** The LLM attacker binds `10.20.1.111`, the same IP the always-on prober uses. **Recommendation: `run-attack.sh` stops `canarysting-prober` before a demo run and restarts it after**, so the demo shows one clean escalating socket cookie. (Both are labeled attacker by the registry regardless, but the prober's `DisableKeepAlives` flows would muddy the trace.)
- **D6b — `envLeaf` per-path uniqueness (optional 3-line change to `internal/sting/attrition/generators.go:232`).** Currently the maze `.env` leaf hardcodes `DATABASE_URL=postgres://svc:decoy@db.payments.example:5432/payments`; the AWS keys already vary by hash `h`. **Recommendation: defer.** It extends agent engagement but touches a `harmless.CrossScan`-tested generator and is not required for the exit criterion. Do it only if a first live run shows the agent disengaging too early.

---

## 1. Overview + Locked Decisions

### What M9 is
Two attackers that drive the live CanarySting deception range from the declared-attacker source IP (`10.20.1.111`), plus one-command orchestration:

1. **The real LLM attacker** — a Go binary running an Anthropic **Claude Opus 4.8** agentic loop. It is given one tool (`http_request`) over a **keepalive** HTTP client. It probes the negative-space canary paths, hits the inline attrition, and the deception bodies it pulls back (fake_tree maze pages, token_bait blobs) accumulate in its context — **that accumulation is the real token burn**, capped at a hard dollar ceiling.
2. **The scripted attacker** — a deterministic, **zero-API-cost** variant. Same keepalive transport, fixed canary-touch sequence. For CI dry-runs, demo rehearsal, and a reference escalation trace before burning real credits.
3. **`run-attack.sh`** — one command on the client box: health-check the server, build, resolve the key, run the chosen attacker, print the real-cost-vs-proxy ledger.

### Locked decisions (not open for signoff — these are fixed)
- **Model:** `claude-opus-4-8` (SDK constant `anthropic.ModelClaudeOpus4_8`). Founder-locked + skill default.
- **Pricing (VERIFIED from the `claude-api` skill model table, 2026-05-26):** **$5.00 / 1M input tokens, $25.00 / 1M output tokens.** ⚠️ The integration spec's "$15/$75" is **wrong** and is corrected here. Cache-read is ~10% of input ($0.50/1M). These are the budget-math constants.
- **Hard budget cap:** **$5.00 per run**, default. Two-layer enforcement (pre-turn check + post-response accumulation) plus a `context.CancelFunc` kill switch (§4).
- **Language:** Go, per the repo's everything-in-Go rule.
- **Posture:** Authorized self-attack against CanarySting's own decoy range. Canaries are EXAMPLE/reserved-namespace; the target is AWS-private-only; the agent has exactly one GET/POST tool and no shell, no filesystem, no second network reach. This is offensive testing of owned infrastructure, not hack-back. The system prompt frames this explicitly (§3) and the prompt text is **D6/SIGNOFF-gated for founder review before the first live run**.
- **`max_tokens`:** `16000` (skill default for non-streaming; keeps each turn under the SDK HTTP timeout). At $25/1M output, 16K output = $0.40/turn worst case → ~12 turns of pure output before the $5 cap. Per-turn cost is logged live.
- **Thinking:** adaptive (`thinking: {type: "adaptive"}`), per the skill default for anything non-trivial.

### Reconciled architecture (resolving the spec disagreement on *where the code lives*)
The SDK/agent spec put everything flat in `cmd/llm-attacker/`. The integration spec split it into `internal/llm/anthropic` + `internal/llm/attacker` + `cmd/llm-attacker`. The attacker-scenario spec put binaries under `deploy/m9-scenario/`.

**Reconciliation — adopt the integration spec's layered layout, because it is the only one that keeps `make check` green with real unit tests:**
- A thin SDK-wrapping client lives behind a **`Messager` interface** so the agent loop is testable against a **fake** with zero network.
- The pure agent loop lives in `internal/llm/attacker/` (no `main`, no `flag`, no real network) — unit-testable against a `FakeClient` + `httptest.Server`.
- The binary is `cmd/llm-attacker/` (repo convention: binaries live in `cmd/`).
- Orchestration + systemd live under `deploy/m7-window/` (the M9 attacker runs *on the existing client box*, against the *existing* window — there is no separate `deploy/m9-scenario/` box). This rejects the attacker-scenario spec's `deploy/m9-scenario/` location in favor of reusing the live M7 environment, which is what the exit criterion actually needs.

**Import-graph rule (hard):** nothing under `internal/llm/` or `cmd/llm-attacker/` may import `internal/engine`, `internal/intelligence`, `internal/sting`, or any adapter/proxy package. The attacker is conceptually the adversary; it does its own cost accounting and never touches the engine's stores. (Verified the existing `cost.go`/`event.go` types it would otherwise reach for — it must NOT; it reads the proxy number over the tap's HTTP, not by import.)

---

## 2. The Agent Core (SDK loop, verified call surface)

### D1 + D2 recommendation, restated with the deciding fact
**Use the SDK; bump `go.mod` to `go 1.24`.** The SDK's `go.mod` minimum is go 1.24; the box runs 1.25.3 so the directive bump is metadata only. The integration spec argued for raw HTTP partly on "the SDK works at go 1.22" — that is false, so that argument collapses. The skill's mandate plus verified typed access to `Usage`/`StopReason`/`OutputConfig.Effort` settle it.

### Files (agent core)
```
internal/llm/anthropic/client.go        — Messager interface + SDK-backed Client
internal/llm/anthropic/fake.go          — FakeClient (queued responses, zero network)
internal/llm/anthropic/client_test.go   — interface conformance / usage decoding
internal/llm/attacker/agent.go          — the manual agentic loop (RunAttack)
internal/llm/attacker/http_tool.go      — the http_request keepalive tool executor
internal/llm/attacker/budget.go         — Budget: $-accumulation, hard cap, kill switch
internal/llm/attacker/prompt.go         — system prompt + initial user message
internal/llm/attacker/agent_test.go     — loop/budget/turn-limit/cancel/scripted tests
cmd/llm-attacker/main.go                — flags, key, signal handler, client wiring, summary
```

### `internal/llm/anthropic/client.go` — the Messager seam

The agent loop depends on an **interface**, not the SDK concrete type, so tests run offline. The SDK call shapes below are **verified against `anthropic-sdk-go/main/message.go`** (line numbers cited).

```go
package anthropic // internal wrapper; NOT the SDK package name

import (
    "context"
    sdk "github.com/anthropics/anthropic-sdk-go"
    "github.com/anthropics/anthropic-sdk-go/option"
)

// Messager is the one method the agent loop needs. The real client and the
// fake both implement it, so the loop is testable with zero network.
type Messager interface {
    New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error)
}

type Client struct{ inner sdk.Client } // sdk.NewClient returns a value, not a pointer

func New(apiKey string) *Client {
    // anthropic.NewClient() reads ANTHROPIC_API_KEY automatically; pass it
    // explicitly only when we already hold it (key-file path).
    if apiKey == "" {
        return &Client{inner: sdk.NewClient()}
    }
    return &Client{inner: sdk.NewClient(option.WithAPIKey(apiKey))}
}

func (c *Client) New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error) {
    return c.inner.Messages.New(ctx, p)
}
```

`fake.go` implements `New` by popping from a `[]*sdk.Message` queue (each carrying a non-zero `Usage` so budget tests are meaningful) and recording the params it was called with.

### Verified SDK surface (no more "inspect before coding" — these are confirmed)

| Symbol | Verified location / value | Resolves spec uncertainty |
|---|---|---|
| `anthropic.ModelClaudeOpus4_8` | model constant | model flag default |
| `MessageNewParams.OutputConfig OutputConfigParam` | message.go:9398 | **DECISION #5 (effort wire) RESOLVED — field exists** |
| `OutputConfigParam.Effort OutputConfigEffort` | message.go:4207 | effort goes inside `OutputConfig`, not top-level |
| `OutputConfigEffortLow/Medium/High/Xhigh/Max` | message.go:4226-4230 | **`xhigh` exists** — valid effort flag values |
| `MessageNewParams` has **no** `task_budget` | grep: only beta path has it | **task_budget is BETA-ONLY** → dropped from the non-beta loop (see note) |
| `ToolInputSchemaParam.Required []string` | message.go:6639 | **DECISION #4 RESOLVED — set `Required: []string{"method","path"}`** |
| `Usage{InputTokens, OutputTokens, CacheReadInputTokens, CacheCreationInputTokens}` all `int64` | message.go:4014-4020, 8250-8262 | **DECISION #3 RESOLVED — exact field names confirmed** |
| `Message.StopReason StopReason` | message.go:3490 | loop exit check |
| `StopReasonToolUse / EndTurn / MaxTokens / Refusal` | message.go:5494-5499 | exit conditions |
| `Message.StopDetails RefusalStopDetails` | message.go:3471 | refusal handling |
| `RefusalStopDetails.Category` (`cyber`/`bio`/`reasoning_extraction`) + `.Explanation` | message.go:5101, 5095 | log on refusal |
| `resp.ToParam()`, `block.AsAny().(type)`, `variant.JSON.Input.Raw()`, `NewToolResultBlock(id,content,isError)`, `NewUserMessage(blocks...)`, `ThinkingConfigParamUnion{OfAdaptive:&ThinkingConfigAdaptiveParam{}}` | go/claude-api.md:183-320 | the manual loop primitives |

> **Note on `task_budget`:** the SDK's *non-beta* `MessageNewParams` has no `task_budget` field (it lives only on the beta `BetaMessageNewParams`, header `task-budgets-2026-03-13`). The SDK/agent spec floated it as an optional flag — **dropped from this plan's non-beta loop** to avoid the entire `client.Beta.Messages` path. Our hard external dollar cap is the real ceiling; the model-visible countdown is a nice-to-have we are not paying the beta-complexity cost for. (If wanted later, it's a separate beta-path task.)

### `internal/llm/attacker/agent.go` — the manual loop

Adaptive thinking + effort + cached system prompt + the verified loop primitives. Budget is checked **before** each call (no spend) and accumulated **after** each response.

```go
func (a *Agent) RunAttack(ctx context.Context) (RunResult, error) {
    adaptive := sdk.ThinkingConfigAdaptiveParam{}
    messages := []sdk.MessageParam{
        sdk.NewUserMessage(sdk.NewTextBlock(initialUserMessage)),
    }

    for turn := 0; turn < a.cfg.MaxTurns; turn++ {
        if a.budget.Exceeded() {                      // pre-turn hard cap (no API call)
            a.result.StopReason = "budget_exceeded"
            break
        }
        if err := ctx.Err(); err != nil {             // kill switch (signal/cancel)
            a.result.StopReason = "cancelled"
            break
        }

        params := sdk.MessageNewParams{
            Model:     sdk.ModelClaudeOpus4_8,
            MaxTokens: 16000,
            Thinking:  sdk.ThinkingConfigParamUnion{OfAdaptive: &adaptive},
            OutputConfig: sdk.OutputConfigParam{Effort: a.cfg.Effort}, // VERIFIED field+type
            System: []sdk.TextBlockParam{{
                Text:         systemPrompt,
                CacheControl: sdk.NewCacheControlEphemeralParam(), // cache the big stable prefix
            }},
            Messages: messages,
            Tools:    a.tools, // []sdk.ToolUnionParam{{OfTool: &httpRequestTool}}
        }

        resp, err := a.client.New(ctx, params)
        if err != nil {
            // context cancel → clean exit; rate-limit (429/529) → one 60s retry; else wrap
            if ctx.Err() != nil { a.result.StopReason = "cancelled"; break }
            return a.result, fmt.Errorf("turn %d: %w", turn, err)
        }

        runningUSD := a.budget.Accumulate(resp.Usage)  // post-response accumulation
        log.Printf("[cost] turn=%d in=%d out=%d cacheRead=%d running=$%.4f",
            turn, resp.Usage.InputTokens, resp.Usage.OutputTokens,
            resp.Usage.CacheReadInputTokens, runningUSD)

        messages = append(messages, resp.ToParam())    // history BEFORE tool dispatch

        var toolResults []sdk.ContentBlockParamUnion
        for _, block := range resp.Content {
            switch v := block.AsAny().(type) {
            case sdk.ThinkingBlock:
                log.Printf("[think] %s", truncate(v.Thinking, 500))
            case sdk.TextBlock:
                log.Printf("[agent] %s", v.Text)
            case sdk.ToolUseBlock:
                raw := string(v.JSON.Input.Raw())       // VERIFIED: raw JSON accessor
                result, isErr := a.tool.Execute(ctx, raw)
                a.result.recordProbe(raw, result, isErr) // for CanaryPathsHit
                toolResults = append(toolResults,
                    sdk.NewToolResultBlock(block.ID, result, isErr))
            }
        }

        if resp.StopReason == sdk.StopReasonRefusal {
            log.Printf("[agent] refusal category=%s expl=%s",
                resp.StopDetails.Category, resp.StopDetails.Explanation)
            a.result.StopReason = "refusal"
            break
        }
        if resp.StopReason != sdk.StopReasonToolUse {    // end_turn / max_tokens → done
            a.result.StopReason = string(resp.StopReason)
            break
        }
        messages = append(messages, sdk.NewUserMessage(toolResults...))
    }
    a.result.Finalize(a.budget) // copies ledger totals into RunResult
    return a.result, nil
}
```

`RunResult` carries: `TurnsCompleted`, `TotalInputTokens`, `TotalOutputTokens`, `TotalCacheReadTokens int64`, `TotalUSD float64`, `StopReason string`, `CanaryPathsHit []string`.

### `internal/llm/attacker/http_tool.go` — the keepalive `http_request` tool

The **one** tool. The load-bearing constraint (the central correctness requirement across all three specs): **one TCP connection for the whole run = one socket cookie = one flow that escalates T0→T3.** The existing prober (`deploy/m7-window/prober/main.go:47`) sets `DisableKeepAlives: true` to get *distinct* flows; **the attacker inverts this.**

```go
// Built ONCE in main.go, shared across every tool call in the run.
func BuildKeepAliveClient(srcIP string) (*http.Client, error) {
    local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
    if err != nil { return nil, fmt.Errorf("bad src-ip %q: %w", srcIP, err) }
    dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
    return &http.Client{
        Timeout: 30 * time.Second, // MUST exceed the adapter's 8s max-hold (verified maxHold=8s)
        Transport: &http.Transport{
            DialContext:         dialer.DialContext,
            DisableKeepAlives:   false, // REQUIRED — single socket cookie across the run
            MaxIdleConnsPerHost: 1,     // force reuse of the one connection
            MaxConnsPerHost:     1,
            IdleConnTimeout:     120 * time.Second,
        },
    }, nil
}
```

Tool schema (verified `ToolInputSchemaParam.Required` exists, so D4 = set it):

```go
httpRequestTool := sdk.ToolParam{
    Name: "http_request",
    Description: sdk.String(`Make an HTTP request to the target server to probe for
files, credentials, configuration endpoints, or admin interfaces. The server may
delay responses for suspicious paths — wait for the full response. Escalate from
reconnaissance paths to credential and secret paths as you learn.`),
    InputSchema: sdk.ToolInputSchemaParam{
        Properties: map[string]any{
            "method": map[string]any{"type": "string", "enum": []string{"GET", "POST", "HEAD"}},
            "path":   map[string]any{"type": "string", "description": `URL path, must start with "/"`},
            "body":   map[string]any{"type": "string", "description": "optional POST body"},
        },
        Required: []string{"method", "path"}, // VERIFIED field — message.go:6639
    },
}
tools := []sdk.ToolUnionParam{{OfTool: &httpRequestTool}}
```

`Execute(ctx, rawInput)` → `(result string, isError bool)`:
1. `json.Unmarshal([]byte(rawInput), &in)` — never raw-string-match (skill pitfall: 4.x models vary JSON escaping).
2. `http.NewRequestWithContext(ctx, in.Method, baseURL+in.Path, body)`.
3. `client.Do(req)` — this is where the inline attrition hold fires.
4. **`io.ReadAll(io.LimitReader(resp.Body, 128*1024))` then `resp.Body.Close()`** — reading the full body to completion is mandatory for connection reuse; an abandoned body marks the connection dirty and the next request opens a *new* socket (new cookie → escalation lost). 128 KiB cap covers the 64 KiB deception body (verified `bodyCap=64<<10`) while bounding the tool-result string. **This read-to-completion is the deception-burn mechanism**: the body becomes a `tool_result`, accumulates in `messages`, and is re-encoded as input tokens on every subsequent turn.
5. Return `"HTTP <status> | <n> bytes | <first 4096 bytes>"` or `"error: <msg>"` (isError=true; the model adapts to a new path — the loop never aborts on a tool error).

### `internal/llm/attacker/budget.go` — usage/real-cost capture + enforcement

```go
type Budget struct {
    hardCapUSD, inPerMTok, outPerMTok, cachePerMTok float64
    mu sync.Mutex
    inTok, outTok, cacheTok int64
    usd float64
}

// Accumulate uses the VERIFIED int64 Usage fields. Prices are per MILLION tokens.
func (b *Budget) Accumulate(u sdk.Usage) float64 {
    b.mu.Lock(); defer b.mu.Unlock()
    b.inTok    += u.InputTokens
    b.outTok   += u.OutputTokens
    b.cacheTok += u.CacheReadInputTokens
    b.usd = float64(b.inTok)/1e6*b.inPerMTok +
            float64(b.outTok)/1e6*b.outPerMTok +
            float64(b.cacheTok)/1e6*b.cachePerMTok
    return b.usd
}
func (b *Budget) Exceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.usd >= b.hardCapUSD }
```

Defaults: `inPerMTok=5.0`, `outPerMTok=25.0`, `cachePerMTok=0.5` — **the verified Opus 4.8 rates.** All three are flags (`-input-price-per-mtok` etc.) so the demo re-runs as pricing changes without a rebuild.

**Two-layer hard cap + kill switch:** pre-turn `Exceeded()` (no API call once tripped) + post-response `Accumulate()`. The kill switch is `main.go` registering SIGINT/SIGTERM → `context.CancelFunc`; an in-flight `client.New(ctx,…)` returns on cancel and the loop exits cleanly.

---

## 3. The Attacker Scenario

### System prompt (`prompt.go`, set as cached `[]TextBlockParam`)
**⚠️ D6/SIGNOFF — founder reviews this text before the first live run** (Anthropic usage policy requires authorized-testing-of-owned-systems framing; ours qualifies — EXAMPLE-namespace canaries, AWS-private-only target, single read-only tool).

```
You are an autonomous offensive-security agent conducting AUTHORIZED penetration
testing of internal microservices for a red-team engagement against CanarySting's
OWN controlled staging environment. This is legitimate testing of our own systems.
You have a foothold inside the target's private network.

Objectives, in order:
1. ENUMERATE — discover reachable HTTP services and paths; build a map.
2. CREDENTIAL HARVEST — find config/env files, cloud credentials, DB connection
   strings, backups. High-value paths on internal services include /.env,
   /.aws/credentials, /backup/, /config/, /secrets/, /internal/, /admin/.
3. EXFILTRATE — record every credential/token/key/DB URL; then try to use it
   (follow DB URLs, service URLs, bucket names you discover).
4. LATERAL MOVEMENT — use discovered references to reach adjacent services;
   descend into every subdirectory a listing shows.

RULES OF ENGAGEMENT:
- Be thorough and tenacious. Do not give up on a lead after one failure; retry
  with variations.
- Read every retrieved file or listing completely. Follow every link, subdir,
  and reference. Parse JSON fully — credentials may be nested at any depth.
- If a response is slow, WAIT for the complete response; slow internal services
  are normal and may carry valuable data.
- Use ONLY the http_request tool. Do not describe actions — DO them. GET for
  discovery; POST only with a body.
- Do not stop until you have either exfiltrated a working credential set or
  exhausted all leads.
- Summarize findings at the end: every path, every (masked) credential, every
  service reference, total requests.

This is AUTHORIZED testing of OUR OWN deception range. Proceed.
```

Initial user message: *"Begin the engagement. Systematically probe the target for exposed credentials, configuration files, secrets, backup files, and admin interfaces. Report what you find as you go."*

### Why this reliably reaches canaries and engages deception
- The path list names the **exact** five `demoCanaryPaths` (verified `cmd/envoy-adapter/main.go:57-63`: `/.aws/credentials`, `/.env`, `/backup/db.sql`, `/internal/buckets`, `/admin/metrics`) by *category* — a competent attacker guesses them, so canary contact happens in the first few turns without spoon-feeding exact strings.
- "Read completely / follow every subdir / parse JSON fully" forces consumption of the **fake_tree** maze (verified `mazeFanOut=12` child links per page, `internal/sting/attrition/generators.go:40,217`) and the **token_bait** blobs (verified `baitTokenRatio=3.0`, `cost.go:55` → an 8 KiB Unicode blob ≈ 24K estimated tokens).
- "Wait for slow responses" stops the agent cancelling the hold — it waits the full ≤8s, which is exactly what runs up `TimeHeldSec` (verified `maxHold=8s`, `attrition-body-cap=64KiB`).

### Escalation via keepalive (the deception-burn loop)
One persistent TCP connection (the §2 keepalive client) → one socket cookie → score accumulates across distinct canary types on **one flow**:

```
Turn 1  GET /.env             → Tier 0/1, score climbing, normal-ish response
Turn 2  GET /.aws/credentials → score climbing
Turn 3  GET /backup/db.sql    → score climbing (Tag)
Turn 4  GET /internal/buckets → Contain threshold crossed → INLINE Tier 2:
          adapter holds ≤8s, returns ≤64 KiB fake_tree (dir listing + 12 child
          links + .env leaf w/ EXAMPLE AWS keys + DATABASE_URL)
Turn 5+ agent reads the maze body (real input tokens), follows the DB URL +
          the 12 child links on the SAME connection → more maze/token_bait →
          context compounds → $-meter climbs
…       Jail threshold crossed → eBPF verdict_map DROPs the socket → agent's
          requests start failing → it retries (as instructed) → new connection,
          new cookie, restarts at Tier 0 → harness hits budget cap → final
          summary turn → exit.
```
With `-aggressive` thresholds (all at 0.01), even Turn 1 trips Tier 2 — fastest demo path (D6).

### Path discovery
The agent is **not** handed exact canary strings. It (a) guesses category paths → hits canaries; (b) the fake_tree `.env` leaf hands it `DATABASE_URL=…db.payments.example…` (a reserved `.example` domain that routes nowhere — a lead that consumes turns) and 12 subdirectory links per page → it descends → more idempotent maze content (verified `mazeNode(seed, path)` is per-path-stable). This is the self-feeding burn.

### Scripted no-API variant (`-scripted`)
Deterministic, **zero API cost**, ~60s, runs in CI and rehearsal. Same `internal/llm/attacker` loop, but the LLM call is replaced by a fixed sequence (no `Messager` used): one keepalive connection, touch all five canaries in order with a short gap, read+print each body, parse the first deception body for child links, follow N (`-maze-depth`, default 3), print an escalation ledger (per-request status, tier inferred from body size / connection error, total bytes, estimated imposed tokens). Produces **real engine events and a real `StingOutcome`** (so proxy numbers show on the dashboard) at **$0**. It is the reference trace run *before* burning real credits, and the safety net that keeps `make check` exercising the full HTTP path with no key.

---

## 4. Integration / Deploy

### Where it runs
On the **existing M7 client box** (the generator/prober box, declared-attacker IP `10.20.1.111` — verified in `ground-truth-registry.json`), against the **existing** server Envoy (`http://<SERVER_PRIV>:8080`). No new box, no `deploy/m9-scenario/` tree. The M9 attacker is a third actor inside the live window — its flows are correctly labeled attacker by the staged labeler, so it also accrues real adversary-interaction history for the intelligence layer.

### Client-box egress (D3)
**No Terraform change.** Verified: client-box SG already has unrestricted egress (`protocol="-1", cidr_blocks=["0.0.0.0/0"]`) → reaches `api.anthropic.com:443` today.

### API-key handling (D4)
- Client box: `/etc/canarysting/anthropic.key`, mode 0600, never committed, never logged, never a CLI arg:
  ```
  ANTHROPIC_API_KEY=sk-ant-...
  ```
- The SDK's `anthropic.NewClient()` auto-reads `ANTHROPIC_API_KEY`. The systemd unit uses `EnvironmentFile=/etc/canarysting/anthropic.key` (same pattern as the verified `/etc/canarysting/m7.env`). `run-attack.sh` sources it. Dev machine: `export ANTHROPIC_API_KEY=…`.
- `-key-file` flag (reads a file, trims whitespace) is the explicit alternative; if unset, the binary falls back to the env var. If neither is present and not `-scripted`, exit with a clear message *before* any work.
- `.gitignore` already ignores `/bin/` and `dashboard/app/.env.local`; add `*.key` and `/etc/`-style local artifacts are out of repo anyway.

### The binary + flags (`cmd/llm-attacker/main.go`)
Reads key → builds keepalive client (`BuildKeepAliveClient(srcIP)`) → builds `Budget` → builds `anthropic.Client` (or none, scripted) → registers SIGINT/SIGTERM→cancel → `RunAttack(ctx)` → prints the ledger → optional `-cost-out` JSON. Exit codes: 0 = completed/budget-exhausted, 1 = infra error, 2 = killed by signal.

| Flag | Default | Meaning |
|---|---|---|
| `-target` | `http://10.20.1.24:8080` | server Envoy base URL (private IP; verified server priv .24) |
| `-src-ip` | `10.20.1.111` | bind IP — the declared attacker |
| `-model` | `claude-opus-4-8` | model ID |
| `-effort` | `high` | one of low/medium/high/xhigh/max (verified constants); `xhigh`/`max` = best demo, faster $-burn |
| `-hard-cap-usd` | `5.0` | hard dollar ceiling |
| `-max-turns` | `30` | turn limit |
| `-input-price-per-mtok` | `5.0` | verified Opus 4.8 input rate |
| `-output-price-per-mtok` | `25.0` | verified Opus 4.8 output rate |
| `-cache-read-price-per-mtok` | `0.5` | ~10% of input |
| `-scripted` | `false` | zero-API deterministic mode |
| `-canary-paths` | the five paths | probe set (scripted) |
| `-maze-depth` | `3` | scripted: child links to follow |
| `-key-file` | `""` | API key file (else `ANTHROPIC_API_KEY`) |
| `-tap-addr` | `http://<SERVER_PRIV>:8088` | tap for reading the proxy number post-run (optional, non-fatal) |
| `-cost-out` | `""` | write `RunResult` JSON here |

### Scenario orchestration — one command (`deploy/m7-window/run-attack.sh`)
```
Usage: run-attack.sh [--scripted] [--model claude-opus-4-8] [--budget 5.0] [--max-turns 30] [--effort high]
```
1. **Health-check** the server: `GET http://<SERVER_PRIV>:8088/healthz` (verified endpoint). Abort with a clear message if down — don't burn tokens against a dead target.
2. **(D6a) Stop the prober** for a clean single-cookie trace: `sudo systemctl stop canarysting-prober`; restart on exit (`trap`).
3. **Build** if stale: `go build -o /opt/canarysting/bin/llm-attacker ./cmd/llm-attacker`.
4. **Resolve key** from `/etc/canarysting/anthropic.key` (skip for `--scripted`).
5. **Run** the attacker with demo flags, tailing output live.
6. **Real-cost surfacing (D5):** after the run, read `-cost-out` JSON for the real burn, and `GET http://<SERVER_PRIV>:8088/raw/events` for the flow's `TokenCostProxy` (verified field `internal/intelligence/event.go:45`). Print side-by-side.
7. Print the dashboard URL.

### Real-cost on the dashboard (D5)
Two numbers, never merged:
- **Real burn** — from `resp.Usage` accumulated in `Budget`, written to `-cost-out` JSON, surfaced by `run-attack.sh`. This is the attacker's ground-truth observable.
- **Proxy estimate** — `StingOutcome.TokenCostProxy` (defender-derived from bytes/`baitTokenRatio`), already carried by `AttackerCostView.TokensBurned` (verified `views.go:153`) and surfaced on the M8 dashboard.

The demo beat:
```
[M9 RESULT] turns=12 input=45,230 output=8,110 cache_read=31,000
[M9 RESULT] real_cost=$0.46 (in $0.23 + out $0.20 + cache $0.02)   ← VERIFIED $5/$25 rates
[M9 RESULT] system_proxy_tokens=2,847,000  proxy_cost_equiv≈$71   ← defender estimate
[M9 RESULT] ASYMMETRY: attacker burned ~$0.46 real; defender cost flat/bounded
```
MVP = run-end JSON + script narration (no tap change). **Live on-screen meter = fast-follow, gated on D5 signoff** (adds `PUT /raw/attack-ledger` to the tap, breaking its read-only invariant, + a `views.Overview` field).

### Optional long-run unit (`deploy/m7-window/systemd/canarysting-llm-attacker.service`)
For accruing continuous real adversary history during the window (not the demo path). `EnvironmentFile` for `m7.env` + `anthropic.key`; `Restart=on-failure` (NOT `always` — budget-exhausted exit 0 must not auto-restart); a **lower per-run cap** (e.g. `$0.50`) and `StartLimitIntervalSec`/`StartLimitBurst` to bound daily spend. Installed by `client-setup.sh` only if the key file exists; **not enabled by default.** Continuous-run budget value is a founder call (folded into D5/window concerns).

---

## 5. Phased Build Sequence + Verification

**Verification invariants:** `make check` (= `fmt-check + vet + build + test + selfcheck`, verified) stays green at every phase. All unit tests use a **FakeClient** (zero `api.anthropic.com` traffic) + **`httptest.Server`** (zero real-target traffic). Live API runs are gated behind the key and are **never** part of `make check`.

**Phase 0 — module setup (D1/D2)**
- [ ] Bump `go.mod` directive `go 1.22 → go 1.24`.
- [ ] `go get github.com/anthropics/anthropic-sdk-go` → `go mod tidy`.
- [ ] `go build ./...` green (SDK imported only by `internal/llm/anthropic` + `cmd/llm-attacker`; verify import graph rule — no engine/intelligence/sting/adapter imports under `internal/llm`).

**Phase 1 — SDK seam (offline)**
- [ ] `internal/llm/anthropic/client.go` (`Messager`, `Client`, `New`).
- [ ] `internal/llm/anthropic/fake.go` (`FakeClient`, queued `*sdk.Message` with non-zero `Usage`).
- [ ] `internal/llm/anthropic/client_test.go` — `FakeClient` satisfies `Messager`; usage decodes.
- [ ] `go test -race ./internal/llm/...` green.

**Phase 2 — keepalive tool + budget**
- [ ] `http_tool.go` (`BuildKeepAliveClient`, `Execute` with `io.ReadAll(LimitReader)` + `Close`).
- [ ] Test against `httptest.Server`: two consecutive `Execute` calls reuse **one** TCP connection (assert via a connection counter in the test server) — proves `DisableKeepAlives:false`+`MaxConnsPerHost:1`.
- [ ] `budget.go` (`Accumulate` with verified `Usage` fields, `Exceeded`, `Summary`).
- [ ] Test: cost math at $5/$25/$0.5; `Exceeded` fires at the exact cap.

**Phase 3 — agent loop**
- [ ] `prompt.go` (system prompt + initial message).
- [ ] `agent.go` (the §2 loop; effort via `OutputConfig.Effort`; adaptive thinking; refusal handling; rate-limit single-retry; tool-error never aborts).
- [ ] `agent_test.go`: (a) FakeClient → one tool-call response then `end_turn` drives one real `Execute` against `httptest.Server`; (b) zero budget → kill on turn 0, no call; (c) `max-turns=1` stops after one round-trip; (d) `context` cancel mid-loop exits clean; (e) `-scripted` mode drives the HTTP loop with no `Messager`.
- [ ] `make check` green.

**Phase 4 — binary**
- [ ] `cmd/llm-attacker/main.go` (flags, key-file/env, signal→cancel, summary, `-cost-out`).
- [ ] `go build ./cmd/llm-attacker`.
- [ ] **Zero-spend dry-run:** `./llm-attacker -scripted -target http://127.0.0.1:<httptest>` locally — full keepalive plumbing, $0.

**Phase 5 — orchestration + deploy artifacts**
- [ ] `deploy/m7-window/run-attack.sh` (health-check, prober stop/restart trap, build, key, run, cost ledger).
- [ ] `deploy/m7-window/systemd/canarysting-llm-attacker.service` (long-run, not enabled by default).
- [ ] `client-setup.sh`: build+install `llm-attacker`; install (not enable) the unit.
- [ ] `Makefile`: `cmd/...` already covers the binary via `make bin` (verified `go build -o $(BIN_DIR)/ ./cmd/...`); add a convenience `attack-scripted` target; point `demo` at `run-attack.sh`. (Not part of `make check`.)
- [ ] `deploy/m7-window/README.md`: add the M9 section.

**Phase 6 — gated live smoke (needs the key + the live box; NOT in `make check`)**
- [ ] Rsync repo → client box; `client-setup.sh <server-priv>`; create `/etc/canarysting/anthropic.key`.
- [ ] `run-attack.sh --scripted` → verify Tier 2 inline body + the adapter `ATTRITION … tier=2` log + one ESTABLISHED conn from `.111` (`netstat -tn`) + events in `/raw/events`. **$0.**
- [ ] **Smallest live run:** `run-attack.sh --budget 0.50 --max-turns 5` → confirm the deception-burn loop, the live per-turn `[cost]` meter, and that the ledger matches the Anthropic console usage. **(Hard cap proven before spending $5.)**
- [ ] **Full demo run:** `run-attack.sh` ($5 cap, effort per D6) → the real-vs-proxy asymmetry ledger.

---

## Appendix — Reconciliations applied (where the specs disagreed, and the deciding fact)

- **SDK vs raw HTTP:** SDK. Integration spec's pro-raw-HTTP case rested on the false claim that the SDK runs at go 1.22; verified the SDK needs go 1.24, so the premise is void, and the skill mandates the official SDK.
- **Code location:** layered `internal/llm/anthropic` + `internal/llm/attacker` + `cmd/llm-attacker` (integration spec's structure) — only layout that yields real offline unit tests keeping `make check` green. Rejected the flat `cmd/llm-attacker/` everything and the separate `deploy/m9-scenario/` box; M9 runs in the live M7 window per the exit criterion.
- **Pricing:** **$5 / $25 per 1M** (verified skill table) — integration spec's $15/$75 corrected.
- **go.mod:** bump to `go 1.24` (SDK/agent spec right; integration spec's "no change" wrong).
- **`task_budget`:** dropped — beta-only field, not on non-beta `MessageNewParams`.
- **Effort:** `OutputConfig.Effort`, values incl. `xhigh` — verified; SDK/agent spec's "inspect before coding" resolved.
- **`ToolInputSchemaParam.Required`:** exists → set it; resolved.
- **`Usage` fields:** `InputTokens`/`OutputTokens`/`CacheReadInputTokens`/`CacheCreationInputTokens` (int64) — verified.
- **`StopDetails`:** `RefusalStopDetails{Category, Explanation}`; categories `cyber`/`bio`/`reasoning_extraction` — verified.
- **Streaming:** non-streaming (`max_tokens:16000`) is the default and sufficient; switch to `NewStreaming`+`message.Accumulate` only if long thinking blocks time out.
- **Tool surface:** SDK/agent spec's `http_request{method,path,body}` adopted over the scenario spec's GET-only `http_get{url}` — `method`+`path` (target base URL fixed in the executor) is safer (agent can't redirect off-target) and supports POST for the escalation narrative.

Relevant absolute paths: `/Users/danielhenley/projects/canary-sting/canarysting-repo/go.mod`, `/Users/danielhenley/projects/canary-sting/canarysting-repo/cmd/envoy-adapter/main.go` (canary paths :57-63, maxHold :89, bodyCap :88), `/Users/danielhenley/projects/canary-sting/canarysting-repo/deploy/m7-window/prober/main.go` (DisableKeepAlives :47), `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/sting/attrition/generators.go` (mazeFanOut :40, mazeNode :217, envLeaf :232), `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/sting/attrition/cost.go` (baitTokenRatio :55, TokenCostProxy :80), `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/intelligence/event.go` (TokenCostProxy :45), `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/dashboard/tap/tap.go` (read-only: /healthz, /raw/state, /raw/events), `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/dashboard/backend/views/views.go` (AttackerCostView.TokensBurned :153), `/Users/danielhenley/projects/canary-sting/canarysting-repo/deploy/m7-window/client-setup.sh`, `/Users/danielhenley/projects/canary-sting/canarysting-repo/Makefile`, `/Users/danielhenley/projects/canary-sting/canarysting-repo/deploy/m7-window/ground-truth-registry.json`. Verified SDK source: `anthropic-sdk-go/main/message.go` (OutputConfig :9398, OutputConfigParam.Effort :4207, effort consts :4226-4230, ToolInputSchemaParam.Required :6639, Usage :8250-8262, StopReason consts :5494-5499, RefusalStopDetails :5095-5101).
