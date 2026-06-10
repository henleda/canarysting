// Command llm-attacker is the M9 adversary: an Anthropic Claude agentic loop
// (or a deterministic zero-API scripted variant) that drives the live
// CanarySting deception range from the declared-attacker source IP over a
// single keepalive connection, burning real tokens on the deception bodies it
// pulls back — bounded by a hard dollar cap.
//
// Import-graph rule (hard): this binary must NOT import internal/engine,
// internal/intelligence, internal/sting, or any adapter/proxy package. It
// reaches the engine only over HTTP (the read-only dashboard tap), and posts
// its own live cost ledger to the tap as raw JSON (no shared types).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
	"github.com/canarysting/canarysting/internal/llm/attacker"
)

func main() {
	var (
		target        = flag.String("target", "http://10.20.1.24:8080", "server Envoy base URL (private IP)")
		srcIP         = flag.String("src-ip", "10.20.1.111", "local bind IP — the declared attacker (empty = OS default)")
		model         = flag.String("model", string(sdk.ModelClaudeOpus4_8), "model ID")
		effort        = flag.String("effort", "high", "thinking effort: low|medium|high|xhigh|max")
		hardCapUSD    = flag.Float64("hard-cap-usd", 5.0, "hard dollar ceiling per run")
		maxTurns      = flag.Int("max-turns", 30, "turn limit")
		maxTokens     = flag.Int64("max-tokens", 16000, "max_tokens per response")
		inPrice       = flag.Float64("input-price-per-mtok", 5.0, "Opus 4.8 input $/1M tokens")
		outPrice      = flag.Float64("output-price-per-mtok", 25.0, "Opus 4.8 output $/1M tokens")
		cachePrice    = flag.Float64("cache-read-price-per-mtok", 0.5, "cache-read $/1M tokens")
		scripted      = flag.Bool("scripted", false, "zero-API deterministic mode (no key needed)")
		canaryCSV     = flag.String("canary-paths", "", "scripted: comma-separated probe set (default: the five demo canaries)")
		mazeDepth     = flag.Int("maze-depth", 3, "scripted: child links to follow from the first deception body")
		keyFile       = flag.String("key-file", "", "API key file (else ANTHROPIC_API_KEY env)")
		tapAddr       = flag.String("tap-addr", "", "dashboard tap base URL for the live cost meter + proxy readback (optional)")
		costOut       = flag.String("cost-out", "", "write the run-result ledger JSON to this path")
		meterInterval = flag.Duration("meter-min-interval", 500*time.Millisecond, "min interval between live-meter POSTs to the tap")
	)
	flag.Parse()

	cfg := attacker.Config{
		Model:     sdk.Model(*model),
		MaxTokens: *maxTokens,
		Effort:    parseEffort(*effort),
		MaxTurns:  *maxTurns,
		Scripted:  *scripted,
		MazeDepth: *mazeDepth,
	}
	if *canaryCSV != "" {
		cfg.CanaryPaths = splitCSV(*canaryCSV)
	}

	// Build the single keepalive client (one socket cookie for the whole run).
	httpClient, err := attacker.BuildKeepAliveClient(*srcIP)
	if err != nil {
		log.Fatalf("llm-attacker: %v", err)
	}
	tool := attacker.NewHTTPTool(httpClient, *target)
	budget := attacker.NewBudget(*hardCapUSD, *inPrice, *outPrice, *cachePrice)

	// Resolve the client (real SDK, or none for scripted).
	var client anthropic.Messager
	if !*scripted {
		key, err := resolveKey(*keyFile)
		if err != nil {
			log.Fatalf("llm-attacker: %v", err)
		}
		client = anthropic.New(key)
	}

	agent := attacker.NewAgent(client, tool, budget, cfg)

	// Live cost meter (D5): POST the running real-cost ledger to the tap each
	// turn (rate-limited). Raw JSON, no shared types — keeps the import rule.
	if *tapAddr != "" {
		meter := newMeter(*tapAddr, *meterInterval)
		agent.SetProgressHook(func(s attacker.Snapshot) { meter.post(s, *model) })
	}

	// Kill switch: SIGINT/SIGTERM cancels the context; an in-flight API call
	// returns on cancel and the loop exits cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mode := "LLM(" + *model + ", effort=" + *effort + ")"
	if *scripted {
		mode = "SCRIPTED(zero-API)"
	}
	log.Printf("llm-attacker: mode=%s target=%s src-ip=%s cap=$%.2f max-turns=%d",
		mode, *target, *srcIP, *hardCapUSD, *maxTurns)

	res, err := agent.RunAttack(ctx)
	if err != nil {
		log.Printf("llm-attacker: run error: %v", err)
		printLedger(res, *tapAddr)
		writeCostOut(*costOut, res)
		os.Exit(1)
	}

	printLedger(res, *tapAddr)
	writeCostOut(*costOut, res)

	if res.StopReason == "cancelled" {
		os.Exit(2)
	}
}

func parseEffort(s string) sdk.OutputConfigEffort {
	switch strings.ToLower(s) {
	case "low":
		return sdk.OutputConfigEffortLow
	case "medium":
		return sdk.OutputConfigEffortMedium
	case "high":
		return sdk.OutputConfigEffortHigh
	case "xhigh":
		return sdk.OutputConfigEffortXhigh
	case "max":
		return sdk.OutputConfigEffortMax
	default:
		log.Printf("llm-attacker: unknown effort %q, defaulting to high", s)
		return sdk.OutputConfigEffortHigh
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolveKey reads the API key from -key-file (trimmed), else ANTHROPIC_API_KEY.
// The key is never a CLI arg (so it never shows in `ps aux`). The file may be a
// bare key or a KEY=VALUE EnvironmentFile line.
func resolveKey(keyFile string) (string, error) {
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("read key file %q: %w", keyFile, err)
		}
		return parseKeyBytes(string(b)), nil
	}
	if k := os.Getenv("ANTHROPIC_API_KEY"); k != "" {
		return k, nil
	}
	return "", fmt.Errorf("no API key: set -key-file or ANTHROPIC_API_KEY (or use -scripted for a zero-API run)")
}

func parseKeyBytes(s string) string {
	s = strings.TrimSpace(s)
	// Accept "ANTHROPIC_API_KEY=sk-..." EnvironmentFile form.
	if i := strings.IndexByte(s, '='); i >= 0 && strings.Contains(s[:i], "ANTHROPIC_API_KEY") {
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

func printLedger(res attacker.RunResult, tapAddr string) {
	// Use the per-category USD computed by the Budget at the run's CONFIGURED
	// prices (not hardcoded rates), so the breakdown always reconciles with
	// TotalUSD even when prices are overridden by flags.
	log.Printf("[M9 RESULT] turns=%d input=%d output=%d cache_read=%d cache_create=%d stop=%s",
		res.TurnsCompleted, res.TotalInputTokens, res.TotalOutputTokens,
		res.TotalCacheReadTokens, res.TotalCacheCreationTokens, res.StopReason)
	log.Printf("[M9 RESULT] real_cost=$%.4f (in $%.4f + out $%.4f + cacheRead $%.4f + cacheCreate $%.4f)",
		res.TotalUSD, res.InputUSD, res.OutputUSD, res.CacheReadUSD, res.CacheCreationUSD)
	if len(res.CanaryPathsHit) > 0 {
		log.Printf("[M9 RESULT] canary_paths_hit=%v", res.CanaryPathsHit)
	}

	// Optional: read the defender's proxy estimate from the tap for the
	// side-by-side asymmetry beat. Non-fatal.
	if tapAddr != "" {
		if proxy, ok := readProxyTokens(tapAddr); ok {
			log.Printf("[M9 RESULT] system_proxy_tokens=%d (defender estimate, separate from real)", proxy)
			log.Printf("[M9 RESULT] ASYMMETRY: attacker burned $%.4f real; defender cost flat/bounded", res.TotalUSD)
		}
	}
}

func writeCostOut(path string, res attacker.RunResult) {
	if path == "" {
		return
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Printf("llm-attacker: marshal cost-out: %v", err)
		return
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		log.Printf("llm-attacker: write cost-out %q: %v", path, err)
		return
	}
	log.Printf("llm-attacker: wrote run ledger to %s", path)
}

// readProxyTokens sums TokenCostProxy across the tap's recent events. Best
// effort: parses only the fields it needs and ignores everything else.
func readProxyTokens(tapAddr string) (int64, bool) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(strings.TrimRight(tapAddr, "/") + "/raw/events")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var events []struct {
		TokenCostProxy int64 `json:"token_cost_proxy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return 0, false
	}
	var total int64
	for _, e := range events {
		total += e.TokenCostProxy
	}
	return total, true
}

// meter posts the live real-cost ledger to the tap's write endpoint. Rate
// limited so a fast loop doesn't hammer the tap.
type meter struct {
	url      string
	client   *http.Client
	minGap   time.Duration
	lastPost time.Time
}

func newMeter(tapAddr string, minGap time.Duration) *meter {
	return &meter{
		url:    strings.TrimRight(tapAddr, "/") + "/raw/attack-ledger",
		client: &http.Client{Timeout: 3 * time.Second},
		minGap: minGap,
	}
}

// attackLedgerWire is the JSON contract with the tap's PUT /raw/attack-ledger.
// Defined locally (not imported) to respect the import-graph rule. Keep in sync
// with internal/dashboard/tap's decode struct.
type attackLedgerWire struct {
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	USD                 float64 `json:"usd"`
	HardCapUSD          float64 `json:"hard_cap_usd"`
	Model               string  `json:"model"`
	Active              bool    `json:"active"`
}

func (m *meter) post(s attacker.Snapshot, model string) {
	now := time.Now()
	if !m.lastPost.IsZero() && now.Sub(m.lastPost) < m.minGap {
		return
	}
	m.lastPost = now
	body, _ := json.Marshal(attackLedgerWire{
		InputTokens:         s.InputTokens,
		OutputTokens:        s.OutputTokens,
		CacheReadTokens:     s.CacheReadTokens,
		CacheCreationTokens: s.CacheCreationTokens,
		USD:                 s.USD,
		HardCapUSD:          s.HardCapUSD,
		Model:               model,
		Active:              true,
	})
	req, err := http.NewRequest(http.MethodPut, m.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return // best effort; the meter never blocks the attack
	}
	_ = resp.Body.Close()
}
