package attacker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
)

// newTarget spins up a fake target that records the paths it was asked for.
func newTarget(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		fmt.Fprintf(w, "body for %s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func toolFor(t *testing.T, baseURL string) *HTTPTool {
	t.Helper()
	target, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test target: %v", err)
	}
	if err := requireLoopbackHost(target.Hostname()); err != nil {
		t.Fatal(err)
	}
	c, err := BuildKeepAliveClient("")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	guardLoopbackClient(t, c)
	return NewHTTPTool(c, baseURL)
}

func guardLoopbackClient(t *testing.T, client *http.Client) {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test client transport is %T, want *http.Transport", client.Transport)
	}
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("test network address %q is invalid: %w", address, err)
		}
		if err := requireLoopbackHost(host); err != nil {
			return nil, err
		}
		return dial(ctx, network, address)
	}
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if err := requireLoopbackHost(req.URL.Hostname()); err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
		return nil
	}
}

func requireLoopbackHost(host string) error {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("test network target %q is outside the loopback allowlist", host)
	}
	return nil
}

// (a) FakeClient returns one tool-call response, then end_turn → drives exactly
// one real Execute against the httptest target and exits cleanly.
func TestAgentLoopOneToolThenEndTurn(t *testing.T) {
	srv, paths := newTarget(t)

	toolUse, err := anthropic.MessageFromJSON(`{
		"id":"m1","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"tool_use",
		"content":[{"type":"tool_use","id":"tu1","name":"http_request","input":{"method":"GET","path":"/.env"}}],
		"usage":{"input_tokens":100,"output_tokens":50}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	done, err := anthropic.MessageFromJSON(`{
		"id":"m2","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"end_turn",
		"content":[{"type":"text","text":"done, found a .env"}],
		"usage":{"input_tokens":200,"output_tokens":20}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	fake := &anthropic.FakeClient{Responses: []*sdk.Message{toolUse, done}}

	a := NewAgent(fake, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{Model: sdk.ModelClaudeOpus4_8})
	res, err := a.RunAttack(context.Background())
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if res.StopReason != "end_turn" {
		t.Fatalf("want end_turn, got %q", res.StopReason)
	}
	if len(*paths) != 1 || (*paths)[0] != "/.env" {
		t.Fatalf("want one Execute of /.env, got %v", *paths)
	}
	// 300 input @ $5/1M + 70 output @ $25/1M
	wantUSD := 300.0/1e6*5 + 70.0/1e6*25
	if res.TotalUSD < wantUSD-1e-9 || res.TotalUSD > wantUSD+1e-9 {
		t.Fatalf("usd: want %.8f got %.8f", wantUSD, res.TotalUSD)
	}
	if res.TurnsCompleted != 2 {
		t.Fatalf("want 2 turns, got %d", res.TurnsCompleted)
	}
}

// (b) Zero budget → killed on turn 0 with no API call.
func TestAgentZeroBudgetKillsBeforeCall(t *testing.T) {
	srv, _ := newTarget(t)
	fake := &anthropic.FakeClient{} // empty queue: any call would error
	a := NewAgent(fake, toolFor(t, srv.URL), NewBudget(0, 5, 25, 0.5), Config{Model: sdk.ModelClaudeOpus4_8})
	res, err := a.RunAttack(context.Background())
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if res.StopReason != "budget_exceeded" {
		t.Fatalf("want budget_exceeded, got %q", res.StopReason)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("budget cap must prevent any API call, got %d", fake.CallCount())
	}
}

// (c) MaxTurns=1 stops after exactly one round-trip even if the model keeps
// asking for tools.
func TestAgentMaxTurnsStops(t *testing.T) {
	srv, _ := newTarget(t)
	mk := func(id string) *sdk.Message {
		m, err := anthropic.MessageFromJSON(fmt.Sprintf(`{
			"id":%q,"type":"message","role":"assistant","model":"claude-opus-4-8",
			"stop_reason":"tool_use",
			"content":[{"type":"tool_use","id":"tu","name":"http_request","input":{"method":"GET","path":"/x"}}],
			"usage":{"input_tokens":10,"output_tokens":5}
		}`, id))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	fake := &anthropic.FakeClient{Responses: []*sdk.Message{mk("a"), mk("b"), mk("c")}}
	a := NewAgent(fake, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{Model: sdk.ModelClaudeOpus4_8, MaxTurns: 1})
	res, err := a.RunAttack(context.Background())
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("max-turns=1 must make exactly one call, got %d", fake.CallCount())
	}
	if res.StopReason != "max_turns" {
		t.Fatalf("want max_turns, got %q", res.StopReason)
	}
}

// (d) Context cancel mid-loop exits clean.
func TestAgentContextCancel(t *testing.T) {
	srv, _ := newTarget(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the loop even starts
	fake := &anthropic.FakeClient{}
	a := NewAgent(fake, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{Model: sdk.ModelClaudeOpus4_8})
	res, err := a.RunAttack(ctx)
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if res.StopReason != "cancelled" {
		t.Fatalf("want cancelled, got %q", res.StopReason)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("cancelled context must prevent any call, got %d", fake.CallCount())
	}
}

// (e) Scripted mode drives the HTTP loop with no Messager.
func TestAgentScripted(t *testing.T) {
	srv, paths := newTarget(t)
	a := NewAgent(nil, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{
		Scripted:    true,
		CanaryPaths: []string{"/.env", "/.aws/credentials", "/backup/db.sql"},
		MazeDepth:   0,
	})
	a.sleep = func(time.Duration) {} // no real sleeps in test
	res, err := a.RunAttack(context.Background())
	if err != nil {
		t.Fatalf("RunAttack: %v", err)
	}
	if res.StopReason != "scripted_complete" {
		t.Fatalf("want scripted_complete, got %q", res.StopReason)
	}
	if len(*paths) != 3 {
		t.Fatalf("want 3 touches, got %v", *paths)
	}
	if len(res.CanaryPathsHit) != 3 {
		t.Fatalf("want 3 canary hits, got %v", res.CanaryPathsHit)
	}
	if res.TotalUSD != 0 {
		t.Fatalf("scripted mode must cost $0, got %.4f", res.TotalUSD)
	}
}

// Progress hook fires once per turn (used by the live cost meter).
func TestAgentProgressHook(t *testing.T) {
	srv, _ := newTarget(t)
	done, _ := anthropic.MessageFromJSON(`{
		"id":"m","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"end_turn","content":[{"type":"text","text":"hi"}],
		"usage":{"input_tokens":10,"output_tokens":5}
	}`)
	fake := &anthropic.FakeClient{Responses: []*sdk.Message{done}}
	a := NewAgent(fake, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{Model: sdk.ModelClaudeOpus4_8})
	var snaps []Snapshot
	a.SetProgressHook(func(s Snapshot) { snaps = append(snaps, s) })
	if _, err := a.RunAttack(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 1 {
		t.Fatalf("want 1 progress emit, got %d", len(snaps))
	}
	if snaps[0].InputTokens != 10 {
		t.Fatalf("progress snapshot wrong: %+v", snaps[0])
	}
}

// scripted maze-follow: the first body's child links are followed.
func TestScriptedFollowsMaze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/buckets" {
			// directory-listing style body with child links
			fmt.Fprint(w, `<a href="/internal/buckets/a">a</a> <a href="/internal/buckets/b">b</a>`)
			return
		}
		fmt.Fprintf(w, "leaf %s", r.URL.Path)
	}))
	defer srv.Close()
	a := NewAgent(nil, toolFor(t, srv.URL), NewBudget(5, 5, 25, 0.5), Config{
		Scripted:    true,
		CanaryPaths: []string{"/internal/buckets"},
		MazeDepth:   2,
	})
	a.sleep = func(time.Duration) {}
	res, err := a.RunAttack(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 1 canary + 2 maze children
	if len(res.Probes) != 3 {
		t.Fatalf("want 3 probes (1 canary + 2 maze), got %d: %+v", len(res.Probes), res.Probes)
	}
	var followed []string
	for _, p := range res.Probes {
		followed = append(followed, p.Path)
	}
	joined := strings.Join(followed, ",")
	if !strings.Contains(joined, "/internal/buckets/a") || !strings.Contains(joined, "/internal/buckets/b") {
		t.Fatalf("maze children not followed: %s", joined)
	}
}

func TestScriptedRejectsRedirectOutsideLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/escape", http.StatusFound)
	}))
	defer srv.Close()
	tool := toolFor(t, srv.URL)
	_, isError, probe := tool.Execute(context.Background(), `{"method":"GET","path":"/redirect"}`)
	if !isError || !strings.Contains(probe.Err, "outside the loopback allowlist") {
		t.Fatalf("external redirect was not blocked before dialing: error=%v probe=%+v", isError, probe)
	}
}

func TestLoopbackTestClientRejectsExternalDial(t *testing.T) {
	client, err := BuildKeepAliveClient("")
	if err != nil {
		t.Fatal(err)
	}
	guardLoopbackClient(t, client)
	_, err = client.Get("http://192.0.2.1/escape")
	if err == nil || !strings.Contains(err.Error(), "outside the loopback allowlist") {
		t.Fatalf("external dial was not blocked: %v", err)
	}
}
