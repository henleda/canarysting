package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/canarysting/canarysting/internal/llm/anthropic"
	"github.com/canarysting/canarysting/internal/llm/attacker"
)

// recordingFake is the injected gatewayCaller test double: it records every path
// requested and always answers 200 — the mock-external-boundary seam (gw.Fetch is
// the ONLY external call service C makes directly; the Redteam persona's attacker
// makes its own calls via HTTPTool, never through gw).
type recordingFake struct {
	paths []string
}

func (f *recordingFake) Fetch(path string) (int, error) {
	f.paths = append(f.paths, path)
	return http.StatusOK, nil
}

// recordingLauncher is the injected redteamLauncher test double: it records how
// many times Launch was called and returns a fixed non-empty run_id (or Err, if
// set, to exercise a failure path).
type recordingLauncher struct {
	calls int
	runID string
	err   error
}

func (l *recordingLauncher) Launch() (string, error) {
	l.calls++
	if l.err != nil {
		return "", l.err
	}
	if l.runID == "" {
		l.runID = "run-fake"
	}
	return l.runID, nil
}

func getPath(t *testing.T, gw gatewayCaller, rt redteamLauncher, path string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	serve(rr, req, gw, rt)
	return rr.Code, rr.Body.String()
}

// postTransaction submits POST /api/transaction with persona as a form value. An
// empty persona omits the field entirely (true "missing", not an empty value).
func postTransaction(t *testing.T, gw gatewayCaller, rt redteamLauncher, persona string) (int, string) {
	t.Helper()
	form := url.Values{}
	if persona != "" {
		form.Set("persona", persona)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/transaction", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serve(rr, req, gw, rt)
	return rr.Code, rr.Body.String()
}

// postTransactionWithAction submits POST /api/transaction with persona AND
// action form values — the extended contract for storefront actions (design
// doc §5.2): persona=standard + action=<name> drives actionPaths[name]
// instead of the legacy standardPaths; persona=redteam ignores action
// entirely. An empty action omits the field (true "missing" — exercises the
// legacy standardPaths path for persona=standard, unchanged behavior).
func postTransactionWithAction(t *testing.T, gw gatewayCaller, rt redteamLauncher, persona, action string) (int, string) {
	t.Helper()
	form := url.Values{}
	if persona != "" {
		form.Set("persona", persona)
	}
	if action != "" {
		form.Set("action", action)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/transaction", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serve(rr, req, gw, rt)
	return rr.Code, rr.Body.String()
}

// mirroredCanaryPrefixes hand-mirrors the negative-space canary prefixes defined in
// deploy/m7-window/mesh/main.go:62-64 (canaryPrefixes) and cmd/envoy-adapter/main.go
// :243-249 (demoCanaryPaths). package main is unimportable across binaries, so this
// hand-mirror is the same pattern the mesh/adapter pair already uses — keep it in
// sync by hand if either source changes.
var mirroredCanaryPrefixes = []string{
	"/.aws/credentials", "/secrets/", "/.env", "/config/", "/backup/", "/internal/", "/admin/",
}

// The scope guard: Standard-mode paths must never collide with the canary negative
// space (rule 8), and must stay within the served surface ("/" or "/api/*").
func TestStandardPathsAreCanaryFree(t *testing.T) {
	for _, p := range standardPaths {
		for _, cp := range mirroredCanaryPrefixes {
			if p == cp || strings.HasPrefix(p, cp) {
				t.Errorf("standardPaths entry %q collides with canary prefix %q — must stay disjoint (rule 8)", p, cp)
			}
		}
		if p != "/" && !strings.HasPrefix(p, "/api/") {
			t.Errorf("standardPaths entry %q must be \"/\" or begin \"/api/\"", p)
		}
	}
}

// TestActionPathsAreCanaryFree is the load-bearing scope guard for the
// storefront action table (design doc §3 actionPaths / §5.6): every path any
// action drives against the gateway must stay disjoint from the canary
// negative space and confined to the served surface ("/" or "/api/*"). Same
// discipline as TestStandardPathsAreCanaryFree, extended to actionPaths.
func TestActionPathsAreCanaryFree(t *testing.T) {
	for action, paths := range actionPaths {
		for _, p := range paths {
			for _, cp := range mirroredCanaryPrefixes {
				if p == cp || strings.HasPrefix(p, cp) {
					t.Errorf("actionPaths[%q] entry %q collides with canary prefix %q — must stay disjoint (rule 8)", action, p, cp)
				}
			}
			if p != "/" && !strings.HasPrefix(p, "/api/") {
				t.Errorf("actionPaths[%q] entry %q must be \"/\" or begin \"/api/\"", action, p)
			}
		}
	}
}

func TestHealthz(t *testing.T) {
	code, body := getPath(t, &recordingFake{}, &recordingLauncher{}, "/healthz")
	if code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if body != "ok" {
		t.Errorf("/healthz body = %q, want \"ok\"", body)
	}
}

func TestServesStorefront(t *testing.T) {
	code, body := getPath(t, &recordingFake{}, &recordingLauncher{}, "/")
	if code != http.StatusOK {
		t.Fatalf("/ = %d, want 200", code)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("/ body does not look like HTML: %q", body)
	}
	if !strings.Contains(body, "Standard") || !strings.Contains(body, "Redteam") {
		t.Errorf("/ body missing persona toggle markers (Standard/Redteam): %q", body)
	}
	if !strings.Contains(body, "Buy") {
		t.Errorf("/ body missing a Buy control: %q", body)
	}
}

func TestStandardTransactionHitsServedPaths(t *testing.T) {
	fake := &recordingFake{}
	code, body := postTransaction(t, fake, &recordingLauncher{}, "standard")
	if code != http.StatusOK {
		t.Fatalf("persona=standard = %d, want 200", code)
	}
	if len(fake.paths) != len(standardPaths) {
		t.Fatalf("gw.Fetch called %v, want exactly %v", fake.paths, standardPaths)
	}
	for i, want := range standardPaths {
		if fake.paths[i] != want {
			t.Errorf("gw.Fetch call %d = %q, want %q", i, fake.paths[i], want)
		}
	}
	var receipt map[string]any
	if err := json.Unmarshal([]byte(body), &receipt); err != nil {
		t.Fatalf("receipt body not JSON: %v (%q)", err, body)
	}
	if receipt["persona"] != "standard" {
		t.Errorf("receipt persona = %v, want \"standard\"", receipt["persona"])
	}
	if receipt["ok"] != true {
		t.Errorf("receipt ok = %v, want true", receipt["ok"])
	}
}

func TestPersonaSelectsPathSet(t *testing.T) {
	standardFake := &recordingFake{}
	if code, _ := postTransaction(t, standardFake, &recordingLauncher{}, "standard"); code != http.StatusOK {
		t.Fatalf("persona=standard = %d, want 200", code)
	}
	if len(standardFake.paths) != len(standardPaths) {
		t.Errorf("standard fake recorded %v, want %v", standardFake.paths, standardPaths)
	} else {
		for i, want := range standardPaths {
			if standardFake.paths[i] != want {
				t.Errorf("standard fake call %d = %q, want %q", i, standardFake.paths[i], want)
			}
		}
	}

	redteamFake := &recordingFake{}
	if code, _ := postTransaction(t, redteamFake, &recordingLauncher{}, "redteam"); code != http.StatusOK {
		t.Fatalf("persona=redteam = %d, want 200", code)
	}
	if len(redteamFake.paths) != 0 {
		t.Errorf("redteam fake recorded %v, want zero gw.Fetch calls", redteamFake.paths)
	}
}

// TestRedteamLaunchesOnce replaces the old P1 TestRedteamStubInert: the Redteam
// persona is no longer an inert stub (P2) — it triggers exactly one in-process
// attacker launch and returns the launcher's run_id.
func TestRedteamLaunchesOnce(t *testing.T) {
	fake := &recordingFake{}
	rt := &recordingLauncher{}
	code, body := postTransaction(t, fake, rt, "redteam")
	if code != http.StatusOK {
		t.Fatalf("persona=redteam = %d, want 200", code)
	}
	if rt.calls != 1 {
		t.Errorf("rt.Launch called %d times, want exactly 1", rt.calls)
	}
	var receipt map[string]any
	if err := json.Unmarshal([]byte(body), &receipt); err != nil {
		t.Fatalf("receipt body not JSON: %v (%q)", err, body)
	}
	if receipt["persona"] != "redteam" {
		t.Errorf("receipt persona = %v, want \"redteam\"", receipt["persona"])
	}
	runID, _ := receipt["run_id"].(string)
	if runID == "" {
		t.Errorf("receipt run_id = %v, want non-empty", receipt["run_id"])
	}
	if receipt["active"] != true {
		t.Errorf("receipt active = %v, want true", receipt["active"])
	}
}

// TestRedteamMakesNoGatewayCalls asserts the seam boundary: service C's redteam
// branch never calls gw.Fetch directly — the ATTACKER makes the canary touches,
// over its own HTTPTool, not service C.
func TestRedteamMakesNoGatewayCalls(t *testing.T) {
	fake := &recordingFake{}
	code, _ := postTransaction(t, fake, &recordingLauncher{}, "redteam")
	if code != http.StatusOK {
		t.Fatalf("persona=redteam = %d, want 200", code)
	}
	if len(fake.paths) != 0 {
		t.Errorf("persona=redteam called gw.Fetch %v, want zero calls", fake.paths)
	}
}

func TestUnknownPersonaLaunchesNothing(t *testing.T) {
	unknown := &recordingFake{}
	unknownRT := &recordingLauncher{}
	code, _ := postTransaction(t, unknown, unknownRT, "foo")
	if code != http.StatusBadRequest {
		t.Errorf("persona=foo = %d, want 400", code)
	}
	if len(unknown.paths) != 0 {
		t.Errorf("persona=foo called gw.Fetch %v, want zero calls", unknown.paths)
	}
	if unknownRT.calls != 0 {
		t.Errorf("persona=foo called rt.Launch %d times, want zero", unknownRT.calls)
	}

	missing := &recordingFake{}
	missingRT := &recordingLauncher{}
	code, _ = postTransaction(t, missing, missingRT, "")
	if code != http.StatusBadRequest {
		t.Errorf("missing persona = %d, want 400", code)
	}
	if len(missing.paths) != 0 {
		t.Errorf("missing persona called gw.Fetch %v, want zero calls", missing.paths)
	}
	if missingRT.calls != 0 {
		t.Errorf("missing persona called rt.Launch %d times, want zero", missingRT.calls)
	}
}

// TestStandardActionDrivesConfiguredPaths freezes the per-action contract
// (design doc §3/§5.2): a Standard-persona transaction naming an action drives
// exactly actionPaths[action] against the gateway, in order, and the receipt
// echoes both persona and action. Table-driven over every entry in
// actionPaths so the implementer has zero ambiguity about the full table.
func TestStandardActionDrivesConfiguredPaths(t *testing.T) {
	for action, wantPaths := range actionPaths {
		t.Run(action, func(t *testing.T) {
			fake := &recordingFake{}
			code, body := postTransactionWithAction(t, fake, &recordingLauncher{}, "standard", action)
			if code != http.StatusOK {
				t.Fatalf("persona=standard action=%s = %d, want 200", action, code)
			}
			if len(fake.paths) != len(wantPaths) {
				t.Fatalf("gw.Fetch called %v, want exactly %v", fake.paths, wantPaths)
			}
			for i, want := range wantPaths {
				if fake.paths[i] != want {
					t.Errorf("gw.Fetch call %d = %q, want %q", i, fake.paths[i], want)
				}
			}
			var receipt map[string]any
			if err := json.Unmarshal([]byte(body), &receipt); err != nil {
				t.Fatalf("receipt body not JSON: %v (%q)", err, body)
			}
			if receipt["persona"] != "standard" {
				t.Errorf("receipt persona = %v, want \"standard\"", receipt["persona"])
			}
			if receipt["action"] != action {
				t.Errorf("receipt action = %v, want %q", receipt["action"], action)
			}
			if receipt["ok"] != true {
				t.Errorf("receipt ok = %v, want true", receipt["ok"])
			}
		})
	}
}

// TestStandardActionUnknownRejected: an action not present in actionPaths is
// rejected the same way an unknown persona is — 400, zero gw.Fetch, zero
// rt.Launch (design doc §5.2 "Unknown action → 400, mirroring the persona
// 400").
func TestStandardActionUnknownRejected(t *testing.T) {
	fake := &recordingFake{}
	rt := &recordingLauncher{}
	code, _ := postTransactionWithAction(t, fake, rt, "standard", "bogus-action")
	if code != http.StatusBadRequest {
		t.Errorf("persona=standard action=bogus-action = %d, want 400", code)
	}
	if len(fake.paths) != 0 {
		t.Errorf("unknown action called gw.Fetch %v, want zero calls", fake.paths)
	}
	if rt.calls != 0 {
		t.Errorf("unknown action called rt.Launch %d times, want zero", rt.calls)
	}
}

// TestStandardTransactionWithoutActionKeepsLegacyPaths freezes backward
// compatibility (design doc §5.3 "Keep POST /api/transaction exactly as-is"):
// persona=standard with NO action field still drives the legacy
// standardPaths and the receipt carries no "action" key at all — existing
// callers (and TestStandardTransactionHitsServedPaths) see unchanged
// behavior.
func TestStandardTransactionWithoutActionKeepsLegacyPaths(t *testing.T) {
	fake := &recordingFake{}
	code, body := postTransactionWithAction(t, fake, &recordingLauncher{}, "standard", "")
	if code != http.StatusOK {
		t.Fatalf("persona=standard (no action) = %d, want 200", code)
	}
	if len(fake.paths) != len(standardPaths) {
		t.Fatalf("gw.Fetch called %v, want exactly %v (legacy standardPaths)", fake.paths, standardPaths)
	}
	for i, want := range standardPaths {
		if fake.paths[i] != want {
			t.Errorf("gw.Fetch call %d = %q, want %q", i, fake.paths[i], want)
		}
	}
	var receipt map[string]any
	if err := json.Unmarshal([]byte(body), &receipt); err != nil {
		t.Fatalf("receipt body not JSON: %v (%q)", err, body)
	}
	if receipt["persona"] != "standard" {
		t.Errorf("receipt persona = %v, want \"standard\"", receipt["persona"])
	}
	if _, hasAction := receipt["action"]; hasAction {
		t.Errorf("receipt unexpectedly has an \"action\" key (%v) for a no-action legacy transaction", receipt["action"])
	}
}

// TestRedteamIgnoresActionParam: an action value alongside persona=redteam
// must not change redteam semantics — the launcher fires exactly once, and
// service C still makes zero gw.Fetch calls (design doc §5.2 "plus standard
// for compatibility"; redteam untouched).
func TestRedteamIgnoresActionParam(t *testing.T) {
	fake := &recordingFake{}
	rt := &recordingLauncher{}
	code, _ := postTransactionWithAction(t, fake, rt, "redteam", "browse")
	if code != http.StatusOK {
		t.Fatalf("persona=redteam action=browse = %d, want 200", code)
	}
	if rt.calls != 1 {
		t.Errorf("rt.Launch called %d times, want exactly 1", rt.calls)
	}
	if len(fake.paths) != 0 {
		t.Errorf("persona=redteam action=browse called gw.Fetch %v, want zero calls", fake.paths)
	}
}

// service C is not covered by harmless.CrossScan — assert by hand it ships no
// real-looking secrets across the storefront, mirroring mesh/main_test.go:85-97.
func TestShipsNoSecrets(t *testing.T) {
	akia := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	pem := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	_, body := getPath(t, &recordingFake{}, &recordingLauncher{}, "/")
	if akia.MatchString(body) {
		t.Errorf("/ body contains an AWS key id")
	}
	if pem.MatchString(body) {
		t.Errorf("/ body contains a PEM private key")
	}
}

// TestCassetteLauncherSingleSlot exercises the PROD redteamLauncher
// (newCassetteLauncher) against a fake Messager (zero API, zero cost) and a local
// httptest.Server gateway (no real omlx, no hung goroutine): a first Launch()
// starts a background attack; a second Launch() issued while that attack's first
// tool call is still in flight must return the SAME run_id and must NOT start a
// second attack (single-slot mutex). The httptest handler blocks on a channel
// until the test explicitly releases it, which is what gives the test a
// deterministic window to observe "still active" without a sleep-based race.
func TestCassetteLauncherSingleSlot(t *testing.T) {
	toolUse, err := anthropic.MessageFromJSON(`{
		"id":"resp-1","type":"message","role":"assistant","model":"test-model",
		"stop_reason":"tool_use",
		"content":[{"type":"tool_use","id":"tu-1","name":"http_request","input":{"method":"GET","path":"/"}}],
		"usage":{"input_tokens":10,"output_tokens":10,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}
	}`)
	if err != nil {
		t.Fatalf("build tool_use response: %v", err)
	}
	endTurn, err := anthropic.MessageFromJSON(`{
		"id":"resp-2","type":"message","role":"assistant","model":"test-model",
		"stop_reason":"end_turn",
		"content":[{"type":"text","text":"done"}],
		"usage":{"input_tokens":5,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}
	}`)
	if err != nil {
		t.Fatalf("build end_turn response: %v", err)
	}
	fakeMsgr := &anthropic.FakeClient{Responses: []*sdk.Message{toolUse, endTurn}}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer gateway.Close()

	launcher := newCassetteLauncher(fakeMsgr, gateway.URL, attacker.Config{Model: "test-model", MaxTurns: 5})

	runID1, err := launcher.Launch()
	if err != nil {
		t.Fatalf("first Launch: %v", err)
	}
	if runID1 == "" {
		t.Fatal("first Launch returned an empty run_id")
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the attacker's first gateway call")
	}

	runID2, err := launcher.Launch()
	if err != nil {
		t.Fatalf("second Launch (while active): %v", err)
	}
	if runID2 != runID1 {
		t.Errorf("second Launch run_id = %q, want same as first %q (single-slot)", runID2, runID1)
	}
	if got := fakeMsgr.CallCount(); got != 1 {
		t.Errorf("Messager.New called %d times while first run still active, want 1 (no second run started)", got)
	}

	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for fakeMsgr.CallCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fakeMsgr.CallCount(); got != 2 {
		t.Fatalf("Messager.New called %d times after run completed, want 2 (one tool_use turn + one end_turn)", got)
	}
}
