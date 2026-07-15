// Command service-c is the storefront web app for the interactive deception
// demo. It serves a small "buy a widget" page with a persona switcher:
// Standard drives genuine, canary-free traffic against the mesh gateway (the
// paths in standardPaths — a real customer browsing the site); Redteam (P2)
// launches an in-process omlx cassette-replay attacker that makes its own
// calls against the gateway over its own HTTPTool — service C itself never
// calls the gateway on that path. Health is /healthz.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/canarysting/canarysting/internal/llm/anthropic"
	"github.com/canarysting/canarysting/internal/llm/attacker"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// gatewayCaller is the seam over the mesh gateway — the ONLY external call
// service C makes. A Standard-persona transaction calls it once per
// standardPaths entry, in order; Redteam calls it zero times (P1 stub).
type gatewayCaller interface {
	Fetch(path string) (int, error)
}

// httpGateway is the real gatewayCaller: GET {baseURL}{path} against the
// mesh gateway.
type httpGateway struct {
	baseURL string
	client  *http.Client
}

func (g *httpGateway) Fetch(path string) (int, error) {
	resp, err := g.client.Get(g.baseURL + path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// redteamLauncher is the seam over the attacker: Launch starts (or, if one is
// already running, rejoins) one attack run and returns its run_id. service C
// never inspects the attack itself — the attacker makes its own calls against
// the gateway over its own HTTPTool, never through gw (TestRedteamMakesNoGatewayCalls).
type redteamLauncher interface {
	Launch() (runID string, err error)
}

// cassetteLauncher is the PROD redteamLauncher: single-slot (mutex-guarded) —
// a Launch() while a run is active returns the SAME run_id and does not start
// a second run. Each accepted Launch runs the attacker's RunAttack in its own
// goroutine so the HTTP handler returns immediately.
type cassetteLauncher struct {
	msgr       anthropic.Messager
	gatewayURL string
	cfg        attacker.Config

	mu     sync.Mutex
	active bool
	runID  string
	seq    atomic.Int64
}

// newCassetteLauncher builds the prod launcher. msgr is typically a replay
// client from anthropic.LoadCassette (deterministic, $0); gatewayURL is the
// live target the attacker's own HTTPTool calls (never through gw).
func newCassetteLauncher(msgr anthropic.Messager, gatewayURL string, cfg attacker.Config) *cassetteLauncher {
	return &cassetteLauncher{msgr: msgr, gatewayURL: gatewayURL, cfg: cfg}
}

// Launch starts a new attack run, or rejoins the currently active one.
func (l *cassetteLauncher) Launch() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active {
		return l.runID, nil
	}

	client, err := attacker.BuildKeepAliveClient("")
	if err != nil {
		return "", fmt.Errorf("cassetteLauncher: build client: %w", err)
	}
	tool := attacker.NewHTTPTool(client, l.gatewayURL)
	budget := attacker.NewBudget(5.0, 0, 0, 0) // sane default cap; zero overrides fall back to Opus defaults
	agent := attacker.NewAgent(l.msgr, tool, budget, l.cfg)

	l.runID = "redteam-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatInt(l.seq.Add(1), 10)
	l.active = true
	runID := l.runID

	go func() {
		_, _ = agent.RunAttack(context.Background())
		l.mu.Lock()
		if l.runID == runID {
			l.active = false
		}
		l.mu.Unlock()
	}()

	return runID, nil
}

// standardPaths are the paths a Standard-persona transaction drives against
// the gateway, in order — ordinary application traffic. Disjoint from the
// canary negative space by construction (rule 8; TestStandardPathsAreCanaryFree
// asserts it against the mirrored prefixes).
var standardPaths = []string{"/", "/api/status"}

// dashboardURL optionally links the storefront to the operator dashboard; a
// blank value (the default) hides the link. Set once in main() from
// DASHBOARD_URL.
var dashboardURL string

func main() {
	gatewayURL := env("GATEWAY_URL", "http://gateway.canarysting.svc.cluster.local:8080")
	listen := env("LISTEN", ":8000")
	dashboardURL = env("DASHBOARD_URL", "")
	cassettePath := env("CASSETTE_PATH", "/cassettes/redteam-omlx.json")

	gw := &httpGateway{
		baseURL: gatewayURL,
		client:  &http.Client{Timeout: 3 * time.Second},
	}

	msgr, err := anthropic.LoadCassette(cassettePath)
	if err != nil {
		log.Fatalf("service-c: load redteam cassette %q: %v", cassettePath, err)
	}
	rt := newCassetteLauncher(msgr, gatewayURL, attacker.Config{MaxTurns: 30})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, gw, rt)
	})

	log.Printf("service-c listening on %s, gateway=%s, cassette=%s", listen, gatewayURL, cassettePath)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// serve is the application router (extracted so it is unit-testable without
// a real listener or a real gateway).
func serve(w http.ResponseWriter, r *http.Request, gw gatewayCaller, rt redteamLauncher) {
	switch {
	case r.URL.Path == "/healthz":
		_, _ = io.WriteString(w, "ok")
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		serveIndex(w)
	case r.URL.Path == "/api/transaction" && r.Method == http.MethodPost:
		serveTransaction(w, r, gw, rt)
	default:
		http.NotFound(w, r)
	}
}

// serveIndex renders the storefront: one product, a Buy control, and a
// Standard/Redteam persona toggle. Ordinary harmless HTML — no secrets, keys,
// or PEMs (TestShipsNoSecrets asserts it). The inline script POSTs the
// selected persona to /api/transaction and shows the receipt.
func serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardLink := ""
	if dashboardURL != "" {
		dashboardLink = fmt.Sprintf(`<p><a href="%s">Operator dashboard</a></p>`, dashboardURL)
	}
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Canary Sting Storefront</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body>
<h1>Canary Sting Storefront</h1>
<p>Widget &mdash; $19.99</p>
<form id="buy-form">
<label><input type="radio" name="persona" value="standard" checked> Standard</label>
<label><input type="radio" name="persona" value="redteam"> Redteam</label>
<button type="submit">Buy</button>
</form>
<pre id="receipt"></pre>
%s
<script>
document.getElementById('buy-form').addEventListener('submit', function (e) {
  e.preventDefault();
  var sel = document.querySelector('input[name="persona"]:checked').value;
  fetch('/api/transaction', {method: 'POST', body: new URLSearchParams({persona: sel})})
    .then(function (r) { return r.text(); })
    .then(function (t) { document.getElementById('receipt').textContent = t; });
});
</script>
</body></html>
`, dashboardLink)
}

// serveTransaction dispatches a persona's purchase attempt. Standard drives
// standardPaths against the gateway in order and returns a receipt; Redteam
// launches (or rejoins) one in-process attacker run via rt.Launch and returns
// its run_id — zero gw.Fetch calls, the attacker makes its own calls over its
// own HTTPTool; anything else is rejected without touching the gateway or
// launching an attack.
func serveTransaction(w http.ResponseWriter, r *http.Request, gw gatewayCaller, rt redteamLauncher) {
	switch r.FormValue("persona") {
	case "standard":
		for _, p := range standardPaths {
			_, _ = gw.Fetch(p)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"persona": "standard",
			"ok":      true,
			"paths":   standardPaths,
		})
	case "redteam":
		runID, err := rt.Launch()
		if err != nil {
			http.Error(w, fmt.Sprintf("redteam launch failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"persona": "redteam",
			"run_id":  runID,
			"active":  true,
		})
	default:
		http.Error(w, "unknown or missing persona", http.StatusBadRequest)
	}
}
