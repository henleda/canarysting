// Command service-c is the storefront web app for the interactive deception
// demo (P1). It serves a small "buy a widget" page with a persona switcher:
// Standard drives genuine, canary-free traffic against the mesh gateway (the
// paths in standardPaths — a real customer browsing the site); Redteam is a
// P1 stub that returns inert without touching the gateway at all, wired to
// the local-model attacker in P2. Health is /healthz.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
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

	gw := &httpGateway{
		baseURL: gatewayURL,
		client:  &http.Client{Timeout: 3 * time.Second},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, gw)
	})

	log.Printf("service-c listening on %s, gateway=%s", listen, gatewayURL)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// serve is the application router (extracted so it is unit-testable without
// a real listener or a real gateway).
func serve(w http.ResponseWriter, r *http.Request, gw gatewayCaller) {
	switch {
	case r.URL.Path == "/healthz":
		_, _ = io.WriteString(w, "ok")
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		serveIndex(w)
	case r.URL.Path == "/api/transaction" && r.Method == http.MethodPost:
		serveTransaction(w, r, gw)
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
  var sel = document.querySelector('input[name=persona]:checked').value;
  fetch('/api/transaction', {method: 'POST', body: 'persona=' + sel})
    .then(function (r) { return r.text(); })
    .then(function (t) { document.getElementById('receipt').textContent = t; });
});
</script>
</body></html>
`, dashboardLink)
}

// serveTransaction dispatches a persona's purchase attempt. Standard drives
// standardPaths against the gateway in order and returns a receipt; Redteam
// is an inert P1 stub (zero gateway calls, wired in P2); anything else is
// rejected without touching the gateway.
func serveTransaction(w http.ResponseWriter, r *http.Request, gw gatewayCaller) {
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"persona": "redteam",
			"status":  "stub",
			"wired":   "P2",
		})
	default:
		http.Error(w, "unknown or missing persona", http.StatusBadRequest)
	}
}
