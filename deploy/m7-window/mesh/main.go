// Command mesh is a tiny configurable east-west service used to build the M7
// staged environment's service graph. One binary is every service; SVC_NAME,
// LISTEN, and DOWNSTREAMS (comma-separated URLs) shape its role. On each request
// to an application path it calls each downstream once, producing GENUINE
// service-to-service traffic — the real east-west adjacencies the M7 baseline
// learns (not a single flat hop).
//
// It serves only NORMAL application paths (a realistic landing page, robots.txt,
// favicon, and /api/* JSON stubs) and returns a real 404 for anything else — so
// an enumerating attacker does NOT see a uniform "ok" stub for every path (the
// dead giveaway that the surface is a honeypot). It has NO canary paths and never
// serves them: the canaries are NEGATIVE-SPACE paths the adapter seeds and
// recognizes (docs/ROADMAP §1), which a legitimate service never returns. Any
// request whose path is at/under a canary prefix gets a plain 404 here (the
// ext_proc adapter is what recognizes the touch and, on escalation, returns the
// deception body) — keeping the canary the ONLY trigger (rule 8). The content is
// ordinary harmless web text: no credentials, keys, PEMs, or routable hosts.
// Health is /healthz.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// listenHost extracts the bind host from a LISTEN value like "127.0.1.2:8002"
// (-> "127.0.1.2"). A bare ":8002" or "0.0.0.0:8002" (or an unparseable value)
// yields "" — the caller then binds NO source address (graceful fallback). This
// is what makes each mesh service dial its downstreams FROM its own distinct
// loopback identity (127.0.1.<K>), so the observe path sees a named src per
// service instead of a single 127.0.0.1 that collapses every initiator.
func listenHost(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return host
}

// canaryPrefixes mirror the negative-space paths the envoy adapter seeds + recognizes
// (cmd/envoy-adapter demoCanaryPaths). The frontend must NEVER serve content at/under
// any of them — they stay negative space so a touch is recognized only by the adapter
// (rule 8). Defense-in-depth: they are not in the served set below anyway, but we 404
// them explicitly and assert it in a test.
var canaryPrefixes = []string{
	"/.aws/credentials", "/secrets/", "/.env", "/config/", "/backup/", "/internal/", "/admin/",
}

func isCanaryPath(p string) bool {
	for _, cp := range canaryPrefixes {
		if p == cp || strings.HasPrefix(p, cp) {
			return true
		}
	}
	return false
}

// parseRouteMap parses the ROUTE_MAP env grammar: ';'-separated "path=svc[,svc]"
// entries. It differentiates per-service fanout — e.g. /api/login only calls auth,
// not the whole downstream set — so the learned east-west fabric (and the Hubble
// edges) show real service-specific traffic instead of a uniform full mesh on every
// request. Malformed entries (no '=') are skipped; an empty string yields an empty
// map, which selectDownstreams treats as "every path falls back to full fanout".
func parseRouteMap(s string) map[string][]string {
	rm := map[string][]string{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		path, svcs, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		var names []string
		for _, n := range strings.Split(svcs, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if path == "" || len(names) == 0 {
			continue
		}
		rm[path] = names
	}
	return rm
}

// matchesService reports whether a downstream URL is addressed to the service named
// name, anchored on "//<name>." so a prefix collision (e.g. "payment" vs "payments")
// never false-positives.
func matchesService(url, name string) bool {
	return strings.Contains(url, "//"+name+".")
}

// selectDownstreams narrows downstreams to the ROUTE_MAP subset for path, in the
// mapped VALUE order. A path with no entry in rm preserves the full downstream list
// (the un-differentiated default). A mapped path whose names ALL fail to resolve
// against downstreams — a ROUTE_MAP typo — falls back to full fanout too: a broken
// ROUTE_MAP degrades to "fanout everything", never "fanout nothing".
func selectDownstreams(path string, downstreams []string, rm map[string][]string) []string {
	names, ok := rm[path]
	if !ok {
		return downstreams
	}
	var selected []string
	for _, name := range names {
		for _, d := range downstreams {
			if matchesService(d, name) {
				selected = append(selected, d)
				break
			}
		}
	}
	if len(selected) == 0 {
		return downstreams
	}
	return selected
}

func main() {
	name := env("SVC_NAME", "svc")
	listen := env("LISTEN", ":8000")
	var downstreams []string
	for _, d := range strings.Split(os.Getenv("DOWNSTREAMS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			downstreams = append(downstreams, d)
		}
	}
	routeMap := parseRouteMap(os.Getenv("ROUTE_MAP"))

	// DisableKeepAlives so each internal hop is a distinct completing flow the
	// observe path folds — the internal east-west adjacencies accrue per-call.
	//
	// Bind the dial SOURCE to this service's own LISTEN host (e.g. 127.0.1.2) so a
	// downstream call originates this service's distinct loopback identity, not the
	// shared 127.0.0.1. That distinct src IP is what the node resolver names — it
	// keeps each service a separate node in the learned east-west fabric. On a bare
	// ":8000" / "0.0.0.0" LISTEN, listenHost returns "" and we bind nothing (the OS
	// picks the source) — graceful fallback for local dev / unit tests.
	transport := &http.Transport{DisableKeepAlives: true}
	if host := listenHost(listen); host != "" {
		dialer := &net.Dialer{
			Timeout:   2 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: 0},
		}
		transport.DialContext = dialer.DialContext
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: transport,
	}
	fanoutFn := func(ctx context.Context, p string) {
		fanout(ctx, p, downstreams, client, routeMap)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, name, fanoutFn)
	})

	log.Printf("mesh service %q listening on %s, downstreams=%v routeMap=%v", name, listen, downstreams, routeMap)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// fanout calls each downstream selectDownstreams resolves for path (per ROUTE_MAP rm),
// forwarding the same path to each (d+path, not a hardcoded d+"/") so the ROUTE_MAP
// differentiation is visible per-downstream in the real HTTP calls — not just decided
// in-process — and shows up as distinct edges in Hubble/the eBPF baseline.
func fanout(ctx context.Context, path string, downstreams []string, client *http.Client, rm map[string][]string) {
	for _, d := range selectDownstreams(path, downstreams, rm) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d+path, nil)
		if err != nil {
			continue
		}
		if resp, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
}

// serve is the application router (extracted so it is unit-testable). It keeps the
// east-west fan-out on real application paths, serves realistic content, returns a
// real 404 for unknown paths, and never serves a canary path (rule 8).
func serve(w http.ResponseWriter, r *http.Request, name string, fanout func(context.Context, string)) {
	w.Header().Set("X-Service", name)
	p := r.URL.Path

	// Rule 8: canary paths are negative space — never served by the app. A plain 404
	// makes them look like any other not-found; the adapter recognizes the touch and
	// (on escalation) returns the deception body inline.
	if isCanaryPath(p) {
		notFound(w)
		return
	}

	switch {
	case p == "/" || p == "/index.html":
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		fanout(ctx, p)
		serveIndex(w, name)
	case p == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /api/\n")
	case p == "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(p, "/api/"):
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		fanout(ctx, p)
		serveAPI(w, name, p)
	default:
		notFound(w)
	}
}

// serveIndex returns a plausible internal-app landing page. Ordinary harmless HTML —
// no secrets, keys, or routable hosts; links only to served /api/* stubs.
func serveIndex(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>%[1]s</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body>
<h1>%[1]s</h1>
<p>Internal service. See <a href="/api/health">/api/health</a> and <a href="/api/status">/api/status</a>.</p>
<ul><li><a href="/api/health">health</a></li><li><a href="/api/status">status</a></li></ul>
</body></html>
`, name)
}

// serveAPI returns small plausible JSON for a couple of real API paths, plus the 7
// storefront stub endpoints the storefront SPA drives (products/search/login/
// session/cart/checkout/orders), naming the resource (last path segment) so each
// stub is distinguishable in logs/Hubble without a canary risk. Else 404.
func serveAPI(w http.ResponseWriter, name, p string) {
	switch p {
	case "/api/health", "/api/health/":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service":%q,"status":"ok"}`+"\n", name)
	case "/api/status", "/api/status/":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service":%q,"status":"ok","uptime_s":%d}`+"\n", name, 86400)
	case "/api/products", "/api/search", "/api/login", "/api/session", "/api/cart", "/api/checkout", "/api/orders":
		resource := strings.TrimPrefix(p, "/api/")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service":%q,"resource":%q,"status":"ok"}`+"\n", name, resource)
	default:
		notFound(w)
	}
}

// notFound serves a realistic 404 (NOT a 200 "ok" stub) so enumeration of nonexistent
// paths looks like a normal app, not a uniform honeypot surface.
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "404 page not found\n")
}
