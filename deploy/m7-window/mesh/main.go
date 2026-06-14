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

func main() {
	name := env("SVC_NAME", "svc")
	listen := env("LISTEN", ":8000")
	var downstreams []string
	for _, d := range strings.Split(os.Getenv("DOWNSTREAMS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			downstreams = append(downstreams, d)
		}
	}

	// DisableKeepAlives so each internal hop is a distinct completing flow the
	// observe path folds — the internal east-west adjacencies accrue per-call.
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	fanout := func(ctx context.Context) {
		for _, d := range downstreams {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, d+"/", nil)
			if err != nil {
				continue
			}
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, name, fanout)
	})

	log.Printf("mesh service %q listening on %s, downstreams=%v", name, listen, downstreams)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// serve is the application router (extracted so it is unit-testable). It keeps the
// east-west fan-out on real application paths, serves realistic content, returns a
// real 404 for unknown paths, and never serves a canary path (rule 8).
func serve(w http.ResponseWriter, r *http.Request, name string, fanout func(context.Context)) {
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
		fanout(ctx)
		serveIndex(w, name)
	case p == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /api/\n")
	case p == "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(p, "/api/"):
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		fanout(ctx)
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

// serveAPI returns small plausible JSON for a couple of real API paths, else 404.
func serveAPI(w http.ResponseWriter, name, p string) {
	switch p {
	case "/api/health", "/api/health/":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service":%q,"status":"ok"}`+"\n", name)
	case "/api/status", "/api/status/":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service":%q,"status":"ok","uptime_s":%d}`+"\n", name, 86400)
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
