// Command mesh is a tiny configurable east-west service used to build the M7
// staged environment's service graph. One binary is every service; SVC_NAME,
// LISTEN, and DOWNSTREAMS (comma-separated URLs) shape its role. On each request
// it calls each downstream once, producing GENUINE service-to-service traffic —
// the real east-west adjacencies the M7 baseline learns (not a single flat hop).
//
// It serves only normal application paths. It has NO canary paths; the canaries
// are negative-space paths the adapter seeds and recognizes, which a legitimate
// service never requests (docs/ROADMAP §1). Health is /healthz.
package main

import (
	"context"
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

func main() {
	name := env("SVC_NAME", "svc")
	listen := env("LISTEN", ":8000")
	var downstreams []string
	for _, d := range strings.Split(os.Getenv("DOWNSTREAMS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			downstreams = append(downstreams, d)
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Fan out to each downstream — this is the east-west the baseline learns.
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
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
		w.Header().Set("X-Service", name)
		_, _ = io.WriteString(w, name+" ok\n")
	})

	log.Printf("mesh service %q listening on %s, downstreams=%v", name, listen, downstreams)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
