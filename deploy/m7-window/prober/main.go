// Command prober is the M7 window's scripted attacker. It connects from the
// DECLARED-attacker source IP and requests the negative-space canary paths a
// legitimate caller never would. Each touch produces a real engine verdict; the
// staged labeler (cmd/staged-range) confirms it malicious from the ground-truth
// registry, so the scope legitimately crosses the analyst-evidence (calibration)
// floor during the window, and the interaction lands as real adversary history
// in the EventStore. It is intentionally simple and repeatable — M9 replaces it
// with a real LLM agent that burns tokens against the attrition.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	var (
		target   = flag.String("target", "http://10.20.1.10:8080", "Envoy base URL on the server box (private IP)")
		srcIP    = flag.String("src-ip", "10.20.1.111", "the DECLARED-attacker source IP to bind (must match the ground-truth registry)")
		pathsCSV = flag.String("canary-paths", "/.env,/.aws/credentials,/backup/db.sql,/internal/buckets,/admin/metrics", "negative-space canary paths to probe")
		interval = flag.Duration("interval", 12*time.Second, "delay between probes")
		count    = flag.Int("count", 0, "stop after this many probes (0 = run forever)")
	)
	flag.Parse()

	paths := splitCSV(*pathsCSV)
	if len(paths) == 0 {
		log.Fatal("prober: need at least one canary path")
	}

	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(*srcIP, "0"))
	if err != nil {
		log.Fatalf("prober: bad src-ip %q: %v", *srcIP, err)
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		// DisableKeepAlives so each canary touch is a distinct, completing flow the
		// observe path folds (and excludes from the baseline-of-normal) on close.
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
	}
	rng := rand.New(rand.NewSource(20260609))

	log.Printf("prober: attacker %s -> %s, every %s, %d canary paths", *srcIP, *target, *interval, len(paths))
	n := 0
	for {
		path := paths[rng.Intn(len(paths))]
		status := probe(client, *target+path)
		n++
		log.Printf("prober: touch #%d %s -> %s", n, path, status)
		if *count > 0 && n >= *count {
			return
		}
		time.Sleep(*interval)
	}
}

func probe(client *http.Client, url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "build-err"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "no-response(" + err.Error() + ")"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Status
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
