// Command client-generator drives the M7 learning window's benign east-west
// traffic from the client box. It runs one worker per declared LEGIT identity,
// each binding its outbound connections to a distinct secondary source IP
// (net.Dialer.LocalAddr) so the server's observe path sees a real population of
// distinct kernel-observed source identities — the baseline of "normal" the
// multiplier learns. It requests ONLY normal application paths through Envoy,
// NEVER a canary path (a legitimate caller never touches the negative-space
// decoys — that honesty is what keeps the baseline clean).
//
// Traffic follows a diurnal + weekly profile (see profile.go) so the coarse
// window bucketer accrues a genuinely time-conditioned baseline. It runs forever
// (a systemd Restart=always unit), so the window survives client reboots.
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
	"sync"
	"time"
)

func main() {
	var (
		target     = flag.String("target", "http://10.20.1.10:8080", "Envoy base URL on the server box (private IP)")
		identities = flag.String("identities", "10.20.1.101,10.20.1.102,10.20.1.103", "comma-separated LEGIT source IPs to bind (one worker each)")
		pathsCSV   = flag.String("paths", "/shop,/search,/products,/account,/cart,/checkout,/orders", "normal application paths to exercise (NEVER canary paths)")
		baseRPM    = flag.Float64("base-rpm", 30, "per-identity peak requests/minute (scaled down by the diurnal/weekly profile)")
	)
	flag.Parse()

	ids := splitCSV(*identities)
	paths := splitCSV(*pathsCSV)
	if len(ids) == 0 || len(paths) == 0 {
		log.Fatal("client-generator: need at least one identity and one path")
	}

	var wg sync.WaitGroup
	for i, ip := range ids {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			runIdentity(i, ip, *target, paths, *baseRPM)
		}(i, ip)
	}
	log.Printf("client-generator: %d identities -> %s, base %.0f rpm/identity, %d paths", len(ids), *target, *baseRPM, len(paths))
	wg.Wait()
}

// runIdentity drives one legit source identity forever, pacing requests by the
// diurnal/weekly profile and rotating over the normal paths.
func runIdentity(idx int, srcIP, target string, paths []string, baseRPM float64) {
	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
	if err != nil {
		log.Fatalf("client-generator: bad identity %q: %v", srcIP, err)
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		// DisableKeepAlives: each request is its own TCP connection that completes,
		// so the observe path sees a distinct flow per request and the baseline
		// accrues per-request (not per-pooled-connection). Realistic for the many
		// short, non-pooled callers a real east-west fabric has.
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
	}
	rng := rand.New(rand.NewSource(int64(idx*7919 + 1)))

	for {
		rpm := requestsPerMinute(time.Now().UTC(), baseRPM)
		if rpm <= 0 {
			time.Sleep(time.Second)
			continue
		}
		// Mean gap = 60/rpm seconds, with +/-50% jitter so traffic is not a metronome.
		mean := 60.0 / rpm
		gap := mean * (0.5 + rng.Float64())
		time.Sleep(time.Duration(gap * float64(time.Second)))

		path := paths[rng.Intn(len(paths))]
		do(client, target+path)
	}
}

func do(client *http.Client, url string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return // a transient miss is fine; the generator is best-effort background load
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
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
