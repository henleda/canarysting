// Command simdriver is the one-box demo's traffic supervisor. It drives a
// continuous, realistic mix of east-west traffic against a single CanarySting
// deployment so the dashboard is alive on its own — a large benign baseline plus
// two adversary classes — with a configurable malicious percentage and a hard,
// fail-closed ceiling on real LLM spend.
//
// THREE flow classes, distinguished STRUCTURALLY (Rule 8), not by a per-request
// label:
//
//   - BENIGN: one worker per declared-legit source IP, requesting ONLY normal
//     application paths, paced by the shared diurnal/weekly profile. Populates the
//     observe baseline; never touches a decoy; never arms anything.
//   - RECON (white space): a single UNLABELED scanner IP probing non-existent,
//     non-canary paths (404s) — negative-space scanning that looks suspicious from
//     the baseline but NEVER touches a canary, so it can never arm a response. It
//     is surfaced as observe-only recon (see T6), not actioned. simdriver REFUSES
//     to start if any recon path is also a canary path, so recon stays arm-free.
//   - MALICIOUS: the declared-attacker IP touching canary paths (a real verdict +
//     escalation), plus periodic LLM-attacker runs — a $0 cassette replay on a
//     slow cadence for a credible escalating flow, and (opt-in, key-gated) bounded
//     live runs whose real spend is gated by a fail-closed daily ledger.
//
// The malicious/recon cadence is derived from the CURRENT benign rate (same
// loadprofile curve) so the configured percentage holds as traffic ebbs and flows
// across the day, rather than spiking overnight.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/deploy/m7-window/internal/loadprofile"
	"github.com/canarysting/canarysting/deploy/m7-window/internal/spendledger"
)

func main() {
	cfg := parseFlags()
	if err := cfg.validate(); err != nil {
		log.Fatalf("simdriver: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ledger := spendledger.Open(cfg.budgetFile, cfg.dailyCapUSD, time.Now())

	// gate serializes the attacker IP: the malicious prober RLocks per touch; an
	// LLM run takes the write lock for its whole duration so the demo trace is one
	// clean escalating socket cookie (matches run-attack.sh's prober-pause).
	var gate sync.RWMutex

	benignTotalRPM := func() float64 {
		return float64(len(cfg.benignIPs)) * loadprofile.RequestsPerMinute(time.Now().UTC(), cfg.baseRPM)
	}

	var wg sync.WaitGroup
	start := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }

	// BENIGN — one diurnal-paced worker per legit identity (short flows -> fold the
	// baseline) PLUS one KEEPALIVE worker per identity (a persistent serving flow the
	// bystander panel shows surviving a jail).
	for i, ip := range cfg.benignIPs {
		p, err := newProber(ip, cfg.target, cfg.normalPaths, int64(i*7919+1), false)
		if err != nil {
			log.Fatalf("simdriver: benign identity %q: %v", ip, err)
		}
		start(func() { runBenign(ctx, p, cfg.baseRPM) })

		kp, err := newProber(ip, cfg.target, cfg.normalPaths, int64(i*104729+7), true)
		if err != nil {
			log.Fatalf("simdriver: keepalive benign identity %q: %v", ip, err)
		}
		start(func() { runKeepaliveBenign(ctx, kp, cfg.keepaliveInterval) })
	}

	// RECON — white-space scanner (unlabeled IP, 404 paths, never a canary).
	reconP, err := newProber(cfg.reconIP, cfg.target, cfg.whitespacePaths, 424242, false)
	if err != nil {
		log.Fatalf("simdriver: recon identity %q: %v", cfg.reconIP, err)
	}
	start(func() { runRatio(ctx, reconP, cfg.reconPct, benignTotalRPM, cfg.recompute, nil) })

	// RECON (held) — a few concurrent scanner flows kept open ~reconHoldSec each so
	// the dashboard's recon surface stays populated (a sub-second probe is almost
	// never open at the poll instant). Each is a distinct churning .112 flow over
	// the white-space, under the bystander threshold so it reads as recon.
	for i := 0; i < cfg.reconLive; i++ {
		seed := int64(i*2654435761 + 99)
		start(func() { runReconHold(ctx, cfg.reconIP, cfg.target, cfg.whitespacePaths, seed, cfg.reconHoldSec) })
	}

	// MALICIOUS — declared-attacker canary touches, gated so LLM runs get a clean trace.
	malP, err := newProber(cfg.attackerIP, cfg.target, cfg.canaryPaths, 1337, false)
	if err != nil {
		log.Fatalf("simdriver: attacker identity %q: %v", cfg.attackerIP, err)
	}
	start(func() { runRatio(ctx, malP, cfg.maliciousPct, benignTotalRPM, cfg.recompute, &gate) })

	// MALICIOUS (sustained) — one persistent attacker flow that touches canaries on a
	// SINGLE cookie so it climbs Tag->Contain->Jail (the escalation panel + kernel jail),
	// reconnecting after each jail. This is the self-running escalation->jail "wow" that
	// the LLM cassette would otherwise drive; 0 disables it.
	if cfg.maliciousKeepaliveInterval > 0 {
		start(func() {
			runKeepaliveMalicious(ctx, cfg.attackerIP, cfg.target, cfg.canaryPaths, 7777, cfg.maliciousKeepaliveInterval)
		})
	}

	// LLM dispatch — Tier-B cassette ($0) + opt-in Tier-C live ($, ledger-gated).
	start(func() { runLLMDispatch(ctx, cfg, ledger, &gate) })

	log.Printf("simdriver: target=%s benign=%d@%.0frpm malicious=%.1f%% recon=%.1f%% reconLive=%d@%.1fs dailyCap=$%.2f live=%s",
		cfg.target, len(cfg.benignIPs), cfg.baseRPM, cfg.maliciousPct, cfg.reconPct, cfg.reconLive, cfg.reconHoldSec, cfg.dailyCapUSD, cfg.liveInterval)
	<-ctx.Done()
	log.Printf("simdriver: shutting down")
	wg.Wait()
}

// ---- pure, testable helpers -------------------------------------------------

// touchCadence is the delay between adversary touches needed to make pct percent
// of TOTAL traffic, given the current benign rate (requests/min across all benign
// identities): malicious share pct/100 of total => touches = benign*pct/(100-pct).
// ok=false (drive no traffic this round) when pct is out of (0,100) or benign is
// non-positive — the degenerate cases where the ratio is undefined.
func touchCadence(benignRPM, pct float64) (time.Duration, bool) {
	if pct <= 0 || pct >= 100 || benignRPM <= 0 {
		return 0, false
	}
	touchesPerMin := benignRPM * pct / (100 - pct)
	if touchesPerMin <= 0 {
		return 0, false
	}
	return time.Duration(60.0 / touchesPerMin * float64(time.Second)), true
}

// parseCostUSD reads total_usd from an llm-attacker cost-out file. ok=false on any
// problem, so the caller records a conservative fallback (the per-run cap) and
// spend is never UNDER-counted against the daily ceiling.
func parseCostUSD(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var r struct {
		TotalUSD float64 `json:"total_usd"`
	}
	if json.Unmarshal(b, &r) != nil || r.TotalUSD < 0 {
		return 0, false
	}
	return r.TotalUSD, true
}

// disjoint reports whether sets a and b share no element — used to guarantee the
// recon (white-space) paths never include a canary path (Rule 8: recon must not
// be able to touch a decoy and arm a response).
func disjoint(a, b []string) (string, bool) {
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return y, false
		}
	}
	return "", true
}

// ---- traffic workers --------------------------------------------------------

// prober binds a source IP and GETs random paths from a set. DisableKeepAlives so
// each request is a distinct completing flow the observe path folds.
type prober struct {
	target string
	paths  []string
	client *http.Client
	rng    *rand.Rand
}

func newProber(srcIP, target string, paths []string, seed int64, keepalive bool) (*prober, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no paths for %s", srcIP)
	}
	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
	if err != nil {
		return nil, fmt.Errorf("bad source IP %q: %w", srcIP, err)
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
	// keepalive=false: a distinct completing flow per request, which the observe
	// path folds into the baseline-of-normal. keepalive=true: REUSE one TCP
	// connection so the observe path sees a single LONG-LIVED serving flow — the
	// persistent "still serving" workload the bystander panel needs (a short flow
	// is almost never "open" when the dashboard polls).
	tr := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: !keepalive}
	if keepalive {
		tr.MaxIdleConnsPerHost = 1
		tr.MaxConnsPerHost = 1
		tr.IdleConnTimeout = 90 * time.Second
	}
	return &prober{
		target: target,
		paths:  paths,
		client: &http.Client{Timeout: 5 * time.Second, Transport: tr},
		rng:    rand.New(rand.NewSource(seed)),
	}, nil
}

func (p *prober) hit() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	path := p.paths[p.rng.Intn(len(p.paths))]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.target+path, nil)
	if err != nil {
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return // best-effort background load; a transient miss is fine
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// runKeepaliveBenign holds ONE persistent connection from a legit identity, making
// a small request every `interval` to keep it warm and serving bytes. That single
// long-lived, low-novelty (once the baseline has learned the identity) serving flow
// is exactly what the bystander panel shows surviving a kernel jail — "same host,
// still serving 200" — which a short, frequently-closing flow can't reliably be.
func runKeepaliveBenign(ctx context.Context, p *prober, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		p.hit() // reuses the kept-alive connection -> one open flow the observe sees
		if sleepCtx(ctx, interval) {
			return
		}
	}
}

// runBenign drives one legit identity forever, paced by the diurnal profile.
func runBenign(ctx context.Context, p *prober, baseRPM float64) {
	for {
		rpm := loadprofile.RequestsPerMinute(time.Now().UTC(), baseRPM)
		if rpm <= 0 {
			if sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		mean := 60.0 / rpm
		gap := mean * (0.5 + p.rng.Float64()) // +/-50% jitter, not a metronome
		if sleepCtx(ctx, time.Duration(gap*float64(time.Second))) {
			return
		}
		p.hit()
	}
}

// runRatio drives an adversary worker at a cadence recomputed each round from the
// current benign rate so its share of total traffic stays ~pct. If gate is
// non-nil (the malicious worker on the shared attacker IP), each touch is taken
// under a read-lock so an LLM run can pause it for a clean single-cookie trace.
func runRatio(ctx context.Context, p *prober, pct float64, benignRPM func() float64, recompute time.Duration, gate *sync.RWMutex) {
	for {
		cad, ok := touchCadence(benignRPM(), pct)
		if !ok {
			if sleepCtx(ctx, recompute) {
				return
			}
			continue
		}
		if sleepCtx(ctx, cad) {
			return
		}
		if gate != nil {
			gate.RLock()
			p.hit()
			gate.RUnlock()
		} else {
			p.hit()
		}
	}
}

// A held-recon flow's worst-case lifetime is holdSec + reconProbeTimeout: the last
// probe can start an instant before the deadline and run to its timeout, after
// which we break WITHOUT a trailing sleep and FIN. reconHoldMaxSec bounds holdSec
// so that worst case stays under the dashboard's 8s bystander threshold (a flow
// open >= ~8s reads as an established serving workload, not a scanner). At the
// cap 5.0 + 2.0 = 7.0s, a full 1s under the threshold.
const (
	reconHoldMaxSec   = 5.0
	reconProbeTimeout = 2 * time.Second
	reconProbeGap     = 1 * time.Second
)

// runReconHold keeps ONE recon scanner flow open at a time: it opens a fresh
// connection from the recon IP (a new socket cookie the observe path sees as a
// LIVE flow), probes the white-space over ~holdSec so the flow is reliably OPEN
// when the dashboard polls (a sub-second probe almost never is — the reason the
// recon surface read empty), then closes it and, after a short jittered gap,
// starts another. holdSec stays under the bystander threshold so the scanner reads
// as recon, never an established workload. All paths are 404 white-space, never a
// canary (Rule 8: recon cannot arm a response). Several run concurrently
// (cfg.reconLive) so the recon surface stays populated without any engine change.
func runReconHold(ctx context.Context, srcIP, target string, paths []string, seed int64, holdSec float64) {
	rng := rand.New(rand.NewSource(seed))
	for {
		if ctx.Err() != nil {
			return
		}
		reconSession(ctx, srcIP, target, paths, rng, holdSec)
		// jittered gap before the next scanner flow, so cookies churn (a stream of
		// distinct short flows) rather than one metronome connection.
		gap := (0.5 + rng.Float64()) * holdSec * 0.4
		if sleepCtx(ctx, time.Duration(gap*float64(time.Second))) {
			return
		}
	}
}

// reconSession opens one keepalive connection from srcIP and probes the white-space
// a few times over ~holdSec, holding a single live flow open, then closes it (FIN
// via CloseIdleConnections). The kept-alive connection means the sequential probes
// reuse ONE socket cookie, so the observe path sees a single flow whose lifetime is
// ~holdSec — long enough to be caught by the dashboard poll, short enough to stay
// under the bystander threshold.
func reconSession(ctx context.Context, srcIP, target string, paths []string, rng *rand.Rand, holdSec float64) {
	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
	if err != nil {
		return
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     time.Duration((holdSec + 2) * float64(time.Second)),
	}
	defer tr.CloseIdleConnections() // FIN the flow when the session ends
	// Short per-probe timeout so a hung request cannot stretch the flow past the
	// bystander threshold: worst-case lifetime = holdSec + reconProbeTimeout.
	client := &http.Client{Timeout: reconProbeTimeout, Transport: tr}
	deadline := time.Now().Add(time.Duration(holdSec * float64(time.Second)))
	for time.Now().Before(deadline) {
		path := paths[rng.Intn(len(paths))]
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+path, nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
		// Break BEFORE sleeping once the deadline has passed, so the trailing gap
		// never inflates the flow's lifetime past holdSec + one probe timeout.
		if !time.Now().Before(deadline) {
			break
		}
		if sleepCtx(ctx, reconProbeGap) {
			return
		}
	}
}

// runKeepaliveMalicious drives ONE sustained attacker flow at a time: a persistent
// connection from the declared-attacker IP that touches canary paths every interval,
// so a SINGLE socket cookie climbs the tiers (Tag -> Contain -> Jail) — the escalation
// panel's clean single-cookie climb and the kernel jail, generated continuously with
// no LLM run or cassette. When the flow is jailed (the kernel drops its socket and
// requests start failing), it closes and reconnects (a fresh cookie) and climbs again,
// so the demo always has a live escalation and accumulating jailed cookies beside the
// surviving bystanders. The attacker IP is the only class allowed to touch canaries
// (Rule 8 — validate() guarantees recon/benign paths are disjoint from canaries).
func runKeepaliveMalicious(ctx context.Context, srcIP, target string, canaryPaths []string, seed int64, interval time.Duration) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	rng := rand.New(rand.NewSource(seed))
	for {
		if ctx.Err() != nil {
			return
		}
		maliciousSession(ctx, srcIP, target, canaryPaths, rng, interval)
		// brief pause, then reconnect with a fresh cookie and climb again.
		if sleepCtx(ctx, 3*time.Second) {
			return
		}
	}
}

// maliciousSession holds one keepalive connection from srcIP and touches canary paths
// every interval until the flow is jailed (consecutive request failures = the kernel
// dropped the socket) or ctx ends, then returns so the caller reconnects fresh.
func maliciousSession(ctx context.Context, srcIP, target string, paths []string, rng *rand.Rand, interval time.Duration) {
	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
	if err != nil {
		return
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}
	tr := &http.Transport{DialContext: dialer.DialContext, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 90 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 2 * time.Second, Transport: tr}
	fails := 0
	for {
		path := paths[rng.Intn(len(paths))]
		ok := false
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+path, nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				ok = true
			}
		}
		if ok {
			fails = 0
		} else {
			fails++
			if fails >= 3 {
				return // jailed (socket dropped) — reconnect with a fresh cookie
			}
		}
		if sleepCtx(ctx, interval) {
			return
		}
	}
}

// ---- LLM dispatch (Tier-B cassette $0, Tier-C live $ ledger-gated) -----------

func runLLMDispatch(ctx context.Context, cfg config, ledger *spendledger.Ledger, gate *sync.RWMutex) {
	if cfg.cassette == "" && cfg.liveInterval == 0 {
		return // no LLM beat configured
	}
	var bC, cC <-chan time.Time
	if cfg.cassette != "" {
		t := time.NewTicker(cfg.cassetteInterval)
		defer t.Stop()
		bC = t.C
	}
	if cfg.liveInterval > 0 {
		t := time.NewTicker(cfg.liveInterval)
		defer t.Stop()
		cC = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-bC:
			runAttacker(ctx, cfg, gate, "cassette(replay $0)", "-cassette", cfg.cassette)
		case <-cC:
			est := cfg.liveBudgetUSD
			if cfg.keyFile == "" || !fileExists(cfg.keyFile) {
				log.Printf("simdriver: Tier-C live run skipped (no key at %q)", cfg.keyFile)
				continue
			}
			if !ledger.CanSpend(time.Now(), est) {
				log.Printf("simdriver: Tier-C live run skipped — daily cap reached (remaining $%.2f)", ledger.Remaining(time.Now()))
				continue
			}
			// Remove any stale cost file so an early-exiting child leaves NO file —
			// then parseCostUSD fails and we record the conservative per-run cap,
			// rather than reading a prior run's lower number and under-counting.
			_ = os.Remove(cfg.costOut)
			runAttacker(ctx, cfg, gate, fmt.Sprintf("live($%.2f cap)", est),
				"-hard-cap-usd", fmt.Sprintf("%.4f", est), "-key-file", cfg.keyFile, "-max-turns", "8")
			// Record actual spend; on any parse failure record the per-run cap so
			// the daily ceiling is never UNDER-counted (fail toward less spend).
			spent, ok := parseCostUSD(cfg.costOut)
			if !ok {
				spent = est
				log.Printf("simdriver: could not read live cost from %q; recording the cap $%.2f conservatively", cfg.costOut, est)
			}
			if err := ledger.Record(time.Now(), spent); err != nil {
				log.Printf("simdriver: ledger.Record failed: %v (ledger now fails closed)", err)
			} else {
				log.Printf("simdriver: live run spent $%.4f; daily remaining $%.2f", spent, ledger.Remaining(time.Now()))
			}
		}
	}
}

// runAttacker execs the reused llm-attacker binary against the attacker IP,
// holding the gate so the steady malicious prober pauses for one clean cookie.
func runAttacker(ctx context.Context, cfg config, gate *sync.RWMutex, label string, modeArgs ...string) {
	gate.Lock()
	defer gate.Unlock()
	args := append([]string{
		"-target", cfg.target, "-src-ip", cfg.attackerIP,
		"-tap-addr", cfg.tapAddr, "-cost-out", cfg.costOut,
	}, modeArgs...)
	log.Printf("simdriver: LLM run %s", label)
	cmd := exec.CommandContext(ctx, cfg.attackerBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		log.Printf("simdriver: LLM run (%s) error: %v", label, err)
	}
}

// ---- config -----------------------------------------------------------------

type config struct {
	target                     string
	tapAddr                    string
	benignIPs                  []string
	normalPaths                []string
	attackerIP                 string
	canaryPaths                []string
	reconIP                    string
	whitespacePaths            []string
	baseRPM                    float64
	maliciousPct               float64
	reconPct                   float64
	reconLive                  int
	reconHoldSec               float64
	maliciousKeepaliveInterval time.Duration
	recompute                  time.Duration
	keepaliveInterval          time.Duration
	dailyCapUSD                float64
	budgetFile                 string
	cassette                   string
	cassetteInterval           time.Duration
	liveInterval               time.Duration
	liveBudgetUSD              float64
	attackerBin                string
	keyFile                    string
	costOut                    string
}

func (c config) validate() error {
	if len(c.benignIPs) == 0 || len(c.normalPaths) == 0 {
		return fmt.Errorf("need at least one benign IP and one normal path")
	}
	if len(c.canaryPaths) == 0 || len(c.whitespacePaths) == 0 {
		return fmt.Errorf("need canary paths (malicious) and white-space paths (recon)")
	}
	// Rule 8 guard: neither the recon (white-space) nor the benign (normal) class
	// may touch a decoy — only the declared-attacker canary class does. Refuse to
	// start if a recon OR a benign path is also a canary path.
	if bad, ok := disjoint(c.canaryPaths, c.whitespacePaths); !ok {
		return fmt.Errorf("recon white-space path %q is also a canary path; recon must never touch a canary (Rule 8)", bad)
	}
	if bad, ok := disjoint(c.canaryPaths, c.normalPaths); !ok {
		return fmt.Errorf("benign normal path %q is also a canary path; benign workers must never touch a canary (Rule 8)", bad)
	}
	if c.maliciousPct < 0 || c.maliciousPct >= 100 || c.reconPct < 0 || c.reconPct >= 100 {
		return fmt.Errorf("malicious/recon pct must be in [0,100)")
	}
	if c.reconLive < 0 {
		return fmt.Errorf("recon-live must be >= 0")
	}
	// A held-recon flow MUST stay under the dashboard's bystander threshold, or the
	// scanner would mis-classify as an established serving workload. Refuse to start
	// otherwise (only matters when held workers are enabled).
	if c.reconLive > 0 && (c.reconHoldSec <= 0 || c.reconHoldSec > reconHoldMaxSec) {
		return fmt.Errorf("recon-hold-sec must be in (0,%.0f] (under the bystander threshold); got %.1f", reconHoldMaxSec, c.reconHoldSec)
	}
	return nil
}

func parseFlags() config {
	var (
		target       = flag.String("target", "http://127.0.0.1:8080", "Envoy base URL (one-box demo: loopback)")
		tapAddr      = flag.String("tap-addr", "http://127.0.0.1:8088", "engine tap base URL for the LLM cost meter")
		benignIPs    = flag.String("benign-ips", "10.20.1.101,10.20.1.102,10.20.1.103", "legit source IPs (one benign worker each)")
		normalPaths  = flag.String("normal-paths", "/shop,/search,/products,/account,/cart,/checkout,/orders", "normal application paths (NEVER canaries)")
		attackerIP   = flag.String("attacker-ip", "10.20.1.111", "declared-attacker source IP (touches canaries)")
		canaryPaths  = flag.String("canary-paths", "/.env,/.aws/credentials,/backup/db.sql,/internal/buckets,/admin/metrics", "seeded canary paths the attacker touches")
		reconIP      = flag.String("recon-ip", "10.20.1.112", "UNLABELED recon/scanner source IP (white-space probing; never a canary)")
		wsPaths      = flag.String("whitespace-paths", "/wp-login.php,/phpmyadmin/,/.svn/entries,/server-status,/actuator/env,/api/v2/admin,/cgi-bin/status,/owa/auth.owa", "non-canary white-space paths (404s) the recon scanner probes")
		baseRPM      = flag.Float64("base-rpm", 30, "per-identity peak benign requests/minute")
		malPct       = flag.Float64("malicious-pct", 3, "malicious canary-touch share of total traffic (%)")
		reconPct     = flag.Float64("recon-pct", 5, "recon white-space share of total traffic (%) for the background (short-probe) scanner")
		reconLive    = flag.Int("recon-live", 3, "concurrent HELD recon scanner flows (kept open ~recon-hold-sec so the dashboard recon surface stays populated; 0 disables)")
		reconHoldSec = flag.Float64("recon-hold-sec", 4.0, "lifetime of each held recon flow in seconds (must stay under the dashboard bystander threshold)")
		malKeepalive = flag.Duration("malicious-keepalive-interval", 3*time.Second, "canary-touch cadence on ONE sustained attacker flow that climbs Tag->Contain->Jail and reconnects (the self-running escalation->jail beat; 0 disables)")
		recompute    = flag.Duration("recompute", 30*time.Second, "how often the adversary cadence is re-derived from the benign rate")
		keepalive    = flag.Duration("keepalive-interval", 2*time.Second, "request cadence on each legit identity's PERSISTENT keepalive connection (the bystander panel's serving flow); keep it under the server idle timeout")
		dailyCap     = flag.Float64("daily-cap-usd", 20, "HARD fail-closed daily ceiling on live LLM spend")
		budgetFile   = flag.String("budget-file", "/var/lib/canarysting/sim-budget.json", "daily spend ledger path")
		cassette     = flag.String("cassette", "/tmp/m9-demo3.cassette", "cassette for Tier-B $0 replays (\"\" disables)")
		cassEvery    = flag.Duration("cassette-interval", 4*time.Minute, "Tier-B cassette replay cadence")
		liveEvery    = flag.Duration("live-interval", 0, "Tier-C live-run attempt cadence (0 = OFF; opt-in)")
		liveBudget   = flag.Float64("live-budget-usd", 0.5, "per-run hard cap for a Tier-C live run")
		attackerBin  = flag.String("attacker-bin", "/opt/canarysting/bin/llm-attacker", "path to the llm-attacker binary")
		keyFile      = flag.String("key-file", "/etc/canarysting/anthropic.key", "Anthropic key for Tier-C live runs (live OFF if absent)")
		costOut      = flag.String("cost-out", "/tmp/sim-llm-cost.json", "where the llm-attacker writes its run ledger")
	)
	flag.Parse()
	return config{
		target: *target, tapAddr: *tapAddr,
		benignIPs: splitCSV(*benignIPs), normalPaths: splitCSV(*normalPaths),
		attackerIP: *attackerIP, canaryPaths: splitCSV(*canaryPaths),
		reconIP: *reconIP, whitespacePaths: splitCSV(*wsPaths),
		baseRPM: *baseRPM, maliciousPct: *malPct, reconPct: *reconPct, reconLive: *reconLive, reconHoldSec: *reconHoldSec,
		maliciousKeepaliveInterval: *malKeepalive, recompute: *recompute, keepaliveInterval: *keepalive,
		dailyCapUSD: *dailyCap, budgetFile: *budgetFile,
		cassette: *cassette, cassetteInterval: *cassEvery,
		liveInterval: *liveEvery, liveBudgetUSD: *liveBudget,
		attackerBin: *attackerBin, keyFile: *keyFile, costOut: *costOut,
	}
}

// ---- small utilities --------------------------------------------------------

func sleepCtx(ctx context.Context, d time.Duration) (done bool) {
	if d <= 0 {
		d = time.Millisecond
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
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
