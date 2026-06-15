package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTouchCadence(t *testing.T) {
	// 50% of total => malicious rate == benign rate. At 60 benign rpm that's 60
	// touches/min => one per second.
	if d, ok := touchCadence(60, 50); !ok || d != time.Second {
		t.Fatalf("touchCadence(60,50) = %v,%v want 1s,true", d, ok)
	}
	// Higher percentage => shorter cadence (more frequent touches).
	hi, _ := touchCadence(100, 10)
	lo, _ := touchCadence(100, 3)
	if !(hi < lo) {
		t.Fatalf("expected 10%% cadence (%v) shorter than 3%% (%v)", hi, lo)
	}
	// Degenerate inputs drive no traffic (ok=false), never a divide-by-zero or a
	// zero-delay hot loop.
	for _, tc := range []struct{ rpm, pct float64 }{{0, 5}, {60, 0}, {60, 100}, {60, 150}, {-1, 5}} {
		if _, ok := touchCadence(tc.rpm, tc.pct); ok {
			t.Fatalf("touchCadence(%v,%v) should be ok=false", tc.rpm, tc.pct)
		}
	}
}

func TestParseCostUSD(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cost.json")
	if err := os.WriteFile(p, []byte(`{"total_usd":0.2282,"stop_reason":"end_turn"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, ok := parseCostUSD(p); !ok || v != 0.2282 {
		t.Fatalf("parseCostUSD = %v,%v want 0.2282,true", v, ok)
	}
	// Missing file and garbage both fail (ok=false) so the caller records the
	// conservative cap instead of under-counting spend.
	if _, ok := parseCostUSD(filepath.Join(t.TempDir(), "nope.json")); ok {
		t.Fatal("missing cost file must be ok=false")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, ok := parseCostUSD(bad); ok {
		t.Fatal("garbled cost file must be ok=false")
	}
}

func TestDisjoint(t *testing.T) {
	if bad, ok := disjoint([]string{"/a", "/b"}, []string{"/c", "/b"}); ok || bad != "/b" {
		t.Fatalf("disjoint should report the shared element /b, got %q,%v", bad, ok)
	}
	if _, ok := disjoint([]string{"/a", "/b"}, []string{"/c", "/d"}); !ok {
		t.Fatal("non-overlapping sets should be disjoint")
	}
}

func validConfig() config {
	return config{
		benignIPs:            []string{"10.20.1.101"},
		normalPaths:          []string{"/shop"},
		attackerIP:           "10.20.1.111",
		canaryPaths:          []string{"/.env", "/.aws/credentials"},
		reconIP:              "10.20.1.112",
		whitespacePaths:      []string{"/wp-login.php", "/phpmyadmin/"},
		carefulMoverIP:       "10.20.1.104",
		carefulMoverPaths:    []string{"/reports/daily", "/internal/inventory"},
		carefulMoverInterval: 25 * time.Second,
		maliciousPct:         3,
		reconPct:             5,
	}
}

// The Rule-8 guard: simdriver must REFUSE to start if a recon (white-space) path
// is also a canary path — otherwise recon could touch a decoy and arm a response.
func TestValidateRule8ReconNeverTouchesCanary(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c := validConfig()
	c.whitespacePaths = []string{"/wp-login.php", "/.env"} // /.env is a canary!
	if err := c.validate(); err == nil {
		t.Fatal("config with a recon path that is also a canary MUST be refused (Rule 8)")
	}
}

// The benign class must also never touch a canary (a misconfigured -normal-paths
// containing a canary would arm responses against legitimate traffic).
func TestValidateRule8BenignNeverTouchesCanary(t *testing.T) {
	c := validConfig()
	c.normalPaths = []string{"/shop", "/.env"} // /.env is a canary
	if err := c.validate(); err == nil {
		t.Fatal("config with a benign path that is also a canary MUST be refused (Rule 8)")
	}
}

func TestValidatePctBounds(t *testing.T) {
	c := validConfig()
	c.maliciousPct = 100
	if err := c.validate(); err == nil {
		t.Fatal("malicious-pct of 100 must be rejected (ratio undefined)")
	}
}

// The load-bearing safety guarantee for the deviant class: the careful-mover walks
// NORMAL paths only, so it must be STRUCTURALLY unable to arm a response. validate()
// must REFUSE to start if a careful-mover path is also a canary path (Rule 8) — and
// PASS when the sets are disjoint.
func TestValidateRule8CarefulMoverNeverTouchesCanary(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("valid careful-mover config rejected: %v", err)
	}
	c := validConfig()
	c.carefulMoverPaths = []string{"/reports/daily", "/.env"} // /.env is a canary!
	if err := c.validate(); err == nil {
		t.Fatal("config with a careful-mover path that is also a canary MUST be refused (Rule 8)")
	}
}

// The careful-mover must stay on NORMAL application paths, distinct from the recon
// white-space — overlapping the scanner's negative-space would blur the deviant.
func TestValidateCarefulMoverDisjointFromWhitespace(t *testing.T) {
	c := validConfig()
	c.carefulMoverPaths = []string{"/reports/daily", "/wp-login.php"} // a recon white-space path
	if err := c.validate(); err == nil {
		t.Fatal("config with a careful-mover path that is also a white-space path MUST be refused")
	}
}

// When the careful-mover is enabled (interval > 0) it MUST have at least one path;
// when disabled (interval 0) the path checks are skipped entirely.
func TestValidateCarefulMoverEnableToggle(t *testing.T) {
	c := validConfig()
	c.carefulMoverPaths = nil
	if err := c.validate(); err == nil {
		t.Fatal("careful-mover enabled with no paths MUST be refused")
	}
	// Disabling the class (interval 0) skips the deviant path checks — even an
	// (unused) overlapping path set is tolerated because no deviant flow runs.
	c.carefulMoverInterval = 0
	c.carefulMoverPaths = []string{"/.env"} // would be illegal if enabled
	if err := c.validate(); err != nil {
		t.Fatalf("disabled careful-mover (interval 0) must skip the deviant checks: %v", err)
	}
}

// The careful-mover worker, run from the configured identity against the configured
// NORMAL paths, must request ONLY those paths and NEVER a canary — the path-selection
// half of the Rule-8 guarantee (validate() is the config half). It uses 127.0.0.1 as
// the source so the test binds without elevated privileges / extra interfaces.
func TestCarefulMoverHitsOnlyNormalPathsNeverCanary(t *testing.T) {
	normal := map[string]struct{}{"/reports/daily": {}, "/internal/inventory": {}, "/analytics/export": {}}
	canary := map[string]struct{}{"/.env": {}, "/.aws/credentials": {}}

	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	paths := []string{"/reports/daily", "/internal/inventory", "/analytics/export"}
	// A short interval so several touches land quickly; the worker stops on ctx cancel.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCarefulMover(ctx, "127.0.0.1", srv.URL, paths, 1, 5*time.Millisecond)
	}()

	// Poll until the worker has made several requests, then stop it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		total := 0
		for _, n := range seen {
			total += n
		}
		mu.Unlock()
		if total >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("careful-mover made no requests")
	}
	for p := range seen {
		if _, ok := canary[p]; ok {
			t.Fatalf("careful-mover touched a CANARY path %q — Rule 8 violation", p)
		}
		if _, ok := normal[p]; !ok {
			t.Fatalf("careful-mover requested unexpected path %q (not in the configured normal set)", p)
		}
	}
}
