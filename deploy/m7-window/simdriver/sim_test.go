package main

import (
	"os"
	"path/filepath"
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
		benignIPs:       []string{"10.20.1.101"},
		normalPaths:     []string{"/shop"},
		attackerIP:      "10.20.1.111",
		canaryPaths:     []string{"/.env", "/.aws/credentials"},
		reconIP:         "10.20.1.112",
		whitespacePaths: []string{"/wp-login.php", "/phpmyadmin/"},
		maliciousPct:    3,
		reconPct:        5,
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

func TestValidatePctBounds(t *testing.T) {
	c := validConfig()
	c.maliciousPct = 100
	if err := c.validate(); err == nil {
		t.Fatal("malicious-pct of 100 must be rejected (ratio undefined)")
	}
}
