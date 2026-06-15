package identity

import (
	"net/netip"
	"path/filepath"
	"testing"
)

// demoConfigPath is the shipped M7-window operator-identity map, relative to this
// package (internal/topology/identity -> repo root is three levels up).
var demoConfigPath = filepath.Join("..", "..", "..", "deploy", "m7-window", "topology-identities.json")

// TestDemoConfigLoadsAndResolves loads the SHIPPED demo operator-map and asserts
// it resolves the known compose topology — the mesh services by LISTEN PORT (the
// all-loopback mesh, so the port disambiguates) and the caller IPs by role. If
// server-compose.yml's ports or the ground-truth caller IPs change, this test
// catches the demo config drifting out of sync.
func TestDemoConfigLoadsAndResolves(t *testing.T) {
	cfg, err := LoadConfigFile(demoConfigPath)
	if err != nil {
		t.Fatalf("LoadConfigFile(%s): %v", demoConfigPath, err)
	}
	r := NewResolver(cfg)

	loopback := netip.MustParseAddr("127.0.0.1")

	// Mesh services by listen port (verified against deploy/m7-window/server-compose.yml).
	// The original 5-service core plus the expanded east-west fabric (8006-8016).
	services := []struct {
		port uint16
		name string
	}{
		{8001, "frontend"},
		{8002, "api"},
		{8003, "auth"},
		{8004, "db"},
		{8005, "cache"},
		{8006, "payments"},
		{8007, "search"},
		{8008, "cdn-edge"},
		{8009, "ledger"},
		{8010, "db-replica"},
		{8011, "session-store"},
		{8012, "inventory"},
		{8013, "orders"},
		{8014, "analytics"},
		{8015, "notifications"},
		{8016, "profile"},
	}
	for _, s := range services {
		got := r.Resolve(loopback, s.port, "", "")
		if got.Label != s.name || got.Kind != KindService {
			t.Errorf("mesh port %d -> {%q, %s}; want {%q, service}", s.port, got.Label, got.Kind, s.name)
		}
	}

	// Caller IPs by role (the .101/.102/.103 legit generators + the expanded
	// .105-.110 benign callers + .111 prober; the names are operator-declared
	// staging metadata, the .111 "caller" kind is NOT an engine verdict). Note
	// .104 is the careful-mover deviant identity, intentionally NOT declared here.
	callers := []struct {
		ip   string
		name string
	}{
		{"10.20.1.101", "reporting-worker"},
		{"10.20.1.102", "batch-client"},
		{"10.20.1.103", "web-client"},
		{"10.20.1.105", "mobile-gateway"},
		{"10.20.1.106", "partner-api"},
		{"10.20.1.107", "ci-runner"},
		{"10.20.1.108", "etl-scheduler"},
		{"10.20.1.109", "support-console"},
		{"10.20.1.110", "ops-dashboard"},
		{"10.20.1.111", "prober"},
	}
	for _, c := range callers {
		got := r.Resolve(netip.MustParseAddr(c.ip), 51000, "", "")
		if got.Label != c.name || got.Kind != KindCaller {
			t.Errorf("caller %s -> {%q, %s}; want {%q, caller}", c.ip, got.Label, got.Kind, c.name)
		}
	}

	// A loopback port the mesh does not declare still degrades cleanly (never drops).
	got := r.Resolve(loopback, 9999, "", "")
	if got.Kind != KindUnknown || got.Label != "127.0.0.1" {
		t.Errorf("undeclared loopback port -> {%q, %s}; want {127.0.0.1, unknown}", got.Label, got.Kind)
	}
}
