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
// it resolves the known compose topology — the mesh services by their distinct
// 127.0.1.<K> IP (the distinct-identity scheme: a service is named by IP alone, so
// its egress[port 0] and listen[port N] sides coalesce to one node), the ingress
// gateway by both its accept and upstream-bind addresses, and the caller IPs by
// role. If server-compose.yml's LISTEN addresses or the ground-truth caller IPs
// change, this test catches the demo config drifting out of sync.
func TestDemoConfigLoadsAndResolves(t *testing.T) {
	cfg, err := LoadConfigFile(demoConfigPath)
	if err != nil {
		t.Fatalf("LoadConfigFile(%s): %v", demoConfigPath, err)
	}
	r := NewResolver(cfg)

	// Mesh services by their distinct 127.0.1.<K> IP (verified against
	// deploy/m7-window/server-compose.yml). K = port-8000. The original 5-service
	// core plus the expanded east-west fabric (payments..profile). Each is keyed by
	// IP only, so we resolve it with BOTH the egress side (port 0) and the listen
	// side (port N) and require the SAME named node — that coalescing is the whole
	// point of the IP keying.
	services := []struct {
		ip   string
		port uint16
		name string
	}{
		{"127.0.1.1", 8001, "frontend"},
		{"127.0.1.2", 8002, "api"},
		{"127.0.1.3", 8003, "auth"},
		{"127.0.1.4", 8004, "db"},
		{"127.0.1.5", 8005, "cache"},
		{"127.0.1.6", 8006, "payments"},
		{"127.0.1.7", 8007, "search"},
		{"127.0.1.8", 8008, "cdn-edge"},
		{"127.0.1.9", 8009, "ledger"},
		{"127.0.1.10", 8010, "db-replica"},
		{"127.0.1.11", 8011, "session-store"},
		{"127.0.1.12", 8012, "inventory"},
		{"127.0.1.13", 8013, "orders"},
		{"127.0.1.14", 8014, "analytics"},
		{"127.0.1.15", 8015, "notifications"},
		{"127.0.1.16", 8016, "profile"},
	}
	for _, s := range services {
		ip := netip.MustParseAddr(s.ip)
		// Egress side: resolved with port 0 (the initiator key). Must name the service.
		if got := r.Resolve(ip, 0, "", ""); got.Label != s.name || got.Kind != KindService {
			t.Errorf("service %s egress -> {%q, %s}; want {%q, service}", s.ip, got.Label, got.Kind, s.name)
		}
		// Listen side: resolved with the listen port. Must name the SAME service.
		if got := r.Resolve(ip, s.port, "", ""); got.Label != s.name || got.Kind != KindService {
			t.Errorf("service %s:%d listen -> {%q, %s}; want {%q, service}", s.ip, s.port, got.Label, got.Kind, s.name)
		}
	}

	// The ingress gateway is declared twice (its accept address 127.0.0.1:8080 and
	// its upstream-bind source 127.0.2.1) under the SAME name so the tap coalesces
	// them into one node. Both must resolve to {ingress-gateway, external}.
	if got := r.Resolve(netip.MustParseAddr("127.0.0.1"), 8080, "", ""); got.Label != "ingress-gateway" || got.Kind != KindExternal {
		t.Errorf("ingress accept 127.0.0.1:8080 -> {%q, %s}; want {ingress-gateway, external}", got.Label, got.Kind)
	}
	if got := r.Resolve(netip.MustParseAddr("127.0.2.1"), 0, "", ""); got.Label != "ingress-gateway" || got.Kind != KindExternal {
		t.Errorf("ingress source 127.0.2.1 -> {%q, %s}; want {ingress-gateway, external}", got.Label, got.Kind)
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

	// An undeclared loopback (ingress is only declared at port 8080, via the ipPort
	// map) still degrades cleanly to an IP-labeled unknown node (never drops).
	got := r.Resolve(netip.MustParseAddr("127.0.0.1"), 9999, "", "")
	if got.Kind != KindUnknown || got.Label != "127.0.0.1" {
		t.Errorf("undeclared loopback port -> {%q, %s}; want {127.0.0.1, unknown}", got.Label, got.Kind)
	}
}
