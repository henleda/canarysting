package identity

import (
	"net/netip"
	"strings"
	"testing"
)

// mustResolver builds a resolver from an inline JSON config, failing the test if
// the config doesn't load.
func mustResolver(t *testing.T, jsonCfg string) *Resolver {
	t.Helper()
	cfg, err := LoadConfig(strings.NewReader(jsonCfg))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return NewResolver(cfg)
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

// TestResolvePrecedence drives the documented precedence ordering: exact (ip,port)
// > exact ip > CIDR > port-only > SPIFFE > IP fallback. The config deliberately
// declares overlapping selectors for the same address so each level can be shown
// to win over the next.
func TestResolvePrecedence(t *testing.T) {
	const cfg = `{
		"entries": [
			{ "ip": "10.0.0.5", "port": 9000, "name": "exact-ip-port", "kind": "service" },
			{ "ip": "10.0.0.5", "name": "exact-ip", "kind": "service" },
			{ "cidr": "10.0.0.0/24", "name": "cidr-24", "kind": "service" },
			{ "cidr": "10.0.0.0/16", "name": "cidr-16", "kind": "service" },
			{ "port": 8002, "name": "port-only-api", "kind": "service" }
		]
	}`
	r := mustResolver(t, cfg)

	tests := []struct {
		name      string
		ip        string
		port      uint16
		spiffe    string
		wantLabel string
		wantKind  NodeKind
	}{
		{"exact (ip,port) wins over exact ip and cidr", "10.0.0.5", 9000, "", "exact-ip-port", KindService},
		{"exact ip wins over cidr when port differs", "10.0.0.5", 1234, "", "exact-ip", KindService},
		{"longest-prefix cidr wins (/24 over /16)", "10.0.0.99", 1234, "", "cidr-24", KindService},
		{"enclosing cidr (/16) matches outside the /24", "10.0.5.7", 1234, "", "cidr-16", KindService},
		{"port-only matches when no ip/cidr entry covers the addr", "192.168.99.99", 8002, "", "port-only-api", KindService},
		{"cidr beats port-only when both could match", "10.0.0.7", 8002, "", "cidr-24", KindService},
		{"spiffe used only after all operator selectors miss", "203.0.113.7", 5555, "spiffe://td/ns/prod/sa/billing", "prod/billing", KindService},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Resolve(addr(t, tt.ip), tt.port, tt.spiffe, "")
			if got.Label != tt.wantLabel || got.Kind != tt.wantKind {
				t.Fatalf("Resolve(%s:%d, %q) = {%q, %s}; want {%q, %s}",
					tt.ip, tt.port, tt.spiffe, got.Label, got.Kind, tt.wantLabel, tt.wantKind)
			}
		})
	}
}

// TestResolveExactIP, CIDR, and port-only each in isolation (no overlap), so a
// single selector kind is exercised cleanly.
func TestResolveSelectorsInIsolation(t *testing.T) {
	const cfg = `{
		"entries": [
			{ "ip": "10.20.1.101", "name": "reporting-worker", "kind": "caller" },
			{ "cidr": "172.16.0.0/12", "name": "corp-range", "kind": "caller" },
			{ "port": 8004, "name": "db", "kind": "service" }
		]
	}`
	r := mustResolver(t, cfg)

	tests := []struct {
		name      string
		ip        string
		port      uint16
		wantLabel string
		wantKind  NodeKind
	}{
		{"exact-ip caller", "10.20.1.101", 40000, "reporting-worker", KindCaller},
		{"cidr caller", "172.16.5.9", 40000, "corp-range", KindCaller},
		{"port-only service", "127.0.0.1", 8004, "db", KindService},
		{"port-only with IPv4-mapped IPv6 address", "::ffff:127.0.0.1", 8004, "db", KindService},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Resolve(addr(t, tt.ip), tt.port, "", "")
			if got.Label != tt.wantLabel || got.Kind != tt.wantKind {
				t.Fatalf("Resolve(%s:%d) = {%q, %s}; want {%q, %s}",
					tt.ip, tt.port, got.Label, got.Kind, tt.wantLabel, tt.wantKind)
			}
		})
	}
}

// TestServiceNameFromSPIFFE covers the SVID path conventions plus tolerant and
// reject cases.
func TestServiceNameFromSPIFFE(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		wantName string
		wantOK   bool
	}{
		{"ns + sa", "spiffe://example.org/ns/prod/sa/payments", "prod/payments", true},
		{"sa only", "spiffe://example.org/sa/auth", "auth", true},
		{"ns only", "spiffe://example.org/ns/staging", "staging", true},
		{"trailing slash tolerated", "spiffe://example.org/ns/prod/sa/api/", "prod/api", true},
		{"tolerant last-segment fallback", "spiffe://td/workload/search", "search", true},
		{"not a spiffe uri", "https://example.org/sa/x", "", false},
		{"trust domain only, no path", "spiffe://example.org", "", false},
		{"empty", "", "", false},
		{"scheme + empty path", "spiffe://example.org/", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := ServiceNameFromSPIFFE(tt.id)
			if name != tt.wantName || ok != tt.wantOK {
				t.Fatalf("ServiceNameFromSPIFFE(%q) = (%q, %v); want (%q, %v)",
					tt.id, name, ok, tt.wantName, tt.wantOK)
			}
		})
	}
}

// TestSPIFFEResolvesToServiceNode confirms a SPIFFE-only flow (no operator entry)
// resolves to a Service node named from the cert.
func TestSPIFFEResolvesToServiceNode(t *testing.T) {
	r := NewResolver(&Config{}) // empty operator map
	got := r.Resolve(addr(t, "203.0.113.50"), 443, "spiffe://mesh.local/ns/prod/sa/ledger", "")
	if got.Label != "prod/ledger" || got.Kind != KindService {
		t.Fatalf("got {%q, %s}; want {prod/ledger, service}", got.Label, got.Kind)
	}
}

// TestDegradeToIP covers the never-drop fallback: a miss yields the IP string,
// External for a routable/foreign addr and Unknown for a private/loopback addr.
func TestDegradeToIP(t *testing.T) {
	r := NewResolver(&Config{}) // empty map -> everything degrades

	tests := []struct {
		name      string
		ip        string
		wantLabel string
		wantKind  NodeKind
	}{
		{"public IPv4 -> External labeled by IP", "203.0.113.9", "203.0.113.9", KindExternal},
		{"public IPv6 -> External", "2606:4700:4700::1111", "2606:4700:4700::1111", KindExternal},
		{"private 10/8 -> Unknown", "10.20.1.55", "10.20.1.55", KindUnknown},
		{"private 192.168 -> Unknown", "192.168.1.10", "192.168.1.10", KindUnknown},
		{"loopback -> Unknown", "127.0.0.1", "127.0.0.1", KindUnknown},
		{"link-local -> Unknown", "169.254.1.2", "169.254.1.2", KindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Resolve(addr(t, tt.ip), 12345, "", "")
			if got.Label != tt.wantLabel || got.Kind != tt.wantKind {
				t.Fatalf("Resolve(%s) = {%q, %s}; want {%q, %s}",
					tt.ip, got.Label, got.Kind, tt.wantLabel, tt.wantKind)
			}
		})
	}
}

// TestDegradeInvalidAddrIsAnonymous: an invalid (zero) addr with no srcAddr hint
// and no SPIFFE yields an anonymous Unknown node — never a panic, never a drop.
func TestDegradeInvalidAddrIsAnonymous(t *testing.T) {
	r := NewResolver(&Config{})
	got := r.Resolve(netip.Addr{}, 0, "", "")
	if got.Kind != KindUnknown || got.Label != "" {
		t.Fatalf("got {%q, %s}; want {\"\", unknown}", got.Label, got.Kind)
	}
}

// TestSrcAddrHintFallback: when the netip is invalid but the adapter stamped a
// source-address hint, the resolver uses the hint to name/label the node.
func TestSrcAddrHintFallback(t *testing.T) {
	const cfg = `{"entries":[{"ip":"10.20.1.111","name":"prober","kind":"caller"}]}`
	r := mustResolver(t, cfg)

	// Invalid netip, but srcAddr matches an operator entry.
	got := r.Resolve(netip.Addr{}, 0, "", "10.20.1.111")
	if got.Label != "prober" || got.Kind != KindCaller {
		t.Fatalf("got {%q, %s}; want {prober, caller}", got.Label, got.Kind)
	}

	// Invalid netip, srcAddr is a public addr with no entry -> External fallback.
	got = r.Resolve(netip.Addr{}, 0, "", "198.51.100.7")
	if got.Label != "198.51.100.7" || got.Kind != KindExternal {
		t.Fatalf("got {%q, %s}; want {198.51.100.7, external}", got.Label, got.Kind)
	}
}

// TestNilAndEmptyConfigNeverPanics: a nil config, a nil resolver-from-nil, and an
// empty Entries slice all degrade gracefully and never panic.
func TestNilAndEmptyConfigNeverPanics(t *testing.T) {
	for _, r := range []*Resolver{
		NewResolver(nil),
		NewResolver(&Config{}),
		NewResolver(&Config{Entries: nil}),
	} {
		got := r.Resolve(addr(t, "203.0.113.1"), 80, "spiffe://td/sa/x", "")
		// Operator map empty -> SPIFFE wins here.
		if got.Label != "x" || got.Kind != KindService {
			t.Fatalf("got {%q, %s}; want {x, service}", got.Label, got.Kind)
		}
		// And a pure miss still degrades.
		got = r.Resolve(addr(t, "203.0.113.1"), 80, "", "")
		if got.Kind != KindExternal {
			t.Fatalf("got kind %s; want external", got.Kind)
		}
	}
}

// TestLoadConfigRejectsMalformed: the loader fails loudly on a bad selector or a
// missing/unknown field, so an operator typo can't silently mis-name a node.
func TestLoadConfigRejectsMalformed(t *testing.T) {
	bad := []string{
		`{"entries":[{"ip":"not-an-ip","name":"x","kind":"service"}]}`,
		`{"entries":[{"cidr":"10.0.0.0/nope","name":"x","kind":"service"}]}`,
		`{"entries":[{"ip":"10.0.0.1","cidr":"10.0.0.0/24","name":"x","kind":"service"}]}`,
		`{"entries":[{"name":"no-selector","kind":"service"}]}`,
		`{"entries":[{"ip":"10.0.0.1","kind":"service"}]}`,           // missing name
		`{"entries":[{"ip":"10.0.0.1","name":"x"}]}`,                 // missing kind
		`{"entries":[{"ip":"10.0.0.1","name":"x","kind":"decoy"}]}`,  // unknown kind
		`{"entries":[{"ip":"10.0.0.1","name":"x","kind":"router"}]}`, // unknown kind
		`not json`,
	}
	for i, b := range bad {
		if _, err := LoadConfig(strings.NewReader(b)); err == nil {
			t.Fatalf("case %d: expected error for %q, got nil", i, b)
		}
	}
}

// TestLoadConfigAcceptsWellFormed: the valid selector combinations all load.
func TestLoadConfigAcceptsWellFormed(t *testing.T) {
	good := `{
		"entries": [
			{ "ip": "10.0.0.1", "port": 8002, "name": "a", "kind": "service" },
			{ "ip": "10.0.0.2", "name": "b", "kind": "caller" },
			{ "cidr": "10.0.0.0/24", "name": "c", "kind": "caller" },
			{ "port": 8003, "name": "d", "kind": "service" }
		]
	}`
	cfg, err := LoadConfig(strings.NewReader(good))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(cfg.Entries))
	}
}
