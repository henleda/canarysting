package main

import (
	"net/http"
	"testing"
)

// TestAdminURL guards the scheme normalization: the -killswitch-admin-addr flag takes a
// bare host:port (mirroring the server), but net/url needs a scheme — a bare host:port
// parses with the host mistaken for the scheme ("first path segment in URL cannot
// contain colon"), which broke every canaryctl call until adminURL prepended http://.
func TestAdminURL(t *testing.T) {
	cases := []struct{ addr, path, want string }{
		{"127.0.0.1:9610", "/killswitch", "http://127.0.0.1:9610/killswitch"},
		{"127.0.0.1:9610/", "/killswitch/engage", "http://127.0.0.1:9610/killswitch/engage"},
		{"http://127.0.0.1:9610", "/killswitch/revive", "http://127.0.0.1:9610/killswitch/revive"},
		{"https://siem.example:443", "/killswitch", "https://siem.example:443/killswitch"},
		{"[::1]:9610", "/killswitch", "http://[::1]:9610/killswitch"},
	}
	for _, c := range cases {
		got := adminURL(c.addr, c.path)
		if got != c.want {
			t.Errorf("adminURL(%q, %q) = %q, want %q", c.addr, c.path, got, c.want)
		}
		// And it must actually be a request-buildable URL (the original bug was a parse
		// failure here, not a string mismatch).
		if _, err := http.NewRequest(http.MethodGet, got, nil); err != nil {
			t.Errorf("adminURL(%q,%q)=%q is not a valid request URL: %v", c.addr, c.path, got, err)
		}
	}
}
