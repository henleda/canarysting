package main

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// noFanout is a no-op downstream caller for the router tests.
func noFanout(context.Context) {}

func get(t *testing.T, path string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	serve(rr, req, "frontend", noFanout)
	return rr.Code, rr.Body.String()
}

// Rule 8: the frontend must NEVER serve a canary path — they stay negative space so a
// touch is recognized only by the adapter. Every canary prefix (and a path under it)
// must 404, not 200.
func TestFrontendNeverServesCanaryPaths(t *testing.T) {
	for _, p := range []string{
		"/.env", "/.env.bak", "/.aws/credentials", "/secrets/", "/secrets/db.json",
		"/config/", "/config/app.yml", "/backup/", "/backup/db.sql",
		"/internal/", "/internal/admin/credentials", "/admin/", "/admin/metrics",
	} {
		code, body := get(t, p)
		if code != 404 {
			t.Errorf("canary path %q returned %d, want 404 (must stay negative space)", p, code)
		}
		if strings.Contains(body, "ok") {
			t.Errorf("canary path %q body %q must not be an ok stub", p, body)
		}
	}
}

// An enumerating attacker must NOT see a uniform "ok" stub for every path: unknown
// paths 404 (including a random nonexistent one), known app paths serve real content.
func TestFrontendRouting(t *testing.T) {
	if code, body := get(t, "/"); code != 200 || !strings.Contains(body, "<html") {
		t.Errorf("/ = %d %q, want 200 HTML", code, body)
	}
	if code, _ := get(t, "/robots.txt"); code != 200 {
		t.Errorf("/robots.txt = %d, want 200", code)
	}
	if code, body := get(t, "/api/health"); code != 200 || !strings.Contains(body, "status") {
		t.Errorf("/api/health = %d %q, want 200 JSON", code, body)
	}
	for _, p := range []string{"/totally-random-nonexistent-12345", "/index.php", "/wp-login.php", "/api/unknown"} {
		if code, _ := get(t, p); code != 404 {
			t.Errorf("unknown path %q = %d, want 404 (not a uniform ok stub)", p, code)
		}
	}
}

// listenHost parses the bind host out of LISTEN so a service dials its downstreams
// from its OWN distinct loopback identity (the named east-west fabric). A bare port
// or a wildcard host must yield "" so we bind no LocalAddr (graceful fallback).
func TestListenHostParsesBindAddress(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   string
	}{
		{"127.0.1.2:8002", "127.0.1.2"},
		{"127.0.1.1:8001", "127.0.1.1"},
		{"127.0.1.16:8016", "127.0.1.16"},
		{":8000", ""},        // bare port -> no bind
		{"0.0.0.0:8080", ""}, // wildcard v4 -> no bind
		{"[::]:8080", ""},    // wildcard v6 -> no bind
		{"not-a-listen", ""}, // unparseable -> no bind
		{"", ""},             // empty -> no bind
	} {
		if got := listenHost(tc.listen); got != tc.want {
			t.Errorf("listenHost(%q) = %q, want %q", tc.listen, got, tc.want)
		}
	}
}

// The frontend is NOT covered by harmless.CrossScan — assert by hand it ships no
// real-looking secrets or routable hosts across all served paths.
func TestFrontendShipsNoSecrets(t *testing.T) {
	akia := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	pem := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	for _, p := range []string{"/", "/index.html", "/robots.txt", "/api/health", "/api/status"} {
		_, body := get(t, p)
		if akia.MatchString(body) {
			t.Errorf("path %q body contains an AWS key id", p)
		}
		if pem.MatchString(body) {
			t.Errorf("path %q body contains a PEM private key", p)
		}
	}
}
