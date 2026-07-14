package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// recordingFake is the injected gatewayCaller test double: it records every path
// requested and always answers 200 — the mock-external-boundary seam (gw.Fetch is
// the ONLY external call service C makes).
type recordingFake struct {
	paths []string
}

func (f *recordingFake) Fetch(path string) (int, error) {
	f.paths = append(f.paths, path)
	return http.StatusOK, nil
}

func getPath(t *testing.T, gw gatewayCaller, path string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	serve(rr, req, gw)
	return rr.Code, rr.Body.String()
}

// postTransaction submits POST /api/transaction with persona as a form value. An
// empty persona omits the field entirely (true "missing", not an empty value).
func postTransaction(t *testing.T, gw gatewayCaller, persona string) (int, string) {
	t.Helper()
	form := url.Values{}
	if persona != "" {
		form.Set("persona", persona)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/transaction", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serve(rr, req, gw)
	return rr.Code, rr.Body.String()
}

// mirroredCanaryPrefixes hand-mirrors the negative-space canary prefixes defined in
// deploy/m7-window/mesh/main.go:62-64 (canaryPrefixes) and cmd/envoy-adapter/main.go
// :243-249 (demoCanaryPaths). package main is unimportable across binaries, so this
// hand-mirror is the same pattern the mesh/adapter pair already uses — keep it in
// sync by hand if either source changes.
var mirroredCanaryPrefixes = []string{
	"/.aws/credentials", "/secrets/", "/.env", "/config/", "/backup/", "/internal/", "/admin/",
}

// The scope guard: Standard-mode paths must never collide with the canary negative
// space (rule 8), and must stay within the served surface ("/" or "/api/*").
func TestStandardPathsAreCanaryFree(t *testing.T) {
	for _, p := range standardPaths {
		for _, cp := range mirroredCanaryPrefixes {
			if p == cp || strings.HasPrefix(p, cp) {
				t.Errorf("standardPaths entry %q collides with canary prefix %q — must stay disjoint (rule 8)", p, cp)
			}
		}
		if p != "/" && !strings.HasPrefix(p, "/api/") {
			t.Errorf("standardPaths entry %q must be \"/\" or begin \"/api/\"", p)
		}
	}
}

func TestHealthz(t *testing.T) {
	code, body := getPath(t, &recordingFake{}, "/healthz")
	if code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if body != "ok" {
		t.Errorf("/healthz body = %q, want \"ok\"", body)
	}
}

func TestServesStorefront(t *testing.T) {
	code, body := getPath(t, &recordingFake{}, "/")
	if code != http.StatusOK {
		t.Fatalf("/ = %d, want 200", code)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("/ body does not look like HTML: %q", body)
	}
	if !strings.Contains(body, "Standard") || !strings.Contains(body, "Redteam") {
		t.Errorf("/ body missing persona toggle markers (Standard/Redteam): %q", body)
	}
	if !strings.Contains(body, "Buy") {
		t.Errorf("/ body missing a Buy control: %q", body)
	}
}

func TestStandardTransactionHitsServedPaths(t *testing.T) {
	fake := &recordingFake{}
	code, body := postTransaction(t, fake, "standard")
	if code != http.StatusOK {
		t.Fatalf("persona=standard = %d, want 200", code)
	}
	if len(fake.paths) != len(standardPaths) {
		t.Fatalf("gw.Fetch called %v, want exactly %v", fake.paths, standardPaths)
	}
	for i, want := range standardPaths {
		if fake.paths[i] != want {
			t.Errorf("gw.Fetch call %d = %q, want %q", i, fake.paths[i], want)
		}
	}
	var receipt map[string]any
	if err := json.Unmarshal([]byte(body), &receipt); err != nil {
		t.Fatalf("receipt body not JSON: %v (%q)", err, body)
	}
	if receipt["persona"] != "standard" {
		t.Errorf("receipt persona = %v, want \"standard\"", receipt["persona"])
	}
	if receipt["ok"] != true {
		t.Errorf("receipt ok = %v, want true", receipt["ok"])
	}
}

func TestPersonaSelectsPathSet(t *testing.T) {
	standardFake := &recordingFake{}
	if code, _ := postTransaction(t, standardFake, "standard"); code != http.StatusOK {
		t.Fatalf("persona=standard = %d, want 200", code)
	}
	if len(standardFake.paths) != len(standardPaths) {
		t.Errorf("standard fake recorded %v, want %v", standardFake.paths, standardPaths)
	} else {
		for i, want := range standardPaths {
			if standardFake.paths[i] != want {
				t.Errorf("standard fake call %d = %q, want %q", i, standardFake.paths[i], want)
			}
		}
	}

	redteamFake := &recordingFake{}
	if code, _ := postTransaction(t, redteamFake, "redteam"); code != http.StatusOK {
		t.Fatalf("persona=redteam = %d, want 200", code)
	}
	if len(redteamFake.paths) != 0 {
		t.Errorf("redteam fake recorded %v, want zero gw.Fetch calls", redteamFake.paths)
	}
}

func TestRedteamStubInert(t *testing.T) {
	fake := &recordingFake{}
	code, body := postTransaction(t, fake, "redteam")
	if code != http.StatusOK {
		t.Fatalf("persona=redteam = %d, want 200", code)
	}
	if len(fake.paths) != 0 {
		t.Errorf("persona=redteam called gw.Fetch %v, want zero calls (P1 stub is inert)", fake.paths)
	}
	var stub map[string]any
	if err := json.Unmarshal([]byte(body), &stub); err != nil {
		t.Fatalf("stub body not JSON: %v (%q)", err, body)
	}
	if stub["persona"] != "redteam" {
		t.Errorf("stub persona = %v, want \"redteam\"", stub["persona"])
	}
	if stub["status"] != "stub" {
		t.Errorf("stub status = %v, want \"stub\"", stub["status"])
	}
	if stub["wired"] != "P2" {
		t.Errorf("stub wired = %v, want \"P2\"", stub["wired"])
	}
	for _, cp := range mirroredCanaryPrefixes {
		if strings.Contains(body, cp) {
			t.Errorf("redteam stub body contains canary path %q — must stay negative space (rule 8)", cp)
		}
	}
}

func TestUnknownPersonaRejected(t *testing.T) {
	unknown := &recordingFake{}
	code, _ := postTransaction(t, unknown, "foo")
	if code != http.StatusBadRequest {
		t.Errorf("persona=foo = %d, want 400", code)
	}
	if len(unknown.paths) != 0 {
		t.Errorf("persona=foo called gw.Fetch %v, want zero calls", unknown.paths)
	}

	missing := &recordingFake{}
	code, _ = postTransaction(t, missing, "")
	if code != http.StatusBadRequest {
		t.Errorf("missing persona = %d, want 400", code)
	}
	if len(missing.paths) != 0 {
		t.Errorf("missing persona called gw.Fetch %v, want zero calls", missing.paths)
	}
}

// service C is not covered by harmless.CrossScan — assert by hand it ships no
// real-looking secrets across the storefront, mirroring mesh/main_test.go:85-97.
func TestShipsNoSecrets(t *testing.T) {
	akia := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	pem := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	_, body := getPath(t, &recordingFake{}, "/")
	if akia.MatchString(body) {
		t.Errorf("/ body contains an AWS key id")
	}
	if pem.MatchString(body) {
		t.Errorf("/ body contains a PEM private key")
	}
}
