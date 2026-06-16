package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence/audit"
	"github.com/canarysting/canarysting/internal/sting/killswitch"
)

// tokenSHA256 mirrors the out-of-band step an operator runs to compute the digest
// stored in the principals file from a raw bearer token.
func tokenSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// writePrincipals writes a principals JSON file (0o600) and returns its path.
func writePrincipals(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "killswitch-principals.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// principalsFileWith writes a two-principal RBAC file (one operator "alice", one
// viewer "ir-bot") and returns its path.
func principalsFileWith(t *testing.T, opTok, viewTok string) string {
	t.Helper()
	doc := `{"principals":[
	  {"name":"alice","token_sha256":"` + tokenSHA256(opTok) + `","role":"operator"},
	  {"name":"ir-bot","token_sha256":"` + tokenSHA256(viewTok) + `","role":"viewer"}
	]}`
	return writePrincipals(t, doc)
}

// bearer issues a request with the given bearer token (and optional spoofed
// X-Operator) and returns the response.
func bearer(t *testing.T, method, url, tok, xOperator, body string) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if xOperator != "" {
		req.Header.Set("X-Operator", xOperator)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// An operator-role token resolves and may engage/revive/status; the audit chain
// records the VERIFIED principal name + role=operator + auth_via=principal, and a
// SPOOFED X-Operator header is IGNORED (not the recorded operator).
func TestRBACOperatorEngagesAndAuditsVerifiedIdentity(t *testing.T) {
	built := buildForAdmin(t) // boundary scope "scopeA", with audit store
	const opTok = "alice-operator-raw-token"
	const viewTok = "ir-bot-viewer-raw-token"
	pf := principalsFileWith(t, opTok, viewTok)

	admin, err := newKillSwitchAdmin(built, "", pf)
	if err != nil {
		t.Fatal(err)
	}
	if admin.mode != modePrincipals {
		t.Fatalf("expected modePrincipals, got %v", admin.mode)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// Engage as alice, but SPOOF X-Operator: mallory. The verified identity (alice)
	// must win — X-Operator is ignored in principals mode.
	resp := bearer(t, http.MethodPost, srv.URL+"/killswitch/engage", opTok, "mallory", `{"duration_seconds":3600,"reason":"incident-7"}`)
	var st killswitch.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator engage = %d, want 200", resp.StatusCode)
	}
	if !st.Engaged {
		t.Fatal("operator engage must trip the switch")
	}
	if st.Operator != "alice" {
		t.Fatalf("recorded operator = %q, want verified %q (X-Operator spoof must be IGNORED)", st.Operator, "alice")
	}

	// The audit chain records the VERIFIED identity, role, and auth_via — not mallory.
	blob, err := built.Audit.Export("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	var report audit.CaseReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Verify.Intact {
		t.Fatalf("audit chain must verify intact: %+v", report.Verify)
	}
	var sawEngage bool
	for _, rec := range report.Records {
		if rec.Kind == audit.KindOperator && rec.Action == "kill_switch_engage" {
			sawEngage = true
			if rec.Posture["operator"] != "alice" {
				t.Fatalf("audit operator = %q, want verified %q (NOT the spoofed X-Operator)", rec.Posture["operator"], "alice")
			}
			if rec.Posture["operator"] == "mallory" {
				t.Fatal("the spoofed X-Operator must NOT be recorded")
			}
			if rec.Posture["role"] != "operator" {
				t.Fatalf("audit role = %q, want operator", rec.Posture["role"])
			}
			if rec.Posture["auth_via"] != "principal" {
				t.Fatalf("audit auth_via = %q, want principal", rec.Posture["auth_via"])
			}
		}
	}
	if !sawEngage {
		t.Fatal("engage operator-action record not found in chain")
	}
}

// An unknown token => 401 on every route and changes nothing.
func TestRBACUnknownTokenIs401(t *testing.T) {
	built := buildForAdmin(t)
	pf := principalsFileWith(t, "alice-tok", "irbot-tok")
	admin, err := newKillSwitchAdmin(built, "", pf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	for _, route := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/killswitch/engage", `{"duration_seconds":60}`},
		{http.MethodPost, "/killswitch/revive", `{}`},
		{http.MethodGet, "/killswitch", ""},
	} {
		resp := bearer(t, route.method, srv.URL+route.path, "totally-unknown-token", "", route.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s with unknown token = %d, want 401", route.method, route.path, resp.StatusCode)
		}
	}
	if built.KillSwitch.Active(time.Now()) {
		t.Fatal("an unknown-token request must NOT engage the switch")
	}
}

// A viewer token is REJECTED on engage/revive (403 forbidden — a resolved-but-
// insufficient identity is FORBIDDEN, distinct from the 401 unknown-token case) but
// is ALLOWED on status (read-only). The 403 must NOT engage the switch.
func TestRBACViewerForbiddenOnMutateAllowedOnStatus(t *testing.T) {
	built := buildForAdmin(t)
	const opTok = "alice-operator-raw-token"
	const viewTok = "ir-bot-viewer-raw-token"
	pf := principalsFileWith(t, opTok, viewTok)
	admin, err := newKillSwitchAdmin(built, "", pf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// Viewer engage => 403, and the switch must remain disengaged.
	resp := bearer(t, http.MethodPost, srv.URL+"/killswitch/engage", viewTok, "", `{"duration_seconds":60,"reason":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer engage = %d, want 403 (forbidden, NOT 401)", resp.StatusCode)
	}
	if built.KillSwitch.Active(time.Now()) {
		t.Fatal("a 403 viewer engage must NOT trip the switch")
	}

	// Viewer revive => 403.
	resp = bearer(t, http.MethodPost, srv.URL+"/killswitch/revive", viewTok, "", `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer revive = %d, want 403", resp.StatusCode)
	}

	// Viewer status => 200 (read-only is exactly what a viewer may do).
	resp = bearer(t, http.MethodGet, srv.URL+"/killswitch", viewTok, "", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer status = %d, want 200 (viewer may read status)", resp.StatusCode)
	}

	// And the operator can still engage (sanity: the gate is role-specific, not a
	// blanket deny).
	resp = bearer(t, http.MethodPost, srv.URL+"/killswitch/engage", opTok, "", `{"duration_seconds":60,"reason":"ok"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator engage = %d, want 200", resp.StatusCode)
	}
	if !built.KillSwitch.Active(time.Now()) {
		t.Fatal("operator engage must trip the switch")
	}
}

// Precedence: when BOTH a token file and a principals file are set, the principals
// file WINS (modePrincipals) and the single shared token is IGNORED.
func TestRBACPrincipalsFileTakesPrecedence(t *testing.T) {
	built := buildForAdmin(t)
	const opTok = "alice-operator-raw-token"
	const singleTok = "legacy-single-shared-token"
	pf := principalsFileWith(t, opTok, "ir-bot-viewer-raw-token")
	tf := writeToken(t, singleTok)

	admin, err := newKillSwitchAdmin(built, tf, pf)
	if err != nil {
		t.Fatal(err)
	}
	if admin.mode != modePrincipals {
		t.Fatalf("with both files set, mode = %v, want modePrincipals (principals wins)", admin.mode)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// The legacy single token must NOT resolve now (it was superseded).
	resp := bearer(t, http.MethodGet, srv.URL+"/killswitch", singleTok, "", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("legacy single token under principals mode = %d, want 401 (single token ignored)", resp.StatusCode)
	}
	// The principal token resolves.
	resp = bearer(t, http.MethodGet, srv.URL+"/killswitch", opTok, "", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("principal token under principals mode = %d, want 200", resp.StatusCode)
	}
}

// BACK-COMPAT: legacy single-token mode still engages + audits, recording the
// ADVISORY X-Operator header as the operator and auth_via=single-token.
func TestSingleTokenBackCompatEngagesAndAudits(t *testing.T) {
	built := buildForAdmin(t)
	const tok = "operator-shared-secret"
	admin, err := newKillSwitchAdmin(built, writeToken(t, tok), "")
	if err != nil {
		t.Fatal(err)
	}
	if admin.mode != modeSingle {
		t.Fatalf("expected modeSingle, got %v", admin.mode)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// Engage with the shared token + advisory X-Operator "bob".
	resp := bearer(t, http.MethodPost, srv.URL+"/killswitch/engage", tok, "bob", `{"duration_seconds":3600,"reason":"legacy"}`)
	var st killswitch.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !st.Engaged {
		t.Fatalf("single-token engage failed: code=%d engaged=%v", resp.StatusCode, st.Engaged)
	}
	if st.Operator != "bob" {
		t.Fatalf("single-token operator = %q, want advisory %q", st.Operator, "bob")
	}

	blob, err := built.Audit.Export("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	var report audit.CaseReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Verify.Intact {
		t.Fatalf("audit chain must verify intact: %+v", report.Verify)
	}
	var sawEngage bool
	for _, rec := range report.Records {
		if rec.Kind == audit.KindOperator && rec.Action == "kill_switch_engage" {
			sawEngage = true
			if rec.Posture["operator"] != "bob" {
				t.Fatalf("audit operator = %q, want advisory %q", rec.Posture["operator"], "bob")
			}
			if rec.Posture["auth_via"] != "single-token" {
				t.Fatalf("audit auth_via = %q, want single-token", rec.Posture["auth_via"])
			}
			if rec.Posture["role"] != "operator" {
				t.Fatalf("audit role = %q, want operator", rec.Posture["role"])
			}
		}
	}
	if !sawEngage {
		t.Fatal("engage operator-action record not found in chain")
	}
}

// A malformed/empty principals file refuses to construct (fail-closed).
func TestRBACMalformedPrincipalsFileRefuses(t *testing.T) {
	built := buildForAdmin(t)
	empty := writePrincipals(t, `{"principals":[]}`)
	if _, err := newKillSwitchAdmin(built, "", empty); err == nil {
		t.Fatal("an empty principals list must refuse to start (fail-closed)")
	}
	bad := writePrincipals(t, `{"principals":[{"name":"a","token_sha256":"short","role":"operator"}]}`)
	if _, err := newKillSwitchAdmin(built, "", bad); err == nil {
		t.Fatal("a malformed token_sha256 must refuse to start")
	}
}
