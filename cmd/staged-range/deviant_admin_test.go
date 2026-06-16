package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canarysting/canarysting/internal/intelligence/audit"
)

// adminDeviantKeyHex is a fake canonical deviantKey, hex-encoded for the wire (the
// ONE pinned encoding the admin route decodes and the dashboard/canaryctl emit).
var adminDeviantKeyHex = hex.EncodeToString([]byte{0x01, 0x00, 0x02, 10, 20, 1, 104, 10, 20, 1, 9, 0x1f, 0x42, 0x01})

// An OPERATOR may suppress/ack/unsuppress a deviant pattern; each route returns the
// resulting state and is AUDITED into the boundary scope's chain with the deviant key
// in Posture["deviant_key"] (NOT the SocketCookie). The verified principal name +
// role=operator + auth_via=principal are recorded (X-Operator spoof ignored).
func TestDeviantRouteOperatorSuppressesAndAudits(t *testing.T) {
	built := buildForAdmin(t) // boundary scope "scopeA", with audit store
	const opTok = "alice-operator-raw-token"
	const viewTok = "ir-bot-viewer-raw-token"
	pf := principalsFileWith(t, opTok, viewTok)

	admin, err := newKillSwitchAdmin(built, "", pf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	body := `{"key":"` + adminDeviantKeyHex + `","reason":"known benign scanner"}`
	// Suppress as alice, SPOOF X-Operator: mallory. Verified identity (alice) must win.
	resp := bearer(t, http.MethodPost, srv.URL+"/deviant/suppress", opTok, "mallory", body)
	var dr deviantTriageResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator suppress = %d, want 200", resp.StatusCode)
	}
	if dr.State != "suppressed" || dr.Key != adminDeviantKeyHex || dr.Scope != "scopeA" {
		t.Fatalf("suppress response wrong: %+v", dr)
	}

	// Audited: verified alice, role/auth_via, deviant_key in Posture, NOT a cookie.
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
	var sawSuppress bool
	for _, rec := range report.Records {
		if rec.Kind == audit.KindOperator && rec.Action == "deviant_suppress" {
			sawSuppress = true
			if rec.Posture["operator"] != "alice" || rec.Posture["operator"] == "mallory" {
				t.Fatalf("audit operator = %q, want verified alice (X-Operator spoof ignored)", rec.Posture["operator"])
			}
			if rec.Posture["deviant_key"] != adminDeviantKeyHex {
				t.Fatalf("audit deviant_key = %q, want %q", rec.Posture["deviant_key"], adminDeviantKeyHex)
			}
			if rec.Posture["role"] != "operator" || rec.Posture["auth_via"] != "principal" {
				t.Fatalf("audit missing role/auth_via: %+v", rec.Posture)
			}
			if rec.SocketCookie != 0 {
				t.Fatalf("deviant action recorded a SocketCookie %d; a deviant is keyed by deviant_key", rec.SocketCookie)
			}
		}
	}
	if !sawSuppress {
		t.Fatal("deviant_suppress operator-action record not found in chain")
	}

	// ack then unsuppress also 200 with the right resulting state.
	resp = bearer(t, http.MethodPost, srv.URL+"/deviant/ack", opTok, "", body)
	_ = json.NewDecoder(resp.Body).Decode(&dr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || dr.State != "acked" {
		t.Fatalf("operator ack = %d state=%q, want 200/acked", resp.StatusCode, dr.State)
	}
	resp = bearer(t, http.MethodPost, srv.URL+"/deviant/unsuppress", opTok, "", body)
	_ = json.NewDecoder(resp.Body).Decode(&dr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || dr.State != "normal" {
		t.Fatalf("operator unsuppress = %d state=%q, want 200/normal", resp.StatusCode, dr.State)
	}
}

// A VIEWER is FORBIDDEN (403) on all three deviant routes — they are MUTATING (write
// an overlay row + an audit entry), so they require RoleOperator exactly like
// engage/revive. An unknown token is 401. A 403/401 writes nothing.
func TestDeviantRouteViewerForbiddenUnknown401(t *testing.T) {
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

	body := `{"key":"` + adminDeviantKeyHex + `","reason":"x"}`
	for _, path := range []string{"/deviant/suppress", "/deviant/unsuppress", "/deviant/ack"} {
		// Viewer => 403 (resolved-but-insufficient, distinct from 401).
		resp := bearer(t, http.MethodPost, srv.URL+path, viewTok, "", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer %s = %d, want 403", path, resp.StatusCode)
		}
		// Unknown token => 401.
		resp = bearer(t, http.MethodPost, srv.URL+path, "totally-unknown", "", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unknown-token %s = %d, want 401", path, resp.StatusCode)
		}
	}

	// The viewer's forbidden suppress wrote NO overlay row (and thus no audit).
	if _, ok, _ := built.Persist.GetDeviantTriage(built.BoundaryScope, mustHex(t, adminDeviantKeyHex)); ok {
		t.Fatal("a 403 viewer suppress must NOT write an overlay row")
	}
}

// Non-POST is 405; a non-hex / empty key is 400 (and writes nothing).
func TestDeviantRouteMethodAndKeyValidation(t *testing.T) {
	built := buildForAdmin(t)
	const opTok = "alice-operator-raw-token"
	pf := principalsFileWith(t, opTok, "ir-bot-viewer-raw-token")
	admin, err := newKillSwitchAdmin(built, "", pf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// GET => 405.
	resp := bearer(t, http.MethodGet, srv.URL+"/deviant/suppress", opTok, "", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /deviant/suppress = %d, want 405", resp.StatusCode)
	}
	// Non-hex key => 400.
	resp = bearer(t, http.MethodPost, srv.URL+"/deviant/suppress", opTok, "", `{"key":"not-hex!!","reason":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-hex key = %d, want 400", resp.StatusCode)
	}
	// Empty key => 400.
	resp = bearer(t, http.MethodPost, srv.URL+"/deviant/suppress", opTok, "", `{"key":"","reason":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty key = %d, want 400", resp.StatusCode)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
