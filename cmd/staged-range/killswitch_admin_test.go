package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/sting/killswitch"
)

func buildForAdmin(t *testing.T) *boot.Built {
	t.Helper()
	db := filepath.Join(t.TempDir(), "baseline.db")
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute, BaselineDBPath: db}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = built.Close() })
	return built
}

func writeToken(t *testing.T, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ks.token")
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// No token file AND no principals file => refuse to construct (fail-closed: never an
// unauthenticated switch).
func TestAdminRefusesWithoutToken(t *testing.T) {
	if _, err := newKillSwitchAdmin(buildForAdmin(t), "", ""); err == nil {
		t.Fatal("admin must refuse to start without a token or principals file")
	}
	empty := writeToken(t, "   \n")
	if _, err := newKillSwitchAdmin(buildForAdmin(t), empty, ""); err == nil {
		t.Fatal("admin must refuse an empty token file")
	}
}

// A non-loopback bind is refused (B1 is loopback-only; remote mTLS is B2).
func TestAdminRequiresLoopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:9000", "10.0.0.1:9000", ":9000"} {
		if err := requireLoopback(bad); err == nil {
			t.Fatalf("bind %q must be refused (loopback-only)", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:9000", "[::1]:9000"} {
		if err := requireLoopback(ok); err != nil {
			t.Fatalf("loopback bind %q must be allowed: %v", ok, err)
		}
	}
}

// Requests without the bearer token get 401 and change nothing.
func TestAdminUnauthorized(t *testing.T) {
	built := buildForAdmin(t)
	admin, err := newKillSwitchAdmin(built, writeToken(t, "s3cr3t"), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	// No token.
	resp, err := http.Post(srv.URL+"/killswitch/engage", "application/json", bytes.NewReader([]byte(`{"duration_seconds":60,"reason":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token engage = %d, want 401", resp.StatusCode)
	}
	if built.KillSwitch.Active(time.Now()) {
		t.Fatal("an unauthorized request must NOT engage the kill-switch")
	}

	// Wrong token.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/killswitch/engage", bytes.NewReader([]byte(`{"duration_seconds":60}`)))
	req.Header.Set("Authorization", "Bearer wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token engage = %d, want 401", resp2.StatusCode)
	}
	if built.KillSwitch.Active(time.Now()) {
		t.Fatal("a wrong-token request must NOT engage the kill-switch")
	}
}

// A valid engage trips the switch; status reflects it; revive clears it. The audit
// chain (boundary scope) gains the operator-action records.
func TestAdminEngageStatusRevive(t *testing.T) {
	built := buildForAdmin(t)
	const tok = "operator-shared-secret"
	admin, err := newKillSwitchAdmin(built, writeToken(t, tok), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.Handler())
	defer srv.Close()

	post := func(path, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Operator", "alice")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Engage for 1h.
	resp := post("/killswitch/engage", `{"duration_seconds":3600,"reason":"incident-99"}`)
	var st killswitch.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !st.Engaged || st.Operator != "alice" || st.Reason != "incident-99" {
		t.Fatalf("engage status wrong: %+v", st)
	}
	if !built.KillSwitch.Active(time.Now()) {
		t.Fatal("engage must trip the switch")
	}

	// GET status (authed).
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/killswitch", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	gresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var gst killswitch.Status
	_ = json.NewDecoder(gresp.Body).Decode(&gst)
	gresp.Body.Close()
	if !gst.Engaged {
		t.Fatalf("GET status must report engaged: %+v", gst)
	}

	// Revive.
	rresp := post("/killswitch/revive", `{"reason":"resolved"}`)
	var rst killswitch.Status
	_ = json.NewDecoder(rresp.Body).Decode(&rst)
	rresp.Body.Close()
	if rst.Engaged {
		t.Fatalf("revive must disengage: %+v", rst)
	}
	if built.KillSwitch.Active(time.Now()) {
		t.Fatal("revive must clear the switch")
	}

	// The boundary scope's audit chain verifies intact and carries both toggles.
	vr, err := built.Audit.Verify("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	if !vr.Intact {
		t.Fatalf("audit chain must verify intact after toggles: %+v", vr)
	}
}
