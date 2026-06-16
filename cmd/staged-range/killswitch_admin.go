package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/sting/killswitch"
)

// killSwitchAdmin is the SLICE-B1 minimal, token-gated, LOCAL control surface for
// the deployment-wide enforcement DISARM. It is intentionally tiny and out of band
// from the engine's gRPC contract (NO proto/wire change in B1): a loopback-bound
// HTTP listener, OFF by default, that an operator (or an IR runbook) hits to halt /
// resume / inspect enforcement.
//
// AUTH (honest scope): a SHARED OPERATOR SECRET (bearer token) read from a file held
// OUTSIDE baseline.db (mirroring -audit-hmac-key). Constant-time compared. This is
// "minimal RBAC", NOT per-identity auth — there is one secret, not a user directory.
// Real per-identity RBAC / mTLS client-cert identity is the B2 follow-on. Because
// there is no per-identity principal, the "operator" recorded in the audit trail is
// taken from an X-Operator header (free-form, advisory) defaulting to "operator";
// the AUTHORITATIVE access control is possession of the token, and that is what the
// audit chain's tamper-evidence ultimately rests on (the action happened; who-by is
// best-effort until B2).
//
// FAIL-CLOSED: there is NEVER an unauthenticated kill-switch. If no token file is
// configured the listener REFUSES to start. If the token file is empty/whitespace it
// refuses to start. Any request without a matching bearer token gets 401 and changes
// nothing. (A 401 is NOT audited — an unauthenticated probe is not an operator
// action; auditing every drive-by would just be a log-spam DoS surface. Only a
// SUCCESSFUL, authenticated engage/revive is audited, via boot.Built.)
type killSwitchAdmin struct {
	built *boot.Built
	token []byte // the shared operator bearer token (constant-time compared); non-empty by construction
}

// newKillSwitchAdmin builds the admin handler. It reads the bearer token from
// tokenFile (held outside baseline.db) and REFUSES (errors) if the file is missing,
// unreadable, or empty — fail-closed: there is never an unauthenticated kill-switch.
func newKillSwitchAdmin(built *boot.Built, tokenFile string) (*killSwitchAdmin, error) {
	if tokenFile == "" {
		return nil, fmt.Errorf("killswitch-admin: a -killswitch-token-file is REQUIRED to enable the admin endpoint (no unauthenticated kill-switch)")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("killswitch-admin: read token file %q: %w", tokenFile, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return nil, fmt.Errorf("killswitch-admin: token file %q is empty; refusing to start an unauthenticated kill-switch", tokenFile)
	}
	return &killSwitchAdmin{built: built, token: []byte(tok)}, nil
}

// authed reports whether r carries the matching bearer token, compared in constant
// time (so a timing side channel cannot leak the secret). Accepts both
// "Authorization: Bearer <tok>" and a bare "Authorization: <tok>".
func (a *killSwitchAdmin) authed(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	h = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if h == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), a.token) == 1
}

// operatorOf returns the advisory operator identity from the X-Operator header (see
// the type doc: best-effort until B2 per-identity auth), defaulting to "operator".
func operatorOf(r *http.Request) string {
	if op := strings.TrimSpace(r.Header.Get("X-Operator")); op != "" {
		return op
	}
	return "operator"
}

// engageRequest is the POST /killswitch/engage body. DurationSeconds<=0 => indefinite
// (until revived). Reason is recorded into the tamper-evident audit chain.
type engageRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

// reviveRequest is the POST /killswitch/revive body.
type reviveRequest struct {
	Reason string `json:"reason"`
}

// Handler returns the admin mux. Routes:
//
//	POST /killswitch/engage  {duration_seconds, reason}  -> engage + audit, Status JSON
//	POST /killswitch/revive  {reason}                    -> revive + audit, Status JSON
//	GET  /killswitch                                     -> Status JSON (IR/operator)
//
// Every route requires the bearer token (incl. the GET status — this surface is not
// public). The dashboard tap exposes a READ-ONLY status separately for the IR view.
func (a *killSwitchAdmin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/killswitch/engage", a.handleEngage)
	mux.HandleFunc("/killswitch/revive", a.handleRevive)
	mux.HandleFunc("/killswitch", a.handleStatus)
	return mux
}

func (a *killSwitchAdmin) handleEngage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req engageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	op := operatorOf(r)
	d := time.Duration(req.DurationSeconds) * time.Second
	st, err := a.built.EngageKillSwitch(time.Now(), d, op, req.Reason)
	if err != nil {
		// The kill-switch IS engaged (EngageKillSwitch trips it before auditing); only
		// the audit append failed. Surface it loudly but report the (engaged) status —
		// the safety action took effect, the tamper-evidence has a gap.
		log.Printf("killswitch-admin: ENGAGED by %q but audit append FAILED (tamper-evidence gap): %v", op, err)
		writeKSJSON(w, st)
		return
	}
	log.Printf("killswitch-admin: ENFORCEMENT DISARMED by %q (reason=%q, expires=%s)", op, req.Reason, expiryString(st))
	writeKSJSON(w, st)
}

func (a *killSwitchAdmin) handleRevive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req reviveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil && err.Error() != "EOF" {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	op := operatorOf(r)
	st, err := a.built.ReviveKillSwitch(time.Now(), op, req.Reason)
	if err != nil {
		log.Printf("killswitch-admin: REVIVED by %q but audit append FAILED (tamper-evidence gap): %v", op, err)
		writeKSJSON(w, st)
		return
	}
	log.Printf("killswitch-admin: ENFORCEMENT RESUMED by %q (reason=%q)", op, req.Reason)
	writeKSJSON(w, st)
}

func (a *killSwitchAdmin) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeKSJSON(w, a.built.KillSwitch.Status(time.Now()))
}

func writeKSJSON(w http.ResponseWriter, st killswitch.Status) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func expiryString(st killswitch.Status) string {
	if st.ExpiresAt.IsZero() {
		return "indefinite"
	}
	return st.ExpiresAt.UTC().Format(time.RFC3339)
}

// serveKillSwitchAdmin starts the token-gated admin listener on addr (must be a
// loopback bind — it refuses a non-loopback host so the kill-switch control surface
// is never exposed off-box in B1; B2 adds mTLS for a remote operator). It is started
// in a goroutine by the caller. A token file is REQUIRED (newKillSwitchAdmin errors
// without one) — there is no unauthenticated path.
func serveKillSwitchAdmin(addr, tokenFile string, built *boot.Built) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	admin, err := newKillSwitchAdmin(built, tokenFile)
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("killswitch-admin: listen %s: %w", addr, err)
	}
	log.Printf("staged-range: killswitch admin (token-gated, loopback) on %s", addr)
	srv := &http.Server{Handler: admin.Handler(), ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(lis)
}

// requireLoopback refuses to bind the kill-switch admin to anything but loopback in
// B1 (a kill-switch control surface must not be reachable off-box without mTLS,
// which is B2). It parses the host of addr and verifies it is a loopback IP (or the
// empty host, which it treats as a misconfig and rejects — an empty host binds all
// interfaces).
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("killswitch-admin: -killswitch-admin-addr %q must be host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("killswitch-admin: -killswitch-admin-addr %q binds all interfaces; bind loopback (127.0.0.1 / [::1]) — the B1 kill-switch admin is loopback-only (mTLS for remote is B2)", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("killswitch-admin: -killswitch-admin-addr host %q is not loopback; bind 127.0.0.1 or [::1] (the B1 kill-switch admin is loopback-only — mTLS for a remote operator is B2)", host)
	}
	return nil
}
