package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/canarysting/canarysting/internal/sting/killswitch/principals"
)

// killSwitchAdmin is the token-gated, LOOPBACK-bound LOCAL control surface for the
// deployment-wide enforcement DISARM. It is intentionally tiny and out of band from
// the engine's gRPC contract (NO proto/wire change): a loopback-bound HTTP listener,
// OFF by default, that an operator (or an IR runbook) hits to halt / resume /
// inspect enforcement.
//
// AUTH — TWO MODES (the admin carries a mode enum so resolve() can branch):
//
//   - modeSingle (LEGACY, B1, back-compat): a SHARED OPERATOR SECRET (one bearer
//     token) read from -killswitch-token-file, held OUTSIDE baseline.db (mirroring
//     -audit-hmac-key). There is one secret, not a user directory. The "operator"
//     recorded in the audit trail is taken from the X-Operator header (free-form,
//     ADVISORY) defaulting to "operator"; the AUTHORITATIVE access control is
//     possession of the token. Every resolved request is treated as role=operator
//     (full engage/revive), preserving B1 behavior BYTE-FOR-BYTE — this is the mode
//     the live box runs.
//
//   - modePrincipals (PER-IDENTITY TOKEN RBAC, B2): a small operator directory from
//     -killswitch-principals-file (token_sha256 -> {name, role}). The presented
//     bearer token is hashed and looked up; the resolved principal's VERIFIED name
//     is recorded (X-Operator is IGNORED — the audited operator is not spoofable via
//     a header), and the principal's ROLE gates the route (viewer => status only;
//     operator => status + engage + revive). HONEST SCOPE: this is per-identity
//     TOKEN RBAC + roles, NOT mTLS/SSO — the identity guarantee is possession of
//     THIS operator's bearer token. mTLS client-cert identity is the further step.
//
// PRECEDENCE: principals-file > token-file > fail-closed-if-neither. If both flags
// are set, principals-file WINS and the single token is ignored (newKillSwitchAdmin
// logs a one-line notice so the operator is not surprised).
//
// FAIL-CLOSED: there is NEVER an unauthenticated kill-switch. With neither flag the
// listener REFUSES to start; an empty token file or an empty/malformed principals
// file refuses to start. Any request whose token does not resolve gets 401 and
// changes nothing. (A 401 is NOT audited — an unauthenticated probe is not an
// operator action; auditing every drive-by would be a log-spam DoS surface.) A 403
// — a VALID principal whose role lacks the required capability (e.g. a viewer
// hitting engage) — is LIKEWISE not audited: only a SUCCESSFUL, authenticated
// MUTATING action is audited, via boot.Built. The 403-vs-401 split is deliberate: a
// resolved-but-insufficient identity is FORBIDDEN, not unauthenticated, and keeping
// them distinct is the role-denied observability signal (do not "fix" it back to a
// blanket 401 — that loses the distinction, and on a loopback-only surface the small
// "this token is a valid principal" disclosure is acceptable).
type killSwitchAdmin struct {
	built *boot.Built
	mode  authMode

	// principals is the resolved per-identity directory (token_sha256 -> {name,
	// role}). Used in BOTH modes: in modeSingle it holds exactly ONE synthetic
	// operator-role principal whose token digest is the sha256 of the single shared
	// token, so resolve() is identical in both modes (hash-then-map-get) and there is
	// no raw token held in memory in either mode.
	principals *principals.Set
}

// authMode selects how the admin resolves identity.
type authMode int

const (
	modeSingle     authMode = iota // legacy single shared token; X-Operator advisory; role always operator
	modePrincipals                 // per-identity token RBAC; verified name; role gates the route
)

// syntheticOperator is the verified-operator name recorded in legacy single-token
// mode when no X-Operator header is supplied — preserving B1's operatorOf default.
const syntheticOperator = "operator"

// newKillSwitchAdmin builds the admin handler, applying precedence:
// principals-file > token-file > fail-closed-if-neither. It loads the chosen source
// and REFUSES (errors) on a missing/unreadable/empty/malformed source — fail-closed:
// there is never an unauthenticated kill-switch. When BOTH paths are non-empty it
// logs a one-line notice that the principals file takes precedence (so an operator
// who left -killswitch-token-file set is not surprised the single token is ignored).
func newKillSwitchAdmin(built *boot.Built, tokenFile, principalsFile string) (*killSwitchAdmin, error) {
	switch {
	case principalsFile != "":
		if tokenFile != "" {
			// Both set: principals wins. NB: never log the token or any digest — only
			// the precedence decision.
			log.Printf("killswitch-admin: both -killswitch-principals-file and -killswitch-token-file set; per-identity principals file takes PRECEDENCE (the single shared token is IGNORED)")
		}
		set, err := principals.LoadPrincipalsFile(principalsFile)
		if err != nil {
			return nil, fmt.Errorf("killswitch-admin: %w", err)
		}
		return &killSwitchAdmin{built: built, mode: modePrincipals, principals: set}, nil

	case tokenFile != "":
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("killswitch-admin: read token file %q: %w", tokenFile, err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return nil, fmt.Errorf("killswitch-admin: token file %q is empty; refusing to start an unauthenticated kill-switch", tokenFile)
		}
		// Hold the single token as ONE synthetic operator-role principal keyed by its
		// sha256 digest, so resolve() is the SAME hash-then-map-get in both modes and
		// no raw token is held in memory. The synthetic principal's name is a
		// placeholder that operatorOf overrides with the advisory X-Operator header.
		set := principals.NewSingleTokenSet(tok)
		return &killSwitchAdmin{built: built, mode: modeSingle, principals: set}, nil

	default:
		return nil, fmt.Errorf("killswitch-admin: one of -killswitch-principals-file or -killswitch-token-file is REQUIRED to enable the admin endpoint (no unauthenticated kill-switch)")
	}
}

// resolve resolves the presented bearer token to a principal WITHOUT a per-token
// compare loop (which would leak principal count / which entry matched via timing).
// It (1) reads the Authorization header and strips an exact "Bearer " prefix (the
// same presentation canaryctl sends), (2) treats an empty token as not-resolved (no
// lookup), (3) hashes the token ONCE with sha256, and (4) does ONE Go map get keyed
// by the lowercase-hex digest. The sha256 + map-get cost is independent of the
// number of principals and of which entry matches — no per-entry timing side
// channel, no early-break leak. (The lookup key is a sha256 digest of a high-entropy
// bearer token, so a plain map lookup is sound: the digest IS the index, with no
// secret-dependent branch on a comparison.) Returns the resolved principal and true,
// or the zero principal and false (=> 401 unknown token).
func (a *killSwitchAdmin) resolve(r *http.Request) (principals.Principal, bool) {
	h := r.Header.Get("Authorization")
	h = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if h == "" {
		return principals.Principal{}, false
	}
	sum := sha256.Sum256([]byte(h))
	key := hex.EncodeToString(sum[:])
	return a.principals.Lookup(key)
}

// operatorOf returns the operator name to RECORD for a resolved principal. In
// modePrincipals it is the VERIFIED principal.Name — the X-Operator header is
// IGNORED, so the audited operator cannot be spoofed by a header. In modeSingle it
// is the advisory X-Operator header (back-compat with B1), defaulting to "operator".
func (a *killSwitchAdmin) operatorOf(r *http.Request, p principals.Principal) string {
	if a.mode == modePrincipals {
		return p.Name
	}
	if op := strings.TrimSpace(r.Header.Get("X-Operator")); op != "" {
		return op
	}
	return syntheticOperator
}

// identityFor builds the boot.OperatorIdentity threaded into a mutating toggle: the
// recorded operator name (verified or advisory per operatorOf), the role (always
// "operator" for a mutating action — a viewer is 403'd before this is called), and
// the auth_via tag ("principal" when verified, "single-token" in legacy mode).
func (a *killSwitchAdmin) identityFor(r *http.Request, p principals.Principal) boot.OperatorIdentity {
	authVia := "single-token"
	if a.mode == modePrincipals {
		authVia = "principal"
	}
	return boot.OperatorIdentity{
		Name:    a.operatorOf(r, p),
		Role:    string(principals.RoleOperator),
		AuthVia: authVia,
	}
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
	// engage is a MUTATING action: require a resolved principal (401 if unknown token)
	// whose role is operator (403 if a VALID principal lacks the operator role — a
	// resolved-but-insufficient identity is FORBIDDEN, not unauthenticated). Neither
	// the 401 nor the 403 is audited; only the successful engage below is.
	p, ok := a.resolve(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.Role != principals.RoleOperator {
		http.Error(w, "forbidden: role lacks engage capability", http.StatusForbidden)
		return
	}
	var req engageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := a.identityFor(r, p)
	d := time.Duration(req.DurationSeconds) * time.Second
	st, err := a.built.EngageKillSwitch(time.Now(), d, id, req.Reason)
	if err != nil {
		// The kill-switch IS engaged (EngageKillSwitch trips it before auditing); only
		// the audit append failed. Surface it loudly but report the (engaged) status —
		// the safety action took effect, the tamper-evidence has a gap.
		log.Printf("killswitch-admin: ENGAGED by %q but audit append FAILED (tamper-evidence gap): %v", id.Name, err)
		writeKSJSON(w, st)
		return
	}
	log.Printf("killswitch-admin: ENFORCEMENT DISARMED by %q (auth_via=%s, reason=%q, expires=%s)", id.Name, id.AuthVia, req.Reason, expiryString(st))
	writeKSJSON(w, st)
}

func (a *killSwitchAdmin) handleRevive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// revive is a MUTATING action: same gate as engage (operator role required;
	// 401 unknown token, 403 valid-but-not-operator).
	p, ok := a.resolve(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.Role != principals.RoleOperator {
		http.Error(w, "forbidden: role lacks revive capability", http.StatusForbidden)
		return
	}
	var req reviveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil && err.Error() != "EOF" {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := a.identityFor(r, p)
	st, err := a.built.ReviveKillSwitch(time.Now(), id, req.Reason)
	if err != nil {
		log.Printf("killswitch-admin: REVIVED by %q but audit append FAILED (tamper-evidence gap): %v", id.Name, err)
		writeKSJSON(w, st)
		return
	}
	log.Printf("killswitch-admin: ENFORCEMENT RESUMED by %q (auth_via=%s, reason=%q)", id.Name, id.AuthVia, req.Reason)
	writeKSJSON(w, st)
}

func (a *killSwitchAdmin) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// status is READ-ONLY: require ANY resolved principal (viewer or operator). 401 if
	// the token does not resolve. A viewer is fully allowed here (status is exactly
	// what a viewer may do). No role check beyond "resolved".
	if _, ok := a.resolve(r); !ok {
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
// is never exposed off-box; mTLS for a remote operator is the further step). It is
// started in a goroutine by the caller. Either a token file or a principals file is
// REQUIRED (newKillSwitchAdmin errors with neither, applying precedence
// principals-file > token-file) — there is no unauthenticated path.
func serveKillSwitchAdmin(addr, tokenFile, principalsFile string, built *boot.Built) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	admin, err := newKillSwitchAdmin(built, tokenFile, principalsFile)
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("killswitch-admin: listen %s: %w", addr, err)
	}
	modeStr := "single-token"
	if admin.mode == modePrincipals {
		modeStr = fmt.Sprintf("per-identity RBAC (%d principals)", admin.principals.Len())
	}
	log.Printf("staged-range: killswitch admin (%s, loopback) on %s", modeStr, addr)
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
