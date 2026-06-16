// Package principals is the on-disk + in-memory operator directory for the
// SLICE-B2 PER-IDENTITY TOKEN RBAC kill-switch admin. It is the B2 follow-on to
// B1's single-shared-token gate: instead of ONE secret with an advisory
// X-Operator header, it carries a small directory of named operators, each with
// their OWN bearer token and a role (viewer | operator), so the kill-switch
// admin can resolve a VERIFIED identity from the presented token and gate
// engage/revive on role.
//
// HONEST SCOPE (the claim a CISO must be able to hear): this is per-identity
// TOKEN RBAC + roles. It is NOT mTLS, NOT SSO, NOT a SPIFFE/cert identity — the
// identity guarantee is "possession of THIS operator's bearer token", which is
// strictly stronger than B1's "possession of THE shared token + a self-asserted
// X-Operator header" but is still a bearer secret. mTLS client-cert identity is
// the further B2 step (the audit OperatorAction.SPIFFEID field is reserved for
// it). Each operator is issued their raw token OUT OF BAND; the file stores only
// the lowercase hex sha256 of that token (tokens are HASHED, never raw — a lost
// raw token cannot be recovered from the file, by design; rotation = generate a
// new token, replace its sha256, redistribute out of band).
//
// SECRET HANDLING: the file lives OUTSIDE baseline.db, expected 0o600 like
// /etc/canarysting/anthropic.key. There is NO runtime os.Stat/perm check — the
// codebase's established secret idiom is os.ReadFile + parse + fail-closed (see
// boot.readAuditKey), not a perm assertion; the 0o600 expectation is documented,
// not enforced in code.
//
// FAIL-LOUD, FAIL-CLOSED: a malformed file errors at load (a typo'd token or an
// unknown role must not silently mis-grant or silently drop an operator), and a
// PRESENT-BUT-EMPTY principals list is REFUSED (mirroring readAuditKey refusing
// an empty key file: present-but-empty is a misconfig, NOT "no one authorized").
package principals

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Role is one of the validated RBAC roles. The allowlist is closed: any value
// outside it errors at load (an unknown role must never silently degrade to a
// default — that would be a privilege ambiguity).
type Role string

const (
	// RoleViewer may read kill-switch status only — it CANNOT engage or revive.
	RoleViewer Role = "viewer"
	// RoleOperator may read status AND engage/revive (a superset of viewer).
	RoleOperator Role = "operator"
)

// validRole reports whether role is in the closed allowlist.
func validRole(role Role) bool {
	return role == RoleViewer || role == RoleOperator
}

// Principal is one resolved, in-memory operator identity: the VERIFIED name and
// the role gating what they may do. It is the value a token-sha256 lookup yields;
// the raw token is never held (only its digest is the map key). This is the
// in-memory shape — decoupled from the on-disk diskPrincipal (à la
// stagedlabel.Registry vs registryFile).
type Principal struct {
	// Name is the verified operator identity recorded into the audit chain when
	// this principal authenticates (NOT the advisory X-Operator header — in
	// principals mode X-Operator is ignored, so the audited operator cannot be
	// spoofed by a header).
	Name string
	// Role gates the route: viewer => status only; operator => status + engage +
	// revive.
	Role Role
}

// Set is the resolved in-memory directory: a lookup from a lowercase-hex
// sha256(token) digest to the Principal that token authenticates. Keying by the
// DIGEST (not the raw token) means resolution is a single constant-work hash of
// the presented token followed by one Go map get — no per-entry comparison loop,
// so there is no timing side channel that leaks which/how-many principals exist
// or which entry matched (see the admin's resolve()). The digest is itself the
// index of a high-entropy bearer token, so a plain map lookup is sound — there is
// no secret-dependent branch on a comparison.
type Set struct {
	byTokenSHA256 map[string]Principal // key: lowercase 64-hex sha256(rawToken)
}

// Lookup returns the Principal for the given lowercase-hex sha256(token) digest.
// The bool is false when no principal carries that token digest (an unknown
// token => not resolved, which the admin maps to 401). The caller computes the
// digest from the presented bearer token; Lookup does NOT hash — it is the pure
// map get so the hashing happens exactly once at the call site.
func (s *Set) Lookup(tokenSHA256Hex string) (Principal, bool) {
	p, ok := s.byTokenSHA256[tokenSHA256Hex]
	return p, ok
}

// Len returns the number of principals (for boot logging — the COUNT only, never
// any token or name is logged at the secret-bearing boundary).
func (s *Set) Len() int { return len(s.byTokenSHA256) }

// NewSingleTokenSet builds a Set containing exactly ONE synthetic operator-role
// principal whose lookup key is the sha256 digest of rawToken. It is the LEGACY
// single-shared-token bridge: the kill-switch admin's modeSingle holds the one
// shared token as this single-entry Set so resolution is the SAME hash-then-map-get
// as per-identity mode (no separate constant-time-compare code path) and no raw
// token is retained in memory beyond computing its digest here. The principal's Name
// is a placeholder ("operator") that the admin overrides with the advisory
// X-Operator header in modeSingle; the Role is RoleOperator (legacy single-token
// callers have full engage/revive). rawToken MUST be the already-trimmed, non-empty
// shared token (the caller — newKillSwitchAdmin — enforces non-empty).
func NewSingleTokenSet(rawToken string) *Set {
	sum := sha256.Sum256([]byte(rawToken))
	key := hex.EncodeToString(sum[:])
	return &Set{byTokenSHA256: map[string]Principal{
		key: {Name: "operator", Role: RoleOperator},
	}}
}

// diskPrincipal is the on-disk JSON shape of one principal (stdlib-only JSON, no
// YAML dependency — mirroring identity.Entry and stagedlabel.registryFile). It is
// decoupled from the in-memory Principal: the raw on-disk form carries the hex
// token digest, which becomes the map KEY (not a field) in the in-memory Set.
type diskPrincipal struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	Role        string `json:"role"`
}

// principalsFile is the on-disk JSON document: {"principals":[...]}.
type principalsFile struct {
	Principals []diskPrincipal `json:"principals"`
}

// LoadPrincipals parses a JSON principals document and validates it loudly. It
// returns a resolved in-memory Set keyed by token_sha256. Validation (all
// fail-loud, index/name-qualified):
//
//   - the principals list must be NON-EMPTY (present-but-empty is a refused
//     misconfig — fail-closed, mirroring boot.readAuditKey refusing an empty key
//     file; an empty list is NOT "no one authorized", it is "you forgot to fill
//     this in", and an unauthenticated/never-resolvable kill-switch is exactly
//     what we refuse);
//   - each name must be non-empty and UNIQUE (a duplicate name is an operator
//     directory typo);
//   - each token_sha256 must be EXACTLY 64 lowercase hex chars (the sha256 of the
//     raw bearer token; a non-hex / wrong-length / uppercase value is a typo that
//     must not silently fail to ever match);
//   - no two principals may share a token_sha256 (a duplicate digest means the
//     same raw token was issued to two operators — it MUST be caught here, not
//     silently coalesced into one principal, so an accidental shared token is a
//     boot failure not a silent identity collision);
//   - each role must be in the closed allowlist (viewer | operator); an unknown
//     role errors (never silently degrades to a default).
func LoadPrincipals(r io.Reader) (*Set, error) {
	var f principalsFile
	dec := json.NewDecoder(r)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("killswitch/principals: parse principals file: %w", err)
	}

	if len(f.Principals) == 0 {
		// Present-but-empty is a misconfig, NOT "no one authorized". Refuse, exactly
		// as readAuditKey refuses an empty key file — an empty directory would be an
		// unauthenticated kill-switch by another name.
		return nil, fmt.Errorf("killswitch/principals: principals list is EMPTY; refusing to start an unauthenticated kill-switch (a present-but-empty directory is a misconfig, not 'no one authorized')")
	}

	byToken := make(map[string]Principal, len(f.Principals))
	seenName := make(map[string]struct{}, len(f.Principals))

	for i, dp := range f.Principals {
		name := strings.TrimSpace(dp.Name)
		if name == "" {
			return nil, fmt.Errorf("killswitch/principals: principal %d: empty name", i)
		}
		if _, dup := seenName[name]; dup {
			return nil, fmt.Errorf("killswitch/principals: principal %d (%q): duplicate name", i, name)
		}

		if !isLowerHex64(dp.TokenSHA256) {
			return nil, fmt.Errorf("killswitch/principals: principal %d (%q): token_sha256 must be exactly 64 lowercase hex chars (the sha256 of the raw bearer token), got %d-char %q", i, name, len(dp.TokenSHA256), dp.TokenSHA256)
		}

		role := Role(dp.Role)
		if !validRole(role) {
			return nil, fmt.Errorf("killswitch/principals: principal %d (%q): unknown role %q (want %q or %q)", i, name, dp.Role, RoleViewer, RoleOperator)
		}

		if existing, dup := byToken[dp.TokenSHA256]; dup {
			// Two principals sharing a token digest => the same raw token was issued to
			// both. Catch it loudly at boot rather than silently coalescing into one.
			return nil, fmt.Errorf("killswitch/principals: principal %d (%q): duplicate token_sha256 also used by principal %q (the same raw token issued to two operators)", i, name, existing.Name)
		}

		seenName[name] = struct{}{}
		byToken[dp.TokenSHA256] = Principal{Name: name, Role: role}
	}

	return &Set{byTokenSHA256: byToken}, nil
}

// LoadPrincipalsFile loads + validates a principals directory from a JSON file
// path. The file is expected at e.g. /etc/canarysting/killswitch-principals.json,
// mode 0o600, held OUTSIDE baseline.db (like /etc/canarysting/anthropic.key). No
// perm check is performed (the codebase's secret idiom is read + parse +
// fail-closed; the 0o600 expectation is documented, not enforced).
func LoadPrincipalsFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("killswitch/principals: open principals file %q: %w", path, err)
	}
	defer f.Close()
	return LoadPrincipals(f)
}

// isLowerHex64 reports whether s is exactly 64 lowercase hex characters — the
// canonical form of a sha256 digest as lowercase hex. We require lowercase (not
// any-case) so the on-disk form is canonical and a digest produced by
// `sha256sum | cut` (lowercase) matches; an uppercase digest is rejected as a
// typo rather than silently accepted, since the in-memory lookup key (from
// hex.EncodeToString) is always lowercase and an uppercase entry would never
// match a presented token.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
