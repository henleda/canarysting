package network

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
)

// Ledger is the network package's OWN trusted source of "seen in >= k distinct scopes"
// (D6-2) — the single thing that makes the k-anonymity gate's count REAL instead of
// producer-asserted (the closed known-gap; EGRESS_FILTER_DESIGN D6/risk-5). It is the
// SANCTIONED cross-scope structure rule 5 permits for already-anonymized egress patterns:
// it stores ONLY a coarse-pattern -> set-of-distinct-scope-buckets map, NEVER a Profile,
// raw events, baselines, scope state, decoy contents, IPs, cookies, or any behavioral
// field beyond the coarse cleared tuple. The only value ever read out is a set's
// CARDINALITY. Scope identity is reduced to an opaque HMAC bucket, so even a dumped
// ledger is a histogram (coarse pattern -> opaque bucket set) that answers only "how
// many," never "which deployment."
//
// Keying (D6c): the ledger keys on the COARSE CLEARED TUPLE (coarseKey), the exact
// 7-field unit that crosses the wire — NEVER the raw BehavioralHash (which is reversible
// over the small vocab and re-encodes every dropped field). So "k contributing scopes"
// refers to exactly the cell that crosses.
//
// Persistence (D6i): MVP is in-memory. Losing the ledger only LOWERS counts => denies
// more => fails CLOSED. A bbolt fast-follow must (a) live in its own store, (b) persist
// only coarse-tuple -> bucket-set, and (c) NEVER co-persist the salt with the buckets.
type Ledger struct {
	mu   sync.RWMutex
	seen map[coarseKey]map[scopeBucket]struct{}
	salt []byte // process-local; never crosses, never persisted as plaintext
	// enrolled is non-nil ONLY for a central-aggregator ledger (D6-3 / D63e): the
	// cross-scope ingest counts a remote scope's confirmation toward k ONLY if its token
	// passes this check. nil for a normal per-deployment ledger (which records only its
	// OWN local jails via RecordForm — no Sybil concern within one deployment). Making the
	// allowlist a CONSTRUCTOR dependency (not a caller if-check) is what keeps a forged /
	// un-enrolled token from inflating k.
	enrolled func(token string) bool
}

// scopeBucket is an HMAC(salt, ScopeKey) truncation: distinct iff the scopes are
// distinct, but not invertible to a ScopeKey without the process-local salt. An array
// (not a slice) so it is comparable and usable as a map key.
type scopeBucket [16]byte

// coarseKey is the canonical, stable encoding of the coarse cleared fields — the SAME
// tuple that crosses the wire (D6c). It is deliberately NOT the BehavioralHash: the hash
// never leaves a deployment. Field set mirrors profile.ExportForm exactly.
type coarseKey struct {
	ReachedContain  bool
	EngagedVelocity bool
	EngagedPoison   bool
	DisengagedEarly bool
	HeldBand        int
	CadenceBand     int
	PoisonClass     string
}

// ClearContext carries the per-crossing inputs ClearWithLedger needs beyond the
// candidate itself. The lookup key is derived INSIDE the chokepoint from exactly what
// cleared (so it cannot disagree with the wire unit), so only the Ledger is supplied.
type ClearContext struct {
	Ledger *Ledger
}

// NewLedger constructs an empty in-memory ledger with a fresh process-local salt. The
// salt makes scope buckets unlinkable across processes and is never exported/persisted
// in plaintext (D6i). It errors only if the system CSPRNG is unavailable.
func NewLedger() (*Ledger, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("network: ledger salt: %w", err)
	}
	return &Ledger{seen: map[coarseKey]map[scopeBucket]struct{}{}, salt: salt}, nil
}

// NewAggregatorLedger builds the D6-3 CENTRAL AGGREGATOR's ledger (D63a): the one ledger
// the N contributing deployments file-spool confirmations to. It counts a remote scope's
// confirmation toward k ONLY if its token passes `enrolled` (D63e — the allowlist is a
// CONSTRUCTOR dependency, so a forged/un-enrolled token can NEVER fabricate distinct
// scopes to force a sub-k pattern across). enrolled must be non-nil. The k it produces is
// "k distinct ENROLLED tokens" = "k deployments the operator VOUCHES for" (D63f —
// operator-trusted, NOT Sybil-resistant; untrusted-contributor auth is D7).
func NewAggregatorLedger(enrolled func(token string) bool) (*Ledger, error) {
	if enrolled == nil {
		return nil, fmt.Errorf("network: aggregator ledger requires an enrollment check (D63e)")
	}
	l, err := NewLedger()
	if err != nil {
		return nil, err
	}
	l.enrolled = enrolled
	return l, nil
}

// IngestConfirmation records a remote scope's confirmation of a coarse pattern into THIS
// aggregator ledger, counting it toward k ONLY if `token` is enrolled (D63e). It is the
// ONLY cross-scope write path; the local-jail RecordForm path is unchanged. The token is
// bucketed under the aggregator's own salt (so distinct enrolled tokens => distinct
// buckets => the count), and the pattern is the already-validated coarse shape. Returns
// the new distinct-token count for the cell, or an error if this is not an aggregator
// ledger or the token is not enrolled (the caller logs + skips — never silently counts).
func (l *Ledger) IngestConfirmation(token string, sp SharedPattern) (int, error) {
	if l == nil {
		return 0, fmt.Errorf("network: nil ledger")
	}
	if l.enrolled == nil {
		return 0, fmt.Errorf("network: not an aggregator ledger (use NewAggregatorLedger)")
	}
	if token == "" || !l.enrolled(token) {
		return 0, fmt.Errorf("network: scope token not enrolled")
	}
	return l.RecordForm(token, ExportFormFromShared(sp))
}

// bucket reduces a ScopeKey to its opaque, salted bucket. Pure given the salt.
func (l *Ledger) bucket(scope string) scopeBucket {
	mac := hmac.New(sha256.New, l.salt)
	_, _ = mac.Write([]byte(scope))
	var b scopeBucket
	copy(b[:], mac.Sum(nil))
	return b
}

// RecordForm records that `scope` independently exhibited the coarse pattern of
// `export` (the producer's ExportForm). A scope "exhibits" a pattern when it CONFIRMS
// that behavior as malicious in its own deployment (a local Tier-3 jail; the caller
// gates on the Contribute opt-in — D6e). Idempotent per (scope, pattern): re-exhibition
// by the same scope does NOT inflate the count (the whole k-anonymity guarantee).
// Returns the new distinct-scope count (observability only) or an error if the export's
// coarse form is not derivable (i.e. it would not clear anyway).
func (l *Ledger) RecordForm(scope string, export any) (int, error) {
	if l == nil {
		// A nil ledger means NewLedger's CSPRNG failed and a caller dropped the error.
		// Fail closed (record nothing) rather than nil-panic on the jail path.
		return 0, fmt.Errorf("network: nil ledger (construction failed)")
	}
	key, err := coarseKeyFromExport(export)
	if err != nil {
		return 0, err
	}
	b := l.bucket(scope)
	l.mu.Lock()
	defer l.mu.Unlock()
	set := l.seen[key]
	if set == nil {
		set = map[scopeBucket]struct{}{}
		l.seen[key] = set
	}
	set[b] = struct{}{}
	return len(set), nil
}

// Patterns reports how many DISTINCT coarse patterns this deployment has recorded — a
// non-identifying contribution-status metric (e.g. "this deployment has contributed N
// patterns to the network"). It exposes only a cardinality, never a pattern or a scope.
func (l *Ledger) Patterns() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.seen)
}

// distinctScopes is the count ClearWithLedger reads. UNEXPORTED on purpose: only the
// chokepoint (same package) may consult it, so the count's provenance stays inside the
// package. Returns 0 for an unknown key (fail-closed: unknown => sub-k => deny).
func (l *Ledger) distinctScopes(key coarseKey) int {
	if l == nil {
		return 0 // fail closed: no ledger => sub-k => deny
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.seen[key])
}

// coarseKeyFromExport coarse-validates an export form (the same field walk Clear runs,
// minus the opt-in/k checks) and projects it onto the coarseKey. Going through
// clearFields guarantees the Record path and the ClearWithLedger path derive the
// IDENTICAL key for the same pattern (both via clearFields -> payload ->
// coarseKeyFromPayload).
func coarseKeyFromExport(export any) (coarseKey, error) {
	payload, err := clearFields(export)
	if err != nil {
		return coarseKey{}, err
	}
	return coarseKeyFromPayload(payload), nil
}

// coarseKeyFromPayload reads the coarse tuple out of a cleared payload map. Payload
// scalars are the value-copied kinds copyScalar emits (bool, int64, string), so the
// numeric reads tolerate int64/int/float64 defensively.
func coarseKeyFromPayload(p map[string]any) coarseKey {
	b := func(k string) bool { v, _ := p[k].(bool); return v }
	i := func(k string) int {
		switch v := p[k].(type) {
		case int64:
			return int(v)
		case int:
			return v
		case float64:
			return int(v)
		case uint64:
			return int(v)
		}
		return 0
	}
	s := func(k string) string { v, _ := p[k].(string); return v }
	return coarseKey{
		ReachedContain:  b("ReachedContain"),
		EngagedVelocity: b("EngagedVelocity"),
		EngagedPoison:   b("EngagedPoison"),
		DisengagedEarly: b("DisengagedEarly"),
		HeldBand:        i("HeldBand"),
		CadenceBand:     i("CadenceBand"),
		PoisonClass:     s("PoisonClass"),
	}
}
