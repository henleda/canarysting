package transport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Confirmation is the D6-3 cross-scope ingest message: a contributing deployment tells
// the central aggregator "I (this opaque scope TOKEN) independently confirmed this coarse
// pattern" on a LOCAL Tier-3 jail. It is the ONE new cross-scope wire D6-3 adds; the
// aggregator→consumer wire downstream is the already-signed D6 cleared-pattern spool.
//
// Scope is an OPAQUE, random, aggregator-issued token (D63b) — NEVER the raw ScopeKey,
// never a hash of it, never a shared-salt bucket. It rides as envelope metadata OUTSIDE
// the cleared payload (the `scope`/`token` substrings are on the egress name denylist, so
// an identity inside the field walk would be hard-denied — the token must stay outside it).
// Pattern is exactly the 7-field already-cleared coarse shape (what already crosses A→B);
// the aggregator re-validates it through the UNCHANGED network.ParseSharedPattern.
type Confirmation struct {
	Scope   string          `json:"scope"`   // opaque enrolled token; NOT a customer identifier
	Pattern json.RawMessage `json:"pattern"` // the 7 coarse cleared fields; re-validated on ingest
}

// ConfirmSpool is the scope→aggregator confirmation channel: an append-only NDJSON file,
// distinct from the cleared-pattern Spool (D63g). Same file-trust model as Spool (D6f) —
// a file, not an attacker-reachable listener; access-control/rate-limiting/TLS for an
// untrusted contributor is D7. A write into the k-count is a CONTRIBUTION, gated upstream
// by the deployment's Contribute opt-in.
type ConfirmSpool struct{ path string }

// NewConfirmSpool returns a confirmation spool backed by path (created on first send).
func NewConfirmSpool(path string) *ConfirmSpool { return &ConfirmSpool{path: path} }

// SendConfirmation (producer half, on a contributing deployment) appends one confirmation
// as an NDJSON line: the opaque token + the coarse cleared pattern bytes. clearedPattern
// must be the 7-field coarse JSON (json.Marshal of the producer's ExportForm). It does NOT
// validate the pattern here — the aggregator distrusts the wire and re-validates on ingest
// (EGRESS §1.3 two-walk distrust).
func (s *ConfirmSpool) SendConfirmation(scopeToken string, clearedPattern []byte) error {
	if scopeToken == "" {
		return fmt.Errorf("transport: empty scope token")
	}
	if bytes.ContainsRune(clearedPattern, '\n') {
		return fmt.Errorf("transport: pattern contains a newline (would break NDJSON framing)")
	}
	line, err := json.Marshal(Confirmation{Scope: scopeToken, Pattern: json.RawMessage(clearedPattern)})
	if err != nil {
		return fmt.Errorf("transport: marshal confirmation: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("transport: open confirm spool: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("transport: write confirmation: %w", err)
	}
	return nil
}

// ReceiveConfirmations (consumer half, at the aggregator) reads every spooled confirmation,
// fail-closed PER LINE: a malformed line is skipped (folded into the returned error) so one
// bad line never drops the rest; an over-long (>1 MiB) line terminates the scan fail-closed
// (drops more, never misparses); a missing file is empty + no error. The caller still
// distrusts each Pattern (re-validates via network.ParseSharedPattern) and the Scope (must
// be an enrolled token) before recording.
func (s *ConfirmSpool) ReceiveConfirmations() ([]Confirmation, error) {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("transport: open confirm spool: %w", err)
	}
	defer f.Close()

	var out []Confirmation
	var errs []error
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var c Confirmation
		if err := json.Unmarshal(line, &c); err != nil {
			errs = append(errs, err)
			continue
		}
		if c.Scope == "" || len(c.Pattern) == 0 {
			errs = append(errs, fmt.Errorf("transport: confirmation missing scope or pattern"))
			continue
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("transport: scan: %w", err))
	}
	return out, errors.Join(errs...)
}
