// Package transport is the D6 cross-deployment transport seam (D6f): the thinnest honest
// way to move anonymized patterns from deployment A to B. It is a FILE/spool drop, not a
// network listener — a listener adds inbound attack surface (access-control, rate
// limiting) that belongs to D7, not D6, and a file keeps the rule-9 review focused on
// "move opaque bytes A->B." The spooled bytes are cat-inspectable, which IS the
// privacy-proof demo beat (show exactly what crossed).
//
// Send accepts ONLY a *network.Cleared (Go-type-enforced: the caller must have passed
// the egress chokepoint) and emits ONLY its Marshal() bytes — which re-runs the carrier
// re-validation AND the ledger-verified gate, so a form-only carrier cannot be sent.
// Receive validates each line back into a network.SharedPattern (the inbound mirror of
// Clear, fail-closed) — never into a *Cleared, so the receive path cannot masquerade as
// an egress path.
package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/canarysting/canarysting/internal/intelligence/network"
)

// Spool is an append-only NDJSON file of cleared patterns.
type Spool struct{ path string }

// NewSpool returns a spool backed by path (created on first Send).
func NewSpool(path string) *Spool { return &Spool{path: path} }

// Send appends a cleared pattern's wire bytes as one NDJSON line. It is the producer
// half of the boundary; the bytes are exactly what ParseSharedPattern re-validates on
// the far side.
func (s *Spool) Send(c *network.Cleared) error {
	if c == nil {
		return fmt.Errorf("transport: nil cleared")
	}
	b, err := c.Marshal() // re-validates scalars + the ledger-verified gate
	if err != nil {
		return fmt.Errorf("transport: marshal: %w", err)
	}
	if bytes.ContainsRune(b, '\n') {
		return fmt.Errorf("transport: marshalled pattern contains a newline (would break NDJSON framing)")
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("transport: open spool: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("transport: write: %w", err)
	}
	return nil
}

// Receive reads every spooled line and validates each into a SharedPattern, fail-closed
// PER LINE: a malformed (but in-bounds) line is skipped (its error folded into the
// returned error) so one bad line never drops the rest. A missing spool file is empty +
// no error. The returned error is non-nil iff at least one line failed; the good patterns
// are still returned alongside it (the caller logs the error and consumes the good ones).
//
// One exception, fail-closed: a line exceeding the 1 MiB scan cap TERMINATES the scan
// (bufio.Scanner returns "token too long"), so lines AFTER an over-long one are NOT
// consumed. This drops MORE context (never fewer; the giant line never reaches
// ParseSharedPattern, so it cannot truncate-and-misparse) — acceptable for a local,
// operator-trusted file spool. NOTE (trust boundary): the spool path is operator config,
// opened without symlink/traversal hardening; a future networked D7 transport is an
// attacker-reachable surface and MUST add access-control + rate-limiting + resync past an
// over-long frame rather than inherit this file-trust model.
func (s *Spool) Receive() ([]network.SharedPattern, error) {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("transport: open spool: %w", err)
	}
	defer f.Close()

	var out []network.SharedPattern
	var errs []error
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		sp, err := network.ParseSharedPattern(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, sp)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("transport: scan: %w", err))
	}
	return out, errors.Join(errs...)
}
