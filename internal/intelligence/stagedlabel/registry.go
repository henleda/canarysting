// Package stagedlabel is a STAGING-ONLY mechanism that turns the known ground
// truth of a staged range into real analyst-equivalent feedback labels, so a
// scope can legitimately reach calibrated mode during the M7 learning window
// without any human in the loop and without any fabricated data.
//
// The honesty argument (the one a CISO must be able to hear): in a staged range
// WE control who the attacker is and who the legitimate generators are — we
// declared it. So labeling a canary-touch verdict from the declared attacker as
// "malicious" is not a guess or a placeholder; it is a confirmed fact about an
// environment we built. The same is true of a benign generator that happens to
// brush a decoy. These are real confirmations of real ground truth, fed through
// the SAME single feedback seam (internal/engine/feedback) a human analyst uses.
//
// PRODUCTION SAFETY (defense in depth): (1) the Labeler is disabled by default
// and is a no-op unless explicitly enabled; (2) an undeclared source identity
// yields NO label (fail-safe) — so even if enabled in a real deployment with no
// registry, nothing is ever labeled; (3) this package is reachable ONLY from the
// dedicated cmd/staged-range binary, never from the production cmd/engine
// (enforced by an import-graph guard), so a production build cannot construct a
// Labeler at all; (4) a label is only ever produced in response to a REAL canary-
// touch verdict — there is no code path that fabricates a decision (rule 8).
package stagedlabel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/canarysting/canarysting/internal/contract"
)

// Disposition is the declared ground-truth role of a source identity.
type Disposition int

const (
	DispUnknown  Disposition = iota // not declared → never labeled (fail-safe)
	DispLegit                       // a declared legitimate generator
	DispAttacker                    // the declared attacker
)

// Registry is the per-scope staged ground truth: which source addresses are
// legitimate and which are the attacker. It is the SINGLE source of truth from
// which both the Labeler (what to confirm) and the baseline exclusion (whom to
// keep out of the baseline-of-normal) derive. Scope-isolated (rule 5).
type Registry struct {
	scopes map[contract.ScopeKey]map[netip.Addr]Disposition
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{scopes: map[contract.ScopeKey]map[netip.Addr]Disposition{}}
}

// Declare records addr's disposition within scope.
func (r *Registry) Declare(scope contract.ScopeKey, addr netip.Addr, disp Disposition) {
	m := r.scopes[scope]
	if m == nil {
		m = map[netip.Addr]Disposition{}
		r.scopes[scope] = m
	}
	m[addr.Unmap()] = disp
}

// Lookup returns the declared disposition of addr in scope, DispUnknown if the
// address (or scope) was never declared.
func (r *Registry) Lookup(scope contract.ScopeKey, addr netip.Addr) Disposition {
	return r.scopes[scope][addr.Unmap()]
}

// AttackerAddrs returns the declared attacker addresses in scope — the set the
// composition root marks into the baseline exclusion so the attacker's observed
// flows never enter the baseline-of-normal.
func (r *Registry) AttackerAddrs(scope contract.ScopeKey) []netip.Addr {
	var out []netip.Addr
	for a, d := range r.scopes[scope] {
		if d == DispAttacker {
			out = append(out, a)
		}
	}
	return out
}

// Scopes returns the declared scope keys.
func (r *Registry) Scopes() []contract.ScopeKey {
	out := make([]contract.ScopeKey, 0, len(r.scopes))
	for s := range r.scopes {
		out = append(out, s)
	}
	return out
}

// registryFile is the on-disk JSON shape (stdlib only — no YAML dependency).
type registryFile struct {
	Scopes []struct {
		Scope    string   `json:"scope"`
		Legit    []string `json:"legit"`
		Attacker []string `json:"attacker"`
	} `json:"scopes"`
}

// LoadRegistry parses a JSON ground-truth registry. Every address must parse, or
// it errors loudly — a staged range must not silently mis-declare identities.
func LoadRegistry(r io.Reader) (*Registry, error) {
	var f registryFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("stagedlabel: parse registry: %w", err)
	}
	reg := NewRegistry()
	for _, s := range f.Scopes {
		if s.Scope == "" {
			return nil, fmt.Errorf("stagedlabel: registry entry with empty scope")
		}
		scope := contract.ScopeKey(s.Scope)
		for _, ipStr := range s.Legit {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("stagedlabel: bad legit address %q in scope %q: %w", ipStr, s.Scope, err)
			}
			reg.Declare(scope, addr, DispLegit)
		}
		for _, ipStr := range s.Attacker {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("stagedlabel: bad attacker address %q in scope %q: %w", ipStr, s.Scope, err)
			}
			reg.Declare(scope, addr, DispAttacker)
		}
	}
	return reg, nil
}

// LoadRegistryFile loads a registry from a JSON file path.
func LoadRegistryFile(path string) (*Registry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("stagedlabel: open registry %q: %w", path, err)
	}
	defer f.Close()
	return LoadRegistry(f)
}
