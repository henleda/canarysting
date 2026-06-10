// Package signal is the seam between an observed canary interaction and the
// engine contract. The canary layer DEFINES what a valid signal event is; an
// adapter (a later milestone) physically observes the touch at the proxy and
// calls Build. The builder resolves the touched location to its placement WITHIN
// a scope and constructs a fully-populated contract.SignalEvent — it carries NO
// scoring, tiering, or decision logic. See docs/CANARY.md "Signal emission".
package signal

import (
	"errors"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
)

// Touch is what an adapter observes: a flow interacting with a location.
type Touch struct {
	Flow     contract.FlowIdentity // MUST carry a non-zero SocketCookie (docs/IDENTITY.md)
	Location seeder.Location       // the observed canary location
	At       time.Time             // observation time; the engine windows on it
}

var (
	// ErrNoScope rejects a touch with no resolved scope. The adapter passes its
	// already-resolved scope; the builder never guesses one.
	ErrNoScope = errors.New("signal: empty scope; refusing to emit")
	// ErrNoSocketCookie rejects an unattributable flow (zero socket cookie).
	ErrNoSocketCookie = errors.New("signal: flow has zero socket cookie; unattributable, refusing to emit")
	// ErrNoPlacement rejects a touch at a location where no canary is placed in
	// the scope — a non-canary touch must NEVER become a signal.
	ErrNoPlacement = errors.New("signal: no canary placed at location in scope; not a canary touch")
)

// Builder turns observed touches into valid signal events by resolving them
// against the placement registry.
type Builder struct {
	reg seeder.Registry
}

// NewBuilder returns a Builder over a placement registry.
func NewBuilder(reg seeder.Registry) *Builder { return &Builder{reg: reg} }

// Build is the only sanctioned path from a touch to a contract.SignalEvent. It
// enforces three guards before constructing a complete event:
//  1. a non-empty scope (the adapter's resolved scope, never guessed),
//  2. a non-zero socket cookie (an attributable flow),
//  3. a real placement at the location IN THAT SCOPE (a real canary touch).
//
// On any failure it returns a sentinel error and a zero event — never a partial
// one. The canary type and scope come from the registry (the builder's own
// placement record), never trusted from the wire.
func (b *Builder) Build(scope contract.ScopeKey, t Touch) (contract.SignalEvent, error) {
	if scope == "" {
		return contract.SignalEvent{}, ErrNoScope
	}
	if t.Flow.SocketCookie == 0 {
		return contract.SignalEvent{}, ErrNoSocketCookie
	}
	p, ok := b.resolve(scope, t.Location)
	if !ok {
		return contract.SignalEvent{}, ErrNoPlacement
	}
	at := t.At
	if at.IsZero() {
		at = time.Now()
	}
	return contract.SignalEvent{
		Flow:      t.Flow,
		Canary:    p.Type,
		Scope:     scope,
		Timestamp: at,
	}, nil
}

// resolve maps an observed location to a placement. It first tries an EXACT
// match (the common, precise case). On a miss it falls back to DIRECTORY
// canaries: a placement whose location ends in "/" matches any path at or below
// it. This lets an attacker's natural enumeration of a hostile directory
// (e.g. GET /admin/, /admin/login, /admin/whatever) register as a touch of the
// canary seeded at "/admin/", without seeding every exact leaf. The walk is
// O(path depth) Lookups — no registry enumeration on the hot path — and a
// non-canary path (e.g. a legit "/shop") falls through to ErrNoPlacement fast.
//
// SAFETY: directory canaries must be seeded ONLY at negative-space roots a
// legitimate caller never requests (rule 8). The demo set seeds them at
// /admin/, /backup/, /config/, /secrets/, /internal/ — disjoint from the legit
// application paths.
func (b *Builder) resolve(scope contract.ScopeKey, loc seeder.Location) (seeder.Placement, bool) {
	// 1. exact match
	if p, ok := b.reg.Lookup(scope, loc); ok {
		return p, true
	}
	// 2. directory-canary prefix walk: try the path (and each ancestor) as a
	//    trailing-slash directory; accept only a placement whose own location is
	//    a directory canary (ends in "/").
	cur := string(loc)
	for {
		dir := cur
		if !strings.HasSuffix(dir, "/") {
			dir += "/"
		}
		if p, ok := b.reg.Lookup(scope, seeder.Location(dir)); ok && strings.HasSuffix(string(p.Location), "/") {
			return p, true
		}
		trimmed := strings.TrimRight(cur, "/")
		idx := strings.LastIndex(trimmed, "/")
		if idx <= 0 { // reached the root ("/x" -> stop; never treat "/" as a canary)
			break
		}
		cur = trimmed[:idx]
	}
	return seeder.Placement{}, false
}
