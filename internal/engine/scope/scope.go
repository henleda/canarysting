// Package scope resolves the single scope key that isolates all learned state.
// Resolution order: operator zone > derived cluster identity (also the catch-
// all) > operator-defined boundary > hard fail. Never fall back to a global
// scope. See docs/SCOPE.md.
package scope

import (
	"errors"

	"github.com/canarysting/canarysting/internal/contract"
)

// ErrUnresolved is returned when no scope can be resolved. Callers MUST treat
// this as fatal at startup, never as a reason to use a global/empty scope.
var ErrUnresolved = errors.New("scope: cannot resolve scope key; refusing to start")

// Resolver maps a flow to exactly one scope key.
type Resolver interface {
	Resolve(contract.FlowIdentity) (contract.ScopeKey, error)
}

// Zone is an operator-defined trust zone. A flow lands in the first zone whose
// Match returns true. Zones are tried in order, so order IS the precedence: a
// flow that would match two zones lands in exactly one (the earlier), which is
// how we keep scopes partitioned cleanly without rejecting config. See
// docs/SCOPE.md ("Reject overlapping zones, or define a deterministic
// precedence").
type Zone struct {
	Key   contract.ScopeKey
	Match func(contract.FlowIdentity) bool
}

// ClusterIdentity derives a cluster-level scope key from a flow: the SPIFFE
// trust domain in a mesh, or the cluster UID in Kubernetes. It returns ok=false
// where no cluster identity is derivable (e.g. standalone nginx on bare VMs).
// This value also serves as the catch-all scope for unzoned traffic, so the
// catch-all is free and needs no separate config. See docs/SCOPE.md step 2.
type ClusterIdentity func(contract.FlowIdentity) (contract.ScopeKey, bool)

// Config drives a StaticResolver. At least one of Zones, Cluster, or Boundary
// must be set, or the resolver refuses to start (Validate returns ErrUnresolved).
type Config struct {
	// Zones are matched first, in order.
	Zones []Zone
	// Cluster derives the cluster-level scope and the unzoned catch-all. Optional.
	Cluster ClusterIdentity
	// Boundary is the operator-defined boundary, required where no cluster
	// identity is derivable. It is the last resort before a hard fail.
	Boundary contract.ScopeKey
}

// StaticResolver implements Resolver from a Config.
type StaticResolver struct {
	cfg Config
}

// NewStaticResolver validates the config and returns a resolver. It returns
// ErrUnresolved if the config could never resolve a scope — the caller must
// treat that as fatal (refuse to start) rather than defaulting to a global scope.
func NewStaticResolver(cfg Config) (*StaticResolver, error) {
	r := &StaticResolver{cfg: cfg}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate reports whether the resolver can resolve any scope at all. A
// standalone deployment with no zones and no derivable cluster identity MUST set
// a Boundary; otherwise we fail loud at startup. See docs/SCOPE.md step 4.
func (r *StaticResolver) Validate() error {
	if len(r.cfg.Zones) == 0 && r.cfg.Cluster == nil && r.cfg.Boundary == "" {
		return ErrUnresolved
	}
	return nil
}

// Resolve returns the single scope key for a flow, following the documented
// order. It never returns an empty scope with a nil error: on no match it
// returns ErrUnresolved.
func (r *StaticResolver) Resolve(f contract.FlowIdentity) (contract.ScopeKey, error) {
	// 1. operator-defined trust zone (first match wins).
	for _, z := range r.cfg.Zones {
		if z.Match != nil && z.Match(f) {
			if z.Key == "" {
				return "", ErrUnresolved
			}
			return z.Key, nil
		}
	}
	// 2. derived cluster identity (also the unzoned catch-all).
	if r.cfg.Cluster != nil {
		if k, ok := r.cfg.Cluster(f); ok && k != "" {
			return k, nil
		}
	}
	// 3. operator-defined boundary.
	if r.cfg.Boundary != "" {
		return r.cfg.Boundary, nil
	}
	// 4. hard fail — never a global/empty scope.
	return "", ErrUnresolved
}
