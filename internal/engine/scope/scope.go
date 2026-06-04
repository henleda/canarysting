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

// TODO: implement the resolution order; reject overlapping zones (or apply a
// deterministic precedence); derive cluster identity from SPIFFE trust domain
// (mesh) or cluster UID (k8s); return ErrUnresolved otherwise.
