// Package workload is the single entry point for workload-identity resolution: it
// prefers verified mesh/SPIFFE identity over label-derived identity, and is what
// attribution and the blast-radius graph consume. It encodes the CLAUDE.md rule
// that mesh identity is primary and label-derived identity is a strictly
// lower-confidence fallback — the two are never blended.
//
// Status: prototype (M1 slice 1).
package workload

import (
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/identity"
	"github.com/canarysting/canarysting/internal/identity/labels"
	"github.com/canarysting/canarysting/internal/identity/mesh"
)

// Resolver resolves the single workload identity for a flow.
type Resolver struct {
	// Labels is the label-derived fallback source (a read-only Kubernetes
	// informer). A nil Labels means mesh-only resolution — correct for a
	// mesh-only deployment with no informer wired. It is never consulted when the
	// flow already carries a verified mesh identity.
	Labels labels.Source
}

// Resolve returns the highest-confidence identity available for the flow:
//
//  1. mesh (Verified) if the flow carries a parseable SPIFFE SVID;
//  2. else label-derived (Asserted) if a Labels source is configured and resolves;
//  3. else the zero WorkloadID (Confidence None).
//
// It never blends the two sources: a verified mesh identity short-circuits the
// fallback, and a label-derived identity is only ever returned at Asserted
// confidence.
func (r Resolver) Resolve(f contract.FlowIdentity) identity.WorkloadID {
	if w := mesh.Resolve(f); w.Confidence == identity.ConfidenceVerified {
		return w
	}
	if r.Labels != nil {
		if m, ok := r.Labels.Lookup(f); ok {
			if w := labels.Resolve(m); !w.Empty() {
				return w
			}
		}
	}
	return identity.WorkloadID{}
}
