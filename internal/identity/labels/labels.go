// Package labels resolves the FALLBACK, explicitly lower-confidence workload
// identity: identity derived from Kubernetes pod labels and ServiceAccount. This
// is control-plane-asserted — spoofable by a compromised node and racy under
// pod-IP churn — so it is marked ConfidenceAsserted and must NEVER be treated as
// equal to verified mesh identity (CLAUDE.md safety rule; docs/ARCHITECTURE_SPEC_K8S
// §2 "identity degrades without a mesh").
//
// Status: prototype (M1 slice 1). This package holds only the derivation and its
// confidence tag. The Source that actually maps a flow to its pod's metadata is a
// read-only Kubernetes informer (client-go) that maps ephemeral pod IPs to a
// stable identity via the label/SA set — a time-correct join, NEVER by raw IP
// alone (docs/ARCHITECTURE_SPEC_K8S §5). That informer is net-new and wired in a
// later slice; nothing here talks to a cluster.
package labels

import (
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/identity"
)

// PodMeta is the label/ServiceAccount context an informer supplies for the source
// pod of a flow. It is control-plane-asserted, not cryptographically verified.
type PodMeta struct {
	Namespace      string
	ServiceAccount string
	// Labels are the pod's labels; the workload name is derived from the
	// well-known name labels below.
	Labels map[string]string
}

// Source resolves a flow to its source pod's metadata. It is the seam a read-only
// Kubernetes informer implements. Lookup returns ok=false when the flow's source
// cannot be attributed to a pod (e.g. off-cluster or not yet observed), and the
// caller falls through the precedence chain rather than guessing.
type Source interface {
	Lookup(contract.FlowIdentity) (PodMeta, bool)
}

// nameLabels are the well-known workload-name labels, most specific first.
var nameLabels = []string{"app.kubernetes.io/name", "app", "k8s-app"}

// Resolve derives a workload identity from pod metadata at EXPLICITLY LOWER
// (Asserted) confidence. It returns the zero WorkloadID (Confidence None) when the
// metadata names no namespace, ServiceAccount, or workload label at all — an
// unusable identity must not masquerade as a resolved one.
func Resolve(m PodMeta) identity.WorkloadID {
	name := ""
	for _, k := range nameLabels {
		if v := m.Labels[k]; v != "" {
			name = v
			break
		}
	}
	if name == "" {
		name = m.ServiceAccount
	}
	if name == "" && m.Namespace == "" && m.ServiceAccount == "" {
		return identity.WorkloadID{}
	}
	if name != "" && m.Namespace != "" {
		name = m.Namespace + "/" + name
	}
	return identity.WorkloadID{
		// A label-derived identity has NO SPIFFE trust domain — it is not mesh
		// identity, so TrustDomain stays empty. The cluster-level scope for a
		// non-mesh flow comes from the operator-supplied cluster UID (see
		// scopemap.ClusterIdentity), NOT from a per-pod value smuggled through
		// TrustDomain — otherwise scopemap would emit "td:<uid>" for it and one
		// cluster's learned state would fragment across two scope keys.
		Namespace:      m.Namespace,
		ServiceAccount: m.ServiceAccount,
		Name:           name,
		Confidence:     identity.ConfidenceAsserted,
	}
}
