package labels

import (
	"testing"

	"github.com/canarysting/canarysting/internal/identity"
)

func TestResolve_NameFromKubernetesNameLabel(t *testing.T) {
	w := Resolve(PodMeta{
		Namespace:      "orders",
		ServiceAccount: "payments-sa",
		Labels:         map[string]string{"app.kubernetes.io/name": "payments", "app": "ignored"},
	})
	if w.Confidence != identity.ConfidenceAsserted {
		t.Errorf("confidence = %v, want asserted (label-derived is lower-confidence)", w.Confidence)
	}
	if w.Name != "orders/payments" {
		t.Errorf("name = %q, want orders/payments", w.Name)
	}
	// A label-derived identity carries NO SPIFFE trust domain (it is not mesh):
	// cluster scope for a non-mesh flow comes from the operator UID, not from here.
	if w.TrustDomain != "" || w.Namespace != "orders" || w.ServiceAccount != "payments-sa" {
		t.Errorf("unexpected identity: %+v (TrustDomain must be empty for label identity)", w)
	}
}

func TestResolve_LabelPrecedenceAndFallbacks(t *testing.T) {
	// falls back to `app` when the k8s name label is absent.
	if got := Resolve(PodMeta{Namespace: "ns", Labels: map[string]string{"app": "web"}}).Name; got != "ns/web" {
		t.Errorf("app-label name = %q, want ns/web", got)
	}
	// falls back to ServiceAccount when no name label is present.
	if got := Resolve(PodMeta{Namespace: "ns", ServiceAccount: "robot"}).Name; got != "ns/robot" {
		t.Errorf("SA-derived name = %q, want ns/robot", got)
	}
}

func TestResolve_UnusableMetaIsEmpty(t *testing.T) {
	if !Resolve(PodMeta{}).Empty() {
		t.Error("empty PodMeta must yield Empty identity")
	}
	if !Resolve(PodMeta{Labels: map[string]string{"unrelated": "x"}}).Empty() {
		t.Error("meta with no ns/sa/name label must yield Empty identity")
	}
}

func TestResolve_NamespaceOnlyIsResolvedButLow(t *testing.T) {
	w := Resolve(PodMeta{Namespace: "orders"})
	if w.Empty() || w.Confidence != identity.ConfidenceAsserted || w.Namespace != "orders" {
		t.Fatalf("namespace-only meta: got %+v, want asserted orders identity", w)
	}
}
