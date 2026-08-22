package cilium

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/k8s/cnp"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// fakeWriter records the CNPs an enforcer writes/deletes so a test can assert the
// exact object without a cluster.
type fakeWriter struct {
	ensured map[string]*unstructured.Unstructured // namespace/name -> object
	deleted []string                              // namespace/name, in order
}

func newFakeWriter() *fakeWriter {
	return &fakeWriter{ensured: map[string]*unstructured.Unstructured{}}
}

var _ cnp.PolicyWriter = (*fakeWriter)(nil)

func (f *fakeWriter) Ensure(_ context.Context, obj *unstructured.Unstructured) error {
	f.ensured[obj.GetNamespace()+"/"+obj.GetName()] = obj
	return nil
}

func (f *fakeWriter) Delete(_ context.Context, namespace, name string) error {
	f.deleted = append(f.deleted, namespace+"/"+name)
	delete(f.ensured, namespace+"/"+name)
	return nil
}

func mustEnforcer(t *testing.T, w cnp.PolicyWriter, r SourceResolver) *Enforcer {
	t.Helper()
	e, err := New(Config{
		Writer:          w,
		Scope:           "m7-window",
		TargetNamespace: "default",
		TargetLabels:    map[string]string{"app": "srv"},
		Resolver:        r,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// attributedVerdict is a Tier-3 async verdict for cli(10.0.0.235) with a non-zero
// socket cookie, mirroring what the adapter delivers to the enforcer seam.
func attributedVerdict() contract.Verdict {
	return contract.Verdict{
		Flow: contract.FlowIdentity{
			SocketCookie: 0xC0,
			L7Attributes: map[string]string{contract.AttrSourceAddress: "10.0.0.235"},
		},
		Scope: "m7-window",
		Tier:  contract.TierJail,
		Mode:  contract.ModeAsync,
	}
}

// TestApplyWritesExpectedCNP: the enforcer's IP path produces the golden fromCIDR
// CNP and Ensures it under the deterministic name.
func TestApplyWritesExpectedCNP(t *testing.T) {
	w := newFakeWriter()
	e := mustEnforcer(t, w, nil)

	if err := e.Apply(attributedVerdict(), containment.Jail); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	wantName := cnp.Name(cnp.Params{
		Scope: "m7-window", SourceIP: "10.0.0.235",
		TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"},
	})
	key := "default/" + wantName
	obj, ok := w.ensured[key]
	if !ok {
		t.Fatalf("no CNP written at %s; wrote: %v", key, keys(w.ensured))
	}

	// endpointSelector picks the decoy (target) workload.
	sel, _, _ := unstructured.NestedStringMap(obj.Object, "spec", "endpointSelector", "matchLabels")
	if sel["app"] != "srv" {
		t.Fatalf("endpointSelector wrong: %v", sel)
	}
	// ingressDeny denies the attributed source by /32 CIDR.
	deny, _, _ := unstructured.NestedSlice(obj.Object, "spec", "ingressDeny")
	if len(deny) != 1 {
		t.Fatalf("want one ingressDeny rule, got %d", len(deny))
	}
	rule := deny[0].(map[string]interface{})
	cidrs, ok := rule["fromCIDR"].([]interface{})
	if !ok || len(cidrs) != 1 || cidrs[0] != "10.0.0.235/32" {
		t.Fatalf("fromCIDR wrong: %#v", rule)
	}
	// Audit stamps present.
	if obj.GetLabels()[cnp.LabelSocketCookie] != "192" { // 0xC0
		t.Fatalf("socket-cookie stamp wrong: %v", obj.GetLabels())
	}
	if obj.GetLabels()[cnp.LabelTier] != "3" {
		t.Fatalf("tier stamp wrong: %v", obj.GetLabels())
	}
	if obj.GetAnnotations()[cnp.AnnScope] != "m7-window" {
		t.Fatalf("scope stamp wrong: %v", obj.GetAnnotations())
	}
}

// TestReleaseDeletesTheSameObject: Release addresses the SAME deterministic name
// Apply wrote — so an applied containment is actually lifted.
func TestReleaseDeletesTheSameObject(t *testing.T) {
	w := newFakeWriter()
	e := mustEnforcer(t, w, nil)
	v := attributedVerdict()

	if err := e.Apply(v, containment.Jail); err != nil {
		t.Fatal(err)
	}
	wantName := cnp.Name(cnp.Params{
		Scope: "m7-window", SourceIP: "10.0.0.235",
		TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"},
	})
	if err := e.Release(v); err != nil {
		t.Fatal(err)
	}
	if len(w.deleted) != 1 || w.deleted[0] != "default/"+wantName {
		t.Fatalf("Release did not delete the applied object: deleted=%v want default/%s", w.deleted, wantName)
	}
	if _, still := w.ensured["default/"+wantName]; still {
		t.Fatal("object still present after Release")
	}
}

// TestApplyRefusesUnresolvableSource: a flow with no source IP and no resolvable
// labels is REFUSED — nothing is written (precision; mirrors the cookie-0 refusal).
func TestApplyRefusesUnresolvableSource(t *testing.T) {
	w := newFakeWriter()
	e := mustEnforcer(t, w, nil)

	v := contract.Verdict{
		Flow:  contract.FlowIdentity{SocketCookie: 0xC0}, // cookie set, but NO source address
		Scope: "m7-window",
		Tier:  contract.TierJail,
	}
	if err := e.Apply(v, containment.Jail); !errors.Is(err, ErrUnresolvableSource) {
		t.Fatalf("want ErrUnresolvableSource, got %v", err)
	}
	if len(w.ensured) != 0 {
		t.Fatalf("an over-broad CNP was written for an unresolvable source: %v", keys(w.ensured))
	}
}

// TestReleaseUnresolvableSourceIsNoop: releasing an unattributable flow writes/
// deletes nothing and does not error (idempotent de-escalation).
func TestReleaseUnresolvableSourceIsNoop(t *testing.T) {
	w := newFakeWriter()
	e := mustEnforcer(t, w, nil)
	v := contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 0xC0}, Scope: "m7-window", Tier: contract.TierObserve}
	if err := e.Release(v); err != nil {
		t.Fatalf("release of unresolvable flow should be nil, got %v", err)
	}
	if len(w.deleted) != 0 {
		t.Fatalf("release of unresolvable flow deleted something: %v", w.deleted)
	}
}

// staticResolver resolves every flow to a fixed source label set (the higher-
// confidence fromEndpoints path).
type staticResolver struct{ labels map[string]string }

func (s staticResolver) SourceLabels(contract.Verdict) (map[string]string, bool) {
	return s.labels, true
}

// TestApplyUsesResolverLabelsWhenPresent: with a resolver, the enforcer takes the
// fromEndpoints (higher-confidence) path instead of fromCIDR.
func TestApplyUsesResolverLabelsWhenPresent(t *testing.T) {
	w := newFakeWriter()
	e := mustEnforcer(t, w, staticResolver{labels: map[string]string{"app": "cli"}})

	if err := e.Apply(attributedVerdict(), containment.Jail); err != nil {
		t.Fatal(err)
	}
	wantName := cnp.Name(cnp.Params{
		Scope: "m7-window", SourceLabels: map[string]string{"app": "cli"},
		TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"},
	})
	obj, ok := w.ensured["default/"+wantName]
	if !ok {
		t.Fatalf("no CNP at the endpoints-path name; wrote: %v", keys(w.ensured))
	}
	deny, _, _ := unstructured.NestedSlice(obj.Object, "spec", "ingressDeny")
	rule := deny[0].(map[string]interface{})
	if _, ok := rule["fromEndpoints"]; !ok {
		t.Fatalf("expected fromEndpoints path with a resolver, got %#v", rule)
	}
	if obj.GetLabels()[cnp.LabelConfidence] != "label" {
		t.Fatalf("confidence stamp should be 'label', got %v", obj.GetLabels())
	}
}

// TestNewRejectsEmptyTarget: an enforcer that would select every pod is refused at
// construction.
func TestNewRejectsEmptyTarget(t *testing.T) {
	if _, err := New(Config{Writer: newFakeWriter(), TargetNamespace: "default"}); err == nil {
		t.Fatal("New should reject empty TargetLabels")
	}
	if _, err := New(Config{Writer: newFakeWriter(), TargetLabels: map[string]string{"app": "srv"}}); err == nil {
		t.Fatal("New should reject empty TargetNamespace")
	}
	if _, err := New(Config{TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}); err == nil {
		t.Fatal("New should reject a nil Writer")
	}
}

func keys(m map[string]*unstructured.Unstructured) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
