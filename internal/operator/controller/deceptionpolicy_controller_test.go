package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	deceptionv1alpha1 "github.com/canarysting/canarysting/internal/operator/api/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := deceptionv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func reconcilerFor(t *testing.T, dp *deceptionv1alpha1.DeceptionPolicy, known map[string]bool) *DeceptionPolicyReconciler {
	t.Helper()
	s := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(dp).WithStatusSubresource(dp).Build()
	return &DeceptionPolicyReconciler{Client: cl, Scheme: s, KnownDecoys: known}
}

func reconcileOnce(t *testing.T, r *DeceptionPolicyReconciler, name, ns string) *deceptionv1alpha1.DeceptionPolicy {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got deceptionv1alpha1.DeceptionPolicy
	if err := r.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatalf("get after reconcile: %v", err)
	}
	return &got
}

func acceptedCond(t *testing.T, dp *deceptionv1alpha1.DeceptionPolicy) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(dp.Status.Conditions, conditionAccepted)
	if c == nil {
		t.Fatalf("no Accepted condition on %s", dp.Name)
	}
	return c
}

func TestReconcile_ValidPolicyIsAccepted(t *testing.T) {
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "orders", Generation: 3},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{Namespace: "orders"},
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "fake_secret", Count: 2}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true}), "p1", "orders")
	if c := acceptedCond(t, got); c.Status != metav1.ConditionTrue {
		t.Fatalf("want Accepted=True, got %s/%s", c.Status, c.Reason)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
	if got.Status.SeededCount != 0 {
		t.Errorf("SeededCount = %d, want 0 (skeleton plants nothing)", got.Status.SeededCount)
	}
}

func TestReconcile_UnknownDecoyTypeRejected(t *testing.T) {
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "orders"},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{Namespace: "orders"},
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "not_a_real_decoy", Count: 1}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true}), "p2", "orders")
	if c := acceptedCond(t, got); c.Status != metav1.ConditionFalse || c.Reason != reasonUnknownType {
		t.Fatalf("want Accepted=False/%s, got %s/%s", reasonUnknownType, c.Status, c.Reason)
	}
}

func TestReconcile_EmptySelectorRejected(t *testing.T) {
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: "orders"},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Decoys: []deceptionv1alpha1.DecoySpec{{Type: "fake_secret", Count: 1}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true}), "p3", "orders")
	if c := acceptedCond(t, got); c.Status != metav1.ConditionFalse || c.Reason != reasonEmptySel {
		t.Fatalf("want Accepted=False/%s, got %s/%s", reasonEmptySel, c.Status, c.Reason)
	}
}

func TestReconcile_NotFoundIsNoop(t *testing.T) {
	s := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	r := &DeceptionPolicyReconciler{Client: cl, Scheme: s}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "missing", Namespace: "x"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile of a missing object must be a no-op, got %v", err)
	}
}

func TestReconcile_SkeletonNeverSeeds(t *testing.T) {
	// Invariant for the M1 skeleton: even a fully valid policy plants nothing.
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: "orders"},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "fake_secret"}, {Type: "decoy_file"}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true, "decoy_file": true}), "p4", "orders")
	if got.Status.SeededCount != 0 {
		t.Fatalf("skeleton must never seed: SeededCount = %d", got.Status.SeededCount)
	}
	if c := acceptedCond(t, got); c.Status != metav1.ConditionTrue {
		t.Fatalf("valid label-selector policy should be accepted, got %s/%s", c.Status, c.Reason)
	}
}

func TestReconcile_MatchAllSelectorRejected(t *testing.T) {
	// A present-but-empty labelSelector with no namespace matches everything.
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: "orders"},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{LabelSelector: &metav1.LabelSelector{}},
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "fake_secret", Count: 1}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true}), "p5", "orders")
	if c := acceptedCond(t, got); c.Status != metav1.ConditionFalse || c.Reason != reasonEmptySel {
		t.Fatalf("empty labelSelector must be rejected as match-all, got %s/%s", c.Status, c.Reason)
	}
}

func TestReconcile_CrossNamespaceSelectorRejected(t *testing.T) {
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p6", Namespace: "orders"},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{Namespace: "payments"}, // a foreign namespace
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "fake_secret", Count: 1}},
		},
	}
	got := reconcileOnce(t, reconcilerFor(t, dp, map[string]bool{"fake_secret": true}), "p6", "orders")
	if c := acceptedCond(t, got); c.Status != metav1.ConditionFalse || c.Reason != reasonCrossNamespace {
		t.Fatalf("cross-namespace selector must be rejected, got %s/%s", c.Status, c.Reason)
	}
}

func TestReconcile_IsIdempotent(t *testing.T) {
	dp := &deceptionv1alpha1.DeceptionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p7", Namespace: "orders", Generation: 1},
		Spec: deceptionv1alpha1.DeceptionPolicySpec{
			Selector: deceptionv1alpha1.WorkloadSelector{Namespace: "orders"},
			Decoys:   []deceptionv1alpha1.DecoySpec{{Type: "fake_secret", Count: 1}},
		},
	}
	r := reconcilerFor(t, dp, map[string]bool{"fake_secret": true})
	first := reconcileOnce(t, r, "p7", "orders")
	c1 := acceptedCond(t, first)
	// A second reconcile of the settled policy is a no-op: still exactly one
	// condition, and its LastTransitionTime does not move (guarded write).
	second := reconcileOnce(t, r, "p7", "orders")
	if n := len(second.Status.Conditions); n != 1 {
		t.Fatalf("expected exactly 1 condition after re-reconcile, got %d", n)
	}
	if c2 := acceptedCond(t, second); !c1.LastTransitionTime.Time.Equal(c2.LastTransitionTime.Time) {
		t.Fatalf("LastTransitionTime moved on a no-op reconcile: %v -> %v", c1.LastTransitionTime, c2.LastTransitionTime)
	}
}
