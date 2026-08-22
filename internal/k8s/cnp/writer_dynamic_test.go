package cnp

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// newFakeWriter builds a DynamicWriter over a fake dynamic client that knows the CNP
// GVR's list kind (required for the tracker to serve the custom resource).
func newFakeWriter(objs ...runtime.Object) *DynamicWriter {
	scheme := runtime.NewScheme()
	c := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{GVR: "CiliumNetworkPolicyList"},
		objs...,
	)
	return NewDynamicWriter(c)
}

func mustRender(t *testing.T, p Params) *unstructured.Unstructured {
	t.Helper()
	obj, err := Render(p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return obj
}

func baseParams() Params {
	return Params{
		Scope:           "m7-window",
		SourceIP:        "10.0.0.235",
		TargetNamespace: "default",
		TargetLabels:    map[string]string{"app": "srv"},
		SocketCookie:    42,
		Tier:            "3",
		Confidence:      "source-ip",
		Reason:          "jail",
	}
}

func TestEnsureCreatesThenIsIdempotent(t *testing.T) {
	w := newFakeWriter()
	ctx := context.Background()
	obj := mustRender(t, baseParams())

	if err := w.Ensure(ctx, obj); err != nil {
		t.Fatalf("first Ensure (create): %v", err)
	}
	got, err := w.client.Resource(GVR).Namespace("default").Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if got.GetLabels()[LabelManagedBy] != managedByValue {
		t.Fatalf("managed-by label missing on the created CNP: %v", got.GetLabels())
	}

	// Re-Ensure the same object: must update in place, not error with AlreadyExists.
	if err := w.Ensure(ctx, obj); err != nil {
		t.Fatalf("second Ensure (update): %v", err)
	}
	// Still exactly one object of this GVR in the namespace.
	list, err := w.client.Resource(GVR).Namespace("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("idempotent Ensure produced %d objects, want 1", len(list.Items))
	}
}

func TestEnsureUpdatesChangedSpec(t *testing.T) {
	w := newFakeWriter()
	ctx := context.Background()
	if err := w.Ensure(ctx, mustRender(t, baseParams())); err != nil {
		t.Fatal(err)
	}

	// Same identity (same name), different audit field (reason) → update in place.
	p2 := baseParams()
	p2.Reason = "rate-limit"
	obj2 := mustRender(t, p2)
	if err := w.Ensure(ctx, obj2); err != nil {
		t.Fatalf("Ensure update: %v", err)
	}
	got, err := w.client.Resource(GVR).Namespace("default").Get(ctx, obj2.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()[AnnReason] != "rate-limit" {
		t.Fatalf("update did not take: reason=%q", got.GetAnnotations()[AnnReason])
	}
}

func TestDeleteRemovesAndIgnoresNotFound(t *testing.T) {
	w := newFakeWriter()
	ctx := context.Background()
	obj := mustRender(t, baseParams())
	name := obj.GetName()

	if err := w.Ensure(ctx, obj); err != nil {
		t.Fatal(err)
	}
	if err := w.Delete(ctx, "default", name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := w.client.Resource(GVR).Namespace("default").Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("object still present after delete: %v", err)
	}
	// Second delete of the now-absent object is a no-op nil (idempotent release).
	if err := w.Delete(ctx, "default", name); err != nil {
		t.Fatalf("delete of absent object should be nil, got %v", err)
	}
}
