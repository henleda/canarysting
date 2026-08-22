package cnp

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// PolicyWriter is the narrow write seam the CNP actuator drives. It is deliberately
// tiny (create-or-update, delete) so the enforcer can be unit-tested against a fake
// and the real implementation is a thin shell over the dynamic client.
type PolicyWriter interface {
	// Ensure creates the CNP, or updates it in place if one with the same name
	// already exists (idempotent). The object carries its own namespace/name.
	Ensure(ctx context.Context, obj *unstructured.Unstructured) error
	// Delete removes the CNP by namespace+name. A NotFound is treated as success
	// (idempotent): releasing a flow that was never contained is a no-op.
	Delete(ctx context.Context, namespace, name string) error
}

// DynamicWriter is the real PolicyWriter over client-go's dynamic client. It
// addresses CNPs through GVR and never imports github.com/cilium/cilium.
type DynamicWriter struct {
	client dynamic.Interface
}

var _ PolicyWriter = (*DynamicWriter)(nil)

// NewDynamicWriter builds a DynamicWriter over a dynamic client.
func NewDynamicWriter(c dynamic.Interface) *DynamicWriter {
	return &DynamicWriter{client: c}
}

// Ensure is create-or-update: it attempts a Create and, if the object already
// exists, Gets the live object to carry its resourceVersion into an Update (the
// apiserver requires the current resourceVersion for an update). This makes Apply
// idempotent — re-applying the same containment reconciles rather than errors.
func (w *DynamicWriter) Ensure(ctx context.Context, obj *unstructured.Unstructured) error {
	ns := obj.GetNamespace()
	name := obj.GetName()
	ri := w.client.Resource(GVR).Namespace(ns)

	_, err := ri.Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("cnp: create %s/%s: %w", ns, name, err)
	}

	// Already present: fetch the live resourceVersion and update in place.
	existing, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("cnp: get %s/%s for update: %w", ns, name, err)
	}
	// Update a copy so the caller's object is not mutated with a resourceVersion.
	upd := obj.DeepCopy()
	upd.SetResourceVersion(existing.GetResourceVersion())
	if _, err := ri.Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("cnp: update %s/%s: %w", ns, name, err)
	}
	return nil
}

// Delete removes the named CNP, ignoring NotFound (idempotent release).
func (w *DynamicWriter) Delete(ctx context.Context, namespace, name string) error {
	err := w.client.Resource(GVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("cnp: delete %s/%s: %w", namespace, name, err)
	}
	return nil
}
