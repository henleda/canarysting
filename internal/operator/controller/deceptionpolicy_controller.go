// Package controller holds the CanarySting operator's reconcilers. Prototype (M1).
package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	deceptionv1alpha1 "github.com/canarysting/canarysting/internal/operator/api/v1alpha1"
)

// DeceptionPolicyReconciler reconciles a DeceptionPolicy.
//
// M1 skeleton scope (deliberately narrow): it VALIDATES the spec and reports the
// result on the object's own status subresource. It plants NO decoys and takes NO
// destructive cluster action — the only write is the DeceptionPolicy's status.
// Wiring the accepted policy to the canary seeder (and reflecting a real
// SeededCount) is the canary milestone (M2), gated on observe-before-enforce.
type DeceptionPolicyReconciler struct {
	client.Client

	// Scheme is reserved for M2, when seeded objects carry owner references back to
	// the DeceptionPolicy; the validate-only skeleton does not read it.
	Scheme *runtime.Scheme

	// KnownDecoys is the set of valid decoy type names, sourced from the canary
	// catalog at startup. A nil map disables type validation (used only in tests).
	KnownDecoys map[string]bool
}

// +kubebuilder:rbac:groups=deception.canarysting.io,resources=deceptionpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=deception.canarysting.io,resources=deceptionpolicies/status,verbs=get;update;patch

// Reconcile validates a DeceptionPolicy and records the outcome in its status.
func (r *DeceptionPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var dp deceptionv1alpha1.DeceptionPolicy
	if err := r.Get(ctx, req.NamespacedName, &dp); err != nil {
		// Deleted or not yet cached: nothing to do (no finalizer in the skeleton,
		// because we own no external state yet).
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	reason, msg := r.validate(&dp)
	accepted := reason == reasonAccepted

	condStatus := metav1.ConditionFalse
	if accepted {
		condStatus = metav1.ConditionTrue
	}
	before := dp.Status.DeepCopy()
	meta.SetStatusCondition(&dp.Status.Conditions, metav1.Condition{
		Type:               conditionAccepted,
		Status:             condStatus,
		ObservedGeneration: dp.Generation,
		Reason:             reason,
		Message:            msg,
	})
	dp.Status.ObservedGeneration = dp.Generation
	// SeededCount is left untouched (0) — the skeleton plants nothing (M2).

	// Guarded write: only touch the apiserver when the status actually changed, so a
	// steady-state re-sync neither writes nor re-enqueues the object.
	if equality.Semantic.DeepEqual(*before, dp.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &dp); err != nil {
		return ctrl.Result{}, fmt.Errorf("update DeceptionPolicy %s status: %w", req.NamespacedName, err)
	}
	l.Info("reconciled DeceptionPolicy", "name", dp.Name, "namespace", dp.Namespace, "accepted", accepted, "reason", reason)
	return ctrl.Result{}, nil
}

const (
	conditionAccepted = "Accepted"

	reasonAccepted       = "Accepted"
	reasonEmptySel       = "EmptySelector"
	reasonCrossNamespace = "CrossNamespaceSelector"
	reasonNoDecoys       = "NoDecoys"
	reasonInvalidSpec    = "InvalidDecoy"
	reasonUnknownType    = "UnknownDecoyType"
)

// validate returns a machine reason and a human message. reason==reasonAccepted
// means the spec is valid. It performs no cluster mutation.
func (r *DeceptionPolicyReconciler) validate(dp *deceptionv1alpha1.DeceptionPolicy) (reason, msg string) {
	sel := dp.Spec.Selector
	// A namespaced DeceptionPolicy targets its OWN namespace; it must not name a
	// foreign one (that would let a policy in namespace A seed workloads in B).
	if sel.Namespace != "" && sel.Namespace != dp.Namespace {
		return reasonCrossNamespace, fmt.Sprintf("spec.selector.namespace %q must be empty or equal the policy's own namespace %q", sel.Namespace, dp.Namespace)
	}
	// The selector must convey a real constraint: an absent namespace together with
	// an empty/absent labelSelector matches everything, and is rejected so a policy
	// can never (once M2 wires seeding) resolve to all workloads.
	if sel.Namespace == "" && labelSelectorEmpty(sel.LabelSelector) {
		return reasonEmptySel, "spec.selector must set namespace and/or a non-empty labelSelector (a policy must not resolve to match-all)"
	}
	if len(dp.Spec.Decoys) == 0 {
		return reasonNoDecoys, "spec.decoys must list at least one decoy"
	}
	unknown := map[string]bool{}
	for _, d := range dp.Spec.Decoys {
		if d.Type == "" {
			return reasonInvalidSpec, "a decoy is missing spec.decoys[].type"
		}
		// Count 0 means "unset": the CRD defaults it to 1 and the apiserver enforces
		// minimum:1 on explicit values, so here we reject only a genuinely negative one.
		if d.Count < 0 {
			return reasonInvalidSpec, fmt.Sprintf("decoy %q has a negative count", d.Type)
		}
		if r.KnownDecoys != nil && !r.KnownDecoys[d.Type] {
			unknown[d.Type] = true
		}
	}
	if len(unknown) > 0 {
		types := make([]string, 0, len(unknown))
		for t := range unknown {
			types = append(types, t)
		}
		sort.Strings(types)
		return reasonUnknownType, fmt.Sprintf("unknown decoy type(s): %s", strings.Join(types, ", "))
	}
	return reasonAccepted, fmt.Sprintf("%d decoy type(s) validated; seeding is deferred to the canary milestone (M2)", len(dp.Spec.Decoys))
}

// labelSelectorEmpty reports whether a label selector conveys no constraint (nil,
// or present with no matchLabels and no matchExpressions — which matches all).
func labelSelectorEmpty(ls *metav1.LabelSelector) bool {
	return ls == nil || (len(ls.MatchLabels) == 0 && len(ls.MatchExpressions) == 0)
}

// SetupWithManager registers the reconciler with the manager.
func (r *DeceptionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&deceptionv1alpha1.DeceptionPolicy{}).
		Named("deceptionpolicy").
		Complete(r)
}
