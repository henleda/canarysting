package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// DeceptionPolicySpec declares decoys to plant near a set of workloads.
type DeceptionPolicySpec struct {
	// Selector chooses the workloads near which decoys are planted.
	Selector WorkloadSelector `json:"selector"`

	// Decoys are the decoy types (and counts) to plant. At least one is required;
	// each Type is validated against the canary catalog by the operator.
	// +kubebuilder:validation:MinItems=1
	Decoys []DecoySpec `json:"decoys"`

	// Scope optionally overrides the derived scope key for this policy. When empty,
	// the operator's identity-derived scope is used. Prototype: recorded but not yet
	// consumed (the seeding path is wired in the canary milestone, M2).
	// +optional
	Scope string `json:"scope,omitempty"`
}

// WorkloadSelector selects target workloads within the policy's OWN namespace. The
// selector must convey a real constraint — a namespace (which, if set, must equal
// the policy's own) and/or a non-empty labelSelector. A match-everything selector
// (no namespace and an empty/absent labelSelector) and a namespace naming a
// different namespace are both rejected in status.
type WorkloadSelector struct {
	// Namespace, if set, must equal the DeceptionPolicy's own namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// LabelSelector narrows the target workloads. An empty selector (no matchLabels
	// and no matchExpressions) matches all and is not treated as "set".
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// DecoySpec is one decoy type and how many instances to plant.
type DecoySpec struct {
	// Type is a canary catalog decoy type (e.g. "fake_secret", "planted_credential",
	// "decoy_file", "fake_bucket", "fake_endpoint"). Unknown types are rejected.
	Type string `json:"type"`

	// Count is how many instances to plant.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	// +optional
	Count int32 `json:"count,omitempty"`
}

// DeceptionPolicyStatus reports the observed state of a DeceptionPolicy.
type DeceptionPolicyStatus struct {
	// ObservedGeneration is the spec generation the operator last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SeededCount is how many decoy instances are currently planted. It is always 0
	// in the M1 skeleton — decoy seeding is wired in the canary milestone (M2).
	// +optional
	SeededCount int32 `json:"seededCount,omitempty"`

	// Conditions describe the policy state. The "Accepted" condition is True when
	// the spec validates.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DeceptionPolicy declares decoys to plant near a set of workloads. In the M1
// skeleton the operator VALIDATES the policy and reports status; it plants no
// decoys and takes no destructive cluster action.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=decpol,categories=canarysting
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Seeded",type=integer,JSONPath=`.status.seededCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type DeceptionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DeceptionPolicySpec   `json:"spec,omitempty"`
	Status DeceptionPolicyStatus `json:"status,omitempty"`
}

// DeceptionPolicyList is a list of DeceptionPolicy.
//
// +kubebuilder:object:root=true
type DeceptionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DeceptionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DeceptionPolicy{}, &DeceptionPolicyList{})
}
