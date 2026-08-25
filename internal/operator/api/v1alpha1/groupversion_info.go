// Package v1alpha1 contains the CanarySting operator's CustomResourceDefinition
// API types. Prototype (M1). The group is deception.canarysting.io.
//
// +kubebuilder:object:generate=true
// +groupName=deception.canarysting.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group/version for the operator's CRDs.
	GroupVersion = schema.GroupVersion{Group: "deception.canarysting.io", Version: "v1alpha1"}

	// SchemeBuilder registers this group-version's types into a runtime.Scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds this group-version's types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
