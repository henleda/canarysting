package main

// cnp_enforcer.go wires the CiliumNetworkPolicy (CNI) containment enforcer into the
// adapter's OnVerdict->enforcer seam. It is deliberately NOT build-tagged: client-go's
// dynamic client, the rest/clientcmd config loaders, and the cnp/cilium packages are
// pure Go, so this compiles and links on every platform (the KERNEL enforcer is the
// build-tagged one). Selecting it is an operator choice (-cni-enforce); the kernel
// eBPF enforcer stays the default so existing behavior and tests are untouched.
//
// Enforcement split (Finding #1, honest "compose with the CNI"): the CNI does drops
// (Tier-3 Jail), while L7 velocity attrition (the tarpit) does throttling (Tier-2).
// The cilium.Enforcer already encodes that: a Tier-2 rate-limit Apply is a no-op that
// writes no CNP.

import (
	"fmt"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/k8s/cnp"
	cilium "github.com/canarysting/canarysting/internal/sting/containment/cilium"
)

// cniEnforcerConfig is the input to newCNIEnforcer: kubeconfig resolution plus the
// decoy (target) workload the written CNPs protect.
type cniEnforcerConfig struct {
	// Kubeconfig is the path to a kubeconfig. Empty => in-cluster config (the adapter
	// running as a pod with a mounted ServiceAccount).
	Kubeconfig string
	// Scope is the CanarySting scope key stamped on every CNP.
	Scope string
	// TargetNamespace / TargetLabels select the decoy workload the CNP protects (its
	// endpointSelector). Both required — an empty target renders a match-all policy,
	// which cilium.New refuses.
	TargetNamespace string
	TargetLabels    map[string]string
}

// newCNIEnforcer builds a *cilium.Enforcer over a REAL client-go dynamic client and
// returns it as the adapter's enforcer interface (the cilium.Enforcer already carries
// Apply/Release/Close). The whole point is the interface swap: everything downstream
// of the composition root (enforceVerdictOrdered, defer enf.Close()) is unchanged.
func newCNIEnforcer(cfg cniEnforcerConfig) (enforcer, error) {
	restCfg, err := cniRESTConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("cni enforcer: build dynamic client: %w", err)
	}
	enf, err := cilium.New(cilium.Config{
		Writer:          cnp.NewDynamicWriter(dyn),
		Scope:           contract.ScopeKey(cfg.Scope),
		TargetNamespace: cfg.TargetNamespace,
		TargetLabels:    cfg.TargetLabels,
	})
	if err != nil {
		return nil, fmt.Errorf("cni enforcer: %w", err)
	}
	return enf, nil
}

// cniRESTConfig resolves the client-go rest.Config: in-cluster when no kubeconfig is
// given (adapter-as-pod), else from the kubeconfig file.
func cniRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("cni enforcer: in-cluster config (no -kubeconfig given): %w", err)
		}
		return cfg, nil
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("cni enforcer: load kubeconfig %q: %w", kubeconfig, err)
	}
	return cfg, nil
}

// parseKVLabels parses "k=v,k=v" into a label map. An empty string yields an empty
// map (the caller rejects an empty target so a CNP never selects every pod).
func parseKVLabels(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, val, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		val = strings.TrimSpace(val)
		if !ok || k == "" {
			return nil, fmt.Errorf("bad label %q: want k=v", pair)
		}
		out[k] = val
	}
	return out, nil
}
