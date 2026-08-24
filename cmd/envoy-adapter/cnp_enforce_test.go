package main

// cnp_enforce_test.go proves the WHOLE tier -> action -> CNI wiring through the REAL
// adapter seam (enforceVerdict), not the cilium.Enforcer in isolation: the enforcer
// under test is a real *cilium.Enforcer over a client-go dynamic FAKE client, and the
// verdicts flow through enforceVerdict exactly as the adapter's OnVerdict handler
// drives them. This is the end-to-end check that a Tier-3 verdict writes a drop CNP,
// a Tier-2 verdict writes NO CNP (the honest L7/CNI split), and a de-escalation
// releases a prior CNP.

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/k8s/cnp"
	cilium "github.com/canarysting/canarysting/internal/sting/containment/cilium"
)

const cnpTestIP = "10.0.0.235"

// newCNPSeamEnforcer builds a real cilium.Enforcer over a fake dynamic client and
// returns both — the enforcer (as the adapter's enforcer interface) and the client
// so a test can inspect the CNPs the seam actually wrote.
func newCNPSeamEnforcer(t *testing.T) (enforcer, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	scheme := runtime.NewScheme()
	fc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{cnp.GVR: "CiliumNetworkPolicyList"},
	)
	enf, err := cilium.New(cilium.Config{
		Writer:          cnp.NewDynamicWriter(fc),
		Scope:           "m7-window",
		TargetNamespace: "default",
		TargetLabels:    map[string]string{"app": "srv"},
	})
	if err != nil {
		t.Fatalf("cilium.New: %v", err)
	}
	return enf, fc
}

// cnpSeamVerdict is a Tier-<tier> async verdict for cli(10.0.0.235) with a non-zero
// socket cookie and the source address stamped the way the adapter stamps it.
func cnpSeamVerdict(tier contract.Tier) contract.Verdict {
	return contract.Verdict{
		Flow: contract.FlowIdentity{
			SocketCookie: 0xC0,
			L7Attributes: map[string]string{contract.AttrSourceAddress: cnpTestIP},
		},
		Scope: "m7-window",
		Tier:  tier,
		Mode:  contract.ModeAsync,
	}
}

func listCNPs(t *testing.T, fc *dynamicfake.FakeDynamicClient) []unstructured.Unstructured {
	t.Helper()
	l, err := fc.Resource(cnp.GVR).Namespace("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list CNPs: %v", err)
	}
	return l.Items
}

// TestSeamTier3WritesDropCNP: a Tier-3 (Jail) verdict driven through enforceVerdict
// writes a deny CNP whose ingressDeny.fromCIDR names the attributed source /32.
func TestSeamTier3WritesDropCNP(t *testing.T) {
	enf, fc := newCNPSeamEnforcer(t)

	act, applied, released, err := enforceVerdict(enf, cnpSeamVerdict(contract.TierJail))
	if err != nil {
		t.Fatalf("enforceVerdict: %v", err)
	}
	if !applied || released {
		t.Fatalf("Tier-3 should apply (applied=%v released=%v)", applied, released)
	}
	if act.String() != "jail" {
		t.Fatalf("Tier-3 action = %s, want jail", act)
	}

	items := listCNPs(t, fc)
	if len(items) != 1 {
		t.Fatalf("Tier-3 should write exactly one CNP, got %d", len(items))
	}
	deny, _, _ := unstructured.NestedSlice(items[0].Object, "spec", "ingressDeny")
	if len(deny) != 1 {
		t.Fatalf("want one ingressDeny rule, got %d", len(deny))
	}
	rule := deny[0].(map[string]interface{})
	cidrs, ok := rule["fromCIDR"].([]interface{})
	if !ok || len(cidrs) != 1 || cidrs[0] != cnpTestIP+"/32" {
		t.Fatalf("ingressDeny.fromCIDR wrong: %#v", rule)
	}
}

// TestSeamTier2WritesNoCNP: a Tier-2 (RateLimit) verdict driven through the seam
// writes NO CNP — the CNI has no rate-limit primitive; Tier-2 throttling is an L7
// concern (the tarpit). Apply still reports applied=true (the seam ran the action),
// but nothing lands in the cluster.
func TestSeamTier2WritesNoCNP(t *testing.T) {
	enf, fc := newCNPSeamEnforcer(t)

	act, applied, released, err := enforceVerdict(enf, cnpSeamVerdict(contract.TierContain))
	if err != nil {
		t.Fatalf("enforceVerdict: %v", err)
	}
	if !applied || released {
		t.Fatalf("Tier-2 should route to Apply (applied=%v released=%v)", applied, released)
	}
	if act.String() != "rate-limit" {
		t.Fatalf("Tier-2 action = %s, want rate-limit", act)
	}
	if items := listCNPs(t, fc); len(items) != 0 {
		t.Fatalf("Tier-2 must write NO CNP (L7 concern), got %d: %v", len(items), items)
	}
}

// TestSeamTier0ReleasesPriorCNP: after a Tier-3 verdict has written a CNP, a later
// Tier-0 verdict for the same flow (de-escalation) drives Release through the seam,
// removing the CNP.
func TestSeamTier0ReleasesPriorCNP(t *testing.T) {
	enf, fc := newCNPSeamEnforcer(t)

	// First contain at Tier-3 so there is something to release.
	if _, applied, _, err := enforceVerdict(enf, cnpSeamVerdict(contract.TierJail)); err != nil || !applied {
		t.Fatalf("seed Tier-3 apply: applied=%v err=%v", applied, err)
	}
	if items := listCNPs(t, fc); len(items) != 1 {
		t.Fatalf("precondition: want one CNP after Tier-3, got %d", len(items))
	}

	// De-escalate to Tier-0: the seam Releases.
	_, applied, released, err := enforceVerdict(enf, cnpSeamVerdict(contract.TierObserve))
	if err != nil {
		t.Fatalf("enforceVerdict (release): %v", err)
	}
	if applied || !released {
		t.Fatalf("Tier-0 should release (applied=%v released=%v)", applied, released)
	}
	if items := listCNPs(t, fc); len(items) != 0 {
		t.Fatalf("Tier-0 de-escalation must remove the prior CNP, still present: %d", len(items))
	}
}
