package mesh

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/identity"
)

func TestParseSPIFFE(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		ok      bool
		td      string
		ns      string
		sa      string
		svcName string
	}{
		{"ns and sa", "spiffe://cluster.local/ns/orders/sa/payments", true, "cluster.local", "orders", "payments", "orders/payments"},
		{"sa only", "spiffe://cluster.local/sa/payments", true, "cluster.local", "", "payments", "payments"},
		{"ns only", "spiffe://cluster.local/ns/orders", true, "cluster.local", "orders", "", "orders"},
		{"tolerant last segment", "spiffe://td/workload/payments", true, "td", "", "", "payments"},
		{"empty", "", false, "", "", "", ""},
		{"not spiffe scheme", "https://example.com/ns/x", false, "", "", "", ""},
		{"trust domain only, no path", "spiffe://cluster.local", false, "", "", "", ""},
		{"trust domain only, trailing slash", "spiffe://cluster.local/", false, "", "", "", ""},
		{"scheme only", "spiffe://", false, "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, ok := ParseSPIFFE(tc.id)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (id=%q)", ok, tc.ok, tc.id)
			}
			if !tc.ok {
				if !w.Empty() {
					t.Fatalf("failed parse must yield Empty identity, got %+v", w)
				}
				return
			}
			if w.Confidence != identity.ConfidenceVerified {
				t.Errorf("confidence = %v, want verified", w.Confidence)
			}
			if w.TrustDomain != tc.td || w.Namespace != tc.ns || w.ServiceAccount != tc.sa {
				t.Errorf("got td=%q ns=%q sa=%q, want td=%q ns=%q sa=%q",
					w.TrustDomain, w.Namespace, w.ServiceAccount, tc.td, tc.ns, tc.sa)
			}
			if w.Name != tc.svcName {
				t.Errorf("name = %q, want %q", w.Name, tc.svcName)
			}
		})
	}
}

func TestResolve_FromFlow(t *testing.T) {
	w := Resolve(contract.FlowIdentity{SPIFFEID: "spiffe://cluster.local/ns/orders/sa/payments"})
	if w.Confidence != identity.ConfidenceVerified || w.Namespace != "orders" {
		t.Fatalf("got %+v, want verified orders identity", w)
	}
	// No SPIFFE id on the flow (plaintext / no mesh) => no mesh identity.
	if got := Resolve(contract.FlowIdentity{SocketCookie: 42}); !got.Empty() {
		t.Fatalf("flow without SPIFFE must resolve Empty, got %+v", got)
	}
}
