package cnp

import (
	"errors"
	"reflect"
	"testing"
)

// TestRenderGolden asserts the EXACT unstructured map structure of the golden CNP
// for both the source-IP (fromCIDR, minimal) path and the source-labels
// (fromEndpoints, higher-confidence) path — the shape proven to DROP on the live
// Cilium 1.19.5 cluster.
func TestRenderGolden(t *testing.T) {
	tests := []struct {
		name string
		in   Params
		want map[string]interface{}
	}{
		{
			name: "fromCIDR minimal path (source IP)",
			in: Params{
				Scope:           "m7-window",
				SourceIP:        "10.0.0.235",
				TargetNamespace: "default",
				TargetLabels:    map[string]string{"app": "srv"},
				SocketCookie:    42,
				Tier:            "3",
				Confidence:      "source-ip",
				Reason:          "jail",
			},
			want: map[string]interface{}{
				"apiVersion": "cilium.io/v2",
				"kind":       "CiliumNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      Name(Params{Scope: "m7-window", SourceIP: "10.0.0.235", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}),
					"namespace": "default",
					"labels": map[string]interface{}{
						"canarysting.io/managed-by":    "canarysting",
						"canarysting.io/socket-cookie": "42",
						"canarysting.io/tier":          "3",
						"canarysting.io/confidence":    "source-ip",
					},
					"annotations": map[string]interface{}{
						"canarysting.io/scope":  "m7-window",
						"canarysting.io/reason": "jail",
						"canarysting.io/source": "cidr:10.0.0.235/32",
					},
				},
				"spec": map[string]interface{}{
					"endpointSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "srv"},
					},
					"ingressDeny": []interface{}{
						map[string]interface{}{
							"fromCIDR": []interface{}{"10.0.0.235/32"},
						},
					},
				},
			},
		},
		{
			name: "fromEndpoints higher-confidence path (source labels)",
			in: Params{
				Scope:           "m7-window",
				SourceLabels:    map[string]string{"app": "cli"},
				TargetNamespace: "default",
				TargetLabels:    map[string]string{"app": "srv"},
				SocketCookie:    7,
				Tier:            "3",
				Confidence:      "label",
				Reason:          "jail",
			},
			want: map[string]interface{}{
				"apiVersion": "cilium.io/v2",
				"kind":       "CiliumNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      Name(Params{Scope: "m7-window", SourceLabels: map[string]string{"app": "cli"}, TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}),
					"namespace": "default",
					"labels": map[string]interface{}{
						"canarysting.io/managed-by":    "canarysting",
						"canarysting.io/socket-cookie": "7",
						"canarysting.io/tier":          "3",
						"canarysting.io/confidence":    "label",
					},
					"annotations": map[string]interface{}{
						"canarysting.io/scope":  "m7-window",
						"canarysting.io/reason": "jail",
						"canarysting.io/source": "ep:app=cli",
					},
				},
				"spec": map[string]interface{}{
					"endpointSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "srv"},
					},
					"ingressDeny": []interface{}{
						map[string]interface{}{
							"fromEndpoints": []interface{}{
								map[string]interface{}{"matchLabels": map[string]interface{}{"app": "cli"}},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.in)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if !reflect.DeepEqual(got.Object, tt.want) {
				t.Fatalf("golden mismatch\n got: %#v\nwant: %#v", got.Object, tt.want)
			}
		})
	}
}

// TestRenderPrefersLabelsOverIP proves the higher-confidence source (labels) wins
// when both are present: the rule is fromEndpoints, never fromCIDR.
func TestRenderPrefersLabelsOverIP(t *testing.T) {
	obj, err := Render(Params{
		SourceLabels:    map[string]string{"app": "cli"},
		SourceIP:        "10.0.0.235",
		TargetNamespace: "default",
		TargetLabels:    map[string]string{"app": "srv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rule := ingressRule(t, obj)
	if _, ok := rule["fromEndpoints"]; !ok {
		t.Fatalf("expected fromEndpoints when labels present, got %#v", rule)
	}
	if _, ok := rule["fromCIDR"]; ok {
		t.Fatal("fromCIDR must not appear when source labels resolve")
	}
}

// TestRenderRefusesUnresolvableSource: no source labels and no source IP → refuse.
func TestRenderRefusesUnresolvableSource(t *testing.T) {
	_, err := Render(Params{TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}})
	if !errors.Is(err, ErrUnresolvableSource) {
		t.Fatalf("want ErrUnresolvableSource, got %v", err)
	}
}

// TestRenderRefusesEmptyTarget: no target namespace or no target labels → refuse
// (never a match-all endpointSelector).
func TestRenderRefusesEmptyTarget(t *testing.T) {
	if _, err := Render(Params{SourceIP: "10.0.0.235", TargetLabels: map[string]string{"app": "srv"}}); !errors.Is(err, ErrEmptyTarget) {
		t.Fatalf("missing namespace: want ErrEmptyTarget, got %v", err)
	}
	if _, err := Render(Params{SourceIP: "10.0.0.235", TargetNamespace: "default"}); !errors.Is(err, ErrEmptyTarget) {
		t.Fatalf("missing target labels: want ErrEmptyTarget, got %v", err)
	}
}

// TestRenderRefusesInvalidSourceIP: a set-but-unparseable source IP is refused
// rather than written into a malformed CIDR.
func TestRenderRefusesInvalidSourceIP(t *testing.T) {
	_, err := Render(Params{SourceIP: "not-an-ip", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}})
	if !errors.Is(err, ErrInvalidSourceIP) {
		t.Fatalf("want ErrInvalidSourceIP, got %v", err)
	}
}

// TestNameDeterministicAndStable: the name depends only on scope+source+target, is
// stable across calls, independent of the audit-only fields (cookie/tier/reason),
// and differs when any identifying field differs.
func TestNameDeterministicAndStable(t *testing.T) {
	base := Params{Scope: "s", SourceIP: "10.0.0.235", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}
	n1 := Name(base)
	// Same identity, different audit fields → same name (Apply/Release must match).
	n2 := Name(Params{Scope: "s", SourceIP: "10.0.0.235", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}, SocketCookie: 999, Tier: "2", Reason: "rate-limit"})
	if n1 != n2 {
		t.Fatalf("name must ignore audit fields: %s != %s", n1, n2)
	}
	// Different source → different name.
	if Name(Params{Scope: "s", SourceIP: "10.0.0.236", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}) == n1 {
		t.Fatal("different source produced the same name")
	}
	// Different scope → different name (scope isolation, rule 5).
	if Name(Params{Scope: "other", SourceIP: "10.0.0.235", TargetNamespace: "default", TargetLabels: map[string]string{"app": "srv"}}) == n1 {
		t.Fatal("different scope produced the same name")
	}
	// Different target → different name.
	if Name(Params{Scope: "s", SourceIP: "10.0.0.235", TargetNamespace: "default", TargetLabels: map[string]string{"app": "other"}}) == n1 {
		t.Fatal("different target produced the same name")
	}
}

func ingressRule(t *testing.T, obj interface{ UnstructuredContent() map[string]interface{} }) map[string]interface{} {
	t.Helper()
	spec := obj.UnstructuredContent()["spec"].(map[string]interface{})
	deny := spec["ingressDeny"].([]interface{})
	if len(deny) != 1 {
		t.Fatalf("want exactly one ingressDeny rule, got %d", len(deny))
	}
	return deny[0].(map[string]interface{})
}
