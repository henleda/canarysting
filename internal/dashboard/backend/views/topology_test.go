package views

import (
	"encoding/json"
	"testing"
)

// DeriveTopology shapes a populated tap view: empty slices stay empty (never
// null), the staged caption is attached, valid edges pass through, and an edge
// with a dangling endpoint (no matching node) is dropped.
func TestDeriveTopologyShapeStable(t *testing.T) {
	raw := TopologyTapView{
		Scope:        "s",
		StagedLabels: true,
		Nodes: []TopologyNodeView{
			{ID: "caller:10.0.0.1", Label: "web-client", Kind: "caller"},
			{ID: "svc:10.0.0.2:8002", Label: "api", Kind: "service"},
			{ID: "decoy:fake_secret", Label: "fake_secret", Kind: "decoy"},
		},
		Edges: []TopologyEdgeView{
			{SrcID: "caller:10.0.0.1", DstID: "svc:10.0.0.2:8002", Port: 8002, Class: "learned", FlowCount: 3},
			{SrcID: "touch-src:0x9", DstID: "decoy:fake_secret", Class: "decoy_touch"}, // dangling src -> dropped
		},
	}
	v := DeriveTopology(raw)

	if v.Scope != "s" || !v.StagedLabels {
		t.Fatalf("scope/staged_labels not carried: %+v", v)
	}
	if v.Caption != topologyStagedCaption {
		t.Fatalf("staged caption wrong: %q", v.Caption)
	}
	if len(v.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(v.Nodes))
	}
	// Only the learned edge survives; the decoy_touch edge had no source node.
	if len(v.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 (dangling-endpoint edge dropped)", len(v.Edges))
	}
	if v.Edges[0].Class != "learned" || v.Edges[0].FlowCount != 3 {
		t.Fatalf("surviving edge wrong: %+v", v.Edges[0])
	}
}

// An empty tap view yields empty (non-null) slices and the UNLABELED caption.
func TestDeriveTopologyEmptyIsNonNull(t *testing.T) {
	v := DeriveTopology(TopologyTapView{Scope: "s", StagedLabels: false})
	if v.Caption != topologyUnlabeledCaption {
		t.Fatalf("unlabeled caption wrong: %q", v.Caption)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// Slices must serialize as [] not null, so the frontend never branches on null.
	var probe struct {
		Nodes json.RawMessage `json:"nodes"`
		Edges json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	if string(probe.Nodes) != "[]" || string(probe.Edges) != "[]" {
		t.Fatalf("empty slices serialized as %s / %s, want [] / []", probe.Nodes, probe.Edges)
	}
}

// A decoy_touch edge whose BOTH endpoints exist survives — the money-shot edge
// must render (the source node is the touching identity, the dst is the decoy).
func TestDeriveTopologyKeepsValidTouchEdge(t *testing.T) {
	raw := TopologyTapView{
		Scope:        "s",
		StagedLabels: true,
		Nodes: []TopologyNodeView{
			{ID: "touch-src:0x9", Label: "0x9", Kind: "unknown"},
			{ID: "decoy:planted_credential", Label: "planted_credential", Kind: "decoy"},
		},
		Edges: []TopologyEdgeView{
			{SrcID: "touch-src:0x9", DstID: "decoy:planted_credential", Class: "decoy_touch", FlowCount: 1},
		},
	}
	v := DeriveTopology(raw)
	if len(v.Edges) != 1 || v.Edges[0].Class != "decoy_touch" {
		t.Fatalf("valid decoy_touch edge not kept: %+v", v.Edges)
	}
}
