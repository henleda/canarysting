package views

// F1 learned east-west topology — the dashboard-backend view (slice 3; see
// docs/TOPOLOGY_AND_DEVIANTS.md §3, §6). The backend fetches the tap's
// GET /raw/topology, validates/normalizes the shape here, and serves it at
// GET /api/topology. This is the read-side mirror of the tap's TopologyView; the
// backend talks to the engine ONLY over HTTP, so it keeps a LOCAL mirror of the
// wire types rather than importing the tap package (read-only by construction).
//
// HONESTY (load-bearing): the view carries a persistent Caption driven by
// StagedLabels. The graph SHAPE/edges/volumes are REAL observed traffic; only the
// node NAMES are operator-registry metadata. The engine never natively knows
// service names (it knows hashed adjacency), and the map NEVER auto-acts (Rule 8).

// topologyStagedCaption is the persistent on-screen honesty fence shown when node
// labels came from an operator registry (staged_labels=true). It is verbatim the
// fence the panel will test (docs/TOPOLOGY_AND_DEVIANTS.md §5 fence 1). It states
// the view is the DECLARED east-west fabric (the named services/callers + the
// ingress gateway) and that unresolved management-plane flows are omitted for
// clarity — never implying the engine knows names or that the map auto-acts.
const topologyStagedCaption = "Declared east-west fabric: edges connect the operator-registry services, callers, and ingress gateway; unresolved management-plane flows are omitted for clarity. Node NAMES come from the operator registry; the engine baseline is hashed and the graph SHAPE/edges are real observed traffic. In production this is drawn from your own service registry, not ours."

// topologyUnlabeledCaption is shown when NO operator registry is loaded
// (staged_labels=false): the nodes are IP labels, so the caption must NOT claim a
// name registry. With nothing named, the clean-fabric filter omits the unresolved
// management-plane flows and the learned fabric is empty; the decoy ring still
// renders. The shape/edges that do show are still real observed traffic.
const topologyUnlabeledCaption = "No node-name registry loaded: nodes are labeled by raw IP and unresolved management-plane flows are omitted for clarity. The graph SHAPE/edges are real observed traffic; the engine baseline is hashed. In production this is drawn from your own service registry."

// topologyEmptyFabricCaption is shown when a registry IS loaded (staged_labels=true)
// but ZERO named east-west edges survived the clean-fabric filter — only the decoy
// ring (and any canary-touch) remains. Without this, the assertive staged caption
// would claim observed named edges that are not on screen — an overclaim. This
// makes the empty case honest rather than fabricating a populated fabric.
const topologyEmptyFabricCaption = "No named east-west edges observed yet in this scope — only the canary decoy ring (and any canary touch) is shown; the legit mesh never touches it. Node NAMES come from the operator registry; the graph SHAPE/edges are real observed traffic. In production this is drawn from your own service registry, not ours."

// TopologyNodeView is one node in the learned graph. Kind is the resolver token:
// "service" | "caller" | "decoy" | "external" | "unknown".
type TopologyNodeView struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

// TopologyEdgeView is one directed adjacency. Class is "learned" | "live" |
// "decoy_touch". A decoy_touch is the highlighted source->decoy edge from a real
// canary touch — the only edge that crosses into the decoy ring.
type TopologyEdgeView struct {
	SrcID     string `json:"src_id"`
	DstID     string `json:"dst_id"`
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`
	FlowCount uint64 `json:"flow_count"`
	Bytes     uint64 `json:"bytes"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Class     string `json:"class"`
}

// TopologyTapView mirrors the tap's wire shape (GET /raw/topology) for decoding.
// Timestamps are RFC3339 strings on the wire; kept as strings here (the backend
// does not re-time them — it validates and passes the shape through).
type TopologyTapView struct {
	Scope        string             `json:"scope"`
	StagedLabels bool               `json:"staged_labels"`
	Nodes        []TopologyNodeView `json:"nodes"`
	Edges        []TopologyEdgeView `json:"edges"`
}

// TopologyView is the served shape at GET /api/topology. It is the validated tap
// view plus the derived honesty Caption. It IS the contract the Next.js frontend
// consumes (dashboard/app/lib/types.ts).
type TopologyView struct {
	Scope        string             `json:"scope"`
	StagedLabels bool               `json:"staged_labels"`
	Caption      string             `json:"caption"`
	Nodes        []TopologyNodeView `json:"nodes"`
	Edges        []TopologyEdgeView `json:"edges"`
}

// DeriveTopology validates/normalizes the tap's raw topology view into the served
// TopologyView. It is total: nil node/edge slices become empty (never JSON null),
// it drops any edge whose endpoints do not BOTH resolve to a node in the set (so
// the frontend never has to render a dangling edge), and it attaches the honesty
// caption driven by staged_labels. The graph data itself is never fabricated —
// only shape-validated.
func DeriveTopology(raw TopologyTapView) TopologyView {
	v := TopologyView{
		Scope:        raw.Scope,
		StagedLabels: raw.StagedLabels,
		Nodes:        []TopologyNodeView{},
		Edges:        []TopologyEdgeView{},
	}

	known := make(map[string]struct{}, len(raw.Nodes))
	for _, n := range raw.Nodes {
		if n.ID == "" {
			continue // a node without an ID cannot be referenced; drop it
		}
		if _, dup := known[n.ID]; dup {
			continue // dedup defensively (the tap already dedups)
		}
		known[n.ID] = struct{}{}
		v.Nodes = append(v.Nodes, n)
	}
	hasLearnedFabric := false
	for _, e := range raw.Edges {
		if _, ok := known[e.SrcID]; !ok {
			continue
		}
		if _, ok := known[e.DstID]; !ok {
			continue
		}
		if e.Class == "learned" {
			hasLearnedFabric = true // a named east-west edge actually survived
		}
		v.Edges = append(v.Edges, e)
	}

	// Caption AFTER the edge filter so it reflects what is ACTUALLY on screen: an
	// assertive "declared fabric" claim must never sit beside a graph that is only
	// the decoy ring (the staged_labels-true-but-empty case — see the on-box
	// caller-source-rewrite risk in docs/TOPOLOGY_AND_DEVIANTS.md).
	switch {
	case !raw.StagedLabels:
		v.Caption = topologyUnlabeledCaption
	case hasLearnedFabric:
		v.Caption = topologyStagedCaption
	default:
		v.Caption = topologyEmptyFabricCaption
	}
	return v
}
