package tap

// F1 learned east-west topology — the READ-SIDE data path (slice 3; see
// docs/TOPOLOGY_AND_DEVIANTS.md §3, §5, §6). GET /raw/topology emits a
// TopologyView built from THREE local-only sources, all per-scope (Rule 5):
//
//   1. the engine's live in-memory learned topology map (the un-hashed directed
//      edges + node catalog) via Aggregator.TopologySnapshot — the REAL observed
//      graph SHAPE and volumes;
//   2. the node-identity resolver (internal/topology/identity), which turns each
//      raw IP/port/SPIFFE into a human-legible {Label, Kind}. The resolver is
//      OPERATOR-DECLARED metadata, NOT an engine verdict, and is nil-tolerant: a
//      nil resolver degrades every node to its IP label (staged_labels=false);
//   3. the canary catalog's decoy types, injected as decoy nodes in the negative
//      space, with a highlighted source->decoy edge for each RECENT real
//      canary-touch event (boltevents, Tier>=1: CanaryType -> decoy node, the
//      touching flow identity -> source node).
//
// CLEAN-FABRIC RULE (the view shows the DECLARED east-west fabric): a learned edge
// is kept ONLY when BOTH endpoints resolve to a NAMED identity (a declared service
// or caller, or the declared ingress gateway). Unresolved management-plane / infra
// flows (the engine gRPC :50051, the tap :8088, the dashboard — none of which an
// operator names) are OMITTED for clarity; they would otherwise clutter the fabric
// with anonymous IP nodes. The decoy ring and the source->decoy touch edges are
// EXEMPT from this filter (the touch-src is ONE synthesized addressless unknown by
// design; the decoy is kind=decoy) — they always render. A NAMED identity that appears as BOTH
// an edge source (its egress, port 0) AND an edge destination (its listen port)
// coalesces to ONE node, keyed by its label+kind — so the dual-role split (a
// service that both initiates and serves) collapses into a single fabric node, and
// the two ingress endpoints (the accept address + the upstream-bind source) merge
// into ONE "ingress-gateway" node.
//
// RULES (load-bearing):
//   - Rule 8 (read-side only): nothing here arms a response. The touch edges are
//     drawn from events that ALREADY entered the response pipeline; surfacing them
//     on a map takes no new action.
//   - Rule 9 (local): the raw IPs/labels stay in the deployment. This path lives
//     in the tap + observebaseline, which the cross-customer egress filter
//     (internal/intelligence/network) is STRUCTURALLY forbidden to import (see its
//     egress_importguard_test.go). No topology data is ever wired into the egress
//     filter.
//   - HONESTY: staged_labels carries the persistent on-screen caption — node NAMES
//     are operator-registry metadata; the engine baseline is hashed; the graph
//     SHAPE/edges are real observed traffic. NEVER imply the engine natively knows
//     service names, and NEVER imply the map auto-acts.

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/topology/identity"
)

// topologyTouchWindow is how far back a canary-touch event is considered "recent"
// for lighting a source->decoy edge. It mirrors the cross-customer/recon windows
// used elsewhere in the tap (most-recent activity, not deep history) so a touch
// snaps onto the map promptly and ages off when the attacker goes quiet.
const topologyTouchWindow = 30 * time.Minute

// TopologyView is the wire contract for GET /raw/topology, mirrored 1:1 in the
// frontend (dashboard/app/lib/types.ts). The dashboard backend validates + serves
// the SAME shape at GET /api/topology. See docs/TOPOLOGY_AND_DEVIANTS.md §3.
type TopologyView struct {
	Scope string `json:"scope"`
	// StagedLabels drives the persistent honesty caption: true when the node NAMES
	// came from an operator-supplied registry (the demo's topology-identities.json
	// or, in production, the customer's own service registry). When no resolver
	// config is loaded the nodes fall back to IP labels and this is false — the
	// caption then says nothing about a name registry.
	StagedLabels bool           `json:"staged_labels"`
	Nodes        []TopologyNode `json:"nodes"`
	Edges        []TopologyEdge `json:"edges"`
}

// TopologyNode is one identity in the graph. Kind is the resolver's lowercase
// token: "service" | "caller" | "decoy" | "external" | "unknown".
type TopologyNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

// TopologyEdge is one directed adjacency. Class is "learned" (an accrued baseline
// edge), "live" (a currently-open observed flow overlaid — reserved for the live
// overlay), or "decoy_touch" (the highlighted source->decoy edge from a real
// canary-touch — the only edge that ever crosses into the decoy ring).
type TopologyEdge struct {
	SrcID     string    `json:"src_id"`
	DstID     string    `json:"dst_id"`
	Port      uint16    `json:"port"`
	Proto     string    `json:"proto"`
	FlowCount uint64    `json:"flow_count"`
	Bytes     uint64    `json:"bytes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Class     string    `json:"class"`
}

const (
	edgeClassLearned    = "learned"
	edgeClassLive       = "live"
	edgeClassDecoyTouch = "decoy_touch"
)

// handleTopology serves GET /raw/topology: the per-scope learned-topology view.
func (s *Source) handleTopology(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.buildTopology(s.now()))
}

// buildTopology assembles the TopologyView from the live in-memory map, the node
// resolver, and the canary decoy injection. It is total: a nil aggregator yields
// an empty graph, a nil resolver degrades to IP labels, and a nil events store
// just omits the decoy-touch edges — every dependency is nil-tolerant.
func (s *Source) buildTopology(now time.Time) TopologyView {
	view := TopologyView{
		Scope:        string(s.Scope),
		StagedLabels: s.Resolver != nil,
		Nodes:        []TopologyNode{},
		Edges:        []TopologyEdge{},
	}
	resolver := s.Resolver
	if resolver == nil {
		resolver = identity.NewResolver(nil) // degrade to IP labels; never panics
	}

	// nodes is the dedup set keyed by node ID, so an identity that is both an
	// initiator and a reached service collapses to one node.
	nodes := map[string]TopologyNode{}
	addNode := func(n TopologyNode) {
		if _, ok := nodes[n.ID]; !ok {
			nodes[n.ID] = n
		}
	}

	// (1) The learned graph: edges from the accrued map, resolved + coalesced.
	// Nodes are derived from the edge ENDPOINTS we actually keep (NOT from
	// snap.Nodes — the catalog's node list carries a service's initiator and
	// service entries separately, the dual-role split that produced orphan/dup
	// nodes). Resolving each endpoint and coalescing by identity collapses that
	// split, and the clean-fabric filter drops any edge touching an unnamed
	// (management-plane/infra) endpoint.
	if s.Aggregator != nil {
		snap := s.Aggregator.TopologySnapshot(s.Scope)
		for _, e := range snap.Edges {
			srcIP := addrFrom(e.SrcIP)
			dstIP := addrFrom(e.DstIP)
			// Resolve the SrcIP as an initiator (port 0 — its egress side) and the
			// DstIP as a service on DstPort (its listen side). With the distinct-
			// identity demo scheme each is named by IP alone, so a service that both
			// initiates and serves resolves to the same {label,kind} on both sides
			// and coalesces to ONE node.
			srcNode := resolver.Resolve(srcIP, 0, "", "")
			dstNode := resolver.Resolve(dstIP, e.DstPort, "", "")
			// Clean-fabric filter: keep the edge ONLY if BOTH endpoints are named.
			if srcNode.Kind == identity.KindUnknown || dstNode.Kind == identity.KindUnknown {
				continue
			}
			srcID := coalescedNodeID(srcNode, srcIP, 0)
			dstID := coalescedNodeID(dstNode, dstIP, e.DstPort)
			addNode(TopologyNode{ID: srcID, Label: srcNode.Label, Kind: srcNode.Kind.String()})
			addNode(TopologyNode{ID: dstID, Label: dstNode.Label, Kind: dstNode.Kind.String()})
			view.Edges = append(view.Edges, TopologyEdge{
				SrcID:     srcID,
				DstID:     dstID,
				Port:      e.DstPort,
				Proto:     "tcp",
				FlowCount: e.FlowCount,
				Bytes:     e.TotalBytes,
				FirstSeen: e.FirstSeen,
				LastSeen:  e.LastSeen,
				Class:     edgeClassLearned,
			})
		}
	}

	// (2) Decoy nodes in the negative space: one per canary catalog type. They have
	// ZERO learned in-edges (the mesh never serves canary paths) — they sit in the
	// ring precisely because nothing learned reaches them. Injected unconditionally
	// so the ring is always present; a source->decoy edge lights only on a real
	// touch (below).
	for _, ct := range catalogTypes(s.Catalog) {
		addNode(TopologyNode{
			ID:    decoyNodeID(ct),
			Label: string(ct),
			Kind:  identity.KindDecoy.String(),
		})
	}

	// (3) Source->decoy touch edges from RECENT real canary-touch events (Tier>=1).
	// The events are addressless by design (only the socket cookie), so ALL touching
	// flows collapse into ONE synthesized unknown-kind source node, with one bright
	// edge per TOUCHED CanaryType (FlowCount = total touches of that type). This is
	// the "flows reached into negative space" visual and the ONLY edge class that
	// crosses into the decoy ring. The src node is added directly (filter-exempt).
	for _, te := range s.recentTouchEdges(now) {
		addNode(te.src)
		view.Edges = append(view.Edges, te.edge)
	}

	view.Nodes = make([]TopologyNode, 0, len(nodes))
	for _, n := range nodes {
		view.Nodes = append(view.Nodes, n)
	}
	return view
}

// touchEdge bundles a synthesized source node with its source->decoy edge.
type touchEdge struct {
	src  TopologyNode
	edge TopologyEdge
}

// recentTouchEdges reads recent canary-touch events (Tier>=1) and AGGREGATES them
// into ONE synthesized source node plus ONE source->decoy edge per TOUCHED
// CanaryType (FIX-2). The events are addressless by design (only the socket
// cookie), so there is no real identity to draw — pre-aggregation, N distinct
// cookies produced up to N source nodes and ~N*types edges, which exploded the
// ring (e.g. ~1180 cookies -> ~1180 nodes / ~1563 edges). Here ALL touching flows
// collapse into a single unknown-kind "decoy-armed flows" node, and each touched
// decoy type gets one edge whose FlowCount is the TOTAL touches of that type
// (summed across cookies); the distinct-cookie (distinct-flow) count is carried in
// the node label/sub-count for honesty ("N flows reached these decoys" — never
// "confirmed adversaries"). So the ring shows at most ~5 bright edges from one
// source. Window/filter semantics are unchanged (30m window, Tier>=1,
// CanaryType!=""). Returns nothing when there is no events store (nil-tolerant) or
// no recent touch. The source node is filter-EXEMPT (added directly in
// buildTopology), the money-shot that always renders.
func (s *Source) recentTouchEdges(now time.Time) []touchEdge {
	if s.Events == nil {
		return nil
	}
	evs, err := s.Events.Query(string(s.Scope), now.Add(-topologyTouchWindow), now)
	if err != nil || len(evs) == 0 {
		return nil
	}
	srcID := touchSourceNodeID()
	// Per-decoy-type aggregate: total touches, the bright edge being built, and the
	// distinct cookies seen so FlowCount stays per-type while the node label can
	// report the distinct-flow count overall.
	type agg struct {
		idx     int             // index into out
		cookies map[uint64]bool // distinct flows touching this type
	}
	byType := map[string]*agg{}
	distinct := map[uint64]bool{} // distinct flows across all touched types
	var out []touchEdge
	for _, e := range evs {
		if e.Tier < 1 || e.CanaryType == "" {
			continue // only events that entered the response pipeline, with a known decoy
		}
		distinct[e.FlowID] = true
		dID := decoyNodeID(contract.CanaryType(e.CanaryType))
		a := byType[dID]
		if a == nil {
			a = &agg{idx: len(out), cookies: map[uint64]bool{}}
			byType[dID] = a
			out = append(out, touchEdge{
				edge: TopologyEdge{
					SrcID:     srcID,
					DstID:     dID,
					Proto:     "decoy",
					FlowCount: 0,
					FirstSeen: e.Timestamp,
					LastSeen:  e.Timestamp,
					Class:     edgeClassDecoyTouch,
				},
			})
		}
		a.cookies[e.FlowID] = true
		out[a.idx].edge.FlowCount++ // total touches of THIS type (summed across cookies)
		if e.Timestamp.After(out[a.idx].edge.LastSeen) {
			out[a.idx].edge.LastSeen = e.Timestamp
		}
		if e.Timestamp.Before(out[a.idx].edge.FirstSeen) {
			out[a.idx].edge.FirstSeen = e.Timestamp
		}
	}
	if len(out) == 0 {
		return nil
	}
	// One shared synthesized source node for every touch edge (addNode dedups by id,
	// so it collapses to a single node). It is addressless (the event carries no raw
	// address — Rule 9 on the egress-bound event), hence unknown-kind. The label
	// reports the distinct-flow count, honest about WHAT was observed: flows reached
	// these decoys — never "confirmed adversaries".
	src := TopologyNode{
		ID:    srcID,
		Label: touchSourceLabel(len(distinct)),
		Kind:  identity.KindUnknown.String(),
	}
	for i := range out {
		out[i].src = src
	}
	return out
}

// touchSourceLabel renders the aggregated touch-source node label from the count of
// DISTINCT touching flows. Honest framing: "N flows reached these decoys", never a
// claim of confirmed adversaries.
func touchSourceLabel(distinctFlows int) string {
	if distinctFlows == 1 {
		return "decoy-armed flows · 1 flow"
	}
	return "decoy-armed flows · " + strconv.Itoa(distinctFlows) + " flows"
}

// catalogTypes returns the canary types to render as decoy nodes. When a catalog
// is wired it uses its registered types (the authoritative 5); otherwise it falls
// back to the five stable type identifiers so the ring is present even without a
// catalog handle (nil-tolerant).
func catalogTypes(c *catalog.Catalog) []contract.CanaryType {
	if c != nil {
		return c.Types()
	}
	return []contract.CanaryType{
		catalog.TypePlantedCredential,
		catalog.TypeFakeSecret,
		catalog.TypeDecoyFile,
		catalog.TypeFakeBucket,
		catalog.TypeFakeEndpoint,
	}
}

// addrFrom builds a netip.Addr from the canonical 4- or 16-byte address slice the
// snapshot carries. An odd-length / empty slice yields an invalid Addr, which the
// resolver degrades to an anonymous Unknown node — never a panic.
func addrFrom(b []byte) netip.Addr {
	switch len(b) {
	case 4:
		var a4 [4]byte
		copy(a4[:], b)
		return netip.AddrFrom4(a4)
	case 16:
		var a16 [16]byte
		copy(a16[:], b)
		return netip.AddrFrom16(a16).Unmap()
	default:
		return netip.Addr{}
	}
}

// coalescedNodeID is the stable ID for a learned-edge endpoint.
//
//   - For a NAMED node (Kind != KindUnknown — a declared service/caller/external)
//     the id is keyed by IDENTITY (label+kind), NOT by address+port. So the SAME
//     identity appearing as an edge source (its egress, port 0) AND an edge
//     destination (its listen port) coalesces into ONE node, and the two declared
//     ingress endpoints (the accept address + the upstream-bind source) — both
//     named "ingress-gateway" — merge into a single ingress node.
//   - For an UNKNOWN node the id is keyed by address+port so distinct infra
//     endpoints stay distinct. (In practice the clean-fabric filter drops edges
//     touching an unknown endpoint, so this branch is only reachable if a future
//     caller keeps unknown endpoints; it is kept correct regardless.)
func coalescedNodeID(node identity.Node, ip netip.Addr, port uint16) string {
	if node.Kind != identity.KindUnknown {
		return "id:" + node.Kind.String() + ":" + node.Label
	}
	addr := ""
	if ip.IsValid() {
		addr = ip.String()
	}
	return "ip:" + addr + ":" + strconv.Itoa(int(port))
}

func decoyNodeID(t contract.CanaryType) string { return "decoy:" + string(t) }

// touchSourceNodeID is the id of the SINGLE synthesized source node that all
// decoy-touch edges originate from (FIX-2 aggregate). It is no longer per-cookie:
// the events are addressless, so every touching flow collapses into this one
// unknown-kind node.
func touchSourceNodeID() string {
	return "touch-src:armed"
}
