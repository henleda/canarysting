// Package identity resolves a flow's raw network/identity attributes (IP, port,
// SPIFFE ID, source-address hint) to a human-legible topology node — a {Label,
// Kind} pair — for the learned east-west topology (F1; see
// docs/TOPOLOGY_AND_DEVIANTS.md §3 "Node identity model").
//
// It is a PURE LOOKUP over an operator-supplied config. It never errors and
// ALWAYS returns a Node: when nothing matches it degrades to the IP string with
// Kind=External (a routable/foreign address) or Kind=Unknown (a private/loopback
// or unparseable address). It NEVER drops an edge for lack of a label — a missing
// label yields an IP/anonymous node, never a gap in the graph.
//
// HONESTY (load-bearing — the on-screen disclosure lives in the view, slice 3,
// but the intent is fixed here): the topology SHAPE — the nodes, edges, and
// volumes — is REAL observed traffic. Only the NAMES come from this resolver, and
// the names are OPERATOR-DECLARED metadata:
//
//   - In PRODUCTION, the operator map is the customer's OWN service registry /
//     CMDB export (IP/CIDR/port -> name), complemented by SPIFFE service names
//     parsed from the mTLS peer cert the adapter already surfaces. The engine
//     does NOT natively know service names; it knows hashed adjacency. These names
//     are the customer telling us what their own nodes are called.
//   - In the DEMO, the operator map is STAGING metadata (deploy/m7-window/
//     topology-identities.json) declaring the known compose topology — the mesh
//     services by listen port and the caller IPs by role. It is separate from, and
//     must not be confused with, the staged-label calibration ground truth
//     (deploy/m7-window/ground-truth-registry.json, a different concern owned by
//     internal/intelligence/stagedlabel).
//
// This package is PRODUCTION-IMPORTABLE: it operates only on plain IP/port/SPIFFE
// values plus its own config and stdlib. It deliberately does NOT depend on
// internal/intelligence/stagedlabel (a staging-only labeler the production
// cmd/engine cannot import) nor on any engine/adapter internals, so the dashboard
// backend AND the engine can both use it. See importguard_test.go.
package identity

import (
	"net/netip"
	"strings"
)

// NodeKind classifies a resolved topology node. It drives how the node renders
// (its class/ring) in the graph view (slice 3); it carries no behavior here.
type NodeKind int

const (
	// KindUnknown is the conservative fallback: a node we could not name AND
	// whose address is private/loopback/unspecified or did not parse — i.e. we
	// can say nothing trustworthy about it. It is the zero value.
	KindUnknown NodeKind = iota
	// KindService is an internal/served node: a mesh service endpoint, named by
	// an operator entry of kind "service" or derived from a SPIFFE service name.
	KindService
	// KindCaller is an initiator/client identity named by an operator entry of
	// kind "caller" (a benign caller, a batch worker, or a declared adversary —
	// the name is operator metadata, NOT an engine verdict).
	KindCaller
	// KindDecoy is a canary/decoy node. The resolver never PRODUCES this kind
	// (decoys are injected from the seeder registry in slice 3); it is defined
	// here so the node-kind vocabulary is single-sourced for the whole feature.
	KindDecoy
	// KindExternal is an unnamed node whose address parses as a NON-private,
	// foreign/routable address — a plausible off-mesh peer. Labeled by its IP.
	KindExternal
)

// String renders the kind as the lowercase token the view/tap serialize.
func (k NodeKind) String() string {
	switch k {
	case KindService:
		return "service"
	case KindCaller:
		return "caller"
	case KindDecoy:
		return "decoy"
	case KindExternal:
		return "external"
	default:
		return "unknown"
	}
}

// Node is the resolved identity of one endpoint in the topology: a human-legible
// Label and its Kind. It is always populated (never a zero-value gap).
type Node struct {
	// Label is the human-legible name: an operator-declared name, a SPIFFE-derived
	// service name, or — on a miss — the IP string itself.
	Label string
	// Kind is the node's class. See NodeKind.
	Kind NodeKind
}

// Resolver turns raw flow attributes into a named Node via a pure lookup over its
// loaded Config. It holds no scope/learned state and is safe for concurrent reads
// (it is never mutated after construction). The zero Resolver (or one built from
// an empty/nil config) is valid and degrades every lookup gracefully.
type Resolver struct {
	// ipPort maps an exact (ip,port) endpoint to its declared node. Highest
	// precedence — disambiguates a single host that serves several named services
	// on distinct ports (the demo's all-loopback mesh).
	ipPort map[ipPortKey]Node
	// ip maps an exact host IP to its declared node (any port).
	ip map[netip.Addr]Node
	// cidrs are CIDR-range entries, evaluated most-specific-first (longest prefix
	// wins) so a /32-ish narrow block beats an enclosing /16.
	cidrs []cidrEntry
	// ports maps a bare listen/destination port to its declared node — the
	// port-only entry that names a service independent of which loopback IP it
	// sits on (the demo mesh is all 127.0.0.1, so the PORT is the discriminator).
	ports map[uint16]Node
}

type ipPortKey struct {
	addr netip.Addr
	port uint16
}

type cidrEntry struct {
	prefix netip.Prefix
	node   Node
}

// NewResolver builds a Resolver from a parsed Config. A nil/empty config yields a
// resolver where every lookup degrades to the IP fallback — valid, never nil.
func NewResolver(cfg *Config) *Resolver {
	r := &Resolver{
		ipPort: map[ipPortKey]Node{},
		ip:     map[netip.Addr]Node{},
		ports:  map[uint16]Node{},
	}
	if cfg == nil {
		return r
	}
	for _, e := range cfg.Entries {
		node := Node{Label: e.Name, Kind: e.kind}
		switch {
		case e.addr.IsValid() && e.hasPort:
			r.ipPort[ipPortKey{addr: e.addr.Unmap(), port: e.Port}] = node
		case e.addr.IsValid():
			r.ip[e.addr.Unmap()] = node
		case e.prefix.IsValid():
			r.cidrs = append(r.cidrs, cidrEntry{prefix: e.prefix, node: node})
		case e.hasPort:
			r.ports[e.Port] = node
		}
	}
	// Most-specific-first so the longest matching prefix wins regardless of file
	// order: sort by descending prefix bits (insertion sort — entry counts are
	// tiny: an operator map is dozens of CIDRs, not thousands).
	for i := 1; i < len(r.cidrs); i++ {
		for j := i; j > 0 && r.cidrs[j].prefix.Bits() > r.cidrs[j-1].prefix.Bits(); j-- {
			r.cidrs[j], r.cidrs[j-1] = r.cidrs[j-1], r.cidrs[j]
		}
	}
	return r
}

// Resolve names the endpoint (ip, port) with optional SPIFFE ID and source-address
// hint. It is total: it always returns a populated Node and never errors.
//
// PRECEDENCE (highest -> lowest; the first that matches wins):
//
//  1. exact (ip,port) operator entry      — a named service on a specific host:port
//  2. exact ip operator entry             — a named host (any port)
//  3. CIDR operator entry                 — a named range (longest prefix wins)
//  4. port-only operator entry            — a named service by listen port (the
//     all-loopback demo mesh: the PORT is the discriminator, not the IP)
//  5. SPIFFE-derived service name         — from the mTLS peer cert (Kind=Service)
//  6. FALLBACK: the IP string itself      — Kind=External if the addr parses as a
//     non-private/foreign address, else Kind=Unknown (private/loopback/unparseable)
//
// The srcAddr hint (contract.AttrSourceAddress, the adapter-stamped caller IP) is
// used only as a fallback IP when ip is invalid — so a flow that arrives with the
// caller's address in L7 attributes but no parsed netip can still be named/labeled.
func (r *Resolver) Resolve(ip netip.Addr, port uint16, spiffe, srcAddr string) Node {
	ip = ip.Unmap()

	// If no usable netip was supplied, fall back to the adapter's source-address
	// hint so an L7-only flow can still be resolved/labeled by address.
	if !ip.IsValid() && srcAddr != "" {
		if a, err := netip.ParseAddr(srcAddr); err == nil {
			ip = a.Unmap()
		}
	}

	if ip.IsValid() {
		// (1) exact (ip,port)
		if n, ok := r.ipPort[ipPortKey{addr: ip, port: port}]; ok {
			return n
		}
		// (2) exact ip
		if n, ok := r.ip[ip]; ok {
			return n
		}
		// (3) CIDR (longest prefix first)
		for _, c := range r.cidrs {
			if c.prefix.Contains(ip) {
				return c.node
			}
		}
	}

	// (4) port-only
	if port != 0 {
		if n, ok := r.ports[port]; ok {
			return n
		}
	}

	// (5) SPIFFE-derived service name
	if name, ok := ServiceNameFromSPIFFE(spiffe); ok {
		return Node{Label: name, Kind: KindService}
	}

	// (6) fallback: the IP string, classified by routability.
	return fallbackNode(ip)
}

// fallbackNode is the never-drop degrade: a valid address becomes its IP string,
// classed External if it is a routable/foreign address or Unknown if it is
// private/loopback/link-local/unspecified (we can say nothing trustworthy about a
// node on our own private space that no operator entry named). An invalid address
// is an anonymous Unknown node with an empty label.
func fallbackNode(ip netip.Addr) Node {
	if !ip.IsValid() {
		return Node{Label: "", Kind: KindUnknown}
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return Node{Label: ip.String(), Kind: KindUnknown}
	}
	return Node{Label: ip.String(), Kind: KindExternal}
}

// ServiceNameFromSPIFFE parses a SPIFFE ID of the SPIFFE Workload-API shape and
// derives a human-legible service name. It recognizes the SVID path conventions:
//
//	spiffe://<trust-domain>/ns/<ns>/sa/<svc>   -> "<ns>/<svc>"
//	spiffe://<trust-domain>/sa/<svc>           -> "<svc>"
//	spiffe://<trust-domain>/ns/<ns>            -> "<ns>"  (namespace-only SVID)
//
// As a tolerant fallback for IDs that carry neither marker, it uses the last
// non-empty path segment (e.g. spiffe://td/workload/payments -> "payments"). It
// returns ok=false only when the input is not a parseable spiffe:// URI with a
// trust domain and at least one path segment — the caller then continues down the
// precedence chain to the IP fallback. Never errors.
func ServiceNameFromSPIFFE(id string) (string, bool) {
	const scheme = "spiffe://"
	if !strings.HasPrefix(id, scheme) {
		return "", false
	}
	rest := id[len(scheme):]
	// Split trust domain from the path.
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", false // trust domain only, no path -> no service name
	}
	trustDomain := rest[:slash]
	pathPart := strings.Trim(rest[slash:], "/")
	if trustDomain == "" || pathPart == "" {
		return "", false
	}

	segs := strings.Split(pathPart, "/")
	var ns, svc string
	for i := 0; i+1 < len(segs); i += 2 {
		switch segs[i] {
		case "ns":
			ns = segs[i+1]
		case "sa":
			svc = segs[i+1]
		}
	}
	switch {
	case ns != "" && svc != "":
		return ns + "/" + svc, true
	case svc != "":
		return svc, true
	case ns != "":
		return ns, true
	}
	// Tolerant fallback: last non-empty segment.
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" {
			return segs[i], true
		}
	}
	return "", false
}
