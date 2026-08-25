//go:build linux

// Command cookiespike is a THROWAWAY diagnostic spike (not production code) that
// empirically tests whether CanarySting's socket-cookie L7<->kernel join
// (AGENTS.md rule 4, docs/IDENTITY.md) survives inside Kubernetes pod network
// namespaces under a CNI. It loads and attaches the real sockops eBPF program via
// the repo's own bpf/sockops.NewMapResolver, dumps every entry the kernel writes
// into the flow_cookies map, and — the actual join assertion — reconstructs a map
// key from a source/destination 4-tuple EXACTLY as the Envoy ext_proc adapter does
// (identity.TupleFromAddrs + MapResolver.Resolve) and reports the resolved cookie.
//
// Background: the sockops program captures on BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB —
// the SERVER accept-side socket. The stored key is {src = REMOTE end (the client),
// dst = LOCAL end (the server)}. So for a flow client->server:port the key is
//
//	src = client_ip:client_ephemeral_port ,  dst = server_ip:server_port
//
// See sockops.bpf.c build_key(): ports are stored HOST byte order; the 16-byte IP
// fields hold the address octets in IP order (IPv4 in the first 4 bytes), exactly
// what netip.As4()/As16() produce — so the dump decodes them by raw copy.
//
// Build for the DGX (linux/arm64) — the whole point — with:
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/cookiespike ./cmd/cookiespike
//
// Run on the node (needs CAP_BPF/CAP_NET_ADMIN + a cgroup-v2 unified hierarchy):
//
//	sudo /tmp/cookiespike -cgroup /sys/fs/cgroup
//	sudo /tmp/cookiespike -cgroup /sys/fs/cgroup -resolve '10.42.0.6:12345->10.42.0.5:80'
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/bpf/sockops"
)

// flowKey / flowVal are byte-for-byte copies of the bpf2go-generated
// sockopsFlowKey / sockopsFlowVal (which mirror the C flow_key / flow_val the
// kernel program writes). We redeclare them here only because those generated
// types are unexported; a layout drift would be caught by the repo's own
// bpf/sockops layout_test.go. Field order/types/sizes MUST match exactly so
// cilium/ebpf unmarshals the raw kernel bytes correctly.
type flowKey struct {
	Family  uint16
	SrcPort uint16 // host byte order (already normalized by the sockops program)
	DstPort uint16 // host byte order
	Pad     uint16
	SrcIP   [16]byte // address octets in IP order; IPv4 in first 4 bytes
	DstIP   [16]byte
}

type flowVal struct {
	Cookie     uint64
	CgroupID   uint64
	PID        uint32
	Generation uint32
}

// repeatable -resolve flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	log.SetFlags(log.Ltime)

	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup-v2 unified hierarchy path to attach the sockops program to")
	interval := flag.Duration("interval", time.Second, "how often to dump the flow_cookies map")
	var resolves stringList
	flag.Var(&resolves, "resolve", "join assertion: 'SRCIP:SPORT->DSTIP:DPORT' — reconstruct the adapter's map key and report the cookie (repeatable)")
	flag.Parse()

	// Parse the -resolve tuples up front so bad input fails before we touch the kernel.
	type probe struct {
		raw string
		ft  identity.FourTuple
	}
	var probes []probe
	for _, r := range resolves {
		ft, err := parseResolve(r)
		if err != nil {
			log.Fatalf("bad -resolve %q: %v", r, err)
		}
		probes = append(probes, probe{raw: r, ft: ft})
	}

	// Load + attach the REAL sockops program via the repo's own loader. This runs
	// the kernel-version pin (kernel.AssertSocketCookie) and attaches
	// AttachCGroupSockOps at cgroup — the identical path the datapath uses.
	res, err := sockops.NewMapResolver(*cgroup)
	if err != nil {
		log.Fatalf("NewMapResolver(%q): %v\n(need root/CAP_BPF+CAP_NET_ADMIN, a cgroup-v2 unified hierarchy, and kernel >= 5.10)", *cgroup, err)
	}
	defer res.Close()
	log.Printf("attached sockops to cgroup %s — capturing PASSIVE_ESTABLISHED (server accept-side) cookies", *cgroup)

	fcMap, err := flowCookiesMap(res)
	if err != nil {
		log.Fatalf("could not reach flow_cookies map for dumping: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(*interval)
	defer tick.Stop()

	report := func() {
		dumpMap(fcMap)
		for _, p := range probes {
			assertResolve(res, p.raw, p.ft)
		}
	}

	log.Printf("dumping every %s; Ctrl-C to stop and dump a final time", *interval)
	report()
	for {
		select {
		case <-tick.C:
			report()
		case <-sig:
			fmt.Println("--- final dump (SIGINT) ---")
			report()
			return
		}
	}
}

// flowCookiesMap extracts the *ebpf.Map behind the (unexported) MapResolver.objs
// .FlowCookies field so the spike can iterate the whole map. This reflect reach-in
// exists ONLY because this is a throwaway spike that must not modify the repo; the
// production adapter never needs to enumerate the map (it only Resolve()s single
// keys). We deliberately reuse the SAME loaded map instance the resolver populates
// so the dump and the -resolve assertion observe identical kernel state.
func flowCookiesMap(res *sockops.MapResolver) (*ebpf.Map, error) {
	v := reflect.ValueOf(res).Elem()
	f := v.FieldByName("objs")
	if !f.IsValid() {
		return nil, fmt.Errorf("MapResolver.objs field not found (struct changed?)")
	}
	f = f.FieldByName("FlowCookies")
	if !f.IsValid() {
		return nil, fmt.Errorf("objs.FlowCookies field not found (struct changed?)")
	}
	// Rebuild a non-read-only Value at the field's address so .Interface() is legal.
	mv := reflect.NewAt(f.Type(), f.Addr().UnsafePointer()).Elem()
	m, ok := mv.Interface().(*ebpf.Map)
	if !ok || m == nil {
		return nil, fmt.Errorf("FlowCookies is not a non-nil *ebpf.Map")
	}
	return m, nil
}

// dumpMap prints every entry currently in flow_cookies.
func dumpMap(m *ebpf.Map) {
	var k flowKey
	var val flowVal
	it := m.Iterate()
	n := 0
	for it.Next(&k, &val) {
		fmt.Printf("  %s:%d -> %s:%d  cookie=%d\n",
			ipString(k.Family, k.SrcIP), k.SrcPort,
			ipString(k.Family, k.DstIP), k.DstPort,
			val.Cookie)
		n++
	}
	if err := it.Err(); err != nil {
		log.Printf("iterate error: %v", err)
	}
	log.Printf("flow_cookies: %d entr%s", n, plural(n))
}

// assertResolve runs the faithful join test: it builds the map key EXACTLY as the
// Envoy adapter does and reports whether it resolves to a non-zero cookie.
func assertResolve(res *sockops.MapResolver, raw string, ft identity.FourTuple) {
	r, ok := res.Resolve(ft)
	switch {
	case ok && r.Cookie != 0:
		fmt.Printf("  RESOLVE %s => JOINED cookie=%d (cgroup_id=%d pid=%d)\n", raw, r.Cookie, r.CgroupID, r.PID)
	case ok && r.Cookie == 0:
		fmt.Printf("  RESOLVE %s => HIT but cookie=0 (present yet unattributable — treat as FAIL)\n", raw)
	default:
		fmt.Printf("  RESOLVE %s => MISS (no entry; flow unattributable — adapter would NOT enforce)\n", raw)
	}
}

// parseResolve parses "SRCIP:SPORT->DSTIP:DPORT" into the host-canonical FourTuple
// the adapter would build, via the repo's own identity.TupleFromAddrs.
func parseResolve(s string) (identity.FourTuple, error) {
	lhs, rhs, found := strings.Cut(s, "->")
	if !found {
		return identity.FourTuple{}, fmt.Errorf("expected SRCIP:SPORT->DSTIP:DPORT")
	}
	sIP, sPort, err := splitHostPort(lhs)
	if err != nil {
		return identity.FourTuple{}, fmt.Errorf("source: %w", err)
	}
	dIP, dPort, err := splitHostPort(rhs)
	if err != nil {
		return identity.FourTuple{}, fmt.Errorf("dest: %w", err)
	}
	ft, ok := identity.TupleFromAddrs(sIP, sPort, dIP, dPort)
	if !ok {
		return identity.FourTuple{}, fmt.Errorf("unparseable/ mixed-family addresses")
	}
	return ft, nil
}

func splitHostPort(hp string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(hp))
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return host, uint16(p), nil
}

// ipString renders the raw 16-byte address field per its family (AF_INET keeps the
// first 4 bytes). The bytes are already in IP order, so a direct netip build is correct.
func ipString(family uint16, b [16]byte) string {
	switch family {
	case identity.AFInet:
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}).String()
	case identity.AFInet6:
		return netip.AddrFrom16(b).String()
	default:
		return fmt.Sprintf("family?%d", family)
	}
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
