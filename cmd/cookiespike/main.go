//go:build linux

// Command cookiespike is a diagnostic binary (not production code) for empirically
// testing CanarySting's socket-cookie L7<->kernel join (AGENTS.md rule 4,
// docs/IDENTITY.md). Its bounded -proof mode covers one host-local child-cgroup
// loopback flow; it does not claim Kubernetes pod/CNI behavior. The manual mode
// loads and attaches the real sockops eBPF program via the repo's own
// bpf/sockops.NewMapResolver, dumps every entry the kernel writes into the
// flow_cookies map, and reconstructs a map key from a source/destination 4-tuple
// exactly as the Envoy ext_proc adapter does (identity.TupleFromAddrs +
// MapResolver.Resolve).
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
//	sudo /tmp/cookiespike -cgroup /sys/fs/cgroup/canarysting-run -proof
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
	"golang.org/x/sys/unix"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/bpf/sockops"
	"github.com/canarysting/canarysting/internal/contract"
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
	proof := flag.Bool("proof", false, "run one bounded loopback socket-cookie join proof and exit with explicit PASS/FAIL")
	var resolves stringList
	flag.Var(&resolves, "resolve", "join assertion: 'SRCIP:SPORT->DSTIP:DPORT' — reconstruct the adapter's map key and report the cookie (repeatable)")
	flag.Parse()
	if *proof && len(resolves) != 0 {
		log.Fatal("-proof cannot be combined with -resolve")
	}

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
	if *proof {
		proofErr := runProof(res)
		closeErr := res.Close()
		switch {
		case proofErr != nil:
			fmt.Printf("RESULT FAIL diagnostic=%q\n", proofErr)
			os.Exit(1)
		case closeErr != nil:
			fmt.Printf("RESULT FAIL diagnostic=%q\n", fmt.Errorf("detach sockops: %w", closeErr))
			os.Exit(1)
		default:
			fmt.Println("RESULT PASS")
			return
		}
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

// runProof performs the bounded M1C integration proof without enforcement. It
// creates one loopback TCP connection, reconstructs the server-side tuple exactly
// as the Envoy adapter does, resolves it through the production staleness guard,
// and compares the result with the accepted socket's independent SO_COOKIE oracle.
// A deliberately absent tuple must remain a MISS, and closing both sockets must
// remove the captured entry. The caller owns resolver teardown.
func runProof(res *sockops.MapResolver) error {
	guarded := identity.NewStaleGuard(res)
	missing, ok := identity.TupleFromAddrs("192.0.2.10", 62001, "192.0.2.20", 62002)
	if !ok {
		return fmt.Errorf("construct missing-attribution fixture")
	}
	if got, hit := guarded.Resolve(missing); hit {
		return fmt.Errorf("missing-attribution fixture unexpectedly resolved cookie %d", got.Cookie)
	}
	fmt.Println("PROOF missing_attribution=PASS result=MISS attribution=refused")
	// Keep the resolver attached briefly so the external DGX harness can observe
	// the live program on this exact child cgroup and confirm it is absent at root.
	fmt.Println("PROOF resolver_ready=PASS live_attachment_observation=pending")
	time.Sleep(250 * time.Millisecond)

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("listen on bounded loopback fixture: %w", err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return fmt.Errorf("dial bounded loopback fixture: %w", err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case result := <-accepted:
		if result.err != nil {
			return fmt.Errorf("accept bounded loopback fixture: %w", result.err)
		}
		server = result.conn
	case <-time.After(2 * time.Second):
		return fmt.Errorf("accept bounded loopback fixture: timed out")
	}
	defer server.Close()

	tuple, err := tupleFromServerConn(server)
	if err != nil {
		return err
	}
	wantCookie, err := socketCookie(server)
	if err != nil {
		return err
	}
	if wantCookie == 0 {
		return fmt.Errorf("SO_COOKIE oracle returned zero")
	}

	var resolution identity.Resolution
	resolved := false
	for i := 0; i < 250; i++ {
		if resolution, resolved = guarded.Resolve(tuple); resolved {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !resolved {
		return fmt.Errorf("adapter tuple remained unattributable after bounded capture wait: %s", formatTuple(tuple))
	}
	if resolution.Cookie == 0 {
		return fmt.Errorf("adapter tuple resolved a zero cookie")
	}
	if resolution.Cookie != wantCookie {
		return fmt.Errorf("socket-cookie mismatch: resolver=%d SO_COOKIE=%d", resolution.Cookie, wantCookie)
	}

	flow := contract.FlowIdentity{
		SocketCookie: resolution.Cookie,
		CgroupID:     resolution.CgroupID,
		PID:          resolution.PID,
	}
	if flow.SocketCookie == 0 {
		return fmt.Errorf("resolved contract flow identity is unattributable")
	}
	fmt.Printf("PROOF tuple_direction=PASS semantics=remote-to-local tuple=%s\n", formatTuple(tuple))
	fmt.Printf("PROOF flow_identity=PASS socket_cookie=%d oracle_cookie=%d resolver=envoy-stale-guard\n",
		flow.SocketCookie, wantCookie)

	if err := client.Close(); err != nil {
		return fmt.Errorf("close loopback client: %w", err)
	}
	if err := server.Close(); err != nil {
		return fmt.Errorf("close loopback server: %w", err)
	}

	deleted := false
	for i := 0; i < 200; i++ {
		_, hit, lookupErr := res.ResolveChecked(tuple)
		if lookupErr != nil {
			return fmt.Errorf("verify close-driven map deletion: %w", lookupErr)
		}
		if !hit {
			deleted = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !deleted {
		return fmt.Errorf("captured tuple remained after both sockets closed: %s", formatTuple(tuple))
	}
	fmt.Println("PROOF close_delete=PASS result=MISS")
	return nil
}

func tupleFromServerConn(conn *net.TCPConn) (identity.FourTuple, error) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.Port < 1 || remote.Port > 65535 {
		return identity.FourTuple{}, fmt.Errorf("invalid loopback remote address: %v", conn.RemoteAddr())
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local.Port < 1 || local.Port > 65535 {
		return identity.FourTuple{}, fmt.Errorf("invalid loopback local address: %v", conn.LocalAddr())
	}
	tuple, ok := identity.TupleFromAddrs(remote.IP.String(), uint16(remote.Port), local.IP.String(), uint16(local.Port))
	if !ok {
		return identity.FourTuple{}, fmt.Errorf("build adapter tuple from %s -> %s", remote, local)
	}
	return tuple, nil
}

func socketCookie(conn *net.TCPConn) (uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("access accepted socket: %w", err)
	}
	var cookie uint64
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		return 0, fmt.Errorf("control accepted socket: %w", err)
	}
	if socketErr != nil {
		return 0, fmt.Errorf("read SO_COOKIE oracle: %w", socketErr)
	}
	return cookie, nil
}

func formatTuple(tuple identity.FourTuple) string {
	return fmt.Sprintf("%s:%d->%s:%d",
		ipString(tuple.Family, tuple.SrcIP), tuple.SrcPort,
		ipString(tuple.Family, tuple.DstIP), tuple.DstPort)
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
