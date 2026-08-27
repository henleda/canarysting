//go:build linux

// Command enforcespike is a THROWAWAY diagnostic spike (not production code) that
// empirically proves CanarySting's eBPF ENFORCE path — the cgroup_skb/egress
// kernel DROP keyed by the socket cookie (docs/STING.md, docs/IDENTITY.md, rule 4)
// — actually drops a targeted flow's egress AND coexists with Cilium inside a
// Kubernetes node's cgroup-v2 hierarchy.
//
// It loads and attaches BOTH real eBPF paths at the cgroup, exactly as production
// does, with ZERO hand-rolled map writes:
//
//   - the M4 sockops resolver (bpf/sockops.NewMapResolver) — observation. On each
//     accepted connection the kernel captures the SERVER accept-side
//     (BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) socket cookie into flow_cookies keyed by
//     the 4-tuple {src = REMOTE/client, dst = LOCAL/server}. This is how the spike
//     DISCOVERS a live flow's cookie.
//   - the M5 enforce loader (bpf/enforce.NewKernelLoader) — enforcement. Its
//     cgroup_skb/egress program looks up the socket cookie of every egress skb in
//     verdict_map; a HARD_DENY/JAIL verdict -> DROP (return 0), rate-limit ->
//     token-bucket throttle, otherwise PASS. FAIL-OPEN by construction: only an
//     explicitly-programmed cookie is ever affected.
//
// The loop: every -interval, enumerate flow_cookies; for any captured flow whose
// DESTINATION matches -jail-dst (mimicking "this flow touched the canary at that
// address"), program a DROP verdict for that flow's cookie THROUGH THE PRODUCTION
// WRITE PATH — internal/sting/containment.KernelContainer.Apply over the real
// bpf/enforce loader (the same call the sting makes; no hand-rolled key/value
// encoding). Idempotent: a cookie already jailed is skipped. The kernel drop
// counters for each jailed cookie are printed every tick.
//
// WHICH socket / WHICH direction: the captured cookie is the SERVER accept-side
// socket's cookie, so the egress that gets DROPped is the SERVER's egress — i.e.
// the server's RESPONSES to the client. Point -jail-dst at the SERVER's listening
// IP:port (the canary). Success looks like: the client's request reaches the
// server but its reply never arrives (the flow hangs / times out) and the drop
// counter climbs, while a control flow to a DIFFERENT dst keeps working — proving
// precise, cookie-scoped enforcement that attaches fine alongside Cilium.
//
// Build for the DGX (linux/arm64) — the whole point — with:
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/enforcespike ./cmd/enforcespike
//
// Run on the node (needs CAP_BPF/CAP_NET_ADMIN + a cgroup-v2 unified hierarchy,
// kernel >= 5.10):
//
//	sudo /tmp/enforcespike -cgroup /sys/fs/cgroup -jail-dst 10.0.0.51:80
//	sudo /tmp/enforcespike -cgroup /sys/fs/cgroup -jail-dst 10.0.0.51:80 -action hard-deny
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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
	"github.com/canarysting/canarysting/bpf/enforce"
	"github.com/canarysting/canarysting/bpf/sockops"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// flowKey / flowVal are byte-for-byte copies of the bpf2go-generated
// sockopsFlowKey / sockopsFlowVal (which mirror the C flow_key / flow_val the
// sockops kernel program writes). We redeclare them here only because those
// generated types are unexported; a layout drift would be caught by the repo's own
// bpf/sockops layout_test.go. Field order/types/sizes MUST match exactly so
// cilium/ebpf unmarshals the raw kernel bytes correctly. Same struct cookiespike
// uses (see cmd/cookiespike/main.go).
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

func main() {
	log.SetFlags(log.Ltime)

	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup-v2 unified hierarchy path to attach BOTH sockops (observe) and enforce (drop) to")
	jailDst := flag.String("jail-dst", "", "target 'IP:port': auto-jail any captured flow whose DESTINATION matches this (mimics 'flow touched the canary'). REQUIRED.")
	interval := flag.Duration("interval", 500*time.Millisecond, "how often to scan flow_cookies and (re)apply the jail")
	action := flag.String("action", "jail", "containment action to program: jail | hard-deny | rate-limit (jail and hard-deny both DROP egress in-kernel)")
	proof := flag.Bool("proof", false, "run one bounded target/control enforcement proof and exit with explicit PASS/FAIL")
	flag.Parse()

	if *proof && *jailDst != "" {
		log.Fatal("-proof cannot be combined with -jail-dst")
	}
	if !*proof && *jailDst == "" {
		log.Fatalf("-jail-dst is REQUIRED (e.g. -jail-dst 10.0.0.51:80). Refusing to run with no target — an empty target would match nothing, but the flag is mandatory so scoping is always explicit.")
	}

	// Parse -jail-dst up front so bad input fails before we touch the kernel. We
	// keep it as a canonical netip.Addr + host-order port and compare it against
	// each captured flow's DST (the LOCAL/server end the sockops key stores).
	var targetAddr netip.Addr
	var targetPort uint16
	if !*proof {
		var err error
		targetAddr, targetPort, err = parseHostPort(*jailDst)
		if err != nil {
			log.Fatalf("bad -jail-dst %q: %v", *jailDst, err)
		}
	}

	act, actLabel, err := parseAction(*action)
	if err != nil {
		log.Fatalf("bad -action %q: %v", *action, err)
	}

	// 1) Load + attach the REAL sockops observation program (the identical path the
	// datapath uses: kernel-version pin + AttachCGroupSockOps at cgroup). This is
	// how we DISCOVER live flows' server accept-side cookies.
	res, err := sockops.NewMapResolver(*cgroup)
	if err != nil {
		log.Fatalf("sockops NewMapResolver(%q): %v\n(need root/CAP_BPF+CAP_NET_ADMIN, a cgroup-v2 unified hierarchy, and kernel >= 5.10)", *cgroup, err)
	}
	log.Printf("attached sockops (observe) to cgroup %s — capturing PASSIVE_ESTABLISHED (server accept-side) cookies", *cgroup)

	// 2) Load + attach the REAL enforce program (cgroup_skb/egress DROP +
	// cgroup/sock_release cleanup) at the SAME cgroup. This is the path under test.
	// It coexists with Cilium's own cgroup programs (both are additive cgroup-BPF
	// attachments; the kernel runs all attached egress programs).
	kl := enforce.NewKernelLoader(*cgroup)
	if err := kl.Load(); err != nil {
		_ = res.Close()
		log.Fatalf("enforce KernelLoader.Load() at %q: %v\n(need CAP_BPF+CAP_NET_ADMIN and a cgroup-v2 unified hierarchy; if THIS is what fails while sockops attached, that is the Cilium-coexistence signal to report)", *cgroup, err)
	}
	log.Printf("attached enforce (cgroup_skb/egress DROP) to cgroup %s — coexisting with any Cilium cgroup programs", *cgroup)

	// The production write path: containment programs verdicts THROUGH the loader.
	// We reuse it verbatim so the key(cookie)/value(action) encoding is identical to
	// what the sting emits — no hand-rolled map write.
	cont, err := containment.New(containment.Config{Loader: kl})
	if err != nil {
		_ = kl.Close()
		_ = res.Close()
		log.Fatalf("containment.New: %v", err)
	}
	if *proof {
		proofErr := runProof(res, kl, cont)
		klCloseErr := kl.Close()
		resCloseErr := res.Close()
		switch {
		case proofErr != nil:
			fmt.Printf("RESULT FAIL diagnostic=%q\n", proofErr)
			os.Exit(1)
		case klCloseErr != nil:
			fmt.Printf("RESULT FAIL diagnostic=%q\n", fmt.Errorf("detach enforcement: %w", klCloseErr))
			os.Exit(1)
		case resCloseErr != nil:
			fmt.Printf("RESULT FAIL diagnostic=%q\n", fmt.Errorf("detach sockops: %w", resCloseErr))
			os.Exit(1)
		default:
			fmt.Println("RESULT PASS proof=precise-cookie-enforcement")
			return
		}
	}
	defer res.Close()
	defer kl.Close()

	fcMap, err := flowCookiesMap(res)
	if err != nil {
		log.Fatalf("could not reach flow_cookies map for enumeration: %v", err)
	}

	log.Printf("JAIL target: dst==%s:%d — will DROP the SERVER egress (server->client responses) of any flow to that dst; action=%s", targetAddr, targetPort, actLabel)
	log.Printf("scoping: ONLY cookies whose flow dst matches the target are ever programmed; every other flow (incl. control-plane/apiserver/Cilium health) is untouched (fail-open)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(*interval)
	defer tick.Stop()

	// jailed tracks the cookies we've already programmed, so re-application is
	// idempotent and we log a given jailing exactly once. On exit we Release these.
	jailed := map[uint64]bool{}

	scan := func() {
		var k flowKey
		var v flowVal
		it := fcMap.Iterate()
		matched := 0
		for it.Next(&k, &v) {
			dst, ok := addrFrom(k.Family, k.DstIP)
			if !ok || dst != targetAddr || k.DstPort != targetPort {
				continue
			}
			matched++
			if v.Cookie == 0 {
				// Unattributable: containment would refuse it anyway. Surface it.
				log.Printf("MATCH dst=%s:%d but cookie=0 (unattributable) src=%s:%d — NOT jailing",
					dst, k.DstPort, mustAddr(k.Family, k.SrcIP), k.SrcPort)
				continue
			}
			if jailed[v.Cookie] {
				continue // already programmed — idempotent skip
			}
			// Program the DROP verdict through the production containment path.
			verdict := contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: v.Cookie}}
			if err := cont.Apply(verdict, act); err != nil {
				log.Printf("Apply(cookie=%d, %s) failed: %v", v.Cookie, actLabel, err)
				continue
			}
			jailed[v.Cookie] = true
			log.Printf("JAILED cookie=%d %s:%d->%s:%d  (%s: server egress to client now DROPped in kernel)",
				v.Cookie, mustAddr(k.Family, k.SrcIP), k.SrcPort, dst, k.DstPort, actLabel)
		}
		if err := it.Err(); err != nil {
			log.Printf("flow_cookies iterate error: %v", err)
		}
		// Print the enforce program's kernel drop counters for each jailed cookie.
		for c := range jailed {
			if ctr, ok := kl.Counters(c); ok {
				fmt.Printf("  counters cookie=%d dropped_pkts=%d dropped_bytes=%d\n", c, ctr.DroppedPkts, ctr.DroppedBytes)
			} else {
				// The sock_release program deletes the entry on socket close — a
				// vanished counter means the jailed socket closed (expected once the
				// client gives up).
				fmt.Printf("  counters cookie=%d GONE (socket closed; verdict auto-released by sock_release)\n", c)
			}
		}
		log.Printf("scan: %d flow(s) to target this tick; %d cookie(s) jailed so far", matched, len(jailed))
	}

	log.Printf("scanning every %s; Ctrl-C to stop, clear the verdicts we wrote, and exit", *interval)
	scan()
	for {
		select {
		case <-tick.C:
			scan()
		case <-sig:
			fmt.Println("--- SIGINT: clearing verdicts we programmed ---")
			for c := range jailed {
				if err := cont.Release(contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: c}}); err != nil {
					log.Printf("release cookie=%d: %v", c, err)
				} else {
					log.Printf("released cookie=%d", c)
				}
			}
			return
		}
	}
}

type loopbackPair struct {
	client *net.TCPConn
	server *net.TCPConn
	cookie uint64
}

func (p *loopbackPair) close() {
	if p.client != nil {
		_ = p.client.Close()
	}
	if p.server != nil {
		_ = p.server.Close()
	}
}

// runProof performs the bounded M1D integration proof. The caller and external
// harness own loader teardown and child-cgroup cleanup. This function first proves
// both sockets are healthy, then treats only target as an explicit proof-fixture
// canary touch, programs its independently verified live cookie through the
// production containment path, proves target-only drop plus control/map-miss
// fail-open behavior, releases the cookie, and proves the same target connection
// recovers. Baseline anomaly is never an input or trigger.
func runProof(res *sockops.MapResolver, kl *enforce.KernelLoader, cont *containment.KernelContainer) error {
	guarded := identity.NewStaleGuard(res)
	missing := contract.Verdict{Flow: contract.FlowIdentity{}}
	if err := cont.Apply(missing, containment.Jail); !errors.Is(err, containment.ErrUnattributable) {
		return fmt.Errorf("unattributable containment refusal: got %v", err)
	}
	fmt.Println("PROOF missing_attribution=PASS cookie=0 action=refused")
	fmt.Println("PROOF loaders_ready=PASS live_attachment_observation=pending")
	// Keep the exact child attachments live long enough for the external harness
	// to assert Cilium and node health while they are attached.
	time.Sleep(3 * time.Second)

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("shared fixture listener: %w", err)
	}
	defer listener.Close()
	control, err := newLoopbackPair(listener, guarded)
	if err != nil {
		return fmt.Errorf("control fixture: %w", err)
	}
	defer control.close()
	target, err := newLoopbackPair(listener, guarded)
	if err != nil {
		return fmt.Errorf("target fixture: %w", err)
	}
	defer target.close()
	if target.cookie == control.cookie {
		return fmt.Errorf("target and control unexpectedly share cookie %d", target.cookie)
	}
	if target.server.LocalAddr().String() != control.server.LocalAddr().String() {
		return fmt.Errorf("target and control do not share a destination: target=%s control=%s", target.server.LocalAddr(), control.server.LocalAddr())
	}
	fmt.Printf("PROOF shared_destination=PASS listener=%s distinct_cookies=PASS\n", listener.Addr())

	if err := roundTrip(target, []byte("target-before-enforce"), time.Second); err != nil {
		return fmt.Errorf("target observe-before-enforce round trip: %w", err)
	}
	if err := roundTrip(control, []byte("control-before-enforce"), time.Second); err != nil {
		return fmt.Errorf("control observe-before-enforce round trip: %w", err)
	}
	fmt.Printf("PROOF observe_before_enforce=PASS target_cookie=%d control_cookie=%d\n", target.cookie, control.cookie)
	fmt.Printf("PROOF canary_touch=PASS source=explicit-proof-fixture target_cookie=%d baseline_trigger=none\n", target.cookie)

	verdict := contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: target.cookie}}
	if err := cont.Apply(verdict, containment.Jail); err != nil {
		return fmt.Errorf("apply target jail through containment: %w", err)
	}
	if _, exists := kl.Counters(control.cookie); exists {
		return fmt.Errorf("control cookie %d unexpectedly has a verdict-map entry", control.cookie)
	}
	fmt.Printf("PROOF target_programmed=PASS cookie=%d action=jail control_map_entry=absent\n", target.cookie)

	blockedPayload := []byte("target-blocked-then-restored")
	if err := target.server.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("set target write deadline: %w", err)
	}
	if _, err := target.server.Write(blockedPayload); err != nil {
		return fmt.Errorf("write target response under jail: %w", err)
	}
	if err := target.client.SetReadDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
		return fmt.Errorf("set target blocked read deadline: %w", err)
	}
	blockedRead := make([]byte, len(blockedPayload))
	if _, err := io.ReadFull(target.client, blockedRead); err == nil {
		return fmt.Errorf("target response arrived while jail was active")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("target read under jail did not time out: %w", err)
	}

	var droppedPkts, droppedBytes uint64
	for i := 0; i < 100; i++ {
		if counters, ok := kl.Counters(target.cookie); ok {
			droppedPkts, droppedBytes = counters.DroppedPkts, counters.DroppedBytes
			if droppedPkts > 0 && droppedBytes > 0 {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if droppedPkts == 0 || droppedBytes == 0 {
		return fmt.Errorf("target jail produced no kernel drop counters")
	}
	if err := roundTrip(control, []byte("control-during-target-jail"), time.Second); err != nil {
		return fmt.Errorf("control fail-open round trip during target jail: %w", err)
	}
	fmt.Printf("PROOF target_only_enforcement=PASS target_cookie=%d dropped_pkts=%d dropped_bytes=%d\n", target.cookie, droppedPkts, droppedBytes)
	fmt.Printf("PROOF bystander_fail_open=PASS control_cookie=%d verdict_map=MISS round_trip=PASS\n", control.cookie)

	if err := cont.Release(verdict); err != nil {
		return fmt.Errorf("release target jail: %w", err)
	}
	if _, exists := kl.Counters(target.cookie); exists {
		return fmt.Errorf("target verdict-map entry remains after release")
	}
	if err := target.client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("set target recovery deadline: %w", err)
	}
	recovered := make([]byte, len(blockedPayload))
	if _, err := io.ReadFull(target.client, recovered); err != nil {
		return fmt.Errorf("read retransmitted target response after release: %w", err)
	}
	if string(recovered) != string(blockedPayload) {
		return fmt.Errorf("target recovery payload mismatch: got %q", recovered)
	}
	if err := roundTrip(control, []byte("control-after-release"), time.Second); err != nil {
		return fmt.Errorf("control round trip after release: %w", err)
	}
	fmt.Printf("PROOF release_restore=PASS target_cookie=%d same_connection=PASS retransmit=PASS\n", target.cookie)
	return nil
}

func newLoopbackPair(listener *net.TCPListener, res identity.CookieResolver) (*loopbackPair, error) {
	pair := &loopbackPair{}
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
		pair.close()
		return nil, fmt.Errorf("dial: %w", err)
	}
	pair.client = client
	select {
	case result := <-accepted:
		if result.err != nil {
			pair.close()
			return nil, fmt.Errorf("accept: %w", result.err)
		}
		pair.server = result.conn
	case <-time.After(2 * time.Second):
		pair.close()
		return nil, fmt.Errorf("accept timed out")
	}
	tuple, err := tupleFromServerConn(pair.server)
	if err != nil {
		pair.close()
		return nil, err
	}
	oracle, err := socketCookie(pair.server)
	if err != nil {
		pair.close()
		return nil, err
	}
	for i := 0; i < 250; i++ {
		if resolution, ok := res.Resolve(tuple); ok {
			if resolution.Cookie == 0 || resolution.Cookie != oracle {
				pair.close()
				return nil, fmt.Errorf("resolver/oracle cookie mismatch: resolver=%d oracle=%d", resolution.Cookie, oracle)
			}
			pair.cookie = resolution.Cookie
			return pair, nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	pair.close()
	return nil, fmt.Errorf("tuple remained unattributable after bounded capture wait")
}

func tupleFromServerConn(conn *net.TCPConn) (identity.FourTuple, error) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.Port < 1 || remote.Port > 65535 {
		return identity.FourTuple{}, fmt.Errorf("invalid remote address: %v", conn.RemoteAddr())
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local.Port < 1 || local.Port > 65535 {
		return identity.FourTuple{}, fmt.Errorf("invalid local address: %v", conn.LocalAddr())
	}
	tuple, ok := identity.TupleFromAddrs(remote.IP.String(), uint16(remote.Port), local.IP.String(), uint16(local.Port))
	if !ok {
		return identity.FourTuple{}, fmt.Errorf("build tuple from %s -> %s", remote, local)
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
	if cookie == 0 {
		return 0, fmt.Errorf("SO_COOKIE oracle returned zero")
	}
	return cookie, nil
}

func roundTrip(pair *loopbackPair, payload []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := pair.server.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if err := pair.client.SetReadDeadline(deadline); err != nil {
		return err
	}
	if _, err := pair.server.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(pair.client, got); err != nil {
		return err
	}
	if string(got) != string(payload) {
		return fmt.Errorf("payload mismatch: got %q want %q", got, payload)
	}
	return nil
}

// flowCookiesMap extracts the *ebpf.Map behind the (unexported) MapResolver.objs
// .FlowCookies field so the spike can iterate the whole map. This reflect reach-in
// exists ONLY because this is a throwaway spike that must not modify the repo; the
// production adapter never needs to enumerate the map (it only Resolve()s single
// keys). We reuse the SAME loaded map instance the resolver populates so the scan
// observes the identical kernel state. Identical to cmd/cookiespike's helper.
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
	mv := reflect.NewAt(f.Type(), f.Addr().UnsafePointer()).Elem()
	m, ok := mv.Interface().(*ebpf.Map)
	if !ok || m == nil {
		return nil, fmt.Errorf("FlowCookies is not a non-nil *ebpf.Map")
	}
	return m, nil
}

// parseAction maps the -action string to a containment.Action. jail and hard-deny
// both DROP egress in-kernel (enforce.bpf.c: action==ACTION_HARD_DENY ||
// action==ACTION_JAIL -> return 0); rate-limit throttles via the token bucket.
func parseAction(s string) (containment.Action, string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "jail":
		return containment.Jail, "jail", nil
	case "hard-deny", "harddeny", "deny":
		return containment.HardDeny, "hard-deny", nil
	case "rate-limit", "ratelimit", "throttle":
		return containment.RateLimit, "rate-limit", nil
	default:
		return 0, "", fmt.Errorf("expected jail | hard-deny | rate-limit")
	}
}

// parseHostPort parses "IP:port" into a canonical (unmapped) netip.Addr and a
// host-order uint16 port. The sockops program stores the key's DstPort in HOST byte
// order (see cmd/cookiespike/main.go), so the parsed port compares directly.
func parseHostPort(hp string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(hp))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad IP %q: %w", host, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return a.Unmap(), uint16(p), nil
}

// addrFrom rebuilds a netip.Addr from the raw 16-byte address field per its family
// (AF_INET keeps the first 4 bytes). The bytes are already in IP order (what
// netip.As4()/As16() produce), so a direct build is correct. Uses identity.AFInet*
// so the family constants match the eBPF side exactly.
func addrFrom(family uint16, b [16]byte) (netip.Addr, bool) {
	switch family {
	case identity.AFInet:
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}), true
	case identity.AFInet6:
		return netip.AddrFrom16(b), true
	default:
		return netip.Addr{}, false
	}
}

// mustAddr is addrFrom for logging, rendering an unknown family rather than failing.
func mustAddr(family uint16, b [16]byte) netip.Addr {
	if a, ok := addrFrom(family, b); ok {
		return a
	}
	return netip.Addr{}
}
