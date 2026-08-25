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
	flag.Parse()

	if *jailDst == "" {
		log.Fatalf("-jail-dst is REQUIRED (e.g. -jail-dst 10.0.0.51:80). Refusing to run with no target — an empty target would match nothing, but the flag is mandatory so scoping is always explicit.")
	}

	// Parse -jail-dst up front so bad input fails before we touch the kernel. We
	// keep it as a canonical netip.Addr + host-order port and compare it against
	// each captured flow's DST (the LOCAL/server end the sockops key stores).
	targetAddr, targetPort, err := parseHostPort(*jailDst)
	if err != nil {
		log.Fatalf("bad -jail-dst %q: %v", *jailDst, err)
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
	defer res.Close()
	log.Printf("attached sockops (observe) to cgroup %s — capturing PASSIVE_ESTABLISHED (server accept-side) cookies", *cgroup)

	fcMap, err := flowCookiesMap(res)
	if err != nil {
		log.Fatalf("could not reach flow_cookies map for enumeration: %v", err)
	}

	// 2) Load + attach the REAL enforce program (cgroup_skb/egress DROP +
	// cgroup/sock_release cleanup) at the SAME cgroup. This is the path under test.
	// It coexists with Cilium's own cgroup programs (both are additive cgroup-BPF
	// attachments; the kernel runs all attached egress programs).
	kl := enforce.NewKernelLoader(*cgroup)
	if err := kl.Load(); err != nil {
		log.Fatalf("enforce KernelLoader.Load() at %q: %v\n(need CAP_BPF+CAP_NET_ADMIN and a cgroup-v2 unified hierarchy; if THIS is what fails while sockops attached, that is the Cilium-coexistence signal to report)", *cgroup, err)
	}
	defer kl.Close()
	log.Printf("attached enforce (cgroup_skb/egress DROP) to cgroup %s — coexisting with any Cilium cgroup programs", *cgroup)

	// The production write path: containment programs verdicts THROUGH the loader.
	// We reuse it verbatim so the key(cookie)/value(action) encoding is identical to
	// what the sting emits — no hand-rolled map write.
	cont, err := containment.New(containment.Config{Loader: kl})
	if err != nil {
		log.Fatalf("containment.New: %v", err)
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
