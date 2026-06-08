//go:build linux

package sockops

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

// cookieOf reads the true kernel socket cookie of a TCP connection's socket via
// getsockopt(SO_COOKIE) — the independent oracle the bridge must match.
func cookieOf(t *testing.T, c net.Conn) uint64 {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	if cerr := raw.Control(func(fd uintptr) {
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); cerr != nil || err != nil {
		t.Fatalf("getsockopt(SO_COOKIE): %v / %v", cerr, err)
	}
	return cookie
}

func tupleOfServerConn(t *testing.T, srv net.Conn) identity.FourTuple {
	t.Helper()
	// From the server's accepted socket: remote = client (our Src), local = server (our Dst).
	rip, rport, _ := net.SplitHostPort(srv.RemoteAddr().String())
	lip, lport, _ := net.SplitHostPort(srv.LocalAddr().String())
	ft, ok := identity.TupleFromAddrs(rip, atoiPort(t, rport), lip, atoiPort(t, lport))
	if !ok {
		t.Fatalf("could not build tuple from %s -> %s", srv.RemoteAddr(), srv.LocalAddr())
	}
	return ft
}

func atoiPort(t *testing.T, s string) uint16 {
	t.Helper()
	var p uint16
	for _, c := range s {
		p = p*10 + uint16(c-'0')
	}
	return p
}

// TestSockopsCookieOracle is the M4 socket-cookie de-risk proof (ROADMAP §7): a
// real accepted connection's cookie, resolved via the sockops bridge from the
// 4-tuple the adapter would build, must equal getsockopt(SO_COOKIE) on that
// socket — proving the byte-order/layout handling end to end. Then closing the
// connection must delete the entry (the stale-cookie / port-reuse guard).
// Requires root (CAP_BPF/CAP_NET_ADMIN + cgroup attach); skipped otherwise.
func TestSockopsCookieOracle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF/CAP_NET_ADMIN + cgroup-v2 attach)")
	}
	r, err := NewMapResolver("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}
	defer r.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted

	want := cookieOf(t, srv)
	ft := tupleOfServerConn(t, srv)

	// The PASSIVE_ESTABLISHED callback runs asynchronously; poll briefly.
	var got identity.Resolution
	var ok bool
	for i := 0; i < 100; i++ {
		if got, ok = r.Resolve(ft); ok {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !ok {
		var dk sockopsFlowKey
		var dv sockopsFlowVal
		it := r.objs.FlowCookies.Iterate()
		n := 0
		for it.Next(&dk, &dv) {
			t.Logf("map entry %d: key=%+v cookie=%#x", n, dk, dv.Cookie)
			n++
		}
		t.Fatalf("sockops bridge miss for tuple %+v; map had %d entries", ft, n)
	}
	if got.Cookie != want {
		t.Fatalf("cookie mismatch: bridge=%#x SO_COOKIE=%#x (the bridge resolved the WRONG socket)", got.Cookie, want)
	}

	// Delete-on-close: after both ends close, the entry must disappear.
	_ = client.Close()
	_ = srv.Close()
	deleted := false
	for i := 0; i < 200; i++ {
		if _, ok := r.Resolve(ft); !ok {
			deleted = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !deleted {
		t.Error("entry not deleted on close — a reused ephemeral port could resurrect a stale cookie")
	}
}
