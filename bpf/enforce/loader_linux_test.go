//go:build linux

package enforce

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/canarysting/canarysting/bpf/loader"
)

// cookieOf reads a connection's true kernel socket cookie via getsockopt(SO_COOKIE)
// — the independent ground truth the loader must agree with.
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

// echoServer accepts connections and echoes whatever it reads. It pushes each
// accepted (server-side) conn to acc so the test can read its cookie — the
// server-accept socket is the one M5 enforces against (mirrors Envoy's accept).
type echoServer struct {
	ln  net.Listener
	acc chan net.Conn
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &echoServer{ln: ln, acc: make(chan net.Conn, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.acc <- c
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return s
}

func (s *echoServer) close() { s.ln.Close() }

// dialPair dials a client and returns (clientConn, serverConn) — serverConn is the
// accepted socket whose cookie M5 keys on.
func (s *echoServer) dialPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	cl, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case srv := <-s.acc:
		return cl, srv
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept")
		return nil, nil
	}
}

// roundTrips reports whether a "ping" written to cl is echoed back within d.
func roundTrips(cl net.Conn, d time.Duration) bool {
	if _, err := cl.Write([]byte("ping")); err != nil {
		return false
	}
	_ = cl.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 16)
	n, err := cl.Read(buf)
	return err == nil && bytes.Equal(buf[:n], []byte("ping"))
}

func newLoader(t *testing.T) *KernelLoader {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF/CAP_NET_ADMIN + cgroup-v2 attach)")
	}
	l := NewKernelLoader("/sys/fs/cgroup")
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return l
}

// TestEnforceJailIsPrecise is the M5 CISO precision proof: jailing one socket's
// egress kills exactly that flow while bystanders on the same host keep working.
func TestEnforceJailIsPrecise(t *testing.T) {
	l := newLoader(t)
	defer l.Close()
	s := newEchoServer(t)
	defer s.close()

	clA, srvA := s.dialPair(t)
	clB, srvB := s.dialPair(t)
	clC, _ := s.dialPair(t) // unprogrammed bystander (fail-open proof)
	defer clA.Close()
	defer clB.Close()
	defer clC.Close()

	cookieA := cookieOf(t, srvA) // jail the SERVER-accept socket's egress (Envoy-analog)
	cookieB := cookieOf(t, srvB)
	if cookieA == cookieB {
		t.Fatalf("distinct sockets shared a cookie: %#x", cookieA)
	}

	// Baseline: everyone works before any jail.
	if !roundTrips(clA, time.Second) || !roundTrips(clB, time.Second) {
		t.Fatal("baseline round-trips failed before jailing")
	}

	if err := l.Program(cookieA, loader.ActionJail, 0, 0); err != nil {
		t.Fatalf("Program jail: %v", err)
	}

	// A's server-egress is now dropped -> A's read times out; B and C still work.
	if roundTrips(clA, 400*time.Millisecond) {
		t.Fatal("jailed flow A still received data (jail failed)")
	}
	if !roundTrips(clB, time.Second) {
		t.Fatal("BYSTANDER B was affected by A's jail — the critical failure")
	}
	if !roundTrips(clC, time.Second) {
		t.Fatal("BYSTANDER C (unprogrammed) was affected — per-packet fail-open broken")
	}

	// Counters: only A was dropped; B was never programmed.
	if ca, ok := l.Counters(cookieA); !ok || ca.DroppedPkts == 0 {
		t.Fatalf("expected drops on A, got %+v ok=%v", ca, ok)
	}
	if _, ok := l.Counters(cookieB); ok {
		t.Fatal("bystander B's cookie was programmed")
	}

	// Release lifts the jail at the map level. (A's TCP connection may already be
	// dead from the jail period — egress dropped -> retransmit timeout — so we prove
	// the un-jail by the entry's removal, not by reviving a broken socket. A fresh
	// flow with a new cookie is naturally un-jailed; TestFailOpenOnMiss covers that.)
	if err := l.Release(cookieA); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := l.Counters(cookieA); ok {
		t.Fatal("verdict entry still present after Release (un-jail failed)")
	}
}

// TestFailOpenOnMiss: with the program attached but the map empty, all traffic
// flows (map-miss => PASS). Guards against an accidental default-deny arm.
func TestFailOpenOnMiss(t *testing.T) {
	l := newLoader(t)
	defer l.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, _ := s.dialPair(t)
	defer cl.Close()
	if !roundTrips(cl, time.Second) {
		t.Fatal("an unprogrammed flow was dropped — the datapath is not fail-open")
	}
}

// TestZeroCookieRefused: the loader refuses to program cookie 0.
func TestZeroCookieRefused(t *testing.T) {
	l := newLoader(t)
	defer l.Close()
	if err := l.Program(0, loader.ActionJail, 0, 0); err == nil {
		t.Fatal("loader programmed cookie 0 (unattributable)")
	}
}

// TestCloseDeleteRemovesEntry: the cgroup/sock_release program deletes a cookie's
// verdict entry when the socket closes, so a stale jail cannot outlive its socket.
func TestCloseDeleteRemovesEntry(t *testing.T) {
	l := newLoader(t)
	defer l.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	cookie := cookieOf(t, srv)
	if err := l.Program(cookie, loader.ActionJail, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Counters(cookie); !ok {
		t.Fatal("entry not present after Program")
	}
	cl.Close()
	srv.Close()
	// sock_release fires asynchronously on close; poll for the deletion.
	deleted := false
	for i := 0; i < 200; i++ {
		if _, ok := l.Counters(cookie); !ok {
			deleted = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !deleted {
		t.Error("verdict entry not deleted on socket close (sock_release lifecycle broken)")
	}
}

// TestRateLimitThrottlesNotJails: a rate-limited flow drops SOME packets (throttle)
// but is not a full jail; a bystander is untouched. Best-effort over loopback.
func TestRateLimitThrottlesNotJails(t *testing.T) {
	l := newLoader(t)
	defer l.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	defer cl.Close()
	cookie := cookieOf(t, srv)
	// Burst above the loopback skb size (~64 KiB) so the bucket lets some through
	// (proving it is NOT a full jail); rate low + payload large so the rest is
	// throttled (proving the throttle is active).
	if err := l.Program(cookie, loader.ActionRateLimit, 16<<10, 128<<10); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 512<<10)
	go func() { _, _ = cl.Write(payload) }()
	_ = cl.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, len(payload))
	got := 0
	for got < len(payload) {
		n, err := cl.Read(buf)
		got += n
		if err != nil {
			break
		}
	}
	c, ok := l.Counters(cookie)
	if !ok || c.DroppedPkts == 0 {
		t.Fatalf("rate-limit dropped nothing (throttle inactive): %+v ok=%v", c, ok)
	}
	if got == 0 {
		t.Fatal("rate-limit behaved as a full jail (let nothing through)")
	}
}
