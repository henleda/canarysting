//go:build linux

package observe

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// cookieOf reads a connection's true kernel socket cookie via getsockopt(SO_COOKIE)
// — the independent ground truth the observe map is keyed by.
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
				buf := make([]byte, 1<<16)
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

func roundTrip(t *testing.T, cl net.Conn) {
	t.Helper()
	if _, err := cl.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = cl.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, err := cl.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("ping")) {
		t.Fatalf("round-trip failed: %v %q", err, buf[:n])
	}
}

func newObserver(t *testing.T) *KernelObserver {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF/CAP_PERFMON + cgroup-v2 attach)")
	}
	o := NewKernelObserver()
	if err := o.Load("/sys/fs/cgroup"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return o
}

// readBySrv polls the observe map for the server-accept socket's stats.
func readBySrv(t *testing.T, o *KernelObserver, cookie uint64) FlowStats {
	t.Helper()
	for i := 0; i < 200; i++ {
		if fs, ok, err := o.ReadStats(cookie); err == nil && ok {
			return fs
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no observe entry for cookie %#x", cookie)
	return FlowStats{}
}

// TestStatsAccrueBothDirections: a round-trip on the server-accept socket accrues
// BOTH ingress (the request it received) and egress (the echo it sent).
func TestStatsAccrueBothDirections(t *testing.T) {
	o := newObserver(t)
	defer o.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	defer cl.Close()

	cookie := cookieOf(t, srv)
	roundTrip(t, cl)
	roundTrip(t, cl)

	fs := readBySrv(t, o, cookie)
	if fs.IngressPackets == 0 || fs.IngressBytes == 0 {
		t.Errorf("no ingress accrued on the server socket: %+v", fs)
	}
	if fs.EgressPackets == 0 || fs.EgressBytes == 0 {
		t.Errorf("no egress accrued on the server socket: %+v", fs)
	}
	if fs.FirstSeenNs == 0 || fs.LastSeenNs < fs.FirstSeenNs {
		t.Errorf("timestamps not captured/monotonic: %+v", fs)
	}
}

// TestTupleCapturedMatchesGetname is the ORIENTATION oracle: the captured tuple's
// SrcPort/SrcIP must be the REMOTE peer (getpeername) and DstPort/DstIP the LOCAL
// end (getsockname) of the accepted server socket. If the kernel's sock src/dst
// fields are oriented the other way on this kernel, this fails LOUD — do not ship
// the identity feature until it passes (docs M7 risk register).
func TestTupleCapturedMatchesGetname(t *testing.T) {
	o := newObserver(t)
	defer o.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	defer cl.Close()

	cookie := cookieOf(t, srv)
	roundTrip(t, cl)
	fs := readBySrv(t, o, cookie)

	local := srv.LocalAddr().(*net.TCPAddr)   // getsockname(srv): the server/workload end
	remote := srv.RemoteAddr().(*net.TCPAddr) // getpeername(srv): the caller end

	if fs.Family != AFInet {
		t.Fatalf("family = %d, want AF_INET", fs.Family)
	}
	// Port orientation (the decisive check — loopback IPs are identical):
	if fs.DstPort != uint16(local.Port) {
		t.Errorf("DstPort (local/workload) = %d, want getsockname port %d — ORIENTATION or ntohs WRONG", fs.DstPort, local.Port)
	}
	if fs.SrcPort != uint16(remote.Port) {
		t.Errorf("SrcPort (remote/caller) = %d, want getpeername port %d — ORIENTATION or ntohs WRONG", fs.SrcPort, remote.Port)
	}
	// IPv4 octets land in order (both ends are 127.0.0.1 on loopback).
	want := [4]byte{127, 0, 0, 1}
	if [4]byte(fs.SrcIP[:4]) != want || [4]byte(fs.DstIP[:4]) != want {
		t.Errorf("ipv4 octets not captured in order: src=%v dst=%v", fs.SrcIP[:4], fs.DstIP[:4])
	}
}

// TestObserveNeverDropsAPacket is the defining transparency proof: with all three
// programs attached, a bulk transfer arrives byte-for-byte — observation cannot
// drop (every program returns PASS).
func TestObserveNeverDropsAPacket(t *testing.T) {
	o := newObserver(t)
	defer o.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	defer cl.Close()
	_ = srv

	const n = 4 << 20 // 4 MiB
	payload := bytes.Repeat([]byte("x"), n)
	go func() { _, _ = cl.Write(payload) }()

	got := make([]byte, 0, n)
	buf := make([]byte, 64<<10)
	_ = cl.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(got) < n {
		m, err := cl.Read(buf)
		got = append(got, buf[:m]...)
		if err != nil {
			t.Fatalf("read failed after %d/%d bytes (observe dropped a packet?): %v", len(got), n, err)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload differs (observe corrupted/dropped): got %d bytes", len(got))
	}
}

// TestSockReleaseDeletes: the cookie's entry is removed when the socket closes, so
// a completed flow leaves the map for the aggregator to fold once.
func TestSockReleaseDeletes(t *testing.T) {
	o := newObserver(t)
	defer o.Close()
	s := newEchoServer(t)
	defer s.close()
	cl, srv := s.dialPair(t)
	cookie := cookieOf(t, srv)
	roundTrip(t, cl)
	_ = readBySrv(t, o, cookie) // present after traffic

	cl.Close()
	srv.Close()
	deleted := false
	for i := 0; i < 200; i++ {
		if _, ok, _ := o.ReadStats(cookie); !ok {
			deleted = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !deleted {
		t.Error("observe entry not deleted on socket close (sock_release lifecycle broken)")
	}
}
