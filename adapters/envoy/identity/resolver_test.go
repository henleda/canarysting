package identity

import (
	"sync"
	"testing"
)

func TestTupleFromAddrsIPv4(t *testing.T) {
	ft, ok := TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	if !ok {
		t.Fatal("valid IPv4 addrs rejected")
	}
	if ft.Family != AFInet {
		t.Fatalf("family = %d, want AFInet", ft.Family)
	}
	if ft.SrcPort != 54321 || ft.DstPort != 8443 {
		t.Fatalf("ports = %d/%d", ft.SrcPort, ft.DstPort)
	}
	if [4]byte(ft.SrcIP[:4]) != [4]byte{203, 0, 113, 7} || [4]byte(ft.DstIP[:4]) != [4]byte{10, 0, 0, 2} {
		t.Fatalf("ip bytes wrong: src=%v dst=%v", ft.SrcIP[:4], ft.DstIP[:4])
	}
	// IPv4 must leave the high 12 bytes zero (uniform layout with IPv6).
	for i := 4; i < 16; i++ {
		if ft.SrcIP[i] != 0 || ft.DstIP[i] != 0 {
			t.Fatalf("IPv4 did not zero high bytes at %d", i)
		}
	}
}

func TestTupleFromAddrsIPv6AndMappedFold(t *testing.T) {
	ft, ok := TupleFromAddrs("2001:db8::1", 1234, "2001:db8::2", 443)
	if !ok || ft.Family != AFInet6 {
		t.Fatalf("IPv6 tuple wrong: ok=%v family=%d", ok, ft.Family)
	}
	// A v4-mapped v6 source must fold to canonical v4 (same key as the plain v4).
	mapped, ok := TupleFromAddrs("::ffff:203.0.113.7", 54321, "10.0.0.2", 8443)
	if !ok {
		t.Fatal("v4-mapped v6 rejected")
	}
	plain, _ := TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	if mapped != plain {
		t.Fatal("v4-mapped v6 did not fold to the same key as plain v4 (would split the map)")
	}
}

func TestTupleFromAddrsRejectsBadAndMixedFamily(t *testing.T) {
	if _, ok := TupleFromAddrs("not-an-ip", 1, "10.0.0.2", 2); ok {
		t.Fatal("unparseable source accepted")
	}
	if _, ok := TupleFromAddrs("203.0.113.7", 1, "2001:db8::2", 2); ok {
		t.Fatal("mixed v4/v6 family accepted (a connection's ends share a family)")
	}
}

func TestFakeResolverHitMissForce(t *testing.T) {
	f := NewFakeResolver()
	ft, _ := TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	if _, ok := f.Resolve(ft); ok {
		t.Fatal("empty resolver should miss")
	}
	want := Resolution{Cookie: 0xC0FFEE, PID: 42}
	f.Set(ft, want)
	if got, ok := f.Resolve(ft); !ok || got != want {
		t.Fatalf("resolve after Set: got %+v ok=%v", got, ok)
	}
	f.SetForceMiss(true)
	if _, ok := f.Resolve(ft); ok {
		t.Fatal("force-miss should miss a known tuple")
	}
}

func TestFakeResolverMissThenHit(t *testing.T) {
	f := NewFakeResolver()
	ft, _ := TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	r := Resolution{Cookie: 7}
	f.MissThenHit(ft, r, 2)
	for i := 0; i < 2; i++ {
		if _, ok := f.Resolve(ft); ok {
			t.Fatalf("expected miss %d", i)
		}
	}
	if got, ok := f.Resolve(ft); !ok || got != r {
		t.Fatalf("expected hit after the misses: got %+v ok=%v", got, ok)
	}
}

func TestFakeResolverConcurrent(t *testing.T) {
	f := NewFakeResolver()
	ft, _ := TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	f.Set(ft, Resolution{Cookie: 1})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.Resolve(ft); f.Set(ft, Resolution{Cookie: 1}) }()
	}
	wg.Wait()
}
