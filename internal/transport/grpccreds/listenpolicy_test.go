package grpccreds_test

import (
	"errors"
	"testing"

	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:50052": true,
		"localhost:50052": true,
		"[::1]:50052":     true,
		":50052":          false, // bind-all is routable, NOT loopback
		"0.0.0.0:50052":   false,
		"10.0.0.5:50052":  false,
		"example.com:443": false, // non-literal hostname: cannot prove loopback
		"garbage":         false, // unparseable: fail closed
	}
	for addr, want := range cases {
		if got := grpccreds.IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestServerOption_RefusesPlaintextOnNonLoopback(t *testing.T) {
	// No TLS material + a routable addr MUST refuse (fail-closed). This is the
	// "never serve the containment surface in plaintext on a reachable port" rule.
	for _, addr := range []string{":50052", "0.0.0.0:50052", "10.0.0.5:50052"} {
		_, _, _, err := grpccreds.ServerOption(addr, grpccreds.ServerConfig{})
		if !errors.Is(err, grpccreds.ErrPlaintextNonLoopback) {
			t.Errorf("ServerOption(%q, no-tls) err = %v, want ErrPlaintextNonLoopback", addr, err)
		}
	}
}

func TestServerOption_AllowsBareLoopbackWithWarning(t *testing.T) {
	opts, posture, bareLoopback, err := grpccreds.ServerOption("127.0.0.1:50052", grpccreds.ServerConfig{})
	if err != nil {
		t.Fatalf("loopback bare plaintext should be allowed, got %v", err)
	}
	if !bareLoopback {
		t.Fatal("bareLoopback should be true so the caller can warn")
	}
	if len(opts) != 0 {
		t.Fatalf("bare loopback should apply no transport-credential options, got %d", len(opts))
	}
	if posture == "" {
		t.Fatal("posture should be described for the log line")
	}
}

func TestServerOption_BuildsMTLSWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)
	// mTLS configured on a routable addr is fine — that is exactly what mTLS is for.
	opts, _, bareLoopback, err := grpccreds.ServerOption(":50052", grpccreds.ServerConfig{
		CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.caPEM,
	})
	if err != nil {
		t.Fatalf("ServerOption with full mTLS config: %v", err)
	}
	if bareLoopback {
		t.Fatal("an mTLS config is not bare loopback")
	}
	if len(opts) != 1 {
		t.Fatalf("mTLS should apply exactly one grpc.Creds option, got %d", len(opts))
	}
}

func TestServerOption_PartialTLSConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)
	// Cert+key but no client-CA on a routable addr: this is a partial mTLS config,
	// which must error (not silently fall back to plaintext, and not skip client auth).
	_, _, _, err := grpccreds.ServerOption(":50052", grpccreds.ServerConfig{CertFile: srvCert, KeyFile: srvKey})
	if err == nil {
		t.Fatal("partial TLS config (no client-CA) must fail closed, not serve")
	}
}
