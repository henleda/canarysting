package grpccreds_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

// serveMTLS stands up a bufconn gRPC server with the given server credentials and
// returns a dialer the tests use to attempt a connection with various client
// credentials. The registered service is irrelevant — we only probe the TLS
// handshake, which the mTLS server enforces before any RPC dispatch.
func serveMTLS(t *testing.T, serverCreds grpc.ServerOption) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(serverCreds)
	healthpb.RegisterHealthServer(srv, &okHealth{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

type okHealth struct {
	healthpb.UnimplementedHealthServer
}

func (okHealth) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// probe dials lis with the given transport credentials and issues one RPC,
// returning the RPC error. A TLS handshake rejection surfaces here as a non-nil
// error (the connection never reaches a SERVING response).
func probe(t *testing.T, lis *bufconn.Listener, creds grpc.DialOption) error {
	t.Helper()
	// Authority "localhost" matches the server leaf's SAN so TLS server-name
	// verification passes over bufconn; the contextDialer still routes to the
	// in-memory listener regardless of the target string.
	cc, err := grpc.NewClient("passthrough:///localhost",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.DialContext(context.Background()) }),
		creds)
	if err != nil {
		return err
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestMTLS_AcceptsProperlySignedClient(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)
	cliCert, cliKey := ca.issue(t, dir, "client", false)

	sc, err := grpccreds.ServerCreds(grpccreds.ServerConfig{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.caPEM})
	if err != nil {
		t.Fatalf("ServerCreds: %v", err)
	}
	cc, err := grpccreds.ClientCreds(grpccreds.ClientConfig{CertFile: cliCert, KeyFile: cliKey, CAFile: ca.caPEM})
	if err != nil {
		t.Fatalf("ClientCreds: %v", err)
	}
	lis := serveMTLS(t, grpc.Creds(sc))
	if err := probe(t, lis, grpc.WithTransportCredentials(cc)); err != nil {
		t.Fatalf("a CA-signed client should be accepted, got %v", err)
	}
}

func TestMTLS_RejectsNoCertClient(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)

	sc, err := grpccreds.ServerCreds(grpccreds.ServerConfig{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.caPEM})
	if err != nil {
		t.Fatalf("ServerCreds: %v", err)
	}
	lis := serveMTLS(t, grpc.Creds(sc))
	// An insecure (no client cert, no TLS) dial — the forging attacker's posture.
	if err := probe(t, lis, grpc.WithTransportCredentials(insecure.NewCredentials())); err == nil {
		t.Fatal("mTLS server accepted a no-cert/plaintext client — B1 not closed")
	}
}

// TestMTLS_RejectsTLSClientWithoutCert isolates RequireAndVerifyClientCert from the
// plaintext-vs-TLS distinction: the client DOES speak TLS and DOES trust the server's
// CA (so it sails past server-name + server-cert verification), but presents NO client
// certificate. A correct mTLS server must still reject the handshake. Without this case
// TestMTLS_RejectsNoCertClient's pass could be explained purely by "the server demands
// TLS and the client spoke plaintext" — this proves the server actually demands the
// CLIENT cert, which is the B1 forge defense.
func TestMTLS_RejectsTLSClientWithoutCert(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)

	sc, err := grpccreds.ServerCreds(grpccreds.ServerConfig{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.caPEM})
	if err != nil {
		t.Fatalf("ServerCreds: %v", err)
	}

	// A TLS client that trusts the server CA but offers no client certificate.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	clientNoCert := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: "localhost", // matches the server leaf SAN over bufconn
		MinVersion: tls.VersionTLS12,
		// No Certificates: the client speaks TLS but presents no client cert.
	})

	lis := serveMTLS(t, grpc.Creds(sc))
	if err := probe(t, lis, grpc.WithTransportCredentials(clientNoCert)); err == nil {
		t.Fatal("mTLS server accepted a TLS client that presented no client certificate — RequireAndVerifyClientCert not enforced, B1 not closed")
	}
}

func TestMTLS_RejectsWrongCAClient(t *testing.T) {
	dir := t.TempDir()
	serverCA := newCA(t, dir)
	srvCert, srvKey := serverCA.issue(t, dir, "server", true)

	// A client cert signed by a DIFFERENT CA the server does not trust.
	rogueDir := t.TempDir()
	rogueCA := newCA(t, rogueDir)
	rogueCert, rogueKey := rogueCA.issue(t, rogueDir, "client", false)

	sc, err := grpccreds.ServerCreds(grpccreds.ServerConfig{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: serverCA.caPEM})
	if err != nil {
		t.Fatalf("ServerCreds: %v", err)
	}
	// The rogue client still trusts the real server CA (so it would proceed past
	// server verification), but presents a cert the server's client-CA rejects.
	cc, err := grpccreds.ClientCreds(grpccreds.ClientConfig{CertFile: rogueCert, KeyFile: rogueKey, CAFile: serverCA.caPEM})
	if err != nil {
		t.Fatalf("ClientCreds: %v", err)
	}
	lis := serveMTLS(t, grpc.Creds(sc))
	if err := probe(t, lis, grpc.WithTransportCredentials(cc)); err == nil {
		t.Fatal("mTLS server accepted a client signed by an untrusted CA — B1 not closed")
	}
}

func TestServerCreds_RejectsPartialConfig(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	srvCert, srvKey := ca.issue(t, dir, "server", true)
	cases := []grpccreds.ServerConfig{
		{},                                   // all empty
		{CertFile: srvCert, KeyFile: srvKey}, // missing client-CA (not mTLS)
		{CertFile: srvCert, ClientCAFile: ca.caPEM},                     // missing key
		{KeyFile: srvKey, ClientCAFile: ca.caPEM},                       // missing cert
		{CertFile: "/no/such", KeyFile: srvKey, ClientCAFile: ca.caPEM}, // unreadable cert
	}
	for i, c := range cases {
		if _, err := grpccreds.ServerCreds(c); err == nil {
			t.Errorf("case %d: ServerCreds(%+v) returned nil error; a partial/bad config must fail closed", i, c)
		}
	}
}

func TestClientCreds_RejectsPartialConfig(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	cliCert, cliKey := ca.issue(t, dir, "client", false)
	cases := []grpccreds.ClientConfig{
		{},
		{CertFile: cliCert, KeyFile: cliKey},  // missing CA
		{CertFile: cliCert, CAFile: ca.caPEM}, // missing key
		{KeyFile: cliKey, CAFile: ca.caPEM},   // missing cert
	}
	for i, c := range cases {
		if _, err := grpccreds.ClientCreds(c); err == nil {
			t.Errorf("case %d: ClientCreds(%+v) returned nil error; a partial config must fail closed", i, c)
		}
	}
	if _, err := grpccreds.ClientCreds(grpccreds.ClientConfig{}); !errors.Is(err, grpccreds.ErrMissingPath) {
		t.Errorf("empty ClientConfig should be ErrMissingPath, got %v", err)
	}
}
