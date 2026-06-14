// Package grpccreds builds mutual-TLS gRPC transport credentials for the engine
// gRPC boundary (the only out-of-process seam CanarySting exposes). It is a
// small, pure helper: it loads cert/key/CA material from file paths and returns
// grpc credentials.TransportCredentials, with no dependency on the contract, the
// engine, or any adapter — so both the engine server (cmd/engine,
// cmd/staged-range) and the adapter client (cmd/envoy-adapter) can use it
// without crossing a layer seam.
//
// WHY mTLS here: the engine gRPC surface accepts a SignalEvent and drives a
// kernel containment verdict (CLAUDE.md rules 4 + 8). An unauthenticated,
// plaintext surface lets any party that can reach the port forge a touch against
// a victim's flow. The SERVER credentials therefore REQUIRE and VERIFY a client
// certificate (tls.RequireAndVerifyClientCert) against a configured client-CA,
// and the CLIENT credentials present a client cert and verify the server against
// a CA. Only a holder of a CA-signed client cert can submit.
package grpccreds

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// ErrMissingPath is returned when a required file path is empty. Callers treat a
// partial TLS config as a misconfiguration, never as "disable TLS".
var ErrMissingPath = errors.New("grpccreds: required cert/key/CA path is empty")

// ServerConfig names the files for the engine's mTLS server credentials.
//   - CertFile / KeyFile: the server's own leaf certificate + private key.
//   - ClientCAFile: the CA bundle every client certificate MUST chain to.
//
// All three are required; mTLS without a client-CA is not mTLS.
type ServerConfig struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// ClientConfig names the files for the adapter's mTLS client credentials.
//   - CertFile / KeyFile: the client's own leaf certificate + private key it
//     presents to the server.
//   - CAFile: the CA bundle the server's certificate MUST chain to.
type ClientConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// ServerCreds builds mTLS server transport credentials that REQUIRE and VERIFY a
// client certificate against the configured client-CA
// (tls.RequireAndVerifyClientCert). A client that presents no certificate, or
// one that does not chain to ClientCAFile, is rejected at the TLS handshake —
// before any SignalEvent reaches the engine. Returns an error (never a
// half-configured insecure server) if any path is empty or unreadable.
func ServerCreds(cfg ServerConfig) (credentials.TransportCredentials, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ClientCAFile == "" {
		return nil, fmt.Errorf("%w: server needs cert, key, and client-CA", ErrMissingPath)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpccreds: load server keypair: %w", err)
	}
	clientCAs, err := loadCAPool(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("grpccreds: load client CA: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS: client MUST present a CA-signed cert
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// ClientCreds builds mTLS client transport credentials that present the client
// certificate and verify the server against the configured CA. Returns an error
// (never a half-configured insecure client) if any path is empty or unreadable.
func ClientCreds(cfg ClientConfig) (credentials.TransportCredentials, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
		return nil, fmt.Errorf("%w: client needs cert, key, and CA", ErrMissingPath)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpccreds: load client keypair: %w", err)
	}
	rootCAs, err := loadCAPool(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("grpccreds: load server CA: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// loadCAPool reads a PEM CA bundle from path into a fresh x509 pool. It returns
// an error if the file is unreadable or contains no usable certificate, so a
// typo'd or empty CA file fails closed rather than verifying against an empty
// pool (which would reject every peer, but for the wrong reason).
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %q contains no usable PEM certificate", path)
	}
	return pool, nil
}
