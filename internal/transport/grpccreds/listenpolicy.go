package grpccreds

import (
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// ErrPlaintextNonLoopback is returned by ServerOption when TLS material is not
// configured AND the listen address is routable (not loopback). The engine gRPC
// surface drives kernel containment, so it MUST NOT be served in plaintext on a
// reachable address — the caller treats this as fatal (refuse to start).
var ErrPlaintextNonLoopback = errors.New("grpccreds: refusing to serve the engine gRPC surface in plaintext on a non-loopback address (configure mTLS cert/key/client-CA)")

// ServerOption decides the transport posture for the engine gRPC server from the
// listen addr and the (possibly empty) mTLS file paths, and returns the
// grpc.ServerOption(s) to apply, the human-readable posture, and whether bare
// loopback plaintext was selected (so the caller can emit a WARNING).
//
// Policy (fail-closed):
//   - Any of cert/key/client-CA set -> ALL three required -> mTLS creds.
//   - No TLS material + LOOPBACK addr -> bare plaintext allowed (warn=true).
//   - No TLS material + ROUTABLE addr -> ErrPlaintextNonLoopback (refuse).
//
// This is the single place the loopback/plaintext exception lives, so both
// cmd/engine and cmd/staged-range enforce it identically.
func ServerOption(addr string, cfg ServerConfig) (opts []grpc.ServerOption, posture string, bareLoopback bool, err error) {
	anyTLS := cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ClientCAFile != ""
	if anyTLS {
		creds, cerr := ServerCreds(cfg)
		if cerr != nil {
			return nil, "", false, cerr
		}
		return []grpc.ServerOption{grpc.Creds(creds)}, "mTLS (RequireAndVerifyClientCert)", false, nil
	}
	if IsLoopbackAddr(addr) {
		return nil, "plaintext (loopback only)", true, nil
	}
	return nil, "", false, fmt.Errorf("%w: addr %q", ErrPlaintextNonLoopback, addr)
}

// IsLoopbackAddr reports whether a "host:port" (or ":port") listen address binds
// only the loopback interface. A bare ":port" / empty host binds ALL interfaces
// (routable), so it is NOT loopback. An unparseable address is treated as
// non-loopback (fail closed). A hostname host (not an IP literal) is also treated
// as non-loopback unless it is the literal "localhost".
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":port" binds every interface
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a non-literal hostname: cannot prove loopback, fail closed
	}
	return ip.IsLoopback()
}
