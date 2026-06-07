// Command envoy-selfcheck drives the Envoy adapter end-to-end against a REAL
// in-process engine and a FakeResolver — no Envoy, no kernel — and prints the
// attacker -> verdict ledger that the M4 exit bar is about: a canary touch
// produces a real verdict with the socket cookie carried end-to-end, a non-canary
// request is waved through with no engine round-trip, and an unattributable touch
// is observed but never enforced. It exits non-zero on any invariant violation,
// so it doubles as a CI gate (mirrors cmd/sting-selfcheck). The real Envoy +
// sockops round-trip is the on-box exit test (M4 on-box phase).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/canarysting/canarysting/adapters/envoy"
	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
)

const scopeKey = contract.ScopeKey("demo-scope")

// recordingEngine wraps the real engine to record what the adapter submitted, so
// the ledger can prove the cookie was carried across the contract.
type recordingEngine struct {
	inner       contract.Engine
	submits     int
	lastCookie  uint64
	lastVerdict contract.Verdict
}

func (r *recordingEngine) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	r.submits++
	r.lastCookie = ev.Flow.SocketCookie
	v, err := r.inner.Submit(ev)
	r.lastVerdict = v
	return v, err
}

func tierName(t contract.Tier) string {
	switch t {
	case contract.TierObserve:
		return "T0 observe"
	case contract.TierTag:
		return "T1 tag"
	case contract.TierContain:
		return "T2 contain"
	case contract.TierJail:
		return "T3 jail"
	default:
		return "T?"
	}
}

// buildEngine wires the real in-process engine (same recipe as cmd/engine).
func buildEngine() (contract.Engine, error) {
	resolver, err := scope.NewStaticResolver(scope.Config{Boundary: scopeKey})
	if err != nil {
		return nil, err
	}
	cat := catalog.Default()
	calib := calibration.New(calibration.Config{SeedWeights: cat.SeedWeights()})
	base := baseline.New(baseline.Config{Calibrated: func(s contract.ScopeKey) bool { return calib.State(s).Calibrated }})
	scorer := scoring.New(scoring.DefaultWindow, calib, scoring.NoExclusions{}).UseMultiplier(base)
	return engine.New(engine.Config{
		Resolver:    resolver,
		Scorer:      scorer,
		Decider:     tiers.StaticDecider{},
		Tiers:       tiers.DefaultConfig(),
		Calibration: calib,
	})
}

// localStream feeds canned ProcessingRequests to Adapter.Process and captures the
// responses (a minimal ext_proc server stream, no network).
type localStream struct {
	grpc.ServerStream
	ctx context.Context
	in  []*extprocv3.ProcessingRequest
	i   int
	out []*extprocv3.ProcessingResponse
}

func (s *localStream) Context() context.Context { return s.ctx }
func (s *localStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if s.i >= len(s.in) {
		return nil, io.EOF
	}
	r := s.in[s.i]
	s.i++
	return r, nil
}
func (s *localStream) Send(r *extprocv3.ProcessingResponse) error {
	s.out = append(s.out, r)
	return nil
}

func headersReq(path, src, dst string) *extprocv3.ProcessingRequest {
	req := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":path", Value: path}, {Key: ":method", Value: "GET"},
		}}},
	}}
	if src != "" {
		a, _ := structpb.NewStruct(map[string]interface{}{"source.address": src, "destination.address": dst})
		req.Attributes = map[string]*structpb.Struct{"conn": a}
	}
	return req
}

func action(r *extprocv3.ProcessingResponse) string {
	if ir := r.GetImmediateResponse(); ir != nil {
		switch ir.GetStatus().GetCode() {
		case typev3.StatusCode_Forbidden:
			return "DENY(403)"
		case typev3.StatusCode_TooManyRequests:
			return "RATELIMIT(429)"
		default:
			return fmt.Sprintf("IMMEDIATE(%d)", ir.GetStatus().GetCode())
		}
	}
	if r.GetDynamicMetadata() != nil {
		return "CONTINUE+tag"
	}
	return "CONTINUE"
}

func main() {
	inner, err := buildEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: building engine: %v\n", err)
		os.Exit(1)
	}
	eng := &recordingEngine{inner: inner}

	// Canaries seeded in the negative space: paths legit traffic never uses.
	reg := seeder.NewMemRegistry()
	canaries := []struct {
		path string
		typ  contract.CanaryType
	}{
		{"/.env", "decoy_file"},
		{"/admin-secrets", "planted_credential"},
		{"/backup-db.sql", "fake_secret"},
		{"/.git/config", "fake_endpoint"},
		{"/internal/metrics-creds", "fake_bucket"},
		{"/.aws/credentials", "planted_credential"},
	}
	for _, c := range canaries {
		if err := reg.Put(seeder.Placement{Scope: scopeKey, Type: c.typ, Location: seeder.Location(c.path)}); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: seeding %s: %v\n", c.path, err)
			os.Exit(1)
		}
	}

	res := identity.NewFakeResolver()
	const attackerCookie = uint64(0x5713C0FFEE)
	ft, _ := identity.TupleFromAddrs("203.0.113.9", 44001, "10.0.0.2", 8443)
	res.Set(ft, identity.Resolution{Cookie: attackerCookie, PID: 31337})

	a, err := envoy.New(envoy.Config{Engine: eng, Registry: reg, Resolver: res, Scope: scopeKey, Inline: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: building adapter: %v\n", err)
		os.Exit(1)
	}

	failed := false
	fmt.Println("CanarySting M4 adapter self-check — attacker -> real verdict, socket cookie carried end-to-end")
	fmt.Printf("%-24s %-13s %-12s %-7s %-14s\n", "request", "engine verdict", "L7 action", "score", "cookie")
	fmt.Printf("%-24s %-13s %-12s %-7s %-14s\n", "-------", "--------------", "---------", "-----", "------")

	drive := func(path, src, dst string) *extprocv3.ProcessingResponse {
		s := &localStream{ctx: context.Background(), in: []*extprocv3.ProcessingRequest{headersReq(path, src, dst)}}
		if err := a.Process(s); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: Process(%s): %v\n", path, err)
			os.Exit(1)
		}
		return s.out[0]
	}

	// 1) Recon over legit paths — zero signals (CLAUDE.md rule 8: deviation is not a trigger).
	before := eng.submits
	r := drive("/orders?id=42", "203.0.113.9:44001", "10.0.0.2:8443")
	if eng.submits != before {
		fmt.Fprintln(os.Stderr, "FAIL: a non-canary request submitted to the engine")
		failed = true
	}
	fmt.Printf("%-24s %-13s %-12s %-7s %-14s\n", "/orders (legit)", "-", action(r), "-", "no-submit")

	// 2) The attacker brushes canaries in the negative space — each a real verdict,
	//    the cookie carried across the contract; the tier ladder climbs.
	src := "203.0.113.9:44001"
	for _, c := range canaries {
		before = eng.submits
		r := drive(c.path, src, "10.0.0.2:8443")
		if eng.submits != before+1 {
			fmt.Fprintf(os.Stderr, "FAIL: canary touch %s did not submit exactly once\n", c.path)
			failed = true
		}
		if eng.lastCookie != attackerCookie {
			fmt.Fprintf(os.Stderr, "FAIL: %s did not carry the socket cookie (got %x)\n", c.path, eng.lastCookie)
			failed = true
		}
		fmt.Printf("%-24s %-13s %-12s %-7.2f %#-14x\n", c.path, tierName(eng.lastVerdict.Tier), action(r), eng.lastVerdict.Score, eng.lastCookie)
	}

	// 3) A canary touch from an UNATTRIBUTABLE flow (no cookie) — observed, never enforced.
	before = eng.submits
	r = drive("/.env", "198.51.100.5:60000", "10.0.0.2:8443") // a tuple the resolver has no cookie for
	if eng.submits != before {
		fmt.Fprintln(os.Stderr, "FAIL: an unattributable canary touch submitted/enforced")
		failed = true
	}
	if ir := r.GetImmediateResponse(); ir != nil {
		fmt.Fprintln(os.Stderr, "FAIL: an unattributable canary touch was enforced at L7")
		failed = true
	}
	fmt.Printf("%-24s %-13s %-12s %-7s %-14s\n", "/.env (no cookie)", "-", action(r), "-", "observe-only")

	_ = time.Now
	if failed {
		fmt.Fprintln(os.Stderr, "\nenvoy-selfcheck: FAILED")
		os.Exit(1)
	}
	fmt.Println("\nenvoy-selfcheck: OK — canary touches produce real verdicts with the cookie carried; non-canary and unattributable flows are never enforced.")
}
