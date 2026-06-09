package enginegrpc_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/internal/contract"
)

// fakeEngine is a contract.Engine that records the last event and returns a
// scripted verdict (or error), so the test exercises the transport + conversion,
// not the real engine.
type fakeEngine struct {
	last contract.SignalEvent
	out  contract.Verdict
	err  error
}

func (f *fakeEngine) Submit(e contract.SignalEvent) (contract.Verdict, error) {
	f.last = e
	return f.out, f.err
}

// fakeReporter records the last reported outcome (or returns a scripted error),
// so the ReportOutcome transport + conversion is exercised end to end.
type fakeReporter struct {
	last contract.OutcomeRecord
	got  bool
	err  error
}

func (r *fakeReporter) ReportOutcome(rec contract.OutcomeRecord) error {
	r.last = rec
	r.got = true
	return r.err
}

func dial(t *testing.T, eng contract.Engine) (contract.Engine, func()) {
	t.Helper()
	cli, _, done := dialFull(t, eng, nil)
	return cli, done
}

// dialFull wires both the engine client and the outcome client over one bufconn,
// registering the optional reporter on the server.
func dialFull(t *testing.T, eng contract.Engine, reporter contract.OutcomeReporter) (contract.Engine, *enginegrpc.OutcomeClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	enginegrpc.Register(srv, eng, reporter)
	go func() { _ = srv.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.DialContext(context.Background()) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return enginegrpc.NewClient(cc, 2*time.Second), enginegrpc.NewOutcomeClient(cc, 2*time.Second), func() { _ = cc.Close(); srv.Stop() }
}

func TestRoundTripPreservesFields(t *testing.T) {
	fe := &fakeEngine{out: contract.Verdict{
		Flow:       contract.FlowIdentity{SocketCookie: 0xC0FFEE, PID: 99, SPIFFEID: "spiffe://x"},
		Scope:      "scope-a",
		Tier:       contract.TierJail,
		Mode:       contract.ModeInline,
		Score:      4.2,
		Calibrated: true,
	}}
	cli, done := dial(t, fe)
	defer done()

	ev := contract.SignalEvent{
		Flow:      contract.FlowIdentity{SocketCookie: 0xC0FFEE, CgroupID: 7, PID: 99, SPIFFEID: "spiffe://x", L7Attributes: map[string]string{"k": "v"}},
		Canary:    contract.CanaryType("planted_credential"),
		Scope:     "scope-a",
		Timestamp: time.UnixMilli(1_700_000_000_123),
	}
	got, err := cli.Submit(ev)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Verdict round-tripped intact (incl. the socket cookie — the whole point).
	if !reflect.DeepEqual(got, fe.out) {
		t.Fatalf("verdict mismatch:\n got %+v\nwant %+v", got, fe.out)
	}
	// The engine received the event with the cookie + canary + scope + timestamp.
	if fe.last.Flow.SocketCookie != 0xC0FFEE {
		t.Fatalf("server lost socket cookie: %x", fe.last.Flow.SocketCookie)
	}
	if fe.last.Canary != "planted_credential" || fe.last.Scope != "scope-a" {
		t.Fatalf("server lost canary/scope: %+v", fe.last)
	}
	if !fe.last.Timestamp.Equal(time.UnixMilli(1_700_000_000_123)) {
		t.Fatalf("server lost timestamp: %v", fe.last.Timestamp)
	}
	if fe.last.Flow.L7Attributes["k"] != "v" {
		t.Fatalf("server lost L7 attributes: %+v", fe.last.Flow.L7Attributes)
	}
}

func TestEngineErrorPropagates(t *testing.T) {
	cli, done := dial(t, &fakeEngine{err: errors.New("scope unresolved")})
	defer done()
	if _, err := cli.Submit(contract.SignalEvent{Timestamp: time.UnixMilli(1)}); err == nil {
		t.Fatal("engine error did not propagate across the gRPC boundary")
	}
}

func TestReportOutcomeRoundTrip(t *testing.T) {
	fr := &fakeReporter{}
	_, oc, done := dialFull(t, &fakeEngine{}, fr)
	defer done()

	rec := contract.OutcomeRecord{
		SocketCookie:    0xC0FFEE,
		Scope:           "scope-a",
		TimestampUnixMs: 1_700_000_000_123,
		Outcome: contract.StingOutcome{
			Mechanism:      "fake_tree",
			TimeHeldSec:    2.5,
			BytesServed:    4096,
			RequestsAbsrb:  9,
			TokenCostProxy: 1024,
			DepthReached:   3,
			DoneReason:     5,
		},
	}
	if err := oc.ReportOutcome(rec); err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	if !fr.got {
		t.Fatal("server never received the outcome")
	}
	// DoneReason is attrition control flow, not durable cost — the amend path drops
	// it, so the engine-side reporter sees it (round-trip) but the store ignores it.
	if !reflect.DeepEqual(fr.last, rec) {
		t.Fatalf("outcome mismatch across gRPC:\n got %+v\nwant %+v", fr.last, rec)
	}
}

// A nil reporter (engine without an EventStore) acks ReportOutcome without error,
// so the adapter's fire-and-forget report never fails against such an engine.
func TestReportOutcomeNilReporterAcks(t *testing.T) {
	_, oc, done := dialFull(t, &fakeEngine{}, nil)
	defer done()
	if err := oc.ReportOutcome(contract.OutcomeRecord{Scope: "scope-a"}); err != nil {
		t.Fatalf("nil-reporter ReportOutcome should ack, got %v", err)
	}
}

func TestReportOutcomeErrorPropagates(t *testing.T) {
	fr := &fakeReporter{err: errors.New("amend failed")}
	_, oc, done := dialFull(t, &fakeEngine{}, fr)
	defer done()
	if err := oc.ReportOutcome(contract.OutcomeRecord{Scope: "scope-a"}); err == nil {
		t.Fatal("reporter error did not propagate across the gRPC boundary")
	}
}
