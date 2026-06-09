// Package enginegrpc is the out-of-process transport for the engine contract: a
// server that exposes any contract.Engine over gRPC, and a client that presents a
// remote engine back AS a contract.Engine. This is the boundary the api/proto
// Engine.Submit service anticipates; it lets the Envoy adapter (a separate
// process / a K8s DaemonSet) talk to the engine (a separate process / Deployment)
// while depending only on internal/contract. Both sides share api/convert, so the
// wire translation cannot drift.
package enginegrpc

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/canarysting/canarysting/api/convert"
	pb "github.com/canarysting/canarysting/api/gen"
	"github.com/canarysting/canarysting/internal/contract"
)

// --- server side ---

type server struct {
	pb.UnimplementedEngineServer
	eng      contract.Engine
	reporter contract.OutcomeReporter // optional; nil => ReportOutcome is a no-op ack
}

func (s *server) Submit(_ context.Context, req *pb.SignalEvent) (*pb.Verdict, error) {
	v, err := s.eng.Submit(convert.SignalFromProto(req))
	if err != nil {
		return nil, err
	}
	return convert.VerdictToProto(v), nil
}

// ReportOutcome amends the engine's durable interaction store with an adapter-
// side attrition outcome. It is nil-safe: an engine wired without an outcome
// reporter (e.g. the production engine with no EventStore) acks without acting,
// so the adapter's fire-and-forget report never errors against such an engine.
func (s *server) ReportOutcome(_ context.Context, req *pb.OutcomeRecord) (*pb.Empty, error) {
	if s.reporter == nil {
		return &pb.Empty{}, nil
	}
	if err := s.reporter.ReportOutcome(convert.OutcomeFromProto(req)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}

// Register exposes a contract.Engine as the gRPC Engine service on s. The engine
// package is never imported here — only the contract — so the proxy-agnostic seam
// holds across the process boundary. reporter is optional (nil => ReportOutcome
// acks without durable capture); pass the engine's OutcomeReporter to persist
// adapter-side attrition outcomes.
func Register(s grpc.ServiceRegistrar, eng contract.Engine, reporter contract.OutcomeReporter) {
	pb.RegisterEngineServer(s, &server{eng: eng, reporter: reporter})
}

// --- client side ---

// client adapts a generated pb.EngineClient back to contract.Engine so callers
// (the Envoy adapter) depend only on the contract while talking to a remote
// engine.
type client struct {
	c       pb.EngineClient
	timeout time.Duration // hard per-call safety cap; <=0 means no deadline
}

var _ contract.Engine = (*client)(nil)

func (c *client) Submit(e contract.SignalEvent) (contract.Verdict, error) {
	ctx := context.Background()
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	v, err := c.c.Submit(ctx, convert.SignalToProto(e))
	if err != nil {
		return contract.Verdict{}, err
	}
	return convert.VerdictFromProto(v), nil
}

// NewClient wraps a gRPC connection as a contract.Engine. callTimeout is a hard
// safety cap on each Submit so a hung engine cannot block a request forever; the
// adapter still applies its own per-tier InlineTimeout + FailPolicy on top. A
// zero callTimeout means no deadline.
func NewClient(cc grpc.ClientConnInterface, callTimeout time.Duration) contract.Engine {
	return &client{c: pb.NewEngineClient(cc), timeout: callTimeout}
}

// OutcomeClient is the adapter-side reporter of attrition outcomes back to the
// engine over the same gRPC connection as the engine client. It satisfies
// contract.OutcomeReporter, so the composition root depends only on the contract.
// It is separate from NewClient's contract.Engine because the report path is a
// distinct, fire-and-forget seam (the adapter never blocks the response on it).
type OutcomeClient struct {
	c       pb.EngineClient
	timeout time.Duration // hard per-call safety cap; <=0 means no deadline
}

var _ contract.OutcomeReporter = (*OutcomeClient)(nil)

// ReportOutcome ships one OutcomeRecord to the engine. The caller (composition
// root) runs this off the response path so a slow/hung engine never extends the
// inline request.
func (c *OutcomeClient) ReportOutcome(rec contract.OutcomeRecord) error {
	ctx := context.Background()
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	_, err := c.c.ReportOutcome(ctx, convert.OutcomeToProto(rec))
	return err
}

// NewOutcomeClient wraps a gRPC connection as a contract.OutcomeReporter.
// callTimeout caps each report so a hung engine cannot pile up goroutines on the
// adapter; a zero callTimeout means no deadline.
func NewOutcomeClient(cc grpc.ClientConnInterface, callTimeout time.Duration) *OutcomeClient {
	return &OutcomeClient{c: pb.NewEngineClient(cc), timeout: callTimeout}
}
