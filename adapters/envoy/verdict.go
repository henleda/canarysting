package envoy

import (
	"context"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/canarysting/canarysting/internal/contract"
)

// dynMetaNamespace is the dynamic-metadata namespace the adapter writes the
// suspicious tag under, for downstream filters and access logs.
const dynMetaNamespace = "canarysting"

// continueResp returns a CONTINUE response (the request proceeds upstream),
// optionally attaching dynamic metadata (the suspicious tag).
func continueResp(meta *structpb.Struct) *extprocv3.ProcessingResponse {
	r := &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}, // zero Status == CONTINUE
		},
	}
	if meta != nil {
		r.DynamicMetadata = meta
	}
	return r
}

// continuePhase returns a CONTINUE response whose oneof MATCHES the inbound
// phase. ext_proc requires the response variant to mirror the request variant
// (a response_headers request must be answered with response_headers, trailers
// with trailers, etc.); replying to any phase with a request_headers response is
// a protocol violation Envoy rejects. M4 configures request_header_mode only, but
// the adapter stays correct for any phase rather than relying on that config.
func continuePhase(req *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	switch req.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}}}
	case *extprocv3.ProcessingRequest_RequestBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}
	case *extprocv3.ProcessingRequest_ResponseBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{}}}
	default: // request_headers, or a nil/unknown oneof: a request-headers CONTINUE is correct/safe
		return continueResp(nil)
	}
}

// immediateDeny stops the request at the proxy with an HTTP status + body —
// Tier 3 hard-deny (403) or the Tier 2 rate-limit signal (429).
func immediateDeny(code typev3.StatusCode, body string) *extprocv3.ProcessingResponse {
	return immediateDenyWithBody(code, []byte(body))
}

// immediateDenyWithBody is immediateDeny with a pre-assembled byte body — the
// attrition deception payload. ImmediateResponse is sent by Envoy directly to the
// downstream client, bypassing the response filter chain, so the deception body
// does NOT require response_body_mode in envoy.yaml to be anything but NONE/SKIP.
func immediateDenyWithBody(code typev3.StatusCode, body []byte) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: code},
				Body:   body,
			},
		},
	}
}

// attritionOrDeny returns the ImmediateResponse for a Tier 2/3 inline verdict,
// substituting a live attrition hold for the plain deny when an Attritor is
// configured and produces a live stream.
//
// It opens the stream and drives it through pumpStream, which IMPOSES THE REAL
// HOLD (it sleeps each chunk's delay; see pump.go). When the stream is a noop
// (below Tier 2, kill switch, governor cap, unattributable) it yields no bytes
// and a non-NotDone reason on the first Next, so pumpStream returns an empty body
// — we detect that and fall back to the plain deny. nil Attritor likewise falls
// back. After the body+outcome are assembled, onOutcome is invoked FIRE-AND-
// FORGET (a goroutine) so the engine round-trip never blocks/extends the response.
//
// This is the M6 live pump that the M4 seam anticipated.
func (a *Adapter) attritionOrDeny(ctx context.Context, ev contract.SignalEvent, v contract.Verdict, code typev3.StatusCode, fallbackBody string) *extprocv3.ProcessingResponse {
	if a.cfg.Attritor == nil {
		return immediateDeny(code, fallbackBody)
	}
	s := a.cfg.Attritor.Open(v)
	defer s.Close()

	// Hard-bound the inline hold: the deception body is returned as ONE ext_proc
	// ImmediateResponse, so the whole hold must finish inside the proxy's
	// message_timeout, and the defender must not hold a goroutine past the cap.
	// pumpStream sleeps each chunk's delay and only re-checks the budget at chunk
	// boundaries, so a long chunk delay could otherwise blow past MaxDuration; this
	// deadline cuts any in-progress sleep. holdCtx still derives from ctx, so a real
	// downstream disconnect cancels it sooner than the cap.
	holdCtx := ctx
	if a.cfg.AttritionMaxHold > 0 {
		var cancel context.CancelFunc
		holdCtx, cancel = context.WithTimeout(ctx, a.cfg.AttritionMaxHold)
		defer cancel()
	}
	body, outcome := pumpStream(holdCtx, s, a.cfg.AttritionBodyCap, a.cfg.attritionSleep)

	// A noop stream (DoneNoOp/DoneKilled/DoneGlobalCeiling before any data) yields
	// no body: fall back to the plain deny rather than return an empty deception.
	// The two clauses are not independent conditions: the governor reserves the
	// byte budget BEFORE the pump emits, so BytesServed >= len(body) always holds.
	// Hence len(body)==0 already implies BytesServed==0; the second clause is
	// defensive/redundant (it cannot be the sole reason we fall back), kept only to
	// state the invariant explicitly at the call site.
	if len(body) == 0 && outcome.BytesServed == 0 {
		return immediateDeny(code, fallbackBody)
	}

	// Classify how the hold ended (AX1 / D7) and stamp the attacker-cost meter
	// BEFORE reporting: the attrition stream can't tell a client disconnect from our
	// max-hold deadline (both arrive as a cancelled ctx), but holdCtx can.
	// TimeToDisengageSec lands only when the attacker disengaged first. This runs
	// before defer cancel(), so holdCtx.Err() still distinguishes Canceled (attacker)
	// from DeadlineExceeded (our cap).
	outcome.DisengageReason, outcome.TimeToDisengageSec = classifyDisengage(outcome.Reason, holdCtx.Err(), outcome.TimeHeldSec)

	// Report the outcome OFF the response path: the hold is already complete, so
	// the report is non-blocking from a correctness standpoint, and a goroutine
	// keeps the engine gRPC round-trip from extending the inline request.
	if a.cfg.OnOutcome != nil {
		// The caller's defer s.Close() runs as attritionOrDeny returns — i.e. the
		// governor slot is intentionally RELEASED before this (advisory, non-
		// admission-blocking) outcome report completes. The report cannot hold a slot:
		// it is fire-and-forget and never gates a future flow's admission.
		go a.cfg.OnOutcome(ev, v, outcome)
	}
	return immediateDenyWithBody(code, body)
}

// suspiciousTag builds the Tier-1 dynamic-metadata tag (ADAPTERS.md: carry the
// suspicious tag as flow state). It carries NO decision — only the engine's
// tier/score, for downstream visibility.
func suspiciousTag(v contract.Verdict) *structpb.Struct {
	s, err := structpb.NewStruct(map[string]interface{}{
		dynMetaNamespace: map[string]interface{}{
			"suspicious": true,
			"tier":       float64(v.Tier),
			"score":      v.Score,
			"calibrated": v.Calibrated,
		},
	})
	if err != nil {
		return nil // structpb.NewStruct only errors on unsupported types; ours are supported
	}
	return s
}

// responseForVerdict maps an engine Verdict to the ext_proc response, honoring the
// tier and enforcement mode. It carries NO tiering logic — it only ACTS on the
// verdict the engine already decided (CLAUDE.md rule 1):
//
//	Tier 0/1        -> CONTINUE (+ suspicious tag at Tier 1). Async by design.
//	Tier 2/3 async  -> CONTINUE; the kernel (M5), keyed by the SAME socket cookie,
//	                   enforces on subsequent packets.
//	Tier 2 inline   -> 429 (rate-limit signal).
//	Tier 3 inline   -> 403 (hard deny).
//
// Attrition seam (M6): at Tier 2/3 inline with an Attritor configured, a future
// StreamedImmediateResponse pump replaces the plain deny with a streamed deception
// body. M4 ships the seam (the Attritor injection point), not the live pump — the
// exit bar requires a real verdict, not a deception body (ROADMAP M4 decision).
func responseForVerdict(v contract.Verdict) *extprocv3.ProcessingResponse {
	switch {
	case v.Tier <= contract.TierTag:
		var tag *structpb.Struct
		if v.Tier == contract.TierTag {
			tag = suspiciousTag(v)
		}
		return continueResp(tag)
	case v.Mode == contract.ModeAsync:
		return continueResp(nil) // kernel enforces T2/T3 async out of band
	case v.Tier == contract.TierContain:
		return immediateDeny(typev3.StatusCode_TooManyRequests, "rate limited\n")
	default: // TierJail inline
		return immediateDeny(typev3.StatusCode_Forbidden, "forbidden\n")
	}
}
