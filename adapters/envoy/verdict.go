package envoy

import (
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
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: code},
				Body:   []byte(body),
			},
		},
	}
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
