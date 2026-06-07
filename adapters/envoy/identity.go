package envoy

import (
	"net"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/internal/canary/seeder"
)

// RequestObservation is the slice of an HTTP request the adapter inspects: the
// method, the path (no query), and a lower-cased header map. It is the input to a
// LocationMapper.
type RequestObservation struct {
	Method  string
	Path    string
	Headers map[string]string
}

// LocationMapper deterministically maps a request to a candidate canary location.
// It is a NON-deciding transform: whether the location actually holds a canary is
// answered only by the placement registry inside signal.Builder. ok=false means
// "no candidate" (the request continues with no signal).
type LocationMapper interface {
	ToLocation(obs RequestObservation) (seeder.Location, bool)
}

// StripQueryPathMapper maps the request path (query stripped) to a seeder.Location
// — the default mapper. Path-based canaries (e.g. /.env, /admin-secrets) cover the
// M4 demo; richer mappers (header/host) can be injected without engine changes.
type StripQueryPathMapper struct{}

// ToLocation implements LocationMapper.
func (StripQueryPathMapper) ToLocation(obs RequestObservation) (seeder.Location, bool) {
	p := obs.Path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "", false
	}
	return seeder.Location(p), true
}

// observationFromHeaders extracts the method, path, and headers from an Envoy
// HeaderMap. Envoy carries method/path as the ":method"/":path" pseudo-headers.
func observationFromHeaders(h *corev3.HeaderMap) RequestObservation {
	obs := RequestObservation{Headers: map[string]string{}}
	for _, hv := range h.GetHeaders() {
		k := strings.ToLower(hv.GetKey())
		v := hv.GetValue()
		if v == "" && len(hv.GetRawValue()) > 0 {
			v = string(hv.GetRawValue())
		}
		switch k {
		case ":path":
			obs.Path = v
		case ":method":
			obs.Method = v
		default:
			obs.Headers[k] = v
		}
	}
	return obs
}

// Attribute keys requested via the ext_proc filter's request_attributes. CEL
// renders source/destination Address as an "ip:port" string.
const (
	attrSourceAddress = "source.address"
	attrDestAddress   = "destination.address"
	attrPeerSPIFFE    = "connection.uri_san_peer_certificate"
)

// tupleFromAttributes builds the host-canonical FourTuple from the ext_proc
// connection attributes. ok=false (no usable source/destination) means the flow
// is unattributable downstream — the adapter then leaves the socket cookie zero
// and signal.Builder refuses to emit (observe-only, never enforce).
func tupleFromAttributes(attrs map[string]*structpb.Struct) (identity.FourTuple, bool) {
	src, okS := stringAttr(attrs, attrSourceAddress)
	dst, okD := stringAttr(attrs, attrDestAddress)
	if !okS || !okD {
		return identity.FourTuple{}, false
	}
	sIP, sPort, ok1 := splitHostPort(src)
	dIP, dPort, ok2 := splitHostPort(dst)
	if !ok1 || !ok2 {
		return identity.FourTuple{}, false
	}
	return identity.TupleFromAddrs(sIP, sPort, dIP, dPort)
}

// spiffeFromAttributes returns the peer SPIFFE id if Envoy surfaced one (mTLS),
// else "". It is informational L7 context, never the join key.
func spiffeFromAttributes(attrs map[string]*structpb.Struct) string {
	if s, ok := stringAttr(attrs, attrPeerSPIFFE); ok {
		return s
	}
	return ""
}

// stringAttr finds a string-valued attribute by CEL key across the attribute
// structs (Envoy keys the outer map by the populating context; we scan all).
func stringAttr(attrs map[string]*structpb.Struct, key string) (string, bool) {
	for _, s := range attrs {
		if s == nil {
			continue
		}
		if f, ok := s.GetFields()[key]; ok {
			if sv, ok := f.GetKind().(*structpb.Value_StringValue); ok && sv.StringValue != "" {
				return sv.StringValue, true
			}
		}
	}
	return "", false
}

func splitHostPort(s string) (string, uint16, bool) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, uint16(p), true
}
