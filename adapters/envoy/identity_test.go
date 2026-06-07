package envoy

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
)

func attrs(t *testing.T, m map[string]interface{}) map[string]*structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]*structpb.Struct{"conn": s}
}

func TestTupleFromAttributes(t *testing.T) {
	ft, ok := tupleFromAttributes(attrs(t, map[string]interface{}{
		"source.address":      "203.0.113.7:54321",
		"destination.address": "10.0.0.2:8443",
	}))
	if !ok {
		t.Fatal("valid source/dest attributes should yield a tuple")
	}
	want, _ := identity.TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	if ft != want {
		t.Fatalf("tuple mismatch: %+v vs %+v", ft, want)
	}
}

func TestTupleFromAttributesIPv6(t *testing.T) {
	// Envoy renders IPv6 source/destination as bracketed "[host]:port"; the parser
	// must handle it (net.SplitHostPort requires the brackets).
	ft, ok := tupleFromAttributes(attrs(t, map[string]interface{}{
		"source.address":      "[2001:db8::1]:44000",
		"destination.address": "[2001:db8::2]:8443",
	}))
	if !ok {
		t.Fatal("bracketed IPv6 attributes should yield a tuple")
	}
	want, _ := identity.TupleFromAddrs("2001:db8::1", 44000, "2001:db8::2", 8443)
	if ft != want {
		t.Fatalf("IPv6 tuple mismatch: %+v vs %+v", ft, want)
	}
}

func TestTupleFromAttributesMissingOrBad(t *testing.T) {
	if _, ok := tupleFromAttributes(map[string]*structpb.Struct{}); ok {
		t.Fatal("no attributes should not yield a tuple")
	}
	if _, ok := tupleFromAttributes(attrs(t, map[string]interface{}{"source.address": "203.0.113.7:54321"})); ok {
		t.Fatal("missing destination should not yield a tuple")
	}
	if _, ok := tupleFromAttributes(attrs(t, map[string]interface{}{
		"source.address": "not-an-addr", "destination.address": "10.0.0.2:8443",
	})); ok {
		t.Fatal("unparseable source should not yield a tuple")
	}
}

func TestSpiffeFromAttributes(t *testing.T) {
	got := spiffeFromAttributes(attrs(t, map[string]interface{}{
		"connection.uri_san_peer_certificate": "spiffe://example/sa",
	}))
	if got != "spiffe://example/sa" {
		t.Fatalf("spiffe id = %q", got)
	}
	if spiffeFromAttributes(map[string]*structpb.Struct{}) != "" {
		t.Fatal("absent spiffe should be empty")
	}
}

func TestObservationFromHeaders(t *testing.T) {
	obs := observationFromHeaders(&corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":path", Value: "/.env?x=1"},
		{Key: ":method", Value: "GET"},
		{Key: "X-Forwarded-For", RawValue: []byte("1.2.3.4")},
	}})
	if obs.Path != "/.env?x=1" || obs.Method != "GET" {
		t.Fatalf("method/path wrong: %+v", obs)
	}
	if obs.Headers["x-forwarded-for"] != "1.2.3.4" {
		t.Fatalf("raw header value not read / not lowercased: %+v", obs.Headers)
	}
}

func TestStripQueryPathMapper(t *testing.T) {
	m := StripQueryPathMapper{}
	loc, ok := m.ToLocation(RequestObservation{Path: "/.env?token=abc"})
	if !ok || string(loc) != "/.env" {
		t.Fatalf("query not stripped: %q ok=%v", loc, ok)
	}
	if _, ok := m.ToLocation(RequestObservation{Path: ""}); ok {
		t.Fatal("empty path should not map to a location")
	}
}
