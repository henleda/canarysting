// Package correlation constructs bounded, scope-exact cross-source relationship
// candidates from minimized correlation keys.
//
// It does not build or persist security traces, mutate source observations, make
// security decisions, or authorize actions. Network addresses and source-native
// identifiers enter only as caller-supplied SHA-256/HMAC-SHA-256 digests. A
// CanarySting socket cookie is represented by an opaque digest plus its L7,
// kernel, or engine vantage; it remains the sole CanarySting L7/kernel join.
package correlation
