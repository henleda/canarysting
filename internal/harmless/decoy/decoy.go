// Package decoy is the GENERATION source of truth for harmless decoy bodies:
// deterministic, seed-driven builders of plausible-but-inert credentials, secrets,
// and hostnames drawn from documented EXAMPLE / RFC-reserved namespaces, so they
// authenticate to nothing and route nowhere.
//
// It is the counterpart to internal/harmless (the VALIDATION source of truth):
// `harmless` asserts a body is safe; `decoy` generates bodies that are safe by
// construction. Every builder here passes harmless.CrossScan for all seeds, proven
// over samples in decoy_test.go (the construction-time discipline the canary
// catalog uses).
//
// Builders are pure functions of a uint64 seed (NOT an rng), so callers that need
// reproducible-per-flow output (attrition, keyed by the socket cookie) get
// identical bytes for the same seed. This package imports ONLY the standard
// library, so internal/sting/attrition may import it without breaking its
// {contract, harmless, stdlib}-only import constraint, and internal/canary/catalog
// may adopt it without a cycle. See docs/STING.md and docs/ATTRITION_FIVE_AXIS_DESIGN.md §2.1.
package decoy

import "strings"

const (
	upperAlnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	secretAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
	lowerAlnum  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// reservedTLDs are the RFC 2606 reserved top-level domains. A host under any of
// them is guaranteed non-routable, so an embedded hostname can never reach a real
// service. (`harmless.AllHostsReserved` validates exactly this property.)
var reservedTLDs = []string{".example", ".invalid", ".test"}

// mix is a splitmix64-style deterministic mixer. It is byte-identical to the mixer
// internal/sting/attrition uses, so a decoy builder fed a given seed reproduces the
// exact bytes attrition produced before this package existed (the refactor onto
// decoy is a pure de-duplication, not a behavioral change).
func mix(a, b uint64) uint64 {
	x := a + 0x9e3779b97f4a7c15 + (b << 6) + (b >> 2)
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// token derives an n-character string over alphabet from seed, deterministically.
// Identical to attrition's randToken so shared builders preserve output.
func token(seed uint64, n int, alphabet string) string {
	var b strings.Builder
	b.Grow(n)
	h := seed
	for i := 0; i < n; i++ {
		h = mix(h, uint64(i))
		b.WriteByte(alphabet[h%uint64(len(alphabet))])
	}
	return b.String()
}

// ExampleAWSKeyID returns "AKIA" + 9 random + "EXAMPLE" (20 chars), an access-key
// id in the AWS documentation EXAMPLE namespace (authenticates to nothing).
func ExampleAWSKeyID(seed uint64) string { return "AKIA" + token(seed, 9, upperAlnum) + "EXAMPLE" }

// ExampleAWSSecret returns 30 random + "EXAMPLEKEY" (40 chars), an AWS-shaped
// secret in the EXAMPLE namespace.
func ExampleAWSSecret(seed uint64) string { return token(seed, 30, secretAlpha) + "EXAMPLEKEY" }

// ReservedHost returns a plausible internal hostname under an RFC 2606 reserved
// TLD (.example/.invalid/.test) — realistic in shape, non-routable in fact.
func ReservedHost(seed uint64) string {
	label := token(seed, 8, lowerAlnum)
	tld := reservedTLDs[seed%uint64(len(reservedTLDs))]
	return label + tld
}
