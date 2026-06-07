// Package harmless holds the machine-checkable safety predicates that prove a
// generated payload is non-functional: it grants no real access, holds no real
// data, and points at no routable asset. These predicates are the proof — not a
// comment — that a generator cannot emit a functional secret or a live locator.
//
// It is depended on by BOTH the canary catalog (internal/canary/catalog), whose
// decoys must be harmless when touched, AND the sting attrition layer
// (internal/sting/attrition), whose fake-resource bait must be equally harmless.
// A safety predicate must have a single source of truth so a fix in one place
// can never miss the other; that is why this lives in its own package. It imports
// only the standard library.
//
// The guarantee rests on two structural properties, both reviewer-checkable:
//  1. Reserved / documentation namespaces. Hosts are RFC 2606 reserved domains
//     (.example/.invalid/.test) and IPs are RFC 5737 (TEST-NET) / RFC 3849
//     (2001:db8::/32) — addresses that route nowhere by IETF designation. AWS
//     credential material is drawn only from the AWS-documented EXAMPLE
//     namespace (id ends "EXAMPLE", secret ends "EXAMPLEKEY"), which AWS uses
//     precisely because it authenticates to no IAM principal.
//  2. Structural invalidity. A decoy private key is PEM-armored over a body that
//     is deliberately not valid DER, so EVERY standard key parser fails — a real
//     key parses, so a real key definitionally cannot pass IsInertPrivateKey. A
//     decoy JWT uses alg:"none" with an empty signature, rejected by every
//     compliant verifier.
package harmless

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Error reports why a payload failed the harmlessness check.
type Error struct{ Reason string }

func (e *Error) Error() string { return "harmless: not provably harmless: " + e.Reason }

// --- AWS credential material (AWS-documented EXAMPLE namespace) ---

var (
	awsKeyIDRe  = regexp.MustCompile(`AKIA[A-Z0-9]{16}`)            // 20-char access key id
	awsSecretRe = regexp.MustCompile(`[A-Za-z0-9/+]{30}EXAMPLEKEY`) // 40-char secret ending EXAMPLEKEY
)

// FindAWSKeyIDs returns every AWS-shaped access key id (AKIA + 16 chars) found in
// a payload. The caller pairs it with IsExampleAWSKeyID to assert each is in the
// documentation namespace.
func FindAWSKeyIDs(payload []byte) []string {
	return awsKeyIDRe.FindAllString(string(payload), -1)
}

// HasExampleAWSSecret reports whether the payload contains an AWS-shaped secret in
// the documentation EXAMPLE namespace (a 40-char secret ending "EXAMPLEKEY").
func HasExampleAWSSecret(payload []byte) bool {
	return awsSecretRe.MatchString(string(payload))
}

// IsExampleAWSKeyID reports whether id is a structurally valid AWS access key id
// drawn from the documentation EXAMPLE namespace (so it authenticates to nothing).
// A live-shaped AKIA id that does NOT end "EXAMPLE" is rejected — the predicate
// has teeth.
func IsExampleAWSKeyID(id string) bool {
	return len(id) == 20 && strings.HasPrefix(id, "AKIA") &&
		isUpperAlphaNum(id[4:]) && strings.HasSuffix(id, "EXAMPLE")
}

func isUpperAlphaNum(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// --- Reserved hosts and IPs (RFC 2606 / 5737 / 3849) ---

var (
	reservedTLDSuffixes = []string{".example", ".invalid", ".test", ".localhost"}
	reservedSLDs        = map[string]bool{"example.com": true, "example.net": true, "example.org": true}
	// RFC 5737 TEST-NET ranges and RFC 3849 documentation IPv6 prefix.
	reservedIPNets = mustCIDRs("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("harmless: bad reserved CIDR " + c) // build-time constant; guarded by test
		}
		out = append(out, n)
	}
	return out
}

// IsReservedHost reports whether host (no port) is in an RFC 2606 reserved
// domain, so it resolves to nothing on the public Internet.
func IsReservedHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if reservedSLDs[h] {
		return true
	}
	for _, suf := range reservedTLDSuffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	for sld := range reservedSLDs {
		if strings.HasSuffix(h, "."+sld) {
			return true
		}
	}
	return false
}

// IsReservedIP reports whether ip is in an RFC 5737 TEST-NET range or the RFC
// 3849 documentation IPv6 prefix — non-routable by IETF designation.
func IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range reservedIPNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsReservedHostOrIP accepts a host that is either a reserved domain or a
// reserved IP literal.
func IsReservedHostOrIP(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return IsReservedIP(ip)
	}
	return IsReservedHost(host)
}

// --- Structural invalidity (inert key material, unsigned JWT) ---

// derPrivateKeyLabels are the PEM private-key labels whose body we can
// affirmatively parse-check with the standard library.
var derPrivateKeyLabels = map[string]bool{
	"RSA PRIVATE KEY": true, // PKCS#1
	"EC PRIVATE KEY":  true, // SEC1
	"PRIVATE KEY":     true, // PKCS#8 (unencrypted)
}

// IsInertPrivateKey reports whether b is a PEM private-key block that is
// AFFIRMATIVELY non-functional: a recognized DER label whose body fails every
// standard parser. It is conservative on purpose — anything it cannot prove inert
// it treats as NOT inert (so CrossScan rejects it):
//   - an ENCRYPTED block is a real, passphrase-recoverable key → not inert.
//   - a label we cannot parse-check (e.g. "OPENSSH PRIVATE KEY") → not inert.
//
// A genuine key parses, so a genuine key can never pass this predicate.
func IsInertPrivateKey(b []byte) bool {
	block, _ := pem.Decode(b)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return false
	}
	// Encrypted key material is a real key; never "inert".
	if strings.Contains(block.Type, "ENCRYPTED") || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return false
	}
	// Only labels we can affirmatively parse-check are eligible to be inert.
	if !derPrivateKeyLabels[block.Type] {
		return false
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return false
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return false
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return false
	}
	return true
}

// IsUnsignedJWT reports whether t is a three-segment JWT with alg "none" and an
// empty signature segment — rejected by every compliant verifier.
func IsUnsignedJWT(t string) bool {
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[2] != "" {
		return false
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		return false
	}
	return strings.EqualFold(h.Alg, "none")
}

// --- Universal cross-scan (defense in depth) ---

var pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// urlRe is scheme-agnostic: any scheme://… (https, postgres, ssh, ldap, ftp,
// redis, mongodb, …) so a routable host cannot be smuggled behind an unlisted
// scheme.
var urlRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+`)

// AllHostsReserved asserts every URL host in a payload is an RFC 2606 reserved
// domain or an RFC 5737/3849 reserved IP — so nothing in the payload points at a
// routable asset. url.Hostname() handles IPv6 brackets, ports, and userinfo.
func AllHostsReserved(payload []byte) error {
	for _, raw := range urlRe.FindAllString(string(payload), -1) {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return &Error{Reason: "payload contains an unparseable URL: " + raw}
		}
		if !IsReservedHostOrIP(u.Hostname()) {
			return &Error{Reason: "payload references a routable host: " + u.Hostname()}
		}
	}
	return nil
}

// CrossScan rejects any payload that smuggles a live-shaped secret regardless of
// the payload's intended type: every AWS-shaped key id must be in the EXAMPLE
// namespace, every PEM private-key block must be inert, and every URL host must
// be reserved (so no payload can embed a routable beacon/callback host). It is
// the universal backstop both layers run on every emission, so a generator
// regression cannot place a real-looking live secret or a routable locator.
func CrossScan(payload []byte) error {
	for _, id := range awsKeyIDRe.FindAllString(string(payload), -1) {
		if !IsExampleAWSKeyID(id) {
			return &Error{Reason: "payload contains a live-shaped AWS key id outside the EXAMPLE namespace: " + id}
		}
	}
	for _, block := range pemBlockRe.FindAllString(string(payload), -1) {
		if !IsInertPrivateKey([]byte(block)) {
			return &Error{Reason: "payload contains a parseable or encrypted (non-inert) private key"}
		}
	}
	return AllHostsReserved(payload)
}
