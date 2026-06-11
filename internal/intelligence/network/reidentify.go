package network

import (
	"reflect"
	"strings"
)

// identityNames are field-name substrings (case-insensitive) that can re-identify a
// customer/environment, OR that name a deployment-local-only signal. A field whose
// name contains ANY of these is denied regardless of its tag/kind/value (§5.2 / D4).
// This is NECESSARY but NOT SUFFICIENT — the kind allowlist (D1) + the k-anonymity
// gate (D5) + the recursive walk (D2) are what make the predicate sound; a name
// denylist alone is bypassable by renaming, which is why they run together. Matching
// is fail-closed: an over-match denies a legitimately-coarse field, forcing a rename
// (the safe direction for a leak boundary).
var identityNames = []string{
	// direct identifiers + flow/scope identity
	"scope", "flowid", "flow_id", "cookie", "identity", "token",
	// network / location quasi-identifiers (a single deployment's environment)
	"ip", "host", "addr", "port", "mac", "vlan", "subnet", "cidr",
	"domain", "fqdn", "url", "uri", "region", "geo", "country", "asn",
	// org / tenancy quasi-identifiers
	"org", "tenant", "customer", "account", "cluster", "namespace",
	"spiffe", "cert", "serial", "agent", "method",
	// time, raw-content, learned-state, and config-leaking names
	"timestamp", "time_stamp", "lastseen", "firstseen", "features",
	"decoy", "baseline", "path", "content",
	"sequence", "order", "signature", "fingerprint", "digest", "checksum",
	"hash",     // D9 — no raw deterministic hash crosses (a plain fnv over the small vocab is reversible)
	"exploit",  // AX4 (D4) — a renamed same-valued field is still caught by name
	"exposure", // AX5 (D4)
}

func hasIdentityName(name string) bool {
	n := strings.ToLower(name)
	for _, bad := range identityNames {
		if strings.Contains(n, bad) {
			return true
		}
	}
	return false
}

// canReIdentify is the LINKABILITY half of docs/EGRESS_FILTER_DESIGN.md §5: it denies a
// field whose NAME is a direct/quasi identifier (§5.2). It is one of several checks Clear
// runs, NOT the whole predicate:
//   - singling-out (§5.1.1) is enforced by the candidate-level k-anonymity gate (D5) AND
//     by the per-field COARSENESS check in clearStruct (numeric fields must declare a
//     small band=LO..HI whose value is in range; floats are denied);
//   - no-inference (§5.1.3, raw counts / hashes) is enforced by that same band check
//     plus the "hash"/"digest"/"checksum"/"fingerprint" name tokens below;
//   - linkability (§5.1.2) is THIS function (the name denylist).
//
// This function deliberately checks only the name — coarseness lives in clearStruct's
// band gate, not here. (Earlier this comment overstated that the kind allowlist alone
// "forces bucketed values"; it does not — clearStruct's band requirement does. [leak-review])
// The value param is reserved for future value-domain predicate extensions.
func canReIdentify(name string, _ reflect.Value) (bad bool, reason string) {
	if hasIdentityName(name) {
		return true, "field name matches the identity/semantic denylist (§5.2 — linkability)"
	}
	return false, ""
}
