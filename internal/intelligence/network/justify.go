package network

import (
	"reflect"
	"strconv"
	"strings"
)

// tagKey is the struct-tag key carrying a field's egress justification.
const tagKey = "egress"

// maxBandSpan caps a numeric band's cardinality (HI-LO). A band wider than this is not
// "coarse" and is rejected — this is what stops a raw count / byte-count / second-count
// from masquerading as a band (§5.1.3 [leak-review]). 256 admits percentile buckets
// (0..100) and small byte-ish bands while denying the multi-thousand raw counts the
// leak-review exfiltrated. The egress filter enforces per-FIELD coarseness; it does NOT
// enforce a global information budget — a producer encoding data across MANY individually
// bounded+justified fields is bounded by the small field count, human review of each
// <reason>, and the k-anonymity gate, not by Clear (documented limit, doc.go / §3).
const maxBandSpan = 256

// safeKind is the ALLOWLIST of permissible scalar kinds (D1). It is an allowlist with an
// implicit default-deny: ANY kind not listed — Struct, Array, Slice, Map, Ptr, Interface,
// Chan, Func, Complex64/128, Uintptr, UnsafePointer, AND Float32/Float64 — is NOT safe.
// Floats are denied because a continuous value singles out (§5.1.1 [leak-review]); a
// coarse value must be an int BUCKET or a bool, never a raw float. String is handled
// separately (allowed ONLY against a registered closed enum); numeric (int/uint) fields
// must additionally declare a coarse band=LO..HI (see isBandedKind / parseBand) so the
// gate proves COARSENESS, not just scalar kind. Mirrors the
// TestDriverObservationCarriesNoRawData scalar-allowlist discipline.
func safeKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

// isBandedKind reports the integer kinds that MUST declare a coarse band=LO..HI to
// cross (every numeric kind that is not a bool). Floats are not here (denied outright).
func isBandedKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

// numericAsInt64 returns an int/uint field's value as int64 for the band check. Band
// bounds are small (<= maxBandSpan), so there is no overflow concern for a legitimate
// in-band value; an out-of-band raw value is denied regardless.
func numericAsInt64(v reflect.Value) int64 {
	if k := v.Kind(); k >= reflect.Uint && k <= reflect.Uint64 {
		u := v.Uint()
		if u > 1<<62 { // absurdly large unsigned value: clearly not a coarse band
			return int64(1) << 62
		}
		return int64(u)
	}
	return v.Int()
}

// parseSafeTag returns (reason, true) iff the field carries egress:"safe,<reason>" with
// a NON-EMPTY engineer-written reason (D7). The reason is the §2 per-field justification;
// it is necessary but never sufficient (kind allowlist + band + name denylist must pass).
func parseSafeTag(tag reflect.StructTag) (reason string, ok bool) {
	v, present := tag.Lookup(tagKey)
	if !present {
		return "", false
	}
	const p = "safe,"
	if len(v) <= len(p) || v[:len(p)] != p {
		return "", false
	}
	return v[len(p):], true
}

// parseBand extracts a band=LO..HI clause from egress:"safe,band=LO..HI,<reason>". A
// numeric field MUST carry one; bool/string fields do not. Returns ok=false if absent
// or malformed (=> the field is denied).
func parseBand(tag reflect.StructTag) (lo, hi int64, ok bool) {
	v, present := tag.Lookup(tagKey)
	if !present {
		return 0, 0, false
	}
	for _, part := range strings.Split(v, ",") {
		spec, found := strings.CutPrefix(strings.TrimSpace(part), "band=")
		if !found {
			continue
		}
		l, h, found := strings.Cut(spec, "..")
		if !found {
			return 0, 0, false
		}
		lo, err1 := strconv.ParseInt(strings.TrimSpace(l), 10, 64)
		hi, err2 := strconv.ParseInt(strings.TrimSpace(h), 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return lo, hi, true
	}
	return 0, 0, false
}

// isBlockedTag reports an explicit permanent block marker egress:"blocked,...". A block
// marker HARD-denies regardless of any other state (D4c, defense-in-depth — not the sole
// barrier; type + name denylists also catch AX4/AX5).
func isBlockedTag(tag reflect.StructTag) bool {
	v, ok := tag.Lookup(tagKey)
	return ok && len(v) >= len("blocked,") && v[:len("blocked,")] == "blocked,"
}

// enumValues registers the closed value-sets for the ONLY string fields permitted to
// cross. A String field passes iff its (lowercased) name is a key here AND its value is
// a member. Anything else — a free string, an unknown name, an out-of-set value — is
// denied (D1/D10). Keyed by the lowercased field name.
var enumValues = map[string]map[string]bool{
	// poison reaction class, coarse closed vocab (the poison-field stages).
	"poisonclass": {"": true, "credential": true, "topology": true, "success": true},
}
