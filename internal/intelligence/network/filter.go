package network

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Candidate is anything that wishes to cross a deployment boundary. EgressFields
// returns its TAGGED export struct (whose fields carry egress:"safe,<reason>" tags,
// the coarsened form a producer such as profile.ExportForm builds) plus its
// per-deployment contribution context. Clear independently re-verifies the export —
// producer and gate distrust each other (two independent failures must both occur to
// leak).
type Candidate interface {
	EgressFields() (export any, ctx ContributionContext)
}

// clearMeta is opaque carrier metadata (no candidate data).
type clearMeta struct {
	seenInScopes int
	fieldCount   int
}

// Cleared is the opaque carrier: the ONLY value any cross-boundary transport (D6) may
// accept, and the ONLY thing Clear / ClearWithLedger produce. Its fields are UNEXPORTED,
// so no other package can construct one — the single-chokepoint invariant is enforced by
// the Go type system, not convention. payload holds only value-copied scalars / closed
// enum strings (never a boxed pointer/slice/map/aliased reference); Marshal re-validates
// before producing wire bytes (D3).
type Cleared struct {
	payload map[string]any
	meta    clearMeta
	// ledgerVerified is true ONLY for a carrier produced by ClearWithLedger, where the
	// k-anonymity count was computed INSIDE the chokepoint from the cross-scope ledger
	// (D6c/D6d). A form-only Clear() carrier leaves it false and CANNOT be Marshaled to
	// the wire — so a producer-asserted count can never cross (the closed known-gap).
	ledgerVerified bool
}

// Clear is the FORM-LEVEL egress validator (rule 9; INTELLIGENCE.md §2/§7) — the
// "reference/form-only" path (D6d). It returns (nil, err) — all-or-nothing (D8) — on
// ANY untagged, wrong-kind, identity-named, blocked, denylisted-type, un-opted-in, or
// sub-k candidate, and is used by profile.ValidateProfileForSharing to prove an export
// FORM is constructible. Its carrier is NOT ledger-verified and therefore CANNOT be
// Marshaled to the wire: a REAL cross-deployment crossing MUST go through
// ClearWithLedger, where the k-anonymity count is computed inside the chokepoint from
// the cross-scope ledger (the producer can no longer assert the count — D6c/D6d). It
// does NOT coarsen (that is the producer's ExportForm, upstream); it is the independent
// GATE.
func Clear(c Candidate) (*Cleared, error) {
	if c == nil {
		return nil, fmt.Errorf("egress: nil candidate")
	}
	export, ctx := c.EgressFields()

	// Candidate-level preconditions the field walk cannot see (§1.4). Clear keeps the
	// producer-supplied k check as a FORM-level sanity only; the authoritative,
	// transmittable k comes from the ledger via ClearWithLedger.
	if !ctx.Contribute {
		return nil, fmt.Errorf("egress: scope has not opted in to contribute")
	}
	if ctx.SeenInScopes < aggregationK {
		return nil, fmt.Errorf("egress: pattern seen in %d scope(s) < k=%d (singling-out risk)", ctx.SeenInScopes, aggregationK)
	}

	payload, err := clearFields(export)
	if err != nil {
		return nil, err
	}
	return &Cleared{payload: payload, meta: clearMeta{seenInScopes: ctx.SeenInScopes, fieldCount: len(payload)}}, nil
}

// ClearWithLedger is the PRODUCTION egress path for a cross-deployment crossing (D6d).
// Unlike Clear, the k-anonymity count is COMPUTED INSIDE the chokepoint from the
// package's own cross-scope ledger (never producer-asserted), keyed on the COARSE
// CLEARED TUPLE that actually crosses (D6c) — so "seen in >= k scopes" refers to the
// exact wire unit. The producer MUST NOT supply ctx.SeenInScopes (asserted-zero
// tripwire). Only the carrier this returns is ledger-verified and therefore Marshalable.
func ClearWithLedger(c Candidate, lc ClearContext) (*Cleared, error) {
	if c == nil {
		return nil, fmt.Errorf("egress: nil candidate")
	}
	export, ctx := c.EgressFields()

	if !ctx.Contribute {
		return nil, fmt.Errorf("egress: scope has not opted in to contribute")
	}
	// Tripwire: the count is the ledger's job. A producer that set it is a bug (or an
	// attempt to invert the gate) — fail closed and say so (D6d).
	if ctx.SeenInScopes != 0 {
		return nil, fmt.Errorf("egress: producer supplied SeenInScopes=%d; the count is computed by the cross-scope ledger (tripwire)", ctx.SeenInScopes)
	}
	if lc.Ledger == nil {
		return nil, fmt.Errorf("egress: no cross-scope ledger (cannot establish k-anonymity provenance)")
	}

	payload, err := clearFields(export)
	if err != nil {
		return nil, err
	}
	// Key the count on EXACTLY what cleared (the coarse tuple), so the counted unit ==
	// the wire unit (D6c). The raw BehavioralHash never enters this path.
	n := lc.Ledger.distinctScopes(coarseKeyFromPayload(payload))
	if n < aggregationK {
		return nil, fmt.Errorf("egress: pattern seen in %d scope(s) < k=%d (singling-out risk)", n, aggregationK)
	}
	return &Cleared{payload: payload, meta: clearMeta{seenInScopes: n, fieldCount: len(payload)}, ledgerVerified: true}, nil
}

// clearFields is the shared reflect field-walk: it coarse-validates an export struct
// into a scalar payload, or errors (all-or-nothing, D8). It does NOT check the
// candidate-level opt-in / k-anonymity (those are the callers' job). Both Clear and
// ClearWithLedger run it, so the field-level guarantees are identical on both paths.
func clearFields(export any) (map[string]any, error) {
	rv := reflect.ValueOf(export)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, fmt.Errorf("egress: nil export")
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("egress: export must be a struct, got %s", rv.Kind())
	}
	payload := map[string]any{}
	if err := clearStruct(rv, "", payload); err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("egress: candidate cleared no fields (nothing to share)")
	}
	return payload, nil
}

// clearStruct recursively validates every exported field of a struct (D2). Any field
// that fails any check aborts the WHOLE clear (D8, fail closed).
func clearStruct(rv reflect.Value, prefix string, out map[string]any) error {
	t := rv.Type()
	// (a) candidate-type denylist, re-checked at every level so an embedded/nested
	// denylisted type cannot launder through (D4a).
	if denylistedType(t) {
		return fmt.Errorf("egress: type %s%s is denylisted (scope-local / raw / engine state)", prefix, t)
	}
	if isTimeType(t) {
		return fmt.Errorf("egress: %s%s is not exportable (timestamps are environment-correlatable)", prefix, t)
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			// Unexported: unreadable via reflection without unsafe; a producer must
			// export a field to share it, so an unexported field cannot leak.
			continue
		}
		name := prefix + f.Name
		fv := rv.Field(i)

		// A blocked marker is a HARD deny regardless of anything else (D4c).
		if isBlockedTag(f.Tag) {
			return fmt.Errorf("egress: field %s is permanently blocked", name)
		}

		// Recurse into nested/embedded VALUE structs — no struct is opaque-safe (D2).
		// A pointer/slice/map/interface field (incl. an embedded *struct) is NOT
		// recursed: it falls through to the kind allowlist below and is DENIED
		// (fail-closed). The only walked container is a value struct.
		if fv.Kind() == reflect.Struct && !isTimeType(f.Type) {
			if err := clearStruct(fv, name+".", out); err != nil {
				return err
			}
			continue
		}

		// Leaf field: must be explicitly tagged safe + justified (D7).
		if _, ok := parseSafeTag(f.Tag); !ok {
			return fmt.Errorf("egress: field %s is not marked egress:\"safe,<reason>\" (default-deny)", name)
		}
		// Identity / semantic name denylist + the re-identify predicate (§5 / D4).
		if bad, why := canReIdentify(f.Name, fv); bad {
			return fmt.Errorf("egress: field %s denied: %s", name, why)
		}
		// Kind allowlist + COARSENESS (D1 [leak-review]). The kind allowlist proves a
		// field is a scalar; it does NOT prove it is coarse, so a numeric field must
		// additionally declare a band=LO..HI whose span is small and whose actual value
		// is in range — a raw count / byte-count / second-count is denied. Floats are
		// denied outright (continuous => singling-out). String only as a closed enum.
		switch {
		case fv.Kind() == reflect.String:
			set, known := enumValues[strings.ToLower(f.Name)]
			if !known || !set[fv.String()] {
				return fmt.Errorf("egress: string field %s value %q is not a registered closed-enum value", name, fv.String())
			}
			out[name] = fv.String()
		case fv.Kind() == reflect.Bool:
			out[name] = fv.Bool()
		case isBandedKind(fv.Kind()):
			lo, hi, ok := parseBand(f.Tag)
			if !ok {
				return fmt.Errorf("egress: numeric field %s must declare a coarse band egress:\"safe,band=LO..HI,<reason>\" (scalar kind is not coarseness)", name)
			}
			if hi < lo || hi-lo > maxBandSpan {
				return fmt.Errorf("egress: field %s band %d..%d is not coarse (span > %d) — a band, not a raw count", name, lo, hi, maxBandSpan)
			}
			if val := numericAsInt64(fv); val < lo || val > hi {
				return fmt.Errorf("egress: field %s value %d is outside its declared band %d..%d (raw value, not a coarse band)", name, val, lo, hi)
			}
			out[name] = copyScalar(fv)
		default:
			return fmt.Errorf("egress: field %s has non-allowlisted kind %s (default-deny)", name, fv.Kind())
		}
	}
	return nil
}

func isTimeType(t reflect.Type) bool { return t.PkgPath() == "time" && t.Name() == "Time" }

// copyScalar returns the field's VALUE as a concrete scalar (never a reference into
// the source), so the carrier holds nothing aliased/mutable (D3).
func copyScalar(v reflect.Value) any {
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	default:
		return nil // unreachable: safeKind gated the caller
	}
}

// Marshal produces the wire bytes for a cleared candidate. It RE-VALIDATES every
// payload entry's dynamic kind against the safe set before emitting (D3): the carrier
// is part of the chokepoint, not a second egress surface. D6 transport consumes ONLY
// these bytes, never raw payload access.
func (c *Cleared) Marshal() ([]byte, error) {
	for k, v := range c.payload {
		switch v.(type) {
		case bool, int64, uint64, float64, string:
			// value-copied scalar / closed-enum string — ok
		default:
			return nil, fmt.Errorf("egress: payload field %q holds non-scalar %T (carrier breach)", k, v)
		}
	}
	// Only a ledger-verified carrier may cross the wire: a form-only Clear() result has
	// no real k-anonymity provenance, so it must not be transmittable (D6c/D6d).
	if !c.ledgerVerified {
		return nil, fmt.Errorf("egress: carrier is form-only (not ledger-verified); cross-deployment transport requires ClearWithLedger")
	}
	return json.Marshal(c.payload)
}

// Fields returns a copy of the cleared payload, for tests and the on-screen "what
// crossed" demo. It is a defensive copy; the carrier stays opaque.
func (c *Cleared) Fields() map[string]any {
	out := make(map[string]any, len(c.payload))
	for k, v := range c.payload {
		out[k] = v
	}
	return out
}
