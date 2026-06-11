package network

import (
	"reflect"
	"strings"
)

// denylistedType reports whether a type may NEVER be an egress candidate (D4a) — it
// is rejected outright before any field inspection. Matched by package-path + type
// name (NOT by importing the types, which would couple the egress gate to engine /
// intelligence internals and risk an import cycle). It recurses through embedded
// (anonymous) fields so wrapping a denylisted type in a new struct cannot launder it.
//
// Denylisted: the scope-local CISO KPI (cost.Summary), the raw event / sting-outcome
// types (they carry ScopeKey / FlowID / Features and the AX4/AX5 fields), the
// cross-layer contract carriers, and ANY engine state (baseline / scope / calibration
// — rule 5 local-only). The field-level allowlist would already block their raw
// fields; this is defense-in-depth so they can't even be field-inspected.
func denylistedType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if denylistedTypeName(t.PkgPath(), t.Name()) {
		return true
	}
	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.Anonymous && denylistedType(f.Type) {
				return true
			}
		}
	}
	return false
}

func denylistedTypeName(pkg, name string) bool {
	switch {
	case strings.HasSuffix(pkg, "internal/intelligence/cost") && name == "Summary":
		return true
	case strings.HasSuffix(pkg, "internal/intelligence") &&
		(name == "AdversaryInteractionEvent" || name == "StingOutcome"):
		return true
	case strings.HasSuffix(pkg, "internal/contract") &&
		(name == "StingOutcome" || name == "OutcomeRecord" || name == "Verdict" ||
			name == "SignalEvent" || name == "FlowIdentity" || name == "FeedbackLabel"):
		return true
	case strings.Contains(pkg, "internal/engine/"):
		// baseline / scope / calibration / scoring / tiers / feedback / observebaseline —
		// all scope-local learned/engine state, never exportable (rule 5).
		return true
	}
	return false
}
