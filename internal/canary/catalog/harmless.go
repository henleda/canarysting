// Harmlessness for the canary catalog. A canary must produce nothing of value
// when touched: it never grants real access, holds no real data, and enables no
// real action (docs/CANARY.md). The machine-checkable proof — reserved/EXAMPLE
// namespaces plus structural invalidity — lives in the shared, stdlib-only
// internal/harmless package, which both this catalog and the sting attrition
// layer depend on so the safety predicates have a single source of truth.
//
// This file holds only the catalog-specific marker: a non-secret correlation
// token embedded in every decoy so adapters and tests can recognize bait. The
// marker is NOT the harmlessness guarantee (that is harmless.CrossScan plus the
// per-type predicates); it is a label.
package catalog

import "strings"

// canaryMarker is a non-secret correlation marker embedded in every decoy.
const canaryMarker = "CSTING-CANARY-"

// carriesCanaryMarker reports whether a payload carries the non-secret marker.
func carriesCanaryMarker(b []byte) bool {
	return strings.Contains(string(b), canaryMarker)
}
