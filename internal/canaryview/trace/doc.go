// Package trace constructs and serves immutable, lifecycle-bearing CanaryView
// security-trace records from bounded correlation results.
//
// It preserves source records, all correlation alternatives, explicit gaps,
// conflicts, raw-reference availability, and direct derivation lineage. The
// in-memory store is a backend-neutral proof seam: it enforces scope and
// lifecycle visibility and records projection invalidation, but does not claim
// physical deletion, durable persistence, or source-system mutation.
package trace
