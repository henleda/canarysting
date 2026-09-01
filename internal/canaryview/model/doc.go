// Package model defines CanaryView's vendor-neutral domain records.
//
// The package is deliberately a standard-library-only leaf. Source-specific
// adapters translate into it; CanarySting's runtime contract does not import it.
// The types here describe durable records, lifecycle decisions, explicit
// knowledge state, confidence, verification evidence, and acyclic provenance,
// but perform no persistence, collection, authorization, correlation, or
// enforcement.
package model
