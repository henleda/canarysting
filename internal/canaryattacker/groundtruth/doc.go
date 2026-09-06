// Package groundtruth defines CanaryAttacker's immutable, versioned synthetic
// scenario, intent, and action records. It is a standard-library-only contract
// package: it does not execute tools, call a model, access a target, or ingest
// records into CanaryView production paths.
//
// The package deliberately keeps the development-laboratory namespace,
// lifecycle, and model-use classification on every record. Synthetic ground
// truth describes what the harness declared or attempted; it is never trusted
// network telemetry.
package groundtruth
