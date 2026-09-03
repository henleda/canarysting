// Package dgxstack contains the prototype, read-only normalizers used to prove
// CanaryView intake against the existing CanarySting/DGX reference stack.
//
// The package is deliberately outside the CanarySting runtime packages. It may
// read their exported observation views, but those packages never depend on
// CanaryView. It does not advertise connector support, persist a raw payload,
// resolve credentials, mutate a source, correlate records, or make a verdict.
// M6A owns capability manifests, schema-drift handling, certification, and
// production source bindings.
package dgxstack
