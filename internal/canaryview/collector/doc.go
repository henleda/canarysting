// Package collector defines the bounded, read-only source intake seam for
// CanaryView normalized observations.
//
// Source exposes only discovery and read operations. CheckpointRepository and
// ObservationSink are CanaryView-owned local state seams; they do not grant a
// collector permission to mutate a vendor control plane. Concrete vendor
// collectors, persistent repositories, credentials, and action adapters are
// deliberately outside this package.
package collector
