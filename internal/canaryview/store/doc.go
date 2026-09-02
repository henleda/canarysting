// Package store defines a bounded, backend-neutral CanaryView observation
// store seam.
//
// ProductionObservationStore is intentionally in memory. It proves the scope,
// lifecycle, resource, and model-use contracts that a later persistent backend
// must preserve; it does not select that backend or execute physical deletion.
package store
