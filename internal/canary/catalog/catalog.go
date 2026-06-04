// Package catalog defines canary object types and their SEED intent-strength
// weights. Seed weights are cold-start priors only; the engine's calibration
// overrides them with learned per-scope weights. Canaries must be harmless and
// must never grant real access. Do NOT build fixed chained-credential decoys
// (IP caution). See docs/CANARY.md.
package catalog

import "github.com/canarysting/canarysting/internal/contract"

// Entry describes one canary type.
type Entry struct {
	Type contract.CanaryType
	// SeedWeight is the cold-start prior intent strength. NOT a live weight.
	SeedWeight float64
	// Generate produces a realistic, harmless instance of this decoy.
	Generate func() (Instance, error)
}

// Instance is a concrete placed decoy. It holds nothing of value and grants no
// real access.
type Instance struct {
	Type    contract.CanaryType
	Payload []byte // harmless, non-functional bait
}

// TODO: define the initial catalog (fake secret, bucket, credential, file,
// endpoint) with seed weights; ensure generators cannot emit functional secrets.
