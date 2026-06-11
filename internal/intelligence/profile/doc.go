// Package profile is the D2 adversary-profiling layer (docs/INTELLIGENCE.md §4;
// docs/MOAT_DESIGN.md — the moat keystone): it turns a scope's interaction events into
// a behavioral Profile, the moat's load-bearing artifact and the input to D5 detection
// sharpening (Profile.Similarity), the D6 cross-boundary export (Profile.ToExportForm
// -> the single egress filter), and the dashboard fingerprint-enrichment panel.
//
// ANONYMIZED BY CONSTRUCTION (rule 9 / docs/INTELLIGENCE.md §2). A Profile carries a
// behavioral PATTERN — how an actor probes and reacts — NEVER identity: no ScopeKey,
// FlowID, IP, decoy contents, or raw bytes. Its BehavioralHash keys on the behavioral
// pattern (probe sequence + cadence band + the per-axis engagement signature), NOT on
// FlowID, so the same tool from different flows profiles alike and the hash leaks no
// identity. This is the deliberate difference from the dashboard's per-flow
// FlowFingerprint (which carries FlowID and is a view-layer object, decision E): the
// two are NOT unified.
//
// Guardrails that never relax (docs/INTELLIGENCE.md §8): the canary touch is the only
// trigger (the profile + the D5 sharpening it feeds are scoring CONTEXT, never a
// trigger — rule 8), learned state is scope-isolated (DeriveProfile is pure +
// single-scope — rule 5), and only anonymized patterns cross a boundary (the ExportForm
// projection, through the single egress filter — rule 9).
//
// Import discipline: derivation imports ONLY internal/contract + internal/intelligence;
// the export side additionally imports internal/intelligence/network for the Candidate
// contract. Never engine, attrition, or the dashboard view layer.
package profile
