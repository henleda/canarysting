# docs/SCOPE.md — Scope and isolation guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs `internal/engine/scope/` and constrains anything that persists learned state.

Isolation is a security, correctness, and governance property of CanarySting — not an optimization to relax. **All learned state is isolated per scope and never aggregates across deployments.** Learned state = canary weights, calibration status, evidence counts, and the feedback labels that produce them.

## The scope key

Isolation is implemented as a single **scope key**, not as separate "cluster mode" and "zone mode" code paths. Every piece of learned state is keyed by it. Resolution order:

1. **Operator-defined trust zone**, if the flow matches one.
2. **Else derived cluster identity.** In a service mesh, the SPIFFE trust domain (it already encodes a trust boundary). In Kubernetes, the cluster UID. This value *also* serves as the catch-all scope for unzoned traffic in a cluster that has zones defined — so the catch-all is free and needs no separate config.
3. **Else, where no cluster identity is derivable** (e.g. standalone nginx on bare VMs), an **operator-defined boundary**, which is **required**.
4. **Else hard fail.** The system refuses to start rather than silently defaulting to a global scope. A silent merge of trust boundaries is the exact leak isolation exists to prevent. Fail loud, tell the operator they are in an environment with no automatic cluster identity and must define a boundary.

## Constraints on scopes

These attach to the scope key regardless of how it was populated:

- **Scopes must partition cleanly.** A flow belongs to exactly one scope. Reject overlapping zone definitions, or define a deterministic precedence so a flow that matches two zones lands in exactly one. Never split one flow's signal across two scopes.
- **Each scope needs enough traffic to calibrate.** The finer an operator slices, the longer each slice stays in cold start. Surface **per-scope calibration status** so an operator who carved many small zones can see which remain uncalibrated and why.
- **The seed prior is the only shared artifact.** It ships as static config and carries no environment-specific information, so sharing it leaks nothing. A new zone cold-starts exactly like a new cluster (seed prior + uniform weights + raw count), then diverges on its own feedback.

## Cold start applies per scope

Because state never crosses scopes, every scope cold-starts independently — there is no borrowing a head start from a mature scope. That is intended. The bootstrap path (seed prior, uniform weights, raw-count scoring, documented uncalibrated mode) is the *only* way into a fresh scope. See `docs/ENGINE.md`.

## Implementation rules

- The scope key is the partition key for every store of learned state. There must be no store of learned state that is not scope-keyed.
- `internal/engine/scope/` owns resolution. Other packages ask it for the scope key; they do not re-derive it.
- The seed prior is static config and must not be written back to per-scope learned state as if it were learned.
- On unresolved identity, return a hard error that stops startup. Do not return a default, a global, or an empty scope.

## What scope handling must never do

- Aggregate or share learned state across scopes.
- Fall back to a global scope when identity cannot be resolved.
- Let a single flow's signal accrue to more than one scope.
- Treat the seed prior as learned state.

## Relationship to the intelligence layer

Scope isolation governs learned state *within* a deployment. A separate, stricter rule governs what may cross *between* deployments: only derived, anonymized adversary patterns, never raw data, baselines, or scope state, and only through the single default-deny egress filter in `internal/intelligence/network/`. See `docs/INTELLIGENCE.md` section 2. If you are touching anything that moves data across a deployment boundary, that rule and this one both apply, and the stricter one wins.
