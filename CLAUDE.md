# CLAUDE.md — CanarySting

This file is the entry point for Claude Code working in this repository. Read it fully before writing or changing anything. When a task touches a specific layer, also read that layer's guidance doc under `docs/` before starting.

## What this project is

CanarySting is a proxy-attached deception and active-response platform. It seeds harmless decoy resources ("canaries") within reach of east-west traffic, scores how each network flow interacts with them, and escalates an automated response from silent observation up to aggressive economic attrition against the attacker — enforced in the kernel.

Two product components:
- **Canary** — the detection surface: canary object generation, placement, and observation of interaction.
- **Sting** — the response: containment (blocking, rate-limiting, jailing) and attrition (tarpitting, token-wasting, adversarial responses).

The authoritative product and architecture specification is `docs/ARCHITECTURE.md`. The deep technical architecture, the eBPF baseline-learning capability, and the differentiated-technology rationale are in `docs/TECHNICAL_ARCHITECTURE.md` — read it before working on the engine, the canary seeder, or the eBPF layer. The exact math for how the baseline weights a canary touch (bounded, floored-at-one, multiplicative) is specified in `docs/BASELINE_MULTIPLIER.md`. If anything here conflicts with those documents, the architecture docs win for *intent*; this file wins for *how we build*. When they disagree on intent, stop and ask rather than guessing.

## Core architectural rules (do not violate without explicit approval)

1. **The proxies stay thin.** Adapters in `adapters/` emit signals and apply verdicts. They contain **no** detection or decision logic. All scoring and tiering lives in `internal/engine/`.
2. **The engine is proxy-agnostic.** It talks only to the contract in `internal/contract/`, never to a specific proxy. Adding a proxy must mean writing one adapter, with zero engine changes.
3. **One contract between layers:** a flow identity + a signal event in, a verdict out. The contract is defined in `internal/contract/` and mirrored in `api/proto/`. Changing it is a deliberate, reviewed act — never an incidental one.
4. **Identity join is the socket cookie.** L7 identity (from the proxy) and kernel identity (from eBPF) are bridged by the socket cookie. Any code that attributes a flow across the L7/kernel boundary must key on it. Do not invent a second join mechanism.
5. **Scope isolation is absolute.** All learned state (weights, calibration, evidence counts, feedback labels) is isolated per scope key and **never** aggregates across deployments. See `docs/SCOPE.md`. Code that would share learned state across scopes is a bug, not an optimization.
6. **Tier discipline.** Tiers 0–1 are async-only (never on the request hot path). Tiers 2–3 may be inline or async per operator config. Inline fail behavior is per-tier: fail-open at Tier 1, fail-closed at Tier 3. See `docs/ENGINE.md`.
7. **Every learned parameter has the same shape:** a documented uncalibrated default (from published base rates), a single feedback loop that calibrates it, and an evidence floor that gates the switch from default to learned. Do not add a learned parameter that skips any of the three.
8. **The canary touch is the only trigger. The baseline is weight context.** A learned baseline of normal east-west traffic (built via eBPF, see `docs/TECHNICAL_ARCHITECTURE.md`) sharpens scoring and canary placement and auto-derives the benign-exclusion set. It NEVER triggers a sting on its own. Deviation from normal, novelty, new adjacencies, unfamiliar identities — none of these may tag, contain, tarpit, or attrit a flow. Only a canary interaction enters the response pipeline. If you find yourself writing code where "this flow deviates from baseline" is sufficient to take a punitive action, that is a bug. This is non-negotiable; it is what keeps us from inheriting the false-positive behavior of pure anomaly detection.

## Language and stack

- **Go** for everything feasible: the engine, the control plane, adapters' userspace, the canary and sting userspace logic, the CLI. Target the Go version in `go.mod`.
- **C** only for the eBPF kernel programs in `bpf/enforce/`, kept to the minimum needed. The userspace loader in `bpf/loader/` is Go (cilium/ebpf).
- **No Rust** in this codebase for now. If a hot path seems to need it, raise it rather than introducing it.
- Protobuf for the cross-layer contract and any gRPC surface (`api/proto/`).

## Repository layout

Monorepo. Top-level map:

- `cmd/` — binaries. `engine` (the decision engine service), `canaryctl` (operator CLI).
- `internal/engine/` — scoring, tiers, calibration, scope, feedback. The brain. Proxy-agnostic.
- `internal/canary/` — canary `catalog` (object types + seed weights) and `seeder` (placement).
- `internal/sting/` — `containment` (kernel-enforced blocking) and `attrition` (tarpit/token-burn).
- `internal/contract/` — the in-process Go types for the layer contract. Source of truth.
- `adapters/envoy`, `adapters/nginx` — thin proxy adapters. Envoy first, nginx second.
- `bpf/enforce/` — eBPF C programs (TC/cgroup hooks). `bpf/loader/` — Go loader.
- `api/proto/` — protobuf definitions mirroring the contract for any out-of-process boundary.
- `config/` — example operator configuration (strictness, sting floor, scope).
- `deploy/` — deployment manifests/examples.
- `docs/` — architecture and per-layer guidance. **Read these.**
- `test/integration/` — cross-layer tests.

## Build conventions

- Keep packages small and single-purpose. The directory structure already reflects the intended seams; respect them.
- The contract types in `internal/contract/` must not import from `engine`, `canary`, `sting`, or `adapters`. Dependencies point *toward* the contract, never out of it.
- `internal/engine/` must not import any adapter package or any proxy SDK. If you find yourself wanting to, the abstraction is wrong — stop and reconsider.
- Errors are values; wrap with context. No panics in library code paths.
- Every new learned parameter ships with its uncalibrated default documented inline and in the relevant `docs/` file.

## Safety and posture rules

- **Attrition is aggressive-capable but operator-elective.** The default sting floor is conservative. Code must never make an aggressive response the silent default; the operator chooses the floor explicitly. See `docs/STING.md`.
- **The sting must bound its own resource use.** Attrition that burns the attacker's compute must not burn the defender's. Any fake-resource generator needs a ceiling.
- **Containment must be precise.** Never act on a flow you cannot attribute by socket cookie / cgroup / PID. A jailed bystander is a critical failure.
- **Fail safe on uncertainty.** When scope identity cannot be resolved, refuse to start — never fall back to a global scope. See `docs/SCOPE.md`.

## How to work in this repo

1. Read this file, then `docs/ARCHITECTURE.md`, then the guidance doc for the layer you're touching.
2. Check `internal/contract/` before changing any cross-layer behavior.
3. Make the smallest change that satisfies the task. Respect the layer seams.
4. If a task would violate a core rule above, stop and surface it rather than working around it.
5. Update the relevant `docs/` file when you change intent or add a learned parameter.

## Status

Early scaffold. Most files are placeholders with signatures and TODOs. The structure and contracts are the load-bearing part; implementation is to be filled in against the docs.
