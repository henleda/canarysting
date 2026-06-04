# CanarySting

Proxy-attached deception and active response. CanarySting seeds harmless decoys ("canaries") within reach of east-west traffic, scores how each flow interacts with them, and escalates an automated response — from silent observation up to aggressive economic attrition against automated and AI-driven attackers — enforced in the kernel.

Two components:
- **Canary** — the detection surface (decoy generation, placement, observation).
- **Sting** — the response (containment + attrition).

## Start here

- **Building with Claude Code?** Read `CLAUDE.md` first. It is the entry point and states the rules.
- **Want the full spec?** `docs/ARCHITECTURE.md` is the authoritative product and architecture document.
- **Working on a layer?** Read its guidance doc:
  - `docs/ENGINE.md` — scoring, tiers, calibration, strictness, fail behavior
  - `docs/CANARY.md` — canary catalog and placement
  - `docs/STING.md` — containment and attrition (and the elective-aggression posture)
  - `docs/SCOPE.md` — per-deployment isolation and the scope key
  - `docs/IDENTITY.md` — the socket-cookie join between L7 and the kernel
  - `docs/ADAPTERS.md` — writing a proxy adapter (Envoy first, nginx second)

## Layout

```
cmd/            binaries: engine (decision service), canaryctl (operator CLI)
internal/
  contract/     the single cross-layer contract — source of truth
  engine/       scoring, tiers, calibration, scope, feedback (proxy-agnostic)
  canary/       catalog (decoy types + seed weights), seeder (placement)
  sting/        containment (kernel-enforced), attrition (tarpit/token-burn)
adapters/       thin proxy adapters: envoy, nginx
bpf/            enforce (eBPF C), loader (Go, cilium/ebpf)
api/proto/      protobuf mirror of the contract for out-of-process boundaries
config/         example operator configuration
deploy/         deployment manifests (stub)
docs/           architecture + per-layer guidance
test/           integration tests (stub)
```

## Stack

Go for everything feasible; minimal C only for the eBPF kernel programs in `bpf/enforce/`. Monorepo.

## Status

Early scaffold. The contracts (`internal/contract/`, `api/proto/`) and the guidance docs are the load-bearing parts; most code is signatures and TODOs to be filled in against the docs.
