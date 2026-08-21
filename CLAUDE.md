# CLAUDE.md — CanarySting

This file is the entry point for Claude Code working in this repository. Read it fully before writing or changing anything. When a task touches a specific layer, also read that layer's guidance doc under `docs/` before starting.

## What this project is

# CLAUDE.md additions — Kubernetes-native pivot

These are drop-in edits for the existing `CLAUDE.md`. They are additive. The existing nine core rules all survive unchanged. Paste the new section where indicated and apply the two small edits noted at the end.

---

## INSERT this new section immediately after "## What this project is" (before "## Core architectural rules")

## Build target: Kubernetes-native (current phase)

The current build target is **Kubernetes-only**. CanarySting stays proxy-agnostic in design (the contract and the thin-adapter model do not change), but for this phase we build, test, and demo on Kubernetes and do not invest in generic non-Kubernetes east-west paths. Keep the abstraction, focus the implementation.

Three documents govern the pivot and sit alongside the existing architecture docs. Read them before working on anything Kubernetes-native or anything in the new graph/operator/identity layers:

- `docs/ARCHITECTURE_SPEC_K8S.md` — the target-state Kubernetes-native architecture (deployment model, the blast-radius graph, narrow vs. medium capability split, the K8s API surface, mesh-vs-no-mesh identity, the hardest problems). This is the destination.
- `docs/BUILD_TASK_PLAN.md` — the sequenced milestones to get there.
- `docs/GAP_REPORT.md` — how this repo maps against the target, what is already consistent, and what is net-new. Read it to understand why the pivot is almost entirely additive.

If these conflict with the existing architecture docs on *intent*, stop and ask. They do not override the nine core rules below; they extend the system on top of them.

Three load-bearing facts about the Kubernetes pivot:

- **Deployment is per-node DaemonSet plus a Kubernetes operator. Not sidecar.** The socket-cookie join (rule 4) is per-socket and host-local, so enforcement must live on the same node as the flow. The proxy-agnostic engine runs inside the DaemonSet; the operator manages CRDs and reconciles desired state.
- **Identity is the spine, and mesh-enabled Kubernetes is the beachhead.** Blast radius is an identity-reachability problem. With a service mesh (Istio/Linkerd/Cilium mTLS, SPIFFE/SPIRE) identity is cryptographically verified. Without a mesh, identity is label-derived, spoofable, and racy: support it as an explicitly-lower-confidence fallback, never as the primary assumption.
- **Blast-radius modeling is a first-class capability, built on the existing vantage point.** A new graph layer assembles the engine's already-attributed flow observations into a reachability graph with three edge types: OBSERVED (from the baseline and proxy, the ground truth we already collect), PERMITTED (from ingested K8s policy, the medium case), and ADVERSARIAL (from canary interaction). The gap PERMITTED minus OBSERVED is "dark reachability" and is the most valuable computation. The narrow case (observed/demonstrated blast radius) uses only data we already collect; the medium case adds K8s API policy ingestion.

---

## INSERT these as new core rules 10 and 11 at the end of "## Core architectural rules"

10. **The blast-radius graph reuses the contract, it does not fork the data path.** The new graph layer (`internal/graph/`) consumes the same flow-identity-plus-signal events defined in `internal/contract/`. It must not introduce a parallel observation path or a second source of truth for flow attribution. OBSERVED edges come from the engine's existing attributed observations. Do not duplicate attribution logic in the graph layer.

11. **Permitted-edge ingestion is read-only and medium-case-only.** K8s API ingestion (NetworkPolicy, CiliumNetworkPolicy, mesh AuthorizationPolicy, RBAC, namespaces/labels/ServiceAccounts) feeds PERMITTED edges for the medium case. It is read-only against the cluster. Policy *recommendations* derived from dark reachability are emitted in audit/detect-only mode and require human sign-off and a baseline-maturity gate before any enforce. Never auto-enforce a recommended policy.

---

## INSERT this new subsection at the end of "## Safety and posture rules"

- **Observe before enforce.** On attach, run observe-only and learn the baseline for the defined period before any enforcement rule activates. This applies to the sting (already implied by tier discipline) and to any policy recommendation from the blast-radius layer. Enforcement that activates before baseline maturity is a bug.
- **Mesh identity is primary, label-derived identity is a lower-confidence fallback.** Any code resolving workload identity must prefer verified mesh/SPIFFE identity and must mark label-derived identity with explicitly lower confidence on the edges it produces. Do not treat the two as equivalent.

---

## SMALL EDIT 1 — update the "## Repository layout" map

Add these entries to the layout list (new packages introduced by the pivot):

- `cmd/operator` — the Kubernetes operator binary (controller-runtime). Manages CRDs and reconciles desired state. `canaryctl` remains the human operator CLI alongside it.
- `internal/operator/` — operator/controller logic and CRD types (DeceptionPolicy and scope/graph config).
- `internal/graph/` — the blast-radius graph: node and edge model (OBSERVED/PERMITTED/ADVERSARIAL), dark-reachability, transitive reachable-set computation, ranking. Consumes `internal/contract/` events. Does not fork the data path (rule 10).
- `internal/k8s/` — Kubernetes API ingestion (client-go): permitted-edge and identity sources for the medium case. Read-only (rule 11).
- `internal/identity/` — workload identity resolution: mesh/SPIFFE primary, label-derived fallback. Feeds attribution and the graph.

(If any of these names collide with existing packages, surface it rather than overwriting. See `docs/GAP_REPORT.md`.)

---

## SMALL EDIT 2 — update the "## Status" line

Replace the current Status text with:

Early scaffold pivoting to Kubernetes-native. The structure, the contracts, and the nine-plus-two core rules are the load-bearing part. The existing proxy-agnostic engine, canary, sting, and intelligence layers survive the pivot unchanged in intent; the net-new work is the Kubernetes deployment model (DaemonSet + operator), mesh identity, and the blast-radius graph. See `docs/GAP_REPORT.md` for what exists vs. what is net-new, and `docs/BUILD_TASK_PLAN.md` for the sequence.

CanarySting is a proxy-attached deception and active-response platform. It seeds harmless decoy resources ("canaries") within reach of east-west traffic, scores how each network flow interacts with them, and escalates an automated response from silent observation up to aggressive economic attrition against the attacker — enforced in the kernel.

Two product components:
- **Canary** — the detection surface: canary object generation, placement, and observation of interaction.
- **Sting** — the response: containment (blocking, rate-limiting, jailing) and multi-dimensional attrition (velocity disruption, information poisoning, opportunity-cost injection, exploit-inventory burn, operational exposure). See `docs/STING.md`.

The authoritative product and architecture specification is `docs/ARCHITECTURE.md`. The deep technical architecture, the eBPF baseline-learning capability, and the differentiated-technology rationale are in `docs/TECHNICAL_ARCHITECTURE.md` — read it before working on the engine, the canary seeder, or the eBPF layer. The exact math for how the baseline weights a canary touch (bounded, floored-at-one, multiplicative) is specified in `docs/BASELINE_MULTIPLIER.md`. The intelligence layer — how CanarySting turns its vantage point into a proprietary, compounding data asset (adversary profiling, attacker-cost metric, the cross-customer network, the threat feed) — is specified in `docs/INTELLIGENCE.md`; read it before working anything under `internal/intelligence/`. If anything here conflicts with those documents, the architecture docs win for *intent*; this file wins for *how we build*. When they disagree on intent, stop and ask rather than guessing.

## Build target: Kubernetes-native (current phase)

The current build target is **Kubernetes-only**. CanarySting stays proxy-agnostic in design (the contract and the thin-adapter model do not change), but for this phase we build, test, and demo on Kubernetes and do not invest in generic non-Kubernetes east-west paths. Keep the abstraction, focus the implementation.

Three documents govern the pivot and sit alongside the existing architecture docs. Read them before working on anything Kubernetes-native or anything in the new graph/operator/identity layers:

- `docs/ARCHITECTURE_SPEC_K8S.md` — the target-state Kubernetes-native architecture (deployment model, the blast-radius graph, narrow vs. medium capability split, the K8s API surface, mesh-vs-no-mesh identity, the hardest problems). This is the destination.
- `docs/BUILD_TASK_PLAN.md` — the sequenced milestones to get there.
- `docs/GAP_REPORT.md` — how this repo maps against the target (written from the README + CLAUDE.md, so it under-counts how much is built).
- `docs/GAP_VERIFICATION.md` — the **code-grounded** correction to the gap report: the verified stub-vs-implemented status of every package, the load-bearing-invariant verdicts, and the agreed package layout. Read this before assuming anything is or isn't built.

If these conflict with the existing architecture docs on *intent*, stop and ask. They do not override the core architectural rules below; they extend the system on top of them (and add rules 10–11).

Three load-bearing facts about the Kubernetes pivot:

- **Deployment is per-node DaemonSet plus a Kubernetes operator. Not sidecar.** The socket-cookie join (rule 4) is per-socket and host-local, so enforcement must live on the same node as the flow. The proxy-agnostic engine runs inside the DaemonSet; the operator manages CRDs and reconciles desired state.
- **Identity is the spine, and mesh-enabled Kubernetes is the beachhead.** Blast radius is an identity-reachability problem. With a service mesh (Istio/Linkerd/Cilium mTLS, SPIFFE/SPIRE) identity is cryptographically verified. Without a mesh, identity is label-derived, spoofable, and racy: support it as an explicitly-lower-confidence fallback, never as the primary assumption.
- **Blast-radius modeling is a first-class capability, built on the existing vantage point.** A new graph layer assembles the engine's already-attributed flow observations into a reachability graph with three edge types: OBSERVED (from the baseline and proxy, the ground truth we already collect — and which already exists in `internal/engine/observebaseline`), PERMITTED (from ingested K8s policy, the medium case), and ADVERSARIAL (from canary interaction). The gap PERMITTED minus OBSERVED is "dark reachability" and is the most valuable computation. The narrow case (observed/demonstrated blast radius) uses only data we already collect; the medium case adds K8s API policy ingestion.

## Core architectural rules (do not violate without explicit approval)

1. **The proxies stay thin.** Adapters in `adapters/` emit signals and apply verdicts. They contain **no** detection or decision logic. All scoring and tiering lives in `internal/engine/`.
2. **The engine is proxy-agnostic.** It talks only to the contract in `internal/contract/`, never to a specific proxy. Adding a proxy must mean writing one adapter, with zero engine changes.
3. **One contract between layers:** a flow identity + a signal event in, a verdict out. The contract is defined in `internal/contract/` and mirrored in `api/proto/`. Changing it is a deliberate, reviewed act — never an incidental one.
4. **Identity join is the socket cookie.** L7 identity (from the proxy) and kernel identity (from eBPF) are bridged by the socket cookie. Any code that attributes a flow across the L7/kernel boundary must key on it. Do not invent a second join mechanism.
5. **Scope isolation is absolute.** All learned state (weights, calibration, evidence counts, feedback labels) is isolated per scope key and **never** aggregates across deployments. See `docs/SCOPE.md`. Code that would share learned state across scopes is a bug, not an optimization.
6. **Tier discipline.** Tiers 0–1 are async-only (never on the request hot path). Tiers 2–3 may be inline or async per operator config. Inline fail behavior is per-tier: fail-open at Tier 1, fail-closed at Tier 3. See `docs/ENGINE.md`.
7. **Every learned parameter has the same shape:** a documented uncalibrated default (from published base rates), a single feedback loop that calibrates it, and an evidence floor that gates the switch from default to learned. Do not add a learned parameter that skips any of the three.
8. **The canary touch is the only trigger. The baseline is weight context.** A learned baseline of normal east-west traffic (built via eBPF, see `docs/TECHNICAL_ARCHITECTURE.md`) sharpens scoring and canary placement and auto-derives the benign-exclusion set. It NEVER triggers a sting on its own. Deviation from normal, novelty, new adjacencies, unfamiliar identities — none of these may tag, contain, tarpit, or attrit a flow. Only a canary interaction enters the response pipeline. If you find yourself writing code where "this flow deviates from baseline" is sufficient to take a punitive action, that is a bug. This is non-negotiable; it is what keeps us from inheriting the false-positive behavior of pure anomaly detection.
9. **Only anonymized adversary patterns cross a deployment boundary.** The intelligence layer (`internal/intelligence/`, see `docs/INTELLIGENCE.md`) produces our proprietary data asset. Customer traffic, baselines, scope state, decoy contents, and any environment-identifying detail **never** leave the deployment. Only derived, anonymized fingerprints/patterns may, and only through the single default-deny **egress filter** in `internal/intelligence/network/`. Code that exfiltrates raw data, baselines, or scope state across a boundary is a critical bug. This rule sits on top of rule 5: scope isolation governs state within a deployment; this governs what derived intelligence may cross between deployments.
10. **The blast-radius graph reuses the contract, it does not fork the data path.** The new graph layer (`internal/graph/`) consumes the same flow-identity-plus-signal events defined in `internal/contract/`, and reuses the existing OBSERVED node/edge store in `internal/engine/observebaseline`. It must not introduce a parallel observation path or a second source of truth for flow attribution. OBSERVED edges come from the engine's existing attributed observations. Do not duplicate attribution logic in the graph layer.
11. **Permitted-edge ingestion is read-only and medium-case-only.** K8s API ingestion (NetworkPolicy, CiliumNetworkPolicy, mesh AuthorizationPolicy, RBAC, namespaces/labels/ServiceAccounts) feeds PERMITTED edges for the medium case. It is read-only against the cluster. Policy *recommendations* derived from dark reachability are emitted in audit/detect-only mode and require human sign-off and a baseline-maturity gate before any enforce. Never auto-enforce a recommended policy.

## Language and stack

- **Go** for everything feasible: the engine, the control plane, adapters' userspace, the canary and sting userspace logic, the operator, and the CLI. Target the Go version in `go.mod`.
- **C** only for the eBPF kernel programs under `bpf/` (`bpf/observe`, `bpf/sockops`, `bpf/enforce`), kept to the minimum needed. The userspace loaders are Go (cilium/ebpf).
- **No Rust** in this codebase for now. If a hot path seems to need it, raise it rather than introducing it.
- Protobuf for the cross-layer contract and any gRPC surface (`api/proto/`).

## Repository layout

Monorepo. Top-level map (existing unless marked **net-new** / **planned**; see `docs/GAP_VERIFICATION.md` for verified per-package status):

- `cmd/` — binaries. `engine` (decision-engine service), `canaryctl` (human operator CLI), plus self-check/demo/sim binaries. **net-new:** `cmd/operator` (the Kubernetes operator, controller-runtime; `canaryctl` remains the human CLI alongside it).
- `internal/engine/` — the brain, proxy-agnostic: `scoring` (Base×Multiplier), `tiers`, `calibration`, `feedback`, `scope`, `persist` (durable per-scope store), `baseline` (the bounded/floored multiplier), and `observebaseline` (the eBPF observe-only learning window **and** the OBSERVED node/edge topology store the graph layer reuses — rule 10).
- `internal/canary/` — `catalog` (object types + seed weights), `seeder` (placement), `signal` (touch → contract `SignalEvent`).
- `internal/sting/` — `containment` (kernel-enforced blocking), `attrition` (five-axis: velocity, information poisoning, opportunity cost, exploit burn, operational exposure — see `docs/STING.md`), and `killswitch` (disarm-only enforcement floor + per-identity RBAC).
- `internal/intelligence/` — the moat: per-scope adversary profiling, cost metric, feed, and the single default-deny **egress filter** under `internal/intelligence/network/` (rule 9).
- `internal/contract/` — the in-process Go types for the layer contract. Source of truth; imports nothing but stdlib (rule 3).
- `internal/identity/` — **net-new / M1:** the single home for workload-identity resolution ("the spine"). Leaves: `naming` (**moved** from `internal/topology/identity`; stays stdlib/config-only and production-importable, keeps its import guard), `mesh` (mesh/SPIFFE/SPIRE primary, high-confidence; may import client-go/SPIRE), `labels` (label-derived fallback, **explicitly lower confidence**), `workload` (optional facade preferring mesh → labels). The old `internal/topology/` container is **retired** after the move. NB: `adapters/envoy/identity` is a **different concern** (the adapter-local socket-cookie join, rule 1) and stays where it is.
- `internal/graph/` — **net-new:** the blast-radius graph (OBSERVED/PERMITTED/ADVERSARIAL edges, dark-reachability, transitive reachable-set, ranking). Consumes `internal/contract/` events and reuses `internal/engine/observebaseline`'s OBSERVED store — does not fork the data path (rule 10).
- `internal/k8s/` — **net-new:** Kubernetes API ingestion (client-go): permitted-edge and identity sources for the medium case. Read-only (rule 11).
- `internal/operator/` — **net-new:** operator/controller logic and CRD types (DeceptionPolicy and scope/graph config).
- `adapters/envoy`, `adapters/nginx` — thin proxy adapters (rule 1). Envoy is built and thin-guarded; nginx is a stub (built second, thinner).
- `bpf/` — eBPF C programs + Go loaders: `bpf/observe` (observe-only flow accounting), `bpf/sockops` (socket-cookie capture, the L7↔kernel join), `bpf/enforce` (in-kernel containment), `bpf/loader` (loader contract).
- `api/proto/`, `api/gen/`, `api/convert/`, `api/enginegrpc/` — protobuf mirror of the contract and the gRPC transport for the out-of-process boundary.
- `internal/dashboard/`, `internal/boot/` — operator-facing read views (display-only; never on the verdict path) and the composition root.
- `config/` — example operator configuration (strictness, sting floor, scope).
- `deploy/` — deployment examples and the demo harness (`deploy/m7-window/`). **Planned:** K8s DaemonSet/operator manifests.
- `docs/` — architecture and per-layer guidance. **Read these.**
- `test/integration/` — cross-layer tests.

## Build conventions

- Keep packages small and single-purpose. The directory structure already reflects the intended seams; respect them.
- The contract types in `internal/contract/` must not import from `engine`, `canary`, `sting`, or `adapters`. Dependencies point *toward* the contract, never out of it.
- `internal/engine/` must not import any adapter package or any proxy SDK. If you find yourself wanting to, the abstraction is wrong — stop and reconsider. (An executable import-guard test for this seam is part of Milestone 1.)
- Errors are values; wrap with context. No panics in library code paths.
- Every new learned parameter ships with its uncalibrated default documented inline and in the relevant `docs/` file.
- Distinguish prototype / productized / roadmap in code comments and docs. Do not let code or a doc imply maturity that does not exist (honesty discipline, `docs/ARCHITECTURE_SPEC_K8S.md` §10).

## Safety and posture rules

- **Attrition is aggressive-capable but operator-elective.** The default sting floor is conservative. Code must never make an aggressive response the silent default; the operator chooses the floor explicitly. See `docs/STING.md`.
- **The sting must bound its own resource use.** Attrition that burns the attacker's compute must not burn the defender's. Any fake-resource generator needs a ceiling.
- **Containment must be precise.** Never act on a flow you cannot attribute by socket cookie / cgroup / PID. A jailed bystander is a critical failure.
- **Fail safe on uncertainty.** When scope identity cannot be resolved, refuse to start — never fall back to a global scope. See `docs/SCOPE.md`.
- **Observe before enforce.** On attach, run observe-only and learn the baseline for the defined period before any enforcement rule activates. This applies to the sting (already implied by tier discipline) and to any policy recommendation from the blast-radius layer. Enforcement that activates before baseline maturity is a bug.
- **Mesh identity is primary, label-derived identity is a lower-confidence fallback.** Any code resolving workload identity must prefer verified mesh/SPIFFE identity and must mark label-derived identity with explicitly lower confidence on the edges it produces. Do not treat the two as equivalent.
- **Pin the kernel.** The socket-cookie join's never-reused property must be asserted at startup, not assumed. Pin and check a minimum kernel version that provides a system-global socket cookie before enforcing (Milestone 1).

## How to work in this repo

1. Read this file, then `docs/ARCHITECTURE.md`, then the guidance doc for the layer you're touching. For Kubernetes-native or graph/operator/identity work, also read `docs/ARCHITECTURE_SPEC_K8S.md`, `docs/BUILD_TASK_PLAN.md`, and `docs/GAP_VERIFICATION.md`.
2. Check `internal/contract/` before changing any cross-layer behavior.
3. Make the smallest change that satisfies the task. Respect the layer seams.
4. If a task would violate a core rule above, stop and surface it rather than working around it.
5. Update the relevant `docs/` file when you change intent or add a learned parameter.

## Status

**Mid-flight build, pivoting to Kubernetes-native — not an early scaffold.** A code-grounded verification (M0, see `docs/GAP_VERIFICATION.md`) confirmed the existing layers are substantially implemented and green-tested: the proxy-agnostic engine (Base×Multiplier scoring, tiers, calibration, scope, the bounded/floored baseline multiplier, and the eBPF observe-only learning window with its OBSERVED-topology store), the canary catalog/seeder/signal, the five-axis sting (attrition + precise containment + disarm-only kill-switch with RBAC), the one-contract layer plus its gRPC mirror, the intelligence layer including the single default-deny egress filter, and the eBPF datapath (`observe`/`sockops`/`enforce`). The Envoy adapter is built and machine-guarded thin; **the nginx adapter is the one remaining stub.** All eleven core rules are upheld in code, and the two non-negotiable invariants (canary-touch-only trigger; fail-closed per-scope isolation) survived adversarial verification.

The **net-new** work for the pivot is not yet built: the per-node DaemonSet/operator deployment model and CRDs, mesh/label identity resolution (`internal/identity/`), read-only K8s API ingestion (`internal/k8s/`), and the PERMITTED/ADVERSARIAL extensions plus dark-reachability of the blast-radius graph (`internal/graph/`) — the OBSERVED substrate for which already exists in `internal/engine/observebaseline`. Work is milestone-tracked (M1–M7; attrition axes AX0–AX5). See `docs/GAP_VERIFICATION.md` for the verified per-package status, `docs/ARCHITECTURE_SPEC_K8S.md` for the target, and `docs/BUILD_TASK_PLAN.md` for the sequence. Milestone 1 (the K8s-native substrate) also folds in three verification watch-items: the kernel-version pin, an engine-side import-guard test, and uniform scope re-resolution on the outcome-report path.
