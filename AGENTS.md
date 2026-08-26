# AGENTS.md — CanarySting

This file is the entry point for Codex working in this repository. Read it fully before writing or changing anything. When a task touches a specific layer, also read that layer's guidance doc under `docs/` before starting.

## What this project is

CanarySting is a proxy-attached deception and active-response platform. It seeds harmless decoy resources ("canaries") within reach of east-west traffic, scores how each network flow interacts with them, and escalates an automated response from silent observation up to aggressive economic attrition against the attacker — enforced in the kernel.

Two product components:

- **Canary** — the detection surface: canary object generation, placement, and observation of interaction.
- **Sting** — the response: containment (blocking, rate-limiting, jailing) and multi-dimensional attrition (velocity disruption, information poisoning, opportunity-cost injection, exploit-inventory burn, operational exposure). See `docs/STING.md`.

The authoritative CanarySting product and architecture specification is `docs/ARCHITECTURE.md`. The deep technical architecture, the eBPF baseline-learning capability, and the differentiated-technology rationale are in `docs/TECHNICAL_ARCHITECTURE.md` — read it before working on the engine, the canary seeder, or the eBPF layer. The exact math for how the baseline weights a canary touch (bounded, floored-at-one, multiplicative) is specified in `docs/BASELINE_MULTIPLIER.md`. The intelligence layer — how CanarySting turns its vantage point into a proprietary, compounding data asset (adversary profiling, attacker-cost metric, the cross-customer network, the threat feed) — is specified in `docs/INTELLIGENCE.md`; read it before working anything under `internal/intelligence/`. If anything here conflicts with those documents, the architecture docs win for *intent*; this file wins for *how we build*. When they disagree on intent, stop and ask rather than guessing.

## CanaryPlatform product architecture

CanaryPlatform is the overall product architecture. **CanaryView** is its vendor-neutral intelligence plane, **CanarySting** remains its deception, high-confidence detection, containment, and bounded-response system, and **CanaryAttacker** is its bounded synthetic-adversary and validation harness. These are architectural boundaries, not a mandate to mass-rename or move working packages.

Read `docs/CANARY_PLATFORM_ARCHITECTURE.md` for product boundaries and dependencies, `docs/CANARYVIEW_DATA_MODEL.md` for canonical intelligence concepts, `docs/CANARYVIEW_STORAGE_AND_RETENTION.md` for data lifecycle, retention, model-use, and logical storage principles, `docs/CANARYATTACKER_ARCHITECTURE.md` for the attacker laboratory, and `docs/CANARYPLATFORM_OPERATOR_EXPERIENCE.md` for unified operator workflows. `docs/DEVELOPMENT_PLAN.md` remains the execution sequence and status source of truth; `docs/DEVELOPMENT_ENVIRONMENT.md` defines the Mac/DGX development model. This file remains authoritative for coding and safety invariants. The product architecture documents do not override the eleven rules below.

Every new persistent data type must define its data class, retention and expiration, legal-hold behavior, deletion or derived-data invalidation, residency and encryption boundary, model-use permission, derivation lineage, and estimated storage impact before implementation is complete.

## Build target: Kubernetes-native (current phase)

The current build target is **Kubernetes-only**. CanarySting stays proxy-agnostic in design (the contract and the thin-adapter model do not change), but for this phase we build, test, and demo on Kubernetes and do not invest in generic non-Kubernetes east-west paths. Keep the abstraction, focus the implementation.

Three documents govern the pivot and sit alongside the existing architecture docs. Read them before working on anything Kubernetes-native or anything in the graph/operator/identity layers:

- `docs/ARCHITECTURE_SPEC_K8S.md` — the target-state Kubernetes-native architecture (deployment model, the blast-radius graph, narrow vs. medium capability split, the K8s API surface, mesh-vs-no-mesh identity, the hardest problems). This is the destination.
- `docs/BUILD_TASK_PLAN.md` — the original Kubernetes-pivot decomposition. It remains useful design context; `docs/DEVELOPMENT_PLAN.md` is the active cross-product execution sequence and status authority.
- `docs/GAP_REPORT.md` — how this repo maps against the target (written from the README + AGENTS.md, so it under-counts how much is built).
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

Monorepo. Top-level map (existing unless marked **partial** or **absent/planned**; see `docs/GAP_VERIFICATION.md` plus current path evidence for status):

- `cmd/` — binaries. `engine` (decision-engine service), `canaryctl` (human operator CLI), plus self-check/demo/sim binaries. `cmd/operator` is the **prototype** controller-runtime operator; it validates DeceptionPolicy objects and reports status but does not yet plant decoys. `canaryctl` remains the human operator CLI alongside it.
- `internal/engine/` — the brain, proxy-agnostic: `scoring` (Base×Multiplier), `tiers`, `calibration`, `feedback`, `scope`, `persist` (durable per-scope store), `baseline` (the bounded/floored multiplier), and `observebaseline` (the eBPF observe-only learning window **and** the OBSERVED node/edge topology store the graph layer reuses — rule 10).
- `internal/canary/` — `catalog` (object types + seed weights), `seeder` (placement), `signal` (touch → contract `SignalEvent`).
- `internal/sting/` — `containment` (kernel-enforced blocking), `attrition` (five-axis: velocity, information poisoning, opportunity cost, exploit burn, operational exposure — see `docs/STING.md`), and `killswitch` (disarm-only enforcement floor + per-identity RBAC).
- `internal/intelligence/` — the moat: per-scope adversary profiling, cost metric, feed, and the single default-deny **egress filter** under `internal/intelligence/network/` (rule 9).
- `internal/contract/` — the in-process Go types for the layer contract. Source of truth; imports nothing but stdlib (rule 3).
- `internal/identity/` — **prototype / partial:** the single home for workload identity ("the spine"). Implemented leaves are `naming` (moved from the retired `internal/topology/identity`, still stdlib/config-only and import-guarded), `mesh` (verified SPIFFE parsing), `labels` (explicitly lower-confidence derivation), `workload` (mesh → labels precedence), and `scopemap` (identity-driven namespace/cluster scope mapping). Live mesh and read-only Kubernetes informer source bindings are not wired yet. `adapters/envoy/identity` remains the separate adapter-local socket-cookie join (rule 1).
- `internal/graph/` — **absent/planned:** the blast-radius graph (OBSERVED/PERMITTED/ADVERSARIAL edges, dark-reachability, transitive reachable-set, ranking). It must consume `internal/contract/` events and reuse `internal/engine/observebaseline`'s OBSERVED store rather than fork the data path (rule 10).
- `internal/k8s/` — **absent/planned:** read-only Kubernetes API ingestion (client-go) for permitted-edge and identity sources in the medium case (rule 11).
- `internal/operator/` — **prototype / partial:** controller-runtime API and controller code for a namespaced DeceptionPolicy. The current validate-only reconciler updates the policy status; placement, finalizers, full lifecycle reconciliation, and scope/graph configuration remain planned.
- `adapters/envoy`, `adapters/nginx` — thin proxy adapters (rule 1). Envoy is built and thin-guarded; nginx is a stub (built second, thinner).
- `bpf/` — eBPF C programs + Go loaders: `bpf/observe` (observe-only flow accounting), `bpf/sockops` (socket-cookie capture, the L7↔kernel join), `bpf/enforce` (in-kernel containment), `bpf/loader` (loader contract).
- `api/proto/`, `api/gen/`, `api/convert/`, `api/enginegrpc/` — protobuf mirror of the contract and the gRPC transport for the out-of-process boundary.
- `internal/dashboard/`, `internal/boot/` — operator-facing read views (display-only; never on the verdict path) and the composition root.
- `config/` — example operator configuration plus the generated DeceptionPolicy CRD and sample custom resource.
- `deploy/` — deployment examples and the demo harness (`deploy/m7-window/`). **Planned:** K8s DaemonSet/operator manifests.
- `docs/` — architecture and per-layer guidance. **Read these.**
- `test/integration/` — cross-layer tests.

## Build conventions

- Keep packages small and single-purpose. The directory structure already reflects the intended seams; respect them.
- The contract types in `internal/contract/` must not import from `engine`, `canary`, `sting`, or `adapters`. Dependencies point *toward* the contract, never out of it.
- `internal/engine/` must not import any adapter package or any proxy SDK. If you find yourself wanting to, the abstraction is wrong — stop and reconsider. This seam is enforced by `internal/engine/importguard_test.go`.
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
- **Pin the kernel.** The socket-cookie join's never-reused property must be asserted at startup, not assumed. `bpf/kernel` enforces the minimum supported kernel before socket-cookie capture or enforcement attaches; keep that startup gate intact.

## How to work in this repo

1. Read this file, then `docs/ARCHITECTURE.md`, then the guidance doc for the layer you're touching. For CanaryPlatform, CanaryView, CanaryAttacker, or operator-facing work, also read the applicable CanaryPlatform documents named above. For Kubernetes-native or graph/operator/identity work, also read `docs/ARCHITECTURE_SPEC_K8S.md`, `docs/BUILD_TASK_PLAN.md`, and `docs/GAP_VERIFICATION.md`.
2. Check `internal/contract/` before changing any cross-layer behavior.
3. Make the smallest change that satisfies the task. Respect the layer seams.
4. If a task would violate a core rule above, stop and surface it rather than working around it.
5. Update the relevant `docs/` file when you change intent or add a learned parameter.

## Development workflow

- `docs/DEVELOPMENT_PLAN.md` is the source of truth for current development sequencing and status.
- `docs/DEVELOPMENT_ENVIRONMENT.md` defines the Mac plus DGX development environment.
- `.agents/skills/canarysting-dev/SKILL.md` defines the normal development operating loop.
- Architectural rules and safety invariants remain governed by this file.
- Every task declares a validation tier before implementation; kernel, Kubernetes, Cilium, and identity changes require DGX validation.
- A task is not complete until every acceptance criterion and required validation tier passes.
- Update `docs/DEVELOPMENT_PLAN.md` whenever work changes project status.
- Put repository changes through a pull request and wait for the GitHub Actions `ci` suite to be created and for every required job to pass before merging. A queued third-party check suite with zero check runs is not CI evidence. If the normal event is delayed or absent, use the manual `workflow_dispatch` trigger and record the resulting run URL rather than merging without a green run.
- GitHub plan limitations currently prevent enforcing branch protection/rulesets on this private repository, so the green-PR rule above is a mandatory operating procedure until server-side enforcement is available. Keep automatic deletion of merged remote branches enabled and preserve unmerged prototypes through an issue or plan record before deleting a branch.

## Status

**Mid-flight build, pivoting to Kubernetes-native.** A code-grounded verification (M0, see `docs/GAP_VERIFICATION.md`) confirmed the existing layers are substantially implemented and green-tested: the proxy-agnostic engine (Base×Multiplier scoring, tiers, calibration, scope, the bounded/floored baseline multiplier, and the eBPF observe-only learning window with its OBSERVED-topology store), the canary catalog/seeder/signal, the five-axis sting (attrition + precise containment + disarm-only kill-switch with RBAC), the one-contract layer plus its gRPC mirror, the intelligence layer including the single default-deny egress filter, and the eBPF datapath (`observe`/`sockops`/`enforce`). The Envoy adapter is built and machine-guarded thin; **the nginx adapter is the one remaining stub.** All eleven core rules are upheld in code, and the two non-negotiable invariants (canary-touch-only trigger; fail-closed per-scope isolation) survived adversarial verification.

The Kubernetes pivot is **partially implemented**. The prototype workload-identity spine now provides verified SPIFFE parsing, lower-confidence label derivation, mesh-first resolution, and identity-driven namespace/cluster scope mapping; its live mesh and Kubernetes informer bindings remain unwired. A prototype controller-runtime operator, namespaced DeceptionPolicy CRD, generated CRD manifest, and sample resource exist; reconciliation currently validates policy and updates status only, with no decoy placement or complete lifecycle behavior. The minimum-kernel startup assertion, engine import guard, and cookie-bound outcome scope handling identified by the M0 verification are implemented.

Still absent are the per-node DaemonSet and operator deployment/RBAC manifests, `internal/k8s/` read-only policy/identity ingestion, and `internal/graph/`'s PERMITTED/ADVERSARIAL model, dark-reachability, transitive queries, and ranking. The OBSERVED substrate already exists in `internal/engine/observebaseline`. Current task sequencing and completion evidence live in `docs/DEVELOPMENT_PLAN.md`; `docs/GAP_VERIFICATION.md` remains the code-grounded M0 baseline, while `docs/ARCHITECTURE_SPEC_K8S.md` and `docs/BUILD_TASK_PLAN.md` define the target and pivot sequence.
