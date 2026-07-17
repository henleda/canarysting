# CanarySting — Repo vs. K8s-Native Target: Gap Report

**Source reviewed:** github.com/henleda/canarysting (public), README.md and CLAUDE.md read in full. Repo self-describes as "early scaffold, most files are placeholders with signatures and TODOs, the structure and contracts are the load-bearing part."

**Headline finding:** the pivot extends the repo, it does not fight it. The repo is the proxy-agnostic, generic-east-west version of CanarySting. Its nine core architectural rules map almost one-to-one onto the load-bearing decisions in the new Architecture Spec. The divergence is not conflict, it is missing scope: there is no Kubernetes dimension and no blast-radius layer yet. Everything the K8s pivot needs sits on top of what is already here.

---

## What already exists and is consistent with the target (keep, build into)

The repo's design and the new spec agree on the foundations. These need no change in intent:

- **Thin proxies, proxy-agnostic engine, one contract.** Repo rules 1-3 (`adapters/` emit signals and apply verdicts with no logic; `internal/engine/` talks only to `internal/contract/`; flow-identity-plus-signal in, verdict out). This is exactly the spec's component architecture. The proxy-agnostic contract is what lets us add K8s-native proxies (Envoy via mesh) as just another adapter.
- **Socket-cookie join.** Repo rule 4 names the socket cookie as the sole L7-to-kernel join, matching the spec's load-bearing primitive. `docs/IDENTITY.md` already covers it.
- **Scope isolation, fail-closed.** Repo rule 5 plus the safety rule "when scope identity cannot be resolved, refuse to start, never fall back to a global scope" is precisely the spec's per-scope-isolation invariant. `docs/SCOPE.md` exists.
- **Canary-touch-only trigger.** Repo rule 8 is verbatim the spec's false-positive guardrail: baseline deviation never triggers a response, only a canary interaction enters the response pipeline. `docs/BASELINE_MULTIPLIER.md` specifies the bounded, floored, multiplicative math.
- **Tiered response, operator-elective aggression.** Repo rule 6 (tier discipline, per-tier fail behavior) and the safety rules (conservative default floor, precise containment, bounded sting resource use) match the spec's four tiers and posture model. `docs/STING.md` exists.
- **Anonymized-only cross-boundary intelligence.** Repo rule 9 plus the single default-deny egress filter in `internal/intelligence/network/` is exactly the spec's isolation-preserving intelligence boundary. `docs/INTELLIGENCE.md` exists.
- **Stack and structure.** Go monorepo, minimal C in `bpf/enforce/`, cilium/ebpf loader in `bpf/loader/`, protobuf contract in `api/proto/`. Directories already exist for engine, canary (catalog + seeder), sting (containment + attrition), adapters (envoy, nginx), bpf, intelligence, config, deploy, docs, test.

Net: the entire existing skeleton survives the pivot. The contracts and the nine rules are reusable as-is.

---

## What is missing for the K8s-native target (the real gap)

None of this exists in the repo yet. This is the build.

1. **No Kubernetes deployment model.** The repo is structured as an engine service plus adapters, generic east-west. There is no per-node DaemonSet, no Kubernetes operator, no CRDs. `deploy/` is a stub. The spec requires DaemonSet-plus-operator as the deployment shape (because the socket cookie is host-local, enforcement must be per-node).
2. **No operator / CRD layer.** No `DeceptionPolicy`-style CRD, no controller-runtime reconciliation, no operator binary. `canaryctl` exists as an operator CLI but is not a Kubernetes operator.
3. **No mesh identity integration.** The socket-cookie join is specified, but there is no mesh (Istio/Linkerd/SPIFFE-SPIRE) identity resolution, and no label-derived fallback identity. The spec makes mesh-enabled K8s the beachhead and identity the spine. This is net-new.
4. **No blast-radius graph.** This is the largest gap. There is no graph data model, no OBSERVED/PERMITTED/ADVERSARIAL edge types, no dark-reachability computation, no reachability/transitive-closure engine, no graph store. The entire blast-radius capability (narrow and medium) is absent. The repo has the event vantage point (via the baseline and canary observation) but does not assemble it into a reachability graph.
5. **No Kubernetes API ingestion.** No client-go, no ingestion of NetworkPolicy, CiliumNetworkPolicy, mesh AuthorizationPolicy, RBAC, namespaces/labels/SA mappings. The medium case depends entirely on this and none of it is present.
6. **eBPF baseline likely stub-level.** `bpf/enforce/` and the baseline-learning capability are documented but, per the repo's own "early scaffold" status, almost certainly signatures and TODOs rather than working flow observation. Needs verification in code, but treat as to-be-built.
7. **Scope keyed generically, not to K8s.** `docs/SCOPE.md` defines a scope key, but it is not yet mapped to Kubernetes namespaces/clusters. The spec requires scope to map to K8s isolation boundaries.

---

## Direct conflicts (places the pivot changes a prior assumption)

Very few, and all are scope-narrowing rather than contradictions:

- **Generic east-west vs. Kubernetes-only.** The repo is written to be substrate-neutral (any proxy, any east-west). The pivot narrows the build target to Kubernetes-only for now. This is not a conflict in the code (the proxy-agnostic contract still holds), but it is a change in build priority: do not invest in generic non-K8s paths this phase. Keep the abstraction, focus the implementation.
- **`adapters/nginx` priority.** The repo says Envoy first, nginx second. In a K8s-mesh world, Envoy (via the mesh/sidecar/ambient) is even more clearly first, and nginx drops further down. No change needed, just reprioritize.
- **Deployment shape.** The repo's implied deployment (engine service plus adapters) must become DaemonSet-plus-operator. This is an addition, not a rewrite of the engine, the engine stays proxy-agnostic and becomes a component the DaemonSet/operator deploys.

No load-bearing rule in CLAUDE.md is contradicted by the spec. All nine survive.

---

## Recommended reconciliation

1. **Adopt the new Architecture Spec as an additive layer, not a replacement.** Keep CLAUDE.md's nine rules. Add a Kubernetes-native section to `docs/ARCHITECTURE.md` (or a new `docs/KUBERNETES.md`) that introduces the DaemonSet/operator model, mesh identity, and the blast-radius graph, and explicitly states Kubernetes-only as the current build target.
2. **Add the blast-radius graph as a new internal package** (for example `internal/graph/`), consuming the existing contract's flow-identity-plus-signal events. It reuses the engine's attributed observations rather than introducing a parallel data path.
3. **Add the operator and CRDs** as a new top-level concern (`cmd/operator`, `internal/operator/`, CRD types), with the existing engine running inside the DaemonSet. `canaryctl` can remain the human CLI alongside the operator.
4. **Add K8s API ingestion as a new package** (for example `internal/k8s/` or `internal/permitted/`) feeding PERMITTED edges into the graph, for the medium case only.
5. **Add mesh identity resolution** under the existing identity boundary, primary path mesh/SPIFFE, fallback label-derived with lower confidence.
6. **Map the scope key to K8s namespaces/clusters** in `docs/SCOPE.md` and the scope resolver, preserving fail-closed.

None of these touch the engine's proxy-agnostic core or the nine rules. The pivot is almost entirely additive.

---

## Note on confidence

This report is grounded in the README and CLAUDE.md, which explicitly state the repo is an early scaffold of signatures and TODOs with the structure and contracts as the load-bearing part. I was not able to read every source file directly (GitHub raw and tree pages were intermittently blocked to automated fetch). The structural conclusions are reliable because the repo documents its own layout and status clearly. Before building, the agent that can see the code should still run a quick verification pass: confirm which packages are stubs vs. implemented (especially the eBPF baseline and the engine scoring), and confirm `internal/intelligence/network/` and the contract types match what the docs describe. Treat any file-level surprise as a refinement to this report, not a contradiction of its structural conclusions.
