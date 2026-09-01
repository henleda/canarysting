# CanarySting — Kubernetes-Native Platform Architecture Spec
### Standing reference for the build. Read this first, before any task.

**2026-08-31 status note.** This document is preserved as the technical reference architecture for Kubernetes-based CanarySting managed assets and local response (Profiles 3 and 4). Its Kubernetes-only product boundary and build sequence are superseded by `docs/CANARYPLATFORM_PRODUCT_STRATEGY.md` and `docs/DEVELOPMENT_PLAN.md`. The per-node/socket-cookie/eBPF constraints remain load-bearing when this deployment form is selected; they do not make Kubernetes, a DaemonSet, an operator, or local response prerequisites for CanaryView.

**Purpose of this document.** This is the target-state architecture for CanarySting as a Kubernetes-native platform. It is the standing context the project works against. It describes where we are going, not necessarily where the current repo is. The companion document (the Build Task Plan) sequences the work, and its first task is to reconcile this target against the actual repo. Do not assume the repo matches this spec. Treat any divergence as something to surface, not silently overwrite.

**Historical scope decision.** This record originally made CanarySting Kubernetes-only for the foreseeable build. The post-meeting re-baseline replaces that commercial/default sequence with optional progressive CanarySting forms while preserving this design as the Kubernetes reference profile. The proxy-agnostic contract and all safety invariants remain intact.

---

## 1. What CanarySting is

CanarySting is a Kubernetes-native security platform with three capabilities built on one substrate:

1. **Deception (Canary).** Seed harmless decoy resources (fake secrets, credentials, files, endpoints, decoy services) among real workloads, within reach of east-west traffic. A touch of a decoy is near-certain evidence of an intruder, because nothing legitimate has any reason to touch one.
2. **Active response (Sting).** On a confident verdict, act in the kernel via eBPF: contain (jail the flow, deny egress) and attrit (impose multi-dimensional cost, including velocity disruption, information poisoning of an autonomous attacker, opportunity-cost injection, exploit-inventory burn, operational exposure).
3. **Blast-radius modeling.** Build an identity-attributed reachability graph from observed flows, ingested policy, and adversarial (canary) interaction. Answer: if this identity or workload is compromised, what can it reach and exfiltrate, and what should be cut.

The unifying substrate is an eBPF-observed, identity-attributed flow graph joined to L7 proxy verdicts via the socket cookie. The substrate is the product. The three capabilities are expressions of it.

**The moat** is the intelligence layer: real attacker behavior against deception, attributed to a precise flow, isolated per deployment, compounding with every encounter. The sting is how we act on it. The intelligence is the durable asset.

---

## 2. Core architectural decisions (load-bearing, do not silently revisit)

- **Deployment model: per-node DaemonSet plus a Kubernetes operator. Not sidecar.** The socket cookie that joins the L7 verdict to kernel enforcement is per-socket and host-local, so enforcement must live on the same node as the flow. This dictates a per-node datapath agent. The operator manages CRDs (deception policy, scope/isolation config, graph config) and reconciles desired state.
- **The socket-cookie join is host-local only.** `bpf_get_socket_cookie()` returns a per-socket, host-local identifier, stable for the life of the socket, never on the wire. It joins a node-local proxy verdict to node-local kernel enforcement for the same socket. It cannot correlate the two ends of a connection, and it cannot cross hosts. Cross-host correlation must use a different mechanism (numeric identity carried in encapsulation, or control-plane 5-tuple-plus-timestamp correlation). Pin a minimum kernel version that provides a system-global socket cookie.
- **Identity is the spine, and it degrades without a mesh.** Blast radius in the credential-abuse era is an identity-reachability problem, not a network one. With a service mesh (Istio/Linkerd/Cilium mTLS, SPIFFE/SPIRE) identity is cryptographically verified per connection. Without a mesh, identity falls back to label-derived (Cilium ipcache style) which is control-plane-asserted, spoofable by a compromised node, and racy under pod-IP churn. **The beachhead is mesh-enabled Kubernetes.** No-mesh is a graceful-degradation mode with explicitly lower per-edge confidence.
- **The detection trigger is a canary touch, never anomaly alone.** Score = Base x Multiplier. Base is non-zero only on a canary touch. The Multiplier is a bounded, floored-at-one weight derived from the learned baseline. Deviation from normal can never independently trigger a response. This is the false-positive guardrail and a core differentiator. Do not let baseline deviation become a trigger.
- **Learned state is isolated per scope.** All baseline state and intelligence is keyed per deployment/trust zone (mapped to namespaces, or clusters for hard isolation) and never silently aggregated across scopes. Scope resolution must fail closed rather than guess, a silent merge of two tenants' boundaries is the exact leak the design exists to prevent.
- **Enforcement before learning is forbidden.** On attach, run observe-only and learn the baseline for a defined period before any enforcement rule activates. Policy recommendations and enforcement run in audit/detect-only mode first, with human sign-off, before enforce.

---

## 3. The blast-radius graph

**Nodes:** identities (Kubernetes ServiceAccounts, SPIFFE IDs, human/cloud identities), workloads (pods/deployments abstracted to stable logical workloads, never ephemeral pods), services (ClusterIP/headless/logical endpoints), assets/secrets (K8s Secrets, databases, object stores, and the canaries themselves).

**Edge types, by confidence:**
- **OBSERVED (highest confidence, ground truth).** From the eBPF baseline plus node-local proxy, each flow attributed to a source identity via the socket-cookie join. "A did talk to B." This is what CanarySting collects natively.
- **PERMITTED (medium confidence, latent).** From ingested policy: reachable even if never used. "A could reach B because no policy denies it and RBAC grants it."
- **ADVERSARIAL (unique signal).** From canary/deception interaction: "an attacker who compromised A actually traversed toward canary C." Weights which paths attackers actually take.

**Dark reachability = PERMITTED minus OBSERVED.** The allowed-but-never-used paths. This is latent blast radius, and it is the most valuable computation: it is the safe-to-cut set for least-privilege policy recommendation (deny it without breaking observed behavior), and it quantifies the gap between intended and actual posture.

**Blast radius for a compromised identity/workload** = transitive closure over edges, ranked by asset sensitivity and by adversarial weighting. Compute via a graph store with incremental updates keyed on stable identities, not pods. Precompute reachable sets for critical assets.

---

## 4. Narrow vs. medium (the capability split)

**NARROW (near-term wedge): observed/demonstrated blast radius.**
- Inputs, all natively collected: eBPF-observed identity-attributed flow graph (source identity, destination service/workload, port/protocol, L7 verb where the proxy sees it, socket-cookie join, timestamp), canary interaction events (which decoy, which flow, suspicion score, response tier), per-scope baseline. No policy ingestion.
- Outputs: queryable graph of what each identity/workload actually reached, demonstrated blast radius (observed transitive reachable set) for a compromised workload, adversarial-path overlay, reporting and visualization.
- This is buildable on data the substrate already produces plus a graph/query/reporting layer.

**MEDIUM (build toward): predicted blast radius plus safe containment policy recommendation.**
- Additional inputs: Kubernetes policy and identity state ingested from the API (see section 5). Compute PERMITTED edges and dark reachability.
- Outputs: predicted blast radius for not-yet-observed compromise, least-privilege/containment policy recommendations derived from real behavior (allow OBSERVED, deny dark reachability), delivered in audit/detect-only mode first.

---

## 5. Kubernetes API surface (for the medium case)

The permitted and identity graphs come from declaratively queryable K8s objects, which is why Kubernetes makes the medium case tractable:
- **Kubernetes NetworkPolicy** and **CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy** for L3/L4 (and L7/FQDN with Cilium) permitted edges.
- **Service mesh authorization** (Istio AuthorizationPolicy, PeerAuthentication; Linkerd Server/ServerAuthorization) for identity-level permitted edges.
- **RBAC** (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, ServiceAccounts) for identity-to-resource permissions and privilege-escalation edges.
- **Namespaces, labels, selectors** for scope boundaries and pod-to-logical-identity mapping.
- **API server watch** for the pod to ServiceAccount and pod to labels mapping (the pod-IP to stable-identity resolution).
- **Admission webhooks** configs, partly declarative, runtime effect inferred.

Declaratively queryable: policy objects, RBAC, namespaces, labels, SA mappings. Must be inferred: actual runtime effect of admission webhooks, time-correct pod-IP to identity mapping (join API-server state over time with flow timestamps), and whether a permitted edge is actually exploitable (needs observed/adversarial layers). Map ephemeral pod IPs to stable identity via label/SA set, never by IP, to avoid mis-attribution under IP reuse.

---

## 6. Component architecture (target shape)

Three layers behind stable contracts:

- **Canary layer (datapath-adjacent).** Proxy adapters plus decoy generation/seeding. Emits signals, carries no detection logic, so adding a proxy is just a new adapter. Decoys planted by the operator (volume mount or exec into matching workloads).
- **Decision engine (control plane, off-datapath).** Scoring (Base x Multiplier), tiering (observe, tag, contain, attrit), calibration to a target false-positive rate, per-scope isolated state, the learning loop, and the blast-radius graph build and query. Sits behind a stable contract so it does not care which proxy a signal came from.
- **Sting layer (datapath).** Response keyed off the engine verdict, attributed to a precise flow via socket cookie, enforced in-kernel, same-node.

**eBPF attach strategy:** TC hooks on pod veth for L3/L4 flow observation and enforcement; cgroup hooks (connect4/connect6/sock_ops) for connection-level interception and socket-cookie acquisition; kprobes/LSM/tracepoints for process context and canary-file-access detection and inline enforcement; XDP optionally for high-performance drop/tarpit in the contain/attrit tiers. Keep the datapath fast: filter and aggregate in-kernel, do graph modeling asynchronously off-datapath.

**Proxy attachment:** Envoy first (sidecar, or node-local/ambient-style, or mesh waypoint), NGINX as fallback L7. The node-local proxy computes the L7 verdict; the node-local eBPF datapath enforces, joined by socket cookie.

---

## 7. The four response tiers

- **Tier 0 — Observe.** Touch logged, attributed, scored. No action. Absorbs innocent brushes.
- **Tier 1 — Tag and deceive.** Score crosses a bar. Tag the flow, feed richer decoys to confirm intent. No blocking.
- **Tier 2 — Contain and attrit.** Repeated interaction. Kernel rate-limit/tarpit. Low risk, high annoyance. Attrition begins.
- **Tier 3 — Jail / adversarial.** Confirmed hostile flow. Jail the socket, deny egress, full multi-dimensional attrition. Reserved for high confidence.

Operator sets the floor (passive, moderate, aggressive). The platform ships the aggressive ceiling but never forces a posture the operator has not chosen.

---

## 8. Hardest problems (known risks, build around them)

1. **Identity fidelity without a mesh.** The whole graph depends on stable identity attribution. Mitigate: target mesh/Cilium customers, score no-mesh edges lower, keep the narrow (descriptive) case no-mesh-tolerant, gate the medium (predictive/enforcing) case on mesh-grade identity.
2. **Observed-vs-permitted completeness.** A rarely-used legitimate path looks like dark reachability and risks a wrong deny recommendation. Mitigate: minimum baseline-learning period, audit/detect-only before enforce, human sign-off on policy.
3. **Cross-host correlation.** Socket cookies do not cross hosts or connection-ends. Mitigate: numeric identity in encapsulation, or control-plane 5-tuple-plus-timestamp correlation, accepting some fidelity loss.
4. **Reachability at scale.** Transitive closure over a churning graph of many thousands of pods is expensive. Mitigate: graph store with incremental updates keyed on stable identity, precompute for critical assets.
5. **eBPF overhead vs. graph modeling.** Datapath must stay fast. Mitigate: in-kernel filter/aggregate, asynchronous off-datapath graph plane.

---

## 9. Competitive position (so the build stays differentiated)

Each piece exists in isolation: Cilium/Tetragon (runtime enforcement and the observed substrate), Wiz/Sysdig/Orca (config/permission attack-path and blast-radius graphs), KubeHound (RBAC attack graph), Illumio/Zero Networks (microsegmentation), Koney (K8s deception via operator+Tetragon+Istio), Thinkst (honeytokens). The whitespace is the fusion: eBPF-observed identity-attributed runtime flow graph, plus deception-validated adversarial weighting and exfil ground truth, plus in-kernel active response, plus blast-radius prediction with behavior-derived policy, Kubernetes-native. Build toward the fusion. Do not rebuild a commodity layer (a generic WAF, a generic CNI) as if it were the differentiator.

---

## 10. Honesty discipline (carries into code and claims)

- Distinguish prototype-proven, productized, and roadmap in comments, docs, and any generated claims. Do not let code or docs imply maturity that does not exist.
- The false-positive guardrail (no trigger without a canary touch) is a correctness invariant, not a tuning knob. Tests must assert that baseline deviation alone never produces a Tier 1+ action.
- Per-scope isolation is a correctness invariant. Tests must assert no cross-scope state bleed and fail-closed scope resolution.
