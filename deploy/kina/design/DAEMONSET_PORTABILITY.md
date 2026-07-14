# CanarySting DaemonSet Portability — Spike Plan

**Status:** spike plan (prototype + validate), not an implementation spec.
**Author:** plan-daemonset
**Date:** 2026-07-14

Goal: take the eBPF deception stack we proved on a single-node local kina BTF
cluster and validate that it ports to a real multi-node managed cluster
(EKS / GKE Standard) as a per-node DaemonSet, mirroring how Cilium/Tetragon
deploy. Every architecture claim about canarysting below carries a `file:line`.
EKS/GKE-specific claims are framed as reasoned assessment and flagged where they
cannot be verified from the repo.

---

## 1. Goal & non-goals

**Goal.** Prove the node-local unit (Envoy adapter + sockops cookie capture +
kernel enforce, all attached to one node's cgroup-v2 root) runs as a privileged
per-node DaemonSet on a real multi-node managed Kubernetes cluster, and that a
cross-node flow which touches a canary is detected and kernel-jailed on the node
where its socket lands — with **stock node AMIs/images, no custom kernel**,
relying only on the node's own BTF.

**Non-goals.**
- Not a production hardening effort (no HA, no multi-scope tuning, no autoscaling,
  no cost optimization, no supply-chain/image-signing work).
- Not a redesign of the engine, contract, or the socket-cookie join. The join is
  fixed and node-local by design (`docs/IDENTITY.md:46-47`); this spike inherits it.
- Not a resolution of the central-vs-per-node engine question (Section 7 open
  question #1) — the spike picks the restraint-minimal option to prove portability
  and leaves the productionization fork explicit.
- Not Fargate / GKE Autopilot support — both structurally exclude eBPF (Sections 4–5).

---

## 2. Current vs target topology

### 2.1 What we have (single-node, one gateway pod)

`deploy/kina/40-gateway.yaml` runs a **single** `gateway` Deployment
(`replicas: 1`, line 9) with three co-located containers in one pod:

- `envoy` (`envoyproxy/envoy:v1.34.1`, line 20) — L7 proxy, ext_proc to the adapter.
- `adapter` (`cs-adapter`, lines 35-74) — privileged-ish: `runAsUser: 0`,
  `capabilities.add: [BPF, NET_ADMIN, SYS_RESOURCE]` (lines 62-68), hostPath mounts
  `/sys/fs/cgroup` and `/sys/kernel` (lines 69-74). Dials the engine at loopback
  `127.0.0.1:50052` (line 43).
- `engine` (`cs-engine`, lines 76-109) — scoring/baseline, `-baseline-db`,
  `-dashboard-tap-addr 0.0.0.0:8088` (lines 86-89), unprivileged (`runAsNonRoot`,
  line 103).

It works because everything is on ONE node: the sockops program attaches at the
node cgroup root and the enforce program jails on the same root — `resolver_linux.go:13`
(`const cgroupV2Root = "/sys/fs/cgroup"`, "attaching at the root captures every
connection on the host") and `enforcer_linux.go:29-33` ("loads + attaches the
enforce programs at the cgroup-v2 root — the same root the sockops bridge uses").

### 2.2 What breaks at multi-node

One pod sees one node's cgroup. On a real cluster with N nodes, a single gateway
pod attached to its own node's cgroup is blind to the other N-1 nodes' east-west
traffic. The socket cookie is **host-local** and never reused
(`docs/IDENTITY.md:46-47`, `:57-63`), so there is no way for one node's programs
to observe or enforce another node's sockets. This is exactly the constraint that
makes Cilium/Tetragon ship a **privileged DaemonSet, one agent per node, attached
to that node's cgroup root**. We mirror that.

### 2.3 Target: the node-local unit as a DaemonSet

```
                      ┌─────────────────── central engine (Deployment, 1 replica) ──────────────────┐
                      │  cs-engine  ·  scope=<cluster-UID>  ·  one baseline.db  ·  tap :8088 (dash)  │
                      └───────▲───────────────────────▲───────────────────────▲────────────────────┘
                              │ gRPC signal/verdict    │                        │
        ┌─────────────────────┼──────────┐  ┌──────────┼───────────┐  ┌─────────┼──────────┐
        │  NODE 1 (DaemonSet)  │          │  │ NODE 2   │           │  │ NODE 3  │          │
        │  envoy ─ext_proc─ adapter       │  │ envoy ─ adapter      │  │ envoy ─ adapter    │
        │                    │            │  │          │           │  │         │          │
        │  sockops(cgroup /sys/fs/cgroup) │  │ sockops(node cgroup) │  │ sockops(node cgroup)│
        │  enforce (egress jail, node)    │  │ enforce (node)       │  │ enforce (node)     │
        │  observe (baseline features)    │  │ observe              │  │ observe            │
        └─────────────────────────────────┘  └──────────────────────┘  └────────────────────┘
             each pod → its OWN node's cgroup root (hostPath), node-local capture+enforce
```

- **Node-local unit (DaemonSet pod, privileged):** Envoy + adapter + sockops +
  enforce + observe, attached to THAT node's `/sys/fs/cgroup`. This is the atomic
  unit the socket-cookie join requires: L7 observe, cookie capture, and kernel jail
  MUST be co-located on the node holding the offending socket
  (`docs/IDENTITY.md:46-47`). One DaemonSet = one such unit per node — today's
  adapter container plus enabling the currently-disabled observe path (Section 3,
  item 6).
- **Engine placement — the fork.** Two viable models; the spike picks Model B for
  restraint (Section 8), productionization likely wants Model A:
  - **Model A — central engine (one per scope/cluster).** Adapters on every node dial
    a single engine over gRPC (already supported: `api/enginegrpc`, `cmd/engine
    -grpc-addr`, `docs/ADAPTERS.md:73-76`). One scope → one coherent baseline →
    trivial dashboard. **Cost:** the observe→engine baseline feed is **in-process
    today** (`tap.go` runs inside the engine and holds the bbolt write lock,
    `tap.go:1-6`; the `observebaseline.Aggregator` is an engine field). A central
    engine needs a NEW out-of-process transport to stream each node's observe flow
    features to the center. That is real, unbuilt work (open question #1).
  - **Model B — per-node engine (full stack per node).** Each DaemonSet pod carries
    its own engine (today's 3-container pod plus the currently-disabled observe path
    enabled — Section 3, item 6 — replicated per node). Zero new transport; mirrors
    Tetragon precisely. **Cost:** each node learns a PARTIAL
    baseline for the shared `cluster-UID` scope, and the dashboard must aggregate N
    per-node taps. Acceptable for a spike; a coherence problem for production
    (open question #1).
- **Scoring/aggregation location.** Scoring is always in the engine (per rule:
  `CLAUDE.md` core rule 1 — proxies stay thin; adapters emit signals and apply
  verdicts, no scoring). The dashboard tap aggregation lives in the SEPARATE
  dashboard-backend that consumes the raw tap (`tap.go:1-15`). Under Model A the tap
  is already cluster-wide (one engine, one scope); under Model B the dashboard-backend
  fans in N node taps.
- **Socket-cookie correlation stays valid per-node.** Unchanged: on each node the
  sockops program captures the accepted socket's cookie keyed by 4-tuple
  (`docs/IDENTITY.md:33-38`), the adapter resolves its ext_proc 4-tuple against that
  node's `flow_cookies` map, and `enforce_egress` reads the offending socket's cookie
  live on egress (`docs/IDENTITY.md:44-47`). Because capture and enforce are on the
  same node, the host-local cookie is a valid join on that node. No cross-node join
  is ever attempted — and none is needed (Section 7, question #2).

---

## 3. What changes vs our kina manifests

Concretely, relative to `deploy/kina/40-gateway.yaml`:

1. **Deployment → DaemonSet** for the node-local unit. `kind: DaemonSet`, pod
   template = today's adapter(+envoy, +engine under Model B) containers. Keep the
   `securityContext` grant verbatim (`runAsUser: 0`, `add: [BPF, NET_ADMIN,
   SYS_RESOURCE]`, lines 62-68) and the two hostPath mounts (`/sys/fs/cgroup`,
   `/sys/kernel`, lines 111-120). Add DaemonSet-standard fields: `tolerations` (run on
   all nodes incl. control-plane if in scope), `updateStrategy: RollingUpdate`, and a
   node `hostPID`/`hostNetwork` decision (see Envoy strategy below).
2. **cgroup path stays the node root** (`/sys/fs/cgroup`) on a real VM node — matches
   the loader default (`resolver_linux.go:13`). The loaders ALREADY accept an override
   parameter (`NewMapResolver(cgroupPath)` `bpf/sockops/resolver_linux.go:31`;
   `NewKernelLoader(cgroupPath)` `bpf/enforce/loader_linux.go:30`;
   `observe.Load(cgroupPath)` `bpf/observe/loader_linux.go:32`; `cmd/engine`
   `-observe-cgroup` flag `cmd/engine/main.go:40`). The composition-root constant is
   the only hardcoded site (`resolver_linux.go:13`, comment: "Override per deployment
   if cgroups are namespaced" line 12). **Change needed:** thread a cgroup-path flag
   through `cmd/envoy-adapter` so a namespaced-cgroup environment (kind, some CRIs)
   can override; on a real EKS/GKE VM node the default node root is correct.
3. **Envoy topology — pick one:**
   - **(Recommended for spike) per-node Envoy in the DaemonSet pod** (`hostNetwork:
     true`; traffic is routed to it via the gateway Service as today — hostNetwork
     does not itself intercept). Simplest, mirrors a mesh node-proxy; the adapter is
     co-located and dials Envoy locally. Coarser L7 visibility than sidecars but
     sufficient to prove the datapath.
   - **(Production follow-on) sidecar injection per workload** via a mutating admission
     webhook that injects Envoy + points ext_proc at the node-local adapter (reached
     via the node's IP / a `hostPort`, or a Unix socket on a shared hostPath). More
     faithful L7 coverage; materially more complex (webhook, cert rotation, injection
     ordering). Out of scope for the spike; named as the real productionization path.
4. **engine/adapter/tap wiring across nodes.**
   - Model A: adapters get `-engine <central-engine-service>:50052` instead of loopback
     (line 43); the central engine runs as a 1-replica Deployment; verdicts return on
     the same gRPC stream to the origin-node adapter, which drives that node's enforcer.
   - Model B: keep loopback wiring verbatim; each node is self-contained.
5. **Dashboard aggregation across per-node taps.**
   - Model A: the single engine's tap is already the whole scope — dashboard-backend
     consumes one tap. No change beyond addressing.
   - Model B: dashboard-backend must fan in N node taps and merge per-scope. Note the
     hard constraint: each engine holds its own bbolt write lock, so the backend
     CANNOT open a second engine's store read-only (`tap.go:1-6`) — it must go through
     each node's HTTP tap, never the DB directly.
6. **Enable the observe path per node (required for the spike's proofs).** Today's
   engine container runs observe-DISABLED: it is unprivileged (`runAsNonRoot`, drop
   ALL, `40-gateway.yaml:101-106`), has no `/sys/fs/cgroup` mount, and passes no
   `-observe-cgroup` (`""` ⇒ observe disabled, `internal/boot/boot.go:92`). With
   observe off, the `observebaseline.Aggregator` is nil (`internal/boot/boot.go:157`)
   and `buildLiveSurfaces` gets no flows (`tap.go:306`), so BOTH the §6 anti-criterion
   surface (`ReconLiveFlow`) and the P5 bystander proof (`BystanderFlow`) are empty.
   To exercise them the DaemonSet's engine container needs the `/sys/fs/cgroup`
   hostPath mount, `CAP_BPF + CAP_PERFMON` (`bpf/observe/loader_linux.go:20`), and
   `-observe-cgroup /sys/fs/cgroup` (`cmd/engine/main.go:40`). This is a real manifest
   delta, not verbatim reuse — it is why Section 2.3 says "plus enabling the
   currently-disabled observe path."

---

## 4. EKS specifics (reasoned assessment — not verifiable from repo)

- **BTF / CO-RE.** The stack ships committed bpf2go objects (`*_bpfel.o`) embedded via
  `//go:embed`, so RUNNING the programs needs only a BTF-capable kernel, not clang or
  `vmlinux.h` on the node (`docs/TECHNICAL_ARCHITECTURE.md:269-278`). Assessment:
  **AL2023** and **Bottlerocket** ship recent kernels (≥5.15 / 6.1) with
  `CONFIG_DEBUG_INFO_BTF=y` — CO-RE loads with no custom kernel. **Legacy AL2** (5.4,
  some 5.10) may lack in-kernel BTF; that requires a newer AMI or a BTFHub-provided
  BTF blob. Recommendation: target AL2023 or Bottlerocket node groups; treat AL2 5.4
  as unsupported for the spike.
- **cgroup v2.** AL2023 and Bottlerocket default to the cgroup-v2 unified hierarchy,
  which the loaders require (`bpf/observe/observer.go:97-99` — "cgroup v2 mount, e.g.
  /sys/fs/cgroup"). Assessment: node-root `/sys/fs/cgroup` hostPath works as on the
  kina BTF cluster.
- **Privilege / capabilities.** Managed node groups run standard kubelet — privileged
  pods, `CAP_BPF`/`CAP_NET_ADMIN`, and hostPath are allowed. The existing grant
  (lines 62-68) should transfer unchanged.
- **Fargate excluded.** Fargate provides no eBPF, no hostPath, no privileged pods —
  structurally incompatible. Document as unsupported.
- **PodSecurity.** A privileged/hostPath DaemonSet needs the target namespace at PSA
  `privileged` (not `baseline`/`restricted`). Spike action: label the namespace
  `pod-security.kubernetes.io/enforce: privileged`.

## 5. GKE specifics (reasoned assessment — not verifiable from repo)

- **BTF / CO-RE.** Assessment: **COS** and **Ubuntu** GKE node images ship BTF —
  Cilium and Tetragon run on GKE on these images, which is direct evidence the CO-RE
  path is viable. Committed objects mean no on-node toolchain
  (`docs/TECHNICAL_ARCHITECTURE.md:269-278`).
- **cgroup v2.** Recent COS defaults to cgroup v2 (GKE ≥1.26-ish). Assessment:
  node-root hostPath works; on an older COS pinned to cgroup v1 the loaders would fail
  (they require the v2 unified hierarchy) — pick a recent node image.
- **GKE Standard allows privileged DaemonSets + hostPath.** The grant transfers.
- **Autopilot excluded.** Autopilot generally disallows the arbitrary privileged pods
  and hostPath our DaemonSet needs — no self-service eBPF datapath (modern Autopilot
  has a narrow allowlisted-partner path for specific vendor agents, which does not help
  a first-party DaemonSet). Document as unsupported for the spike (same shape as Fargate
  on EKS).

---

## 6. The minimal validation spike

**Smallest thing that proves portability:** a 2-node cluster, the node-local unit as
a DaemonSet (Model B — self-contained per node, zero new transport), one cross-node
A→B flow where A touches a canary, and confirmation that the touch is detected and
kernel-jailed on the node where the offending socket lands.

**Cluster ladder (cheapest first):**
1. **kind, 2 nodes** — cheapest smoke test. CAVEAT: kind "nodes" are containers
   sharing the host kernel with **namespaced cgroups**, so the node-root assumption
   may not hold — this is exactly the case `resolver_linux.go:12` warns about
   ("Override per deployment if cgroups are namespaced"). Use it to exercise the
   DaemonSet manifest + cross-node routing, expect to override the cgroup path.
2. **One real GKE Standard (COS) OR EKS (AL2023) 2-node cluster** — the true proof:
   CO-RE loads against a REAL node VM kernel's BTF with the committed objects, no
   custom kernel, node-root cgroup. This is the load-bearing validation.

**Steps:**
1. Deploy the DaemonSet to a 2-node cluster; confirm one pod per node
   (`kubectl get pods -o wide`).
2. Place a canary reachable from node 1, backed/served such that the touching flow's
   offending socket lives on a known node.
3. Drive one cross-node A→B flow from a workload on node 2 that touches the canary.
4. Observe the engine score it to Tier 3 and the node-local `enforce_egress` jail that
   flow's socket (egress dropped — exfil stopped, `docs/IDENTITY.md:44-47`).
5. Confirm a bystander flow on the SAME node keeps serving (flow-precise jail — the
   `BystanderFlow` tap surface, `tap.go:166-180`).

**Pass criteria (all must hold):**
- P1. CO-RE eBPF **loads on a real node kernel** with the committed objects — BTF
  present, no clang/`vmlinux.h` on the node, no custom kernel.
- P2. sockops captures the cookie on the node where the offending socket lands; the
  adapter resolves its ext_proc 4-tuple to that cookie (MISS ⇒ observe-only, never
  enforce — `docs/ADAPTERS.md:56`).
- P3. The canary touch (and ONLY a canary touch — `CLAUDE.md` core rule 8) drives the
  score to Tier 3.
- P4. `enforce_egress` jails that exact flow's socket on that node; cross-node egress
  from the offending socket is dropped.
- P5. A concurrent bystander flow on the same node is unaffected (flow-precise, not
  host-wide).

**Explicit anti-criterion (guardrail proof):** a novel cross-node flow that does NOT
touch a canary must be surfaced observe-only (`ReconLiveFlow`, `tap.go:150-164`) and
NEVER jailed — deviation-from-baseline is not a trigger (`CLAUDE.md` core rule 8,
`docs/TECHNICAL_ARCHITECTURE.md:119-131`).

---

## 7. Open questions / risks

1. **Central vs per-node engine → baseline coherence (biggest fork).** The K8s scope
   key defaults to the **cluster UID** — one scope for the whole cluster
   (`docs/SCOPE.md:12`). Learned state is per-scope and "never aggregates across
   deployments" (`CLAUDE.md` core rule 5, `docs/SCOPE.md:5`). Under Model B every node
   independently learns a PARTIAL baseline for that ONE shared scope — incoherent for
   production. Model A (central engine) fixes coherence but needs a NEW out-of-process
   transport for the observe→engine flow-feature feed, which is **in-process today**
   (`tap.go:1-6`; `observebaseline.Aggregator` is an engine field). Alternative:
   node-scoped keys (each node its own scope) — but that fragments learned state and
   many small scopes may never reach the evidence floor (`docs/SCOPE.md:21`). This is
   the decision the spike must NOT pretend to resolve.
2. **Cross-node flow attribution.** A connection spanning node2→node1: which node's
   adapter sees the canary touch, which node's enforcer jails? Assessment: sockops
   captures the **accepted downstream socket on `PASSIVE_ESTABLISHED`**
   (`docs/IDENTITY.md:33-38`) — the server-side socket on the node where Envoy/adapter
   accepted the connection. So touch-observation, cookie capture, and enforce are
   co-located on the **proxy node by construction**, not on "the attacker's node." The
   jail is egress-only and node-local (`docs/IDENTITY.md:44-47`): it drops that accepted
   socket's egress (proxy→attacker bytes), stopping exfil regardless of where the peer
   lives. The remaining empirical question the spike confirms is only that the ext_proc
   4-tuple resolves to a cookie captured on the SAME node (a cross-node routing hop that
   re-originates the socket on another node would produce a MISS ⇒ observe-only, never a
   misattributed jail — `docs/ADAPTERS.md:56`).
3. **Envoy topology complexity.** Per-node Envoy (spike) gives coarser L7 coverage;
   sidecar injection (production) needs a mutating webhook + cert rotation + injection
   ordering — significant complexity deferred out of the spike.
4. **kind cgroup namespacing.** kind's namespaced cgroups likely break the node-root
   assumption (`resolver_linux.go:12`); budget time to thread the cgroup-path override
   and don't treat a kind failure as a portability failure — the real-node cluster is
   the verdict.
5. **Node image drift / cost.** BTF and cgroup-v2 presence depends on the exact
   AMI/node-image version (Sections 4–5) — pin known-good images. A 2-node real cluster
   is a small but non-zero spend; tear down after the pass.
6. **CNI cgroup-eBPF coexistence (untested).** A real managed cluster already runs a
   CNI with its own cgroup-root-attached eBPF: **GKE Dataplane V2 IS Cilium**, and EKS
   clusters commonly add Cilium/other agents. Our `enforce_egress` and observe programs
   attach at the same node cgroup root, so multi-attach compatibility (link-based
   attach coexisting with the CNI's programs) and the ordering of our egress DROP
   relative to the CNI's programs are unvalidated — the kina cluster had no competing
   CNI eBPF. Add "our programs load and enforce alongside the cluster CNI's cgroup
   programs" to the spike's pass criteria; a GKE-Dataplane-V2 (Cilium) node is the
   sharpest test of this.

---

## 8. Restraint note

Per `/core:restraint`, this spike climbs the ladder and stops early:

- **Reuse the Cilium/Tetragon deployment pattern** (privileged DaemonSet, one agent
  per node, node-root cgroup) rather than inventing a topology. The composition-root
  comment already points here (`resolver_linux.go:12`).
- **Reuse our existing manifest as the per-node unit.** `deploy/kina/40-gateway.yaml`
  becomes a DaemonSet with the same containers, the same `securityContext` grant, the
  same hostPath mounts — the change is `kind:` plus DaemonSet-standard fields, not a
  rewrite.
- **Reuse the already-parameterized cgroup path.** The loaders take a `cgroupPath`
  argument (`bpf/sockops/resolver_linux.go:31`, `bpf/enforce/loader_linux.go:30`,
  `bpf/observe/loader_linux.go:32`); only the `cmd/envoy-adapter` constant is hardcoded
  (`resolver_linux.go:13`). Threading one flag is the whole code change for cgroup
  portability — do not build a cgroup-discovery subsystem.
- **Pick Model B (per-node engine) for the spike** precisely because it needs ZERO new
  transport — it is today's pod replicated per node. Do NOT build the central-engine
  observe-feed control plane (Model A) to prove portability; that is a productionization
  decision, and building it now would be scaffolding for a decision not yet made
  (rung 1, YAGNI). Flag the baseline-coherence limitation; do not solve it in a spike.
- **Do not design a full control plane.** No custom operator, no CRDs, no HA, no
  autoscaling. The spike proves the datapath ports; everything else is deferred.
