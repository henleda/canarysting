# CanarySting — Unified Build Plan

### Supersedes `docs/BUILD_TASK_PLAN.md`. Folds the SaaS control plane and minted decoys into the milestone sequence.

**Status of this document:** Phase-1 reconciliation output (planning only; no feature code written). It reconciles eight governing documents that were written in layers and are **not** mutually consistent as written, against a **code-grounded** verification of the actual repo at HEAD (`feat/m1-identity-consolidation`; `go build`/`go vet`/`go test ./...` all green, 58 packages `ok`, 0 fail). It is additive: the existing per-layer docs (`ARCHITECTURE.md`, `STING.md`, `BASELINE_MULTIPLIER.md`, `INTELLIGENCE.md`, `SCOPE.md`, `IDENTITY.md`, `CANARY.md`, `ENGINE.md`, `ADAPTERS.md`) remain valid and are not rewritten.

**Document precedence used here (later amends earlier):**
`ARCHITECTURE_SPEC_K8S.md` (target) → `CONTROL_PLANE.md` (authoritative on the plane split) → `MINTED_DECOYS.md` (decoys are minted, adds the ADVERSARIAL harvest-to-use edge + tier classifier) → `SEGMENTATION.md` (attacker-tier context). `BUILD_TASK_PLAN.md` is superseded by this doc. `GAP_REPORT.md`'s "early scaffold" premise is **wrong** (it was written from README+CLAUDE.md only); `GAP_VERIFICATION.md` is the earlier code-grounded correction, and this doc extends it to the control-plane/minting scope that `GAP_VERIFICATION` predated.

**How to read maturity tags:** every milestone is marked **[near-term slice]** (the wedge that wins a design partner) or **[build-toward]**. Every capability is marked **prototype**, **productized**, or **roadmap** in code and docs (honesty discipline, `ARCHITECTURE_SPEC_K8S.md` §10). Do not let any artifact imply maturity that does not exist.

---

## 1. Verified reality — what is built vs. net-new

This corrects `GAP_REPORT.md` against the source and **extends** the gap analysis to the scope `GAP_REPORT` and `BUILD_TASK_PLAN` never covered (the three-plane split, the SaaS control plane, minting, the segment classifier). Legend: ✅ implemented + tested · 🟡 partial/seam · ⛔ stub · ⬜ absent (net-new).

### 1a. Existing in-cluster layers (re-confirmed at HEAD)

| Area | Status | Ground truth (representative) |
|---|---|---|
| `internal/contract` + `api/{proto,gen,convert,enginegrpc}` | ✅ | stdlib-only (rule 3 clean); proto mirrors the `SignalEvent`/`Verdict`/`StingOutcome`/`OutcomeRecord` + `Engine{Submit,ReportOutcome}` RPC boundary with round-trip/enum-alignment tests. **Not mirrored:** `FeedbackLabel`/`FeedbackSink`, `StingFloor`, `DriverObservation` (feedback has no wire transport — decide intent). |
| `internal/engine` core (scoring, tiers, calibration, feedback, scope, persist, baseline, observebaseline) | ✅ | `Score = Base×M`; `M∈[1,M_max]` bounded/floored (5 invariants unit-tested); tier discipline config-validated; rule-7 triad on canary weights + baseline M. **Caveat:** in production the multiplier is **dormant** (`NeutralMultiplier` default + nil `FeatureSource`) — the engine runs *touch-only* until the eBPF observe path is wired (M1). |
| `internal/canary` (catalog/seeder/signal) + `internal/harmless` | ✅ | seed weights 1.8/1.5/1.2/1.1/1.0; touch→`SignalEvent` only via real placement; 4-layer harmlessness. **Decoys are static content** (generated once at placement). |
| `internal/sting` (attrition/containment/killswitch) | ✅ | all **five** attrition axes have real generators (AX4/AX5 **ahead** of their "deferred" doc status); containment refuses cookie 0; kill switch disarm-only + per-identity bearer RBAC; per-flow budget + host governor ceilings. |
| `internal/intelligence` (15 subpkgs; egress `network/`) | ✅ | **single default-deny egress chokepoint**, type-enforced (`*Cleared` opaque carrier), ledger-verified-only, k≥3 gate, `go list -deps` import guards. This is **crossing B**. |
| `bpf/{observe,sockops,enforce,kernel,loader}` | ✅ | all keyed on `bpf_get_socket_cookie` (sole join); **kernel-pin (≥5.10) landed on this branch**, wired fail-loud into sockops capture + enforce load; `NoopLoader` fails loud off-Linux; committed `.o`, root-gated tests. |
| `adapters/envoy` (+ `identity`) | ✅ | full ext_proc server, machine-guarded thin **from both sides now** (`internal/engine/importguard_test.go` landed this branch); **M6 attrition pump is live** (ahead of `ADAPTERS.md`). Response body mode is `NONE/SKIP` — no body rewrite today. |
| `adapters/nginx` | ⛔ | ~14 lines, struct + TODO. The one genuine stub. |
| `internal/dashboard` (tap + backend + views) | ✅ | in-cluster, **single-scope**, display-only read view (topology/deviants/journey/fingerprint/cost). **Not** multi-tenant/SaaS-shaped. |
| `internal/identity` | 🟡 | only `naming/` exists (moved from `internal/topology/identity` this branch; retired the old container). `mesh`/`labels`/`workload` absent. |
| `cmd/aggregator` | ✅ | **the D6-3 crossing-B moat ledger** (cross-customer, k≥3 enrolled-token gate, re-clears through the egress chokepoint). **Not** the in-cluster per-scope aggregator — see the naming collision in §6. |

### 1b. Net-new scope (unmapped by prior plans)

| Area | Status | Note |
|---|---|---|
| K8s deployment model (DaemonSet + operator + CRDs) | ⬜ | **no k8s.io/client-go/controller-runtime deps exist at all.** `deploy/` is docker-compose + Terraform demo harness (m4/m5/m7), not manifests/Helm. |
| `internal/operator` + `cmd/operator` | ⬜ | no controller-runtime, no `DeceptionPolicy` CRD, no reconcile. |
| `internal/k8s` (read-only API ingestion → PERMITTED edges) | ⬜ | medium case depends entirely on it (rule 11). |
| `internal/graph` (blast-radius) | 🟡 | **OBSERVED substrate exists** (`observebaseline/topology.go`: directed edges, counts/bytes/timestamps, role, eviction, gob persist, copy-out `TopologySnap`). **Absent:** identity-keying (edges are IP/port-keyed), edge-type model, PERMITTED, ADVERSARIAL, dark-reachability, transitive closure, graph store. Additive on top of a solid base (rule 10). |
| **In-cluster control plane** (three-plane split) | ⬜ | today everything is one **fused** engine process (data + reduction). The distinct operator + per-scope aggregator/reducer that assembles the graph locally and decides what is safe to send up does **not** exist. |
| **Crossing A** (per-tenant derived-state → SaaS) | ⬜ | net-new, needs its **own** contract parallel to `internal/contract` (logical identifiers only). Must **not** reuse the anonymizing egress filter (which strips tenant identity — wrong for crossing A). |
| **SaaS control plane** (tenant mgmt, 5 stores, multi-tenant dashboard) | ⬜ | none of it exists. Tenant isolation must be a **tested invariant** (backend counterpart of rule 5). |
| Enrollment/registration + signed distribution (Helm, registry, cosign/SLSA) | ⬜ | the "enroll" in code is the intelligence k-anon token allowlist — a *different concept*. |
| BYOC / self-hosted / air-gapped | ⬜ | `CONTROL_PLANE.md` §5: "design early, do not retrofit." |
| **Minted decoys** (harvest-to-use join) | ⬜ | greenfield. Static decoys today; proxy never rewrites bodies. Needs minting engine, mint→identity binding store (per scope), decoy-only response-write path, use/callback detection, ADVERSARIAL harvest-to-use edge. |
| **Attacker-segment classifier** (1/2a/2b/3) | ⬜ | absent. `profile.PeakTier` is the *response ladder*, not the segment. `cost/` computes imposed cost + time-to-disengage but not bucketed by segment. Use the word **"segment"** in new code (not "tier") to avoid collision. |

---

## 2. Load-bearing decisions — confirmed in code (Phase-1b verdicts)

All four load-bearing invariants **HOLD** in code; both non-negotiable ones survived a dedicated adversarial-refutation pass. Two more arrive with the new scope (they can only be tested once the code exists) and are stated as build-time obligations.

| Invariant | Verdict | Decisive evidence |
|---|---|---|
| **Socket cookie is the sole L7↔kernel join (rule 4)** | ✅ holds | `observe`/`sockops`/`enforce` + `containment`/`scoring` all key on the cookie; SPIFFE & PID/cgroup are "context, never the join key." No second mechanism. |
| **Scope isolation fails closed (rule 5)** ⚠ non-negotiable | ✅ holds | resolver never returns `("",nil)`; `engine.New`/`boot.Build` refuse to start unresolved; single `scopeSub` bbolt chokepoint; `Submit` and (this branch) `ReportOutcome` key on the cookie-bound **resolved** scope. **Residual:** the non-jailed Tier-2 `ReportOutcome` path still keys an `AmendOutcome` on the wire `rec.Scope` — a *self-scoped orphan write*, contained (per-scope sub-bucket, empty-scope rejected), cannot aggregate cross-scope. Close or explicitly accept it for the multi-namespace DaemonSet model (M1). |
| **Canary-touch-only trigger (rule 8)** ⚠ non-negotiable | ✅ holds | `base` accrues only from `ev.Canary` touches; `M` floored at 1 and strictly multiplicative ⇒ `base=0 ⇒ score=0`; deviants/topology/novelty are `Score=0` display-only; `scoring`/`tiers`/`sting` do **not** import `observebaseline`. Deviation *sharpens* an existing touch score, never *creates* one. |
| **Thin adapter / proxy-agnostic engine (rules 1–2)** | ✅ holds | `guard_test.go` fences the adapter; `internal/engine/importguard_test.go` (this branch) fences the engine — symmetric `go list -deps` guards, both pass. |
| **[NEW] Never-crosses list stays in-cluster (rule 12/inv 3)** | ⬜ obligation | Enforced today only for crossing B (the egress filter). Crossing A does not exist yet, so nothing leaks — but there is **no guard** preventing raw topology from leaving once crossing A is built. M7 must add a structural guard + a test enumerating `CONTROL_PLANE.md` §2's never-crosses list. |
| **[NEW] A minting fault affects zero legitimate requests (inv 4)** | ⬜ obligation | Isolation is *structural-by-accident* today (response mode `NONE/SKIP`). Introducing a mint write-path removes that guarantee; M5 must re-establish it explicitly (gate identically to attrition; never enable body mutation on non-decoy traffic). |

---

## 3. Proposed CLAUDE.md rules 12–17 (SaaS boundary + minting safety)

**These are proposals, not applied edits** (surface-don't-overwrite; a CLAUDE.md rule change is a deliberate reviewed act). They extend, and do not override, rules 1–11.

- **Rule 12 — Reduce in-cluster; only derived state crosses to the SaaS.** Raw telemetry is reduced by the in-cluster control plane; only derived, logical-identifier state crosses. Every item on `CONTROL_PLANE.md` §2's "never crosses" list — raw flow payloads, the learned baseline, decoy contents, scope state/calibration/feedback labels, observed secrets, environment-identifying detail — **never** leaves the cluster. This is the backend extension of rule 5 and the reason there are three planes, not two.

- **Rule 13 — Two upward crossings, never conflated.** *Crossing A* (per-tenant derived state → the tenant's own SaaS space) is **tenant-isolated and tenant-identified**, governed by tenant isolation (rule 14). *Crossing B* (anonymized adversary fingerprints → the shared intelligence store) carries **no tenant-identifying data** and is the only thing shared across tenants, through the single default-deny egress filter (rule 9). Crossing A must **not** be routed through the anonymizing filter; crossing B must **never** carry tenant identity. Each has its own contract and its own structural guard.

- **Rule 14 — Tenant isolation in the SaaS is a correctness invariant with tests.** A cross-tenant leak in the backend is the same class of bug as a cross-scope leak in the cluster: per-tenant keys/partitions at the data layer, plus a cross-tenant-leak test. Mirrors rule 5.

- **Rule 15 — The data plane never depends on the SaaS at runtime (autonomy).** Enforcement is host-local and keeps observing/deceiving/stinging on last-known-good config when the SaaS is unreachable. The SaaS is for intelligence, dashboards, distribution, and cross-customer learning — never a runtime dependency of enforcement. Downward config that changes enforcement posture is authenticated, authorized, and validated by the **in-cluster operator** before it is applied (trust-but-verify); the cluster does not blindly trust the SaaS.

- **Rule 16 — Minting is decoy-only and fault-isolated to zero legitimate requests.** Per-flow credential minting rewrites content only on the confirmed-decoy response path, gated identically to attrition (a confirmed canary-location match **before** any body mutation), and never enables response-body mutation for non-decoy traffic (invariant 4, with tests). Only **proxied** decoys are minted; static file decoys keep detect-on-touch. The mint→identity binding is per-scope state (rule 5) and never crosses a deployment boundary; only anonymized harvest-to-use pairs may cross, through the egress filter (rule 9).

- **Rule 17 — A derived attacker-segment label is advisory, never a trigger or an auto-escalation.** The attacker-segment classifier (1/2a/2b/3) is intelligence, not a control signal. It may inform operator-visible ranking and (electively) the response floor as an advisory input, but it must never auto-raise a tier or floor, never substitute for the canary-touch trigger (rule 8), and never override the operator-elective floor. Use "**segment**" for the attacker taxonomy; "tier" remains the engine response ladder.

---

## 4. The unified milestone sequence (supersedes BUILD_TASK_PLAN M0–M7)

Sequencing spine preserved from `BUILD_TASK_PLAN.md`: **substrate → canary + join → sting → narrow blast radius → medium → intelligence → demo.** The backend/SaaS and minting work is interleaved into it (rationale in §5). Old→new mapping: old M0→**M0**, M1→**M1**, M2→**M2**, M3→**M3**, M4→**M4**, M5→**M6**, M6→**M9**, M7→**M10**; new inserts are **M5** (minting), **M7** (plane split + crossing A), **M8** (SaaS).

> Because the substrate, canary, sting, contract, intelligence-egress, and eBPF datapath are **already built and tested**, the near-term milestones are mostly *K8s-wrapping + graph-building*, not from-scratch construction.

---

### M0 — Reconcile & unify — ✅ DONE
`GAP_VERIFICATION.md` (code-grounded) + this `UNIFIED_PLAN.md`. **Acceptance met:** every layer has a verified status; every load-bearing decision has a verdict; the new-scope gap (control plane, minting, segment classifier) is mapped; rules 12–17 proposed; package layout collision-checked (§6).

---

### M1 — K8s substrate & the identity spine — **[near-term slice]**
**Goal.** The already-built eBPF-observed, socket-cookie-joined, per-scope substrate running as a per-node **DaemonSet + operator skeleton** on mesh-enabled K8s, with **identity resolution** (mesh primary, label fallback) and **K8s-mapped scope**.
**Work (most substrate exists).**
- `cmd/operator` + `internal/operator` skeleton (controller-runtime; `DeceptionPolicy` + scope/graph-config CRD types). Add `k8s.io`/`client-go`/`controller-runtime` to `go.mod`.
- `internal/identity/{mesh,labels,workload}`: mesh/SPIFFE primary (high-confidence), label-derived fallback (**explicitly lower confidence on the edges it produces**), optional `workload` facade preferring mesh→labels. `naming` stays as-is (stdlib/config-guarded).
- Scope mapping: implement `scope.ClusterIdentity` (cluster UID no-mesh / SPIFFE trust-domain mesh) and derive `scope.Zones` from namespaces/labels; feed the resolver from identity + `internal/k8s` instead of a single static `Boundary`.
- Wire `baseline.FeatureSource` from `bpf/observe` so the multiplier is **live, not neutral**, in production.
- Per-pod attach: TC-on-veth (clsact) or per-pod cgroup, with attach-lifecycle reconciliation as pods churn (today's loaders attach a single host cgroup sized for the demo).
- **Minimal Helm chart** to install DaemonSet+operator on a test cluster (the first, minimal distribution slice — *not* the signed SaaS registry; that's M8).
- Fold the §3.2 residual: close or explicitly accept the non-jailed Tier-2 `ReportOutcome` orphan-write for the multi-namespace model; (optional) add the kernel assertion to `observe` Load for uniformity.
**Acceptance.** On a mesh test cluster: the DaemonSet observes real east-west flows, attributes to mesh identity, renders the OBSERVED map; scope resolves to namespace/cluster and **fails closed**; the cross-scope isolation test passes; overhead measured and recorded.
**Prototype/roadmap.** Substrate = productized; operator/CRDs + mesh identity = prototype this milestone.
**Blocking open questions.** Q1 mesh beachhead (Istio / Linkerd / Cilium)? Q2 attach strategy (TC-on-veth vs per-pod cgroup)? Q3 does label-fallback confidence surface on edges now or at M4?

---

### M2 — Canary & the socket-cookie join, operator-driven — **[near-term slice]**
**Goal.** Operator-seeded decoys; touch → scored identity-attributed event via the socket-cookie join; the false-positive guardrail proven on K8s.
**Work (canary layer built; this is wiring + K8s).**
- `DeceptionPolicy` CRD → `Store.Seed` per scope (wire the existing seeder to the operator; placement via volume-mount/exec into matching workloads).
- Prove the same-host socket-cookie join on the cluster; document the host-local boundary in code.
- Introduce the **file-decoy vs proxied-decoy split** in the catalog (a mintable flag) + LSM/eBPF detect-on-touch for file decoys (prep for M5 minting).
- Harden directory-canary placement to negative-space roots **in code** (today enforced by convention/comment — a mis-seeded directory canary could mis-attribute benign traffic).
**Acceptance.** An operator-seeded decoy touch produces a scored, identity-attributed event via the socket-cookie join; the guardrail test passes (no touch ⇒ no action, however anomalous the traffic).
**Open questions.** `DeceptionPolicy` schema; workload-selector semantics.

---

### M3 — Sting on K8s: in-kernel, flow-precise — **[near-term slice]**
**Goal.** Real in-kernel containment + attrition on the cluster, flow-precise, observe-before-enforce gated.
**Work (sting built; this exercises the kernel path + remote identity).**
- Exercise real `bpf/enforce` on Linux nodes (userspace path built; kernel path unexercised on macOS dev).
- Wire **observe-before-enforce** (baseline-maturity gate) into K8s enforcement activation.
- Remote operator identity for the kill switch: mTLS/SPIFFE replacing loopback+bearer for a distributed deployment.
- Confirm the **AX5 F4 in-perimeter harmlessness predicate** review happened before op-exposure runs at the aggressive floor (code is ahead of its gating review).
**Acceptance.** A post-canary-touch hostile flow is contained in-kernel with no human; legitimate traffic provably untouched; the observe-before-enforce gate is enforced; the kill switch is reachable via authenticated remote identity.
**Open questions.** AX5 F4 sign-off status; test-cluster kernel ≥5.10 confirmed.

---

### M4 — Narrow blast-radius graph (the shippable wedge) — **[near-term slice]**
**Goal.** `internal/graph`: demonstrated blast radius from OBSERVED + ADVERSARIAL edges, **identity-keyed**, no policy ingestion.
**Work.**
- Create `internal/graph` consuming `observebaseline.TopologySnapshot` (**rule 10 — reuse, never fork**; use the copy-out `TopologySnap` seam, *not* the lossy dashboard/tap presentation graph).
- Layer identity resolution over the IP/port edges (map to stable workload identity via `internal/identity`; mark label-derived lower confidence) — the store is IP-keyed today and the spec mandates stable-identity keying to survive pod-IP churn.
- Edge-type model: OBSERVED / ADVERSARIAL + per-edge confidence. ADVERSARIAL edges from canary touches (lift from `boltevents` via the tap seam).
- Transitive reachable-set + ranking by asset sensitivity and adversarial weighting; demonstrated-blast-radius **number** + ranked path list; reporting/visualization for the demo.
- Structural egress import-guard on `internal/graph` (it carries raw addresses/identities — must never reach `intelligence/network`).
**Acceptance.** For a chosen workload, the product reports demonstrated blast radius (a number) + adversarial overlay + ranked path list from real observed+canary data; an architecture check proves `graph` reuses `observebaseline` and never re-folds flows; rule-8 (graph never arms a response) and rule-9 (graph never crosses egress) guards in place.
**Open questions.** Graph-store technology (in-proc incremental vs embedded graph DB) for identity-keyed incremental updates at scale.

---

### M5 — Minted decoys, in-cluster (harvest-to-use join) — **[near-term slice; per MINTED §7.4]**
**Goal.** Per-flow minted credentials on **proxied** decoys + in-cluster use detection + the ADVERSARIAL harvest-to-use edge. No external callback, no policy ingestion — fits the narrow wedge.
**Work.**
- Minting engine: a format-valid but inert credential minted per harvesting flow at the proxy egress (reuse decoy generator format envelopes).
- `internal/canary/mint`: mint→identity binding store, **per scope** (rule 5) — `mint → {mesh/label identity, scope, node, socket cookie, L7 request, harvest ts}`, with expiry/volume policy.
- A response-body write path on `adapters/envoy` for **proxied decoys only** (today response mode is `NONE/SKIP`), gated identically to attrition (confirmed canary-location match before any body mutation).
- In-cluster decoy-API use detection resolving the mint back to the harvest flow; the ADVERSARIAL **harvest-to-use edge** (harvest ts + use ts + off-graph segment + certainty confidence) into `internal/graph`.
**Acceptance.** A minted credential harvested from a proxied decoy and later used against an in-cluster decoy API resolves back to the exact harvest flow/identity and appears as a harvest-to-use ADVERSARIAL edge; **invariant 4 proven** — a test shows the mint write-path is gated identically to attrition and never activates body mutation on non-decoy traffic.
**Deferred (build-toward).** External cloud-credential callback receiver (its own threat model, `cmd/callback-receiver`, MINTED §7.1); cross-deployment harvest-to-use pooling (that's the crossing-B payload in M9).
**Open questions.** Mint lifetime/volume policy (per-flow vs per-identity vs per-scope-window); v1 decoy-credential surface (in-cluster SA-token / decoy-API-key first — no external dependency); host-the-callback vs. canarytokens (deferred); prior-art/patent posture (MINTED §6 — base mechanism is public; only the four narrow deltas are candidate novelty; no novelty claims in code).

---

### M6 — Medium blast-radius: policy ingestion, dark reachability, safe recommendation — **[build-toward]**
**Goal.** `internal/k8s` read-only ingestion → PERMITTED edges; dark reachability; predicted blast radius; **audit/detect-only** policy recommendation. **Gated on mesh identity.**
**Work.**
- `internal/k8s` client-go ingestion: NetworkPolicy, CiliumNetworkPolicy/CiliumClusterwide, mesh AuthorizationPolicy/PeerAuthentication (or Linkerd equivalents), RBAC, namespaces/labels/SA. **Read-only (rule 11).**
- PERMITTED edges into `internal/graph`; **dark reachability = PERMITTED − OBSERVED**; predicted blast radius for not-yet-observed compromise.
- Least-privilege recommendation (allow OBSERVED, deny dark) emitted as NetworkPolicy/CiliumNetworkPolicy in **audit/detect-only**; baseline-maturity gate + **human sign-off before any enforce**. **Never auto-enforce (rule 11).**
**Acceptance.** Ingests cluster policy, computes dark reachability, predicts blast radius, emits a safe recommendation that runs in detect-only and is reviewed before enforce; a test asserts no auto-enforce path exists.
**Open questions.** Which mesh's authz model first; admission-webhook runtime-effect (inferred, not declarative).

---

### M7 — In-cluster control plane split + crossing-A contract + graph store — **[build-toward; the backend-enabler]**
**Goal.** Separate the fused engine into **(data-plane DaemonSet)** vs **(in-cluster control plane: operator + per-scope aggregator/reducer that reduces raw telemetry to derived state and assembles/stores the graph locally)**, and define the **crossing-A** derived-state contract. This is the reduce-in-cluster boundary that makes a SaaS safe and cheap.
**Work.**
- Extract the per-scope **reducer** (`internal/reducer` — **not** `aggregator`; see §6 collision) that projects `boltevents`/`l7events`/`graph` into derived-state deltas; durable per-scope graph store.
- The **crossing-A contract** (`internal/derived` + `api/derived` if it crosses a network): a NEW schema **parallel to** `internal/contract`, carrying only logical-identifier graph node/edge deltas, scored encounters, dark-reachability summaries, metrics-over-time, cluster/agent health — **never** raw IPs/payloads/baselines/scope-state/secrets/decoy-contents.
- A **structural guard** on crossing A analogous to the egress import guard, + a test enumerating the §2 never-crosses list (**invariant 3 extended to crossing A**). Crossing A must **not** reuse the anonymizing egress filter.
- Local buffering when the channel is down (autonomy §8).
**Acceptance.** Raw telemetry never leaves the in-cluster control plane; crossing A carries only derived logical-identifier state (verified by the structural guard + the never-crosses test); the data plane keeps enforcing on last-known-good if the control-plane/SaaS link is down.
**Interleave justification (see §5).** After the graph is real (M4–M6) because crossing A's payload *is* the graph; before the SaaS (M8) because shipping crossing A without in-cluster reduction would let raw telemetry leave — the exact failure §2 warns against.
**Open questions.** `CONTROL_PLANE.md` §10 Q1 (how much graph crosses vs. renders from summary vs. runs back down); §10 Q2 (minimum crossing-A schema).

---

### M8 — SaaS control plane, enrollment & signed distribution — **[build-toward]**
**Goal.** The multi-tenant vendor cloud: receives crossing A per tenant, hosts the dashboard from derived state, the five stores, enrollment/registration, and signed image+Helm distribution. **BYOC seam designed in from M7's contract.**
**Work.**
- Tenant management + the two ingest channels' backend; five stores (per-tenant **graph store** [centerpiece], **event/TS store**, **per-tenant state store**, physically-separate **intelligence store** [crossing-B sink], **registry**), with per-tenant encryption/partitioning.
- Multi-tenant dashboard: re-home the built in-cluster dashboard's SaaS-movable views (tier ladder, cost, journey, recon counts — already anonymized); keep **sensitive topology in-cluster** (topology/deviants render raw IPs/labels — §10 Q1), rendering it from summaries or via queries that run back down.
- **Tenant-isolation invariant + cross-tenant-leak tests** (rule 14).
- Enrollment service: bootstrap token → **outbound-only mTLS** handshake → long-lived least-privilege per-cluster identity; local buffering (autonomy).
- Signed distribution: cosign/sigstore, SBOM, SLSA provenance, **verify-before-run**; separable up/down channels; strict-egress-proxy support.
- The in-cluster operator **validates/authorizes downward posture-changing config before apply** (rule 15, trust-but-verify).
**Acceptance.** A cluster enrolls with a bootstrap token, pulls signed+verified images, registers over outbound-only mTLS, and appears in its tenant dashboard rendered from derived state; a cross-tenant-leak test passes; taking the SaaS offline does not stop in-cluster enforcement (autonomy).
**Consider a separate module/repo** for the SaaS backend (it is multi-tenant infra with a different deploy target; the in-cluster half stays in this monorepo). — open question.
**Open questions.** §10 Q3 BYOC scope (full self-hosted vs. light on-prem collector); §10 Q4 retention tiering + opt-in raw-forensics tier in the customer's own cloud; SaaS-as-separate-module decision.

---

### M9 — Intelligence, the moat & the attacker-segment classifier — **[build-toward]**
**Goal.** Compound encounters into the anonymized cross-customer asset (crossing B is **already built**), and add the per-encounter **attacker-segment classifier** keyed on minted-decoy harvest-to-use telemetry.
**Work.**
- `internal/intelligence/segment`: map harvest-to-use infra-split / tool-change / harvest-to-use-delay features (from M5) onto SEGMENTATION 1/2a/2b/3. **"segment," not "tier."**
- Harvest-to-use **correlation pairs** as the crossing-B payload through the default-deny egress filter (rule 9, anonymized) — the cleanest crossing-B demonstration (attacker's fingerprint, not the customer's data).
- Bucket the existing `cost`/time-to-disengage metrics **by segment** (SEGMENTATION §7).
- Feed the segment label into the response floor **as advisory only** (rule 17 — never auto-escalate; operator-elective; observe-before-enforce).
- Cross-customer priors (day-one-optional per §10 Q5) to bootstrap a new deployment's danger ranking.
**Acceptance.** An encounter yields a segment label + an anonymized harvest-to-use fingerprint that crosses only through the egress filter (a test asserts no tenant-identifying data crosses — invariant 3); the segment label never auto-raises a response floor (test); the within-scope loop measurably sharpens scoring/placement.
**Open questions.** SEGMENTATION §7: the 2a/2b fault line; which axis produces the most measurable cost; intelligence yield by bucket; cross-customer priors day-one vs. later.

---

### M10 — Killer demo enablement — **[near-term for the "wow" cut; build-toward for the medium beats]**
**Goal.** The `DEMO_SPEC.md` seven-scene run on mesh-enabled K8s, with honest prototype/productized/roadmap labels per scene.
**Work.** Mesh demo cluster (ingress gateway, frontend/orders/payments/db/secrets, mesh identity, DaemonSet+operator, canaries seeded incl. a minted decoy); script the seven scenes; ensure silence on legitimate traffic; live + flow-precise enforcement; blast-radius reveal with a **number + action**.
**Acceptance.** Full end-to-end run; Scene 1 valid-credential beat shows detection blind while CanarySting stays silent until the canary touch; containment live + precise; the blast-radius reveal yields a number + a cut recommendation; **no false positives in the live run**. The medium-case (PERMITTED/dark-reachability, M6) is labeled honestly if not yet productized.
**"Wow" cut (near-term).** Scenes 1, 3, 4, 5 (valid-cred entry → canary touch → in-kernel containment → blast-radius reveal) run on M1–M5. Scenes 2/5-permitted/6 depend on M6/M9.
**Open questions.** Mesh choice; the XC/AppStack gating question (whether F5 CE pK8s permits privileged eBPF/CRDs/operator).

---

## 5. Why the backend milestones interleave where they do

The single load-bearing constraint from `CONTROL_PLANE.md` is **reduce-in-cluster: only derived state crosses.** That dictates the interleave:

1. **Nothing SaaS-facing can precede the graph.** Crossing A's payload *is* blast-radius graph deltas + scored encounters. So the SaaS-enabling milestones (M7 plane split, M8 SaaS) must come **after** the narrow graph (M4) and ideally after minting (M5, which adds the highest-value ADVERSARIAL edge). Building crossing A earlier would mean shipping raw telemetry up because there is nothing derived to send — the exact log-lake/privacy failure the three-plane split exists to prevent.

2. **The plane split (M7) must precede the SaaS (M8), not follow it.** The in-cluster reducer is what makes the SaaS safe and cheap. If M8 were built first, the reduce-in-cluster guarantee would live nowhere in code (today it holds only because the engine is in-process with the data plane — *by absence, not by design*). M7 stands up the boundary and its guard before any per-tenant state leaves.

3. **A *minimal* slice of distribution is pulled forward into M1.** You cannot run the substrate on K8s without deploying the DaemonSet+operator, so M1 carries a minimal Helm chart. The *full* signed-registry/enrollment/tenancy distribution stays in M8. This is the one place backend work is deliberately split across milestones.

4. **Minting (M5) rides the narrow wedge, not the SaaS.** Per MINTED §7.4, in-cluster minting + in-cluster use detection needs no policy ingestion and no external callback — so it fits the near-term slice alongside canary/graph. Only the external cloud-credential callback receiver (a new attacker-reachable SaaS surface with its own threat model) defers to M8-era work.

5. **The segment classifier (M9) waits on minting (M5).** Its key input is harvest-to-use telemetry; SEGMENTATION §3/§7 explicitly wants an *observable per-encounter* classifier, which only minting provides. Crossing B is already built, so M9 is additive.

6. **BYOC is a design constraint from M7, not a late retrofit.** §5 warns "design early." The crossing-A contract (M7) and the SaaS ingest (M8) are shaped so the same control plane can run in the customer's environment (self-hosted) or air-gapped (signed periodic intelligence bundles instead of a live feed).

**Near-term slice:** M1–M5 + the M10 "wow" cut. **Build-toward:** M6 (medium), M7 (plane split), M8 (SaaS), M9 (moat + segment). This matches `BUILD_TASK_PLAN` M1-4+7-near / M5-6-toward, and `CONTROL_PLANE.md` §10 Q5 (per-tenant value first, shared moat later).

---

## 6. Final package layout & collision checks

The five original net-new names were collision-checked in `GAP_VERIFICATION.md` §5; re-confirmed clean at HEAD. The new-scope names below are checked against the actual tree (`internal/`, `cmd/`, `internal/intelligence/`, `internal/canary/`).

| Proposed | Collision? | Verdict |
|---|---|---|
| `cmd/operator`, `internal/operator` | none | **use as-is.** Controller-runtime + CRDs. The operator hosts the in-cluster control plane. |
| `internal/k8s` | none | **use as-is.** Read-only ingestion → PERMITTED (rule 11). `internal/permitted` is the only acceptable alt. |
| `internal/graph` | name clean; functional overlap | **use as-is, rule-10 constrained.** Must consume `observebaseline.TopologySnapshot`; must not fork the observed path or depend on the dashboard/tap presentation graph. |
| `internal/identity/{naming,mesh,labels,workload}` | `naming` exists (moved) | **use as-is.** `mesh`/`labels`/`workload` are new leaves; `adapters/envoy/identity` stays put (adapter-local cookie join, rule 1). |
| `internal/canary/mint` | none | **use as-is.** Minting engine + mint→identity binding store (per scope, rule 5). The response-body write path stays in `adapters/envoy` (rule 1); the classifier consumes its telemetry. |
| `internal/intelligence/segment` | none | **use as-is.** Attacker-segment classifier. **Do not name it `tier`** — `profile.PeakTier`/`cost.TierCounts` already mean the engine response ladder. |
| `internal/derived` (+ `api/derived`) | none | **use as-is** (or `internal/crossinga`). The crossing-A derived-state contract, parallel to `internal/contract`, logical-identifier-only. |
| `internal/reducer` | none | **use as-is.** The **in-cluster per-scope aggregator/reducer**. ⚠ **Do NOT call it `aggregator`.** |
| `cmd/controlplane` + `internal/controlplane` | none | SaaS backend. **Flag:** likely a separate module/repo (multi-tenant infra, five stores) — decide at M8. |
| `cmd/callback-receiver` | none | External minted-decoy use detection (build-toward). Attacker-reachable → its **own** threat model, isolated from the customer-facing control plane. |
| **`cmd/aggregator` (EXISTING)** | **concept collision** | ⚠ **Rename or disambiguate.** `cmd/aggregator` is the **D6-3 crossing-B moat ledger** (cross-customer), but `CONTROL_PLANE.md` §1 uses "per-scope aggregator" for the **in-cluster reducer**. Recommend renaming the binary → **`cmd/intel-aggregator`** (or `cmd/moat-ledger`) and never introducing a second "aggregator." |

```
cmd/operator/                 # NEW  controller-runtime operator (hosts in-cluster control plane)
cmd/controlplane/             # NEW  SaaS backend binary (candidate separate module — decide M8)
cmd/callback-receiver/        # NEW  external minted-decoy use detection (own threat model)
cmd/intel-aggregator/         # RENAME of cmd/aggregator (crossing-B moat ledger) to end the name clash
internal/operator/            # NEW  reconcile loop + CRD types (DeceptionPolicy, scope/graph config)
internal/k8s/                 # NEW  read-only client-go ingestion → PERMITTED edges (rule 11)
internal/graph/               # NEW  blast-radius: reuse observebaseline OBSERVED + PERMITTED + ADVERSARIAL,
                              #      dark-reachability, transitive closure, ranking (rule 10)
internal/reducer/             # NEW  in-cluster per-scope aggregator/reducer (NOT "aggregator")
internal/derived/             # NEW  crossing-A derived-state contract (logical identifiers only)
internal/identity/
  naming/                     # MOVED (done)  stdlib/config-guarded
  mesh/  labels/  workload/   # NEW  mesh primary / label fallback / facade
internal/canary/mint/         # NEW  minting engine + mint→identity binding store (per scope)
internal/intelligence/segment/# NEW  attacker-segment classifier (1/2a/2b/3) — advisory only (rule 17)
internal/controlplane/        # NEW  SaaS tenant mgmt + stores + ingest (candidate separate module)
api/derived/                  # NEW  proto mirror of crossing A, if it crosses a network
# adapters/envoy/             # response-body write path for minted PROXIED decoys (rule 1, adapter-local)
# cmd/aggregator/             # RETIRED name → cmd/intel-aggregator
```

---

## 7. Consolidated open-questions register (blocks the named milestone)

- **M1** — Mesh beachhead: Istio / Linkerd / Cilium? · Per-pod attach: TC-on-veth vs per-pod cgroup? · Surface label-fallback confidence on edges now or at M4?
- **M2** — `DeceptionPolicy` CRD schema · workload-selector semantics · directory-canary negative-space enforcement in code.
- **M3** — AX5 F4 in-perimeter predicate sign-off status · test-cluster kernel ≥5.10 confirmed.
- **M4** — Graph-store technology (in-proc incremental vs embedded graph DB) · identity-keying migration for IP/port edges.
- **M5** — Mint lifetime/volume policy · v1 decoy-credential surface (in-cluster SA-token/decoy-API-key first) · host-the-callback vs canarytokens (deferred) · prior-art/patent posture (MINTED §6).
- **M6** — Which mesh authz model first · admission-webhook runtime-effect inference.
- **M7** — How much graph crosses vs. renders from summary vs. runs back down (§10 Q1) · minimum crossing-A schema (§10 Q2) · reconcile the D5 term into `BASELINE_MULTIPLIER.md` **before** flipping `alpha` on.
- **M8** — BYOC scope: full self-hosted vs. light collector (§10 Q3) · retention tiering + raw-forensics opt-in in customer cloud (§10 Q4) · SaaS backend as a separate module/repo?
- **M9** — Cross-customer priors day-one vs. later (§10 Q5) · the 2a/2b fault line + per-axis cost (SEGMENTATION §7).
- **M10** — Mesh choice · XC/AppStack privileged-eBPF/CRD/operator gating.
- **Cross-cutting** — Decide `FeedbackLabel`/`FeedbackSink` proto-mirror intent (does feedback ever run out-of-process?) · rename `cmd/aggregator` → `cmd/intel-aggregator` · reconcile stale docs where code is ahead (`ADAPTERS.md` M6 pump, `ATTRITION_FIVE_AXIS_DESIGN.md` AX4/AX5, `EGRESS_FILTER_DESIGN.md`, `BASELINE_MULTIPLIER.md` D5 term).

---

## 8. Standing invariants and their tests (the 4 confirmed + 2 new)

1. **Baseline deviation alone never produces a Tier 1+ action.** ✅ tested (`TestScore_ZeroBaseStaysZeroUnderAnyMultiplier`, deviant tests). Guard: never let a `MultiplierSource` add rather than multiply; never construct a `SignalEvent` bypassing `signal.Build`.
2. **No cross-scope state bleed; scope resolution fails closed.** ✅ tested (`TestSubmit_ForgedScopeCannotDriveCrossScopeState`, `TestReportOutcomeIgnoresForgedWireScope`, cross-scope no-bleed across 5 pkgs). Residual: close/accept the non-jailed Tier-2 orphan write (M1).
3. **[NEW] Nothing on `CONTROL_PLANE.md` §2's "never crosses" list ever leaves the cluster.** Enforced today for crossing B (egress filter + import guard). **Build obligation (M7):** a structural guard + a test on crossing A enumerating the never-crosses list.
4. **[NEW] A minting fault affects exactly zero legitimate requests.** **Build obligation (M5):** the mint write-path is gated identically to attrition (confirmed canary-location match before any body mutation) and never enables body mutation on non-decoy traffic; proven by test.

---

*End of Phase-1 output. Per the project's standing rules: this plan proposes, it does not apply. No feature code was written. Awaiting review before any Phase-2 milestone work begins.*
