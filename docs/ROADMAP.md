# docs/ROADMAP.md — Path to a Design-Partner Demo

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This document is the build
plan. It sequences the work from the current scaffold to a **working demo we can
run for prospective design partners**. It is a living document: as milestones
land, update status here.

The architecture docs say *what* CanarySting is and *why*. This says *what we
build, in what order, and where it runs*. Where this conflicts with a layer doc
on intent, the layer doc wins; this doc governs sequencing.

---

## 0. The goal that orders everything

**Land design partners by showing, live, the thing no incumbent ships:** a canary
touch triggers an automated, escalating, **kernel-enforced** response that imposes
asymmetric economic cost on an automated/LLM attacker — with low false positives
*by construction* (the guardrail), and learned state that never leaves the
customer's boundary (scope isolation).

### Locked decisions (review on 2026-06-03)

These are settled and now drive the plan:

1. **Audience = enterprise CISOs + enterprise infrastructure teams.** The demo
   must read as production-credible, not a toy. **Kernel enforcement (eBPF) is
   core to the first demo**, not a later beat.
2. **Real Envoy, no reference dataplane.** We integrate the real proxy from the
   start. We have time, and a hand-rolled shim would undercut credibility with
   infra teams.
3. **No placeholder or dummy data, anywhere in the demo.** The baseline and
   calibration panels show **real** learned state, accrued from genuine traffic in
   a persistent staged environment over a real learning window (see M7). We do
   not fake a baseline or seed fake feedback.
4. **Polished Next.js front-end.** The product dashboard is the surface a CISO
   sees; it must be highly polished. (Separate from the corporate
   `canarysting-www` property.)
5. **LLM-attacker, phased:** a scripted client for the development loop, and a
   **real LLM agent** for the demo itself (the why-now, made visible).
6. **No time pressure. Quality over speed.** A 3–4 month horizon is acceptable.
   We do this right.
7. **Single-host containers for the first demo; Kubernetes/EKS to follow.** K8s
   feasibility is being researched (see §8); it is expected to be viable and is a
   post-first-demo milestone.

We optimize for **a credible, real, polished demo** — not feature completeness,
and not raw speed.

---

## 1. The demo narrative (what a prospect sees)

A single live screen, staged in a small AWS environment (containers on one host
for the first demo):

1. **The fabric.** A handful of microservices behind a real **Envoy** proxy.
   Canaries seeded in the *negative space* of normal traffic (paths/ports/
   adjacencies legitimate flows never use), so a touch is almost certainly
   hostile. The baseline that identifies that negative space is **real** —
   learned from genuine traffic the environment has been generating (M7).
2. **The attacker.** An automated client — first a scripted client, then an
   actual **LLM agent** — performs recon and lateral movement.
3. **The escalation.** It brushes a canary → **Tier 0** (observe, score ticks).
   It keeps probing distinct canaries inside a tight window → **Tier 1** (tag) →
   **Tier 2** (contain + attrition begins). The suspicion score and tier ladder
   animate live.
4. **The sting (the wow).** At Tier 2 the attacker is tarpitted and fed an
   endless, plausible fake directory tree / fake secrets engineered to trigger
   expensive parsing. A meter shows **attacker time + tokens + compute burned**.
   The **defender's** cost stays flat — every generator is bounded.
5. **The precision (the CISO proof).** **Tier 3** jails the exact offending
   socket **in the kernel** (by socket cookie, via eBPF). A legitimate bystander
   flow on the same host keeps working — proving we contain the *flow*, not the
   host.
6. **The credibility panels — all backed by real learned state:**
   - *Guardrail:* a wildly abnormal flow that never touches a canary → **nothing
     happens** (deviation is not a trigger).
   - *Baseline:* the same single touch from an abnormal flow escalates faster
     (bounded multiplier sharpening a real signal), driven by the **real**
     accrued baseline.
   - *Scope/calibration:* per-scope calibrated/uncalibrated state, surfaced
     honestly, reflecting **real** accrued evidence.

That screen *is* the product. The milestones below build its pieces.

---

## 2. Environments

| Where | Runs on | What we build there |
|---|---|---|
| **Local dev** | this macOS/arm64 Mac | The pure-Go libraries developed and unit-tested in isolation: engine, baseline math, canary catalog, attrition generators, all unit/integration tests. No kernel needed for these. |
| **AWS Linux (the demo stack)** | EC2, Ubuntu 24.04, kernel ≥5.15 with BTF | Everything that needs a kernel or a real proxy: eBPF loader + `enforce.bpf.c`, the real socket-cookie identity join, the Envoy adapter, the persistent staged environment, the dashboard, the scenario + LLM attacker. The demo runs here. |

**Hard constraint:** eBPF (CO-RE, cilium/ebpf) and the real socket-cookie join
need a recent Linux kernel with BTF, and the Envoy adapter needs real Envoy —
none of which run on macOS. Because the kernel and the proxy are now *core* to
the first demo, **the AWS box is needed early** (M0). We still develop the engine
and the attrition generators as pure-Go libraries locally, then integrate them on
AWS.

---

## 3. Milestones

Three tracks that converge on the demo. Estimates are rough engineering days for
the two of us, under the tests-as-invariants discipline (§5). No date pressure —
estimates size effort, not a deadline.

### Track A — the engine and sting libraries (pure Go, local)

#### M1 — Engine core  · 3–5 days
The brain runs end-to-end in-process — no proxy, no kernel.
- `scope.Resolver` — resolution order (zone → derived cluster id → operator
  boundary → **hard fail**); never a global scope.
- `scoring.Scorer` — windowed weighted sum over *distinct* canary touches;
  uniform weights = raw count at cold start; benign-exclusion as a first-class
  input.
- `tiers.Decider` — score→tier under per-tier strictness; documented static
  uncalibrated threshold map (from `ARCHITECTURE.md` §8 base rates); async-only
  for 0–1; reject async+proxy-only enforcement for 2–3.
- `calibration.Calibrator` + `feedback.Intake` — one evidence floor gates
  uncalibrated→calibrated for **all** learned params together; per-scope only.
- `cmd/engine/main.go` — wire them; serve `contract.Engine`; refuse to start on
  `scope.ErrUnresolved`.
- **Tests are a deliverable:** 0→1→2→3 escalation; scope A never affects scope B;
  cold-start raw-count; refuse-to-start; fail-open T1 / fail-closed T3.
- **Exit:** a flow's signals drive a real verdict end-to-end; every core
  invariant has a test that fails if violated.

#### M2 — Baseline multiplier  · 2–3 days
- Implement `M(d)` exactly per `BASELINE_MULTIPLIER.md`: per-feature caps →
  bounded `d` → saturating `g(d)` → `M ∈ [1, M_max]`; `Score = base × M`.
- Force `M = 1.0` when uncalibrated / stale / time-bucket-sparse.
- Property tests: `M ≥ 1` always; `base = 0 ⇒ Score = 0`; the four worked
  examples in §5 of the spec.
- **Exit:** the guardrail is arithmetic and proven by test.

#### M3 — Canary layer  · 2–4 days
- `catalog` — initial canary types (fake secret, fake bucket listing, planted
  credential, decoy file, fake internal endpoint) with seed weights; generators
  provably cannot emit a functional secret; canaries kept **independent** (no
  chained-credential graph — IP caution, `ARCHITECTURE.md` §11).
- `seeder` — minefield + active placement; automated freshness/rotation;
  scope-aware. Baseline-informed negative-space placement once M7's baseline
  exists.
- **Exit:** the catalog and seeder produce real, harmless canaries and the
  metadata an adapter needs to observe interactions.

#### M6 — Sting: attrition  · 4–6 days · *the differentiator*
- `attrition` — tarpit (slow-drip) + bounded fake-structure generators (deep
  fake directory trees, recursive fake config, token-bait that triggers
  expensive parsing).
- Hard **budget per flow** + **global ceiling** + **kill switch**. Floors
  passive / moderate / aggressive; conservative default; aggressive only by
  explicit config.
- An "attacker cost" meter (bytes served, estimated tokens, wall-time wasted).
- **Exit:** an automated client gets stuck in bounded, endless, cheap-to-us
  deception; the cost meter climbs; defender cost stays flat. (Verified against
  the scripted attacker; the real-agent run is M9.)

### Track B — the kernel + proxy integration (AWS Linux)

#### M0 — Repo + dev infrastructure  · 1 day · *together*  ← in progress
- [x] `git init`, baseline commit, tooling cruft ignored.
- [x] Roadmap committed.
- [x] Private remote created and pushed (`github.com/henleda/canarysting`).
- [ ] `Makefile`: `build vet test proto bpf run-engine demo` targets.
- [ ] Flesh out `.github/workflows/ci.yml` — add a clang/eBPF build job (ubuntu).
- [ ] **Stand up the AWS dev box** (interactive): EC2 Ubuntu 24.04 with a BTF
  kernel, Go + clang/llvm + bpftool + libbpf; security group; SSM or SSH access.
  This is also the host for the persistent staged environment (M7).
- **Exit:** `make test` green locally; AWS box reachable and eBPF-capable;
  `go build ./...` on both.

#### M4 — Envoy adapter (real dataplane)  · 4–6 days
- Real `adapters/envoy` via ext_proc/ext_authz (inline) + dynamic-metadata
  (async); **socket-cookie stamping on every event**; per-tier fail behavior
  (fail-open T1, fail-closed T3).
- A small set of demo microservices behind Envoy, with canaries (M3) reachable
  in the traffic.
- **Exit:** a real HTTP attacker through real Envoy produces a real verdict, with
  the socket cookie carried end-to-end.

#### M5 — eBPF identity join + containment  · 5–8 days · *together* · *the CISO proof*
- `bpf/loader` (cilium/ebpf) + `bpf/enforce/enforce.bpf.c` — cgroup/TC hook,
  verdict map keyed by **socket cookie**, actions rate-limit / hard-deny / jail.
- The real identity join: socket cookie read at both the Envoy adapter and the
  kernel; Tier-3 jail of the exact flow; bystander on the same host unaffected.
- `sting/containment` drives the loader; refuses to act on unattributable flows.
- **Exit:** Tier 3 jails the attacker socket in-kernel on AWS; a bystander keeps
  working (the precision proof) — the moment that lands the CISO.

### Track C — the real environment + the visible product

#### M7 — Persistent staged environment: real baseline + calibration  · ongoing, started early
- Stand up the staged microservice environment as an **always-on** workload on
  the AWS host so it generates **genuine** east-west traffic continuously.
- Run **baseline mode** for a real, operator-set learning window so a real
  per-scope baseline accrues (no placeholder). This also exercises the
  observe-only pilot motion we sell.
- Accrue **real feedback labels** (via the analyst path) so calibrated mode and
  learned weights are genuinely reached before demo day.
- **Exit:** by demo time, the scope is genuinely calibrated and has a real
  baseline; the credibility panels show real state.
- **Note:** start this as early as the environment can run (after M4/M5 give it a
  real dataplane and kernel path) so the window has elapsed by demo day.

#### M8 — Product dashboard (Next.js, polished)  · 6–10 days · parallel once M1 emits data
- The product dashboard (the §1 screen): live scores, tier ladder, scope/
  calibration state, attacker-cost meter, guardrail + baseline panels. Highly
  polished — CISO-grade. **Separate from the corporate `canarysting-www`.**
- Backed only by real engine/environment data (no mock data).
- **Exit:** the screen tells the story end-to-end from real state.

#### M9 — Scenario + LLM attacker  · 4–7 days
- Scenario orchestration: one command stands up the staged attack.
- Scripted attacker for repeatability; then a **real LLM agent** harness that
  actually probes and burns tokens against the attrition — the why-now made
  visible (ties to the GTG-1002 narrative in the market report).
- **Exit:** the demo runs end-to-end with a real agent burning real tokens.

#### M10 — Package for design partners  · 2–4 days
- Scripted, repeatable demo; AWS deploy manifests in `deploy/`; a runbook; the
  **observe-only baseline pilot** framing as the leave-behind
  (`TECHNICAL_ARCHITECTURE.md` §4/§10).
- **Exit:** we can run the demo for a prospect and leave them in observe-only.

#### M11 — Kubernetes / EKS demo  · scoped after §8 research lands · *future*
- Port the staged demo to Kubernetes (likely EKS): eBPF as a privileged
  DaemonSet, the Envoy integration as mesh-native or sidecar, scope key from
  SPIFFE trust domain / cluster UID. Informed by the §8 research findings.
- **Exit:** the same demo runs on a real K8s cluster — the form most enterprise
  prospects actually run.

---

## 4. Sequencing and parallelism

- **Engine track (A)** is developed locally and unblocks everything: M1 → M2,
  M3, M6 in parallel after M1.
- **Integration track (B)** needs the AWS box (M0): M4 (Envoy) → M5 (eBPF join +
  containment). This is now on the critical path because the CISO demo requires
  the kernel proof.
- **M7** (real baseline/calibration) must start as early as the environment can
  run, because a real learning window takes real time — it is the long pole and
  cannot be compressed without faking data, which we've ruled out.
- **M8** (dashboard) starts as soon as M1 emits verdicts and runs in parallel.
- **M9** (LLM attacker) lands last in the core demo; **M10** packages; **M11**
  (K8s) follows the first demo.

```
local  ──► M1 ─┬─► M2
               ├─► M3 ─────────────┐
               └─► M6 ─────────────┤
AWS(M0)──► M4 ──► M5 ──────────────┼─► (env live) ─► M9 ─► M10 ─► M11(K8s)
                  M7  ◄── runs persistently from here, accruing REAL baseline/calibration
local  ──► M8 (dashboard, parallel) ───────────────┘
```

**The long pole is M7**, not engineering effort: a real baseline + real
calibration needs real elapsed time on a real environment. Standing up that
environment early (right after M4/M5) is the single most schedule-sensitive move,
precisely because we refuse to fake it.

---

## 5. How we build (discipline that keeps the demo honest)

- **Tests encode the invariants.** Each `CLAUDE.md` core rule gets a test that
  fails if violated — scope isolation, the guardrail (`base=0 ⇒ score=0`),
  refuse-to-start, fail-open/closed, attrition budget ceiling. The demo is only
  as trustworthy as these.
- **No mock data in the demo path.** Real baseline, real calibration, real
  socket-cookie join, real Envoy, real kernel enforcement. Fixtures are allowed
  in *unit tests*; they never appear on the demo screen.
- **Respect the seams.** The engine never imports an adapter or proxy SDK; the
  contract never imports outward.
- **Smallest change that satisfies the milestone.** No speculative generality.
- **Update docs with intent changes.** New learned parameter ⇒ documented
  uncalibrated default + feedback loop + evidence floor, here and in the layer
  doc.

---

## 6. Decisions

| # | Decision | Resolution (2026-06-03) |
|---|---|---|
| 1 | GitHub remote | **Resolved** — private repo `github.com/henleda/canarysting`; transfer to a `canarysting` org later. |
| 2 | Reference dataplane vs Envoy first | **Resolved** — real Envoy, no reference dataplane. |
| 3 | Front-end stack | **Resolved** — Next.js, highly polished, CISO-grade. |
| 4 | LLM-attacker | **Resolved** — scripted for dev loop, real LLM agent for the demo. |
| 5 | First-demo persona | **Resolved** — enterprise CISOs + infra teams; kernel enforcement is core to demo #1. |
| 6 | Demo data | **Resolved** — no placeholder/dummy data; real baseline + calibration from a persistent staged environment. |
| 7 | First-demo footprint | **Resolved** — single-host containers; K8s/EKS is a follow-on (M11). |
| 8 | AWS specifics | **Open** — account, region, instance type/size, access method (SSM vs SSH). Settled during M0. |

---

## 7. Kubernetes feasibility (research)

Research is underway (background) on whether the design — Envoy ext_proc + host
eBPF cgroup/TC enforcement keyed by the socket cookie + SPIFFE/cluster-UID scope
isolation — runs cleanly in Kubernetes/EKS, including: the socket-cookie join
across the pod/sidecar boundary, the eBPF DaemonSet + BTF requirements on EKS node
AMIs, coexistence with the CNI (Cilium / AWS VPC CNI), Istio ext_proc support and
ambient-mesh implications, and socket→pod→workload-identity attribution. Findings
and a recommended K8s approach will be folded in here and into M11 when the
research completes.

---

## 8. Status log

- **2026-06-03** — M0 in progress. Repo initialized; scaffold committed; roadmap
  added; private remote created and pushed. Design review completed and decisions
  1–7 locked (see §6). Roadmap restructured: kernel enforcement pulled into the
  core demo, reference dataplane dropped in favor of real Envoy, no-placeholder-
  data constraint adopted (persistent staged environment for real baseline +
  calibration, M7), Next.js dashboard, phased LLM attacker, single-host-first
  with a K8s follow-on (M11). Kubernetes feasibility research kicked off (§7).
  Next: Makefile + CI eBPF job + AWS dev box.
