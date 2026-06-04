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
touch triggers an automated, escalating, kernel-enforced response that imposes
asymmetric economic cost on an automated/LLM attacker — with low false positives
*by construction* (the guardrail), and learned state that never leaves the
customer's boundary (scope isolation).

We are optimizing for **time-to-a-credible-demo**, not feature completeness. Every
milestone is judged by how much of the demo narrative it makes real.

---

## 1. The demo narrative (what a prospect sees)

A single live screen, staged in a small AWS environment:

1. **The fabric.** A handful of microservices behind a proxy. Canaries seeded in
   the *negative space* of normal traffic (paths/ports/adjacencies legitimate
   flows never use), so a touch is almost certainly hostile.
2. **The attacker.** An automated client — first a script, then an actual LLM
   agent — performs recon and lateral movement.
3. **The escalation.** It brushes a canary → **Tier 0** (observe, score ticks).
   It keeps probing distinct canaries inside a tight window → **Tier 1** (tag) →
   **Tier 2** (contain + attrition begins). The suspicion score and tier ladder
   animate live.
4. **The sting (the wow).** At Tier 2 the attacker is tarpitted and fed an
   endless, plausible fake directory tree / fake secrets engineered to trigger
   expensive parsing. A meter shows **attacker time + tokens + compute burned**.
   The **defender's** cost stays flat — every generator is bounded.
5. **The precision.** **Tier 3** jails the exact offending socket in the kernel
   (by socket cookie). A legitimate bystander flow on the same host keeps
   working — proving we contain the flow, not the host.
6. **The credibility panels.**
   - *Guardrail:* a wildly abnormal flow that never touches a canary → **nothing
     happens** (deviation is not a trigger).
   - *Baseline:* the same single touch from an abnormal flow escalates ~2.6×
     faster (bounded multiplier sharpening a real signal).
   - *Scope/calibration:* per-scope calibrated/uncalibrated state, surfaced
     honestly.

That screen *is* the product. The milestones below build its pieces in
dependency order.

---

## 2. Environments

| Where | Runs on | What we build there |
|---|---|---|
| **Local** | this macOS/arm64 Mac | All pure-Go work: engine, baseline math, canary catalog, attrition userspace, the reference dataplane, all unit/integration tests. No kernel needed. |
| **AWS Linux** | EC2, Ubuntu 24.04, kernel ≥5.15 with BTF | eBPF loader + `enforce.bpf.c`, the real socket-cookie identity join, Envoy adapter, the staged scenario, the front-end/dashboard. |

**Hard constraint:** eBPF (CO-RE, cilium/ebpf) needs a recent Linux kernel with
BTF. It cannot be built or run on macOS. The three highest-value pieces (engine,
baseline, attrition) are platform-independent Go, so we start them locally now
and stand up AWS in parallel for the kernel + integration work.

---

## 3. Milestones

Estimates are rough engineering days for the two of us; they assume the
tests-as-deliverable discipline below.

### M0 — Repo + dev infrastructure  · ½–1 day · *together*
- [x] `git init`, baseline commit of the scaffold, tooling cruft ignored.
- [x] This roadmap committed.
- [ ] Decide and create the remote (private GitHub repo under a `canarysting` org).
- [ ] `Makefile`: `build vet test proto bpf run-engine demo` targets.
- [ ] Flesh out `.github/workflows/ci.yml` — add a clang/eBPF build job (ubuntu).
- [ ] **Stand up the AWS dev box** (interactive): EC2 Ubuntu 24.04, BTF kernel,
  Go + clang/llvm + bpftool + libbpf; security group; SSM or SSH access.
- **Exit:** `make test` green locally; AWS box reachable; `go build ./...` on both.

### M1 — Engine core (pure Go, local)  · 2–4 days
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
- **Tests are a deliverable, not an afterthought:** 0→1→2→3 escalation; scope A
  never affects scope B; cold-start raw-count behavior; refuse-to-start on
  unresolved scope; fail-open T1 / fail-closed T3.
- **Exit:** a flow's signals drive a real verdict end-to-end; every core
  invariant has a test that fails if the invariant is violated.

### M2 — Baseline multiplier (pure Go, local)  · 1–2 days
- Implement `M(d)` exactly per `BASELINE_MULTIPLIER.md`: per-feature caps →
  bounded `d` → saturating `g(d)` → `M ∈ [1, M_max]`; `Score = base × M`.
- Force `M = 1.0` when uncalibrated / stale / time-bucket-sparse.
- Property tests: `M ≥ 1` always; `base = 0 ⇒ Score = 0`; the four worked
  examples in §5 of the spec.
- **Exit:** the guardrail is arithmetic and proven by test; baseline sharpens a
  real touch and can never manufacture one.

### M3 — Canary layer + reference dataplane (pure Go, local)  · 2–4 days
- `catalog` — initial canary types (fake secret, fake bucket listing, planted
  credential, decoy file, fake internal endpoint) with seed weights; generators
  provably cannot emit a functional secret; canaries kept **independent** (no
  chained-credential graph — IP caution, `ARCHITECTURE.md` §11).
- `seeder` — minefield + active placement; automated freshness/rotation;
  scope-aware.
- **Reference dataplane (demo harness):** a thin Go reverse proxy + service set
  that hosts canaries, observes interactions, stamps a flow identity, and emits
  `SignalEvent`s on the contract. This is the fast path to *real signals* without
  standing up Envoy first. (See decision #2.)
- **Exit:** a real HTTP attacker touching a canary produces a real verdict
  through the engine.

### M4 — Sting: attrition (pure Go, local)  · 3–5 days · *the differentiator*
- `attrition` — tarpit (slow-drip) + bounded fake-structure generators (deep
  fake directory trees, recursive fake config, token-bait that triggers
  expensive parsing).
- Hard **budget per flow** + **global ceiling** + **kill switch**. Floors
  passive / moderate / aggressive; conservative default; aggressive only by
  explicit config.
- An "attacker cost" meter (bytes served, estimated tokens, wall-time wasted) —
  the demo's centerpiece.
- **Exit:** an automated client gets stuck in bounded, endless, cheap-to-us
  deception; the cost meter climbs; defender cost stays flat.

### M5 — eBPF containment (AWS Linux)  · 4–7 days · *together*
- `bpf/loader` (cilium/ebpf) + `bpf/enforce/enforce.bpf.c` — cgroup/TC hook,
  verdict map keyed by **socket cookie**, actions rate-limit / hard-deny / jail.
- The real identity join: socket cookie read at both the dataplane and the
  kernel; Tier-3 jail of the exact flow; bystander on the same host unaffected.
- `sting/containment` drives the loader; refuses to act on unattributable flows.
- **Exit:** Tier 3 jails the attacker socket in-kernel on AWS; a bystander keeps
  working (the precision proof).

### M6 — Envoy adapter (AWS Linux)  · 3–5 days
- Real `adapters/envoy` via ext_proc/ext_authz (inline) + dynamic-metadata
  (async); socket-cookie stamping; per-tier fail behavior.
- Swap the reference dataplane for Envoy with **zero engine changes** — this is
  the live proof of proxy-agnosticism (`CLAUDE.md` rule #2).
- **Exit:** the demo runs on real Envoy.

### M7 — Demo front-end + scenario (parallel once M1 emits data)  · 4–7 days
- The product dashboard (the §1 screen): live scores, tier ladder, scope/
  calibration state, attacker-cost meter, guardrail + baseline panels. **This is
  the product's own front-end — separate from the corporate `canarysting-www`
  property.**
- Scenario orchestration + an LLM-attacker harness (an agent that actually probes
  and burns tokens — the why-now, made visible).
- **Exit:** one command stands up the staged scenario; the screen tells the
  story end-to-end.

### M8 — Package for design partners  · 2–3 days
- Scripted, repeatable demo; AWS deploy manifests in `deploy/`; a runbook; and
  the **observe-only baseline pilot** framing ("run us for two weeks, here's what
  we found, you choose what to turn on" — `TECHNICAL_ARCHITECTURE.md` §4/§10).
- **Exit:** we can run the demo for a prospect and leave them in observe-only.

---

## 4. Sequencing and parallelism

- **Critical path to a *compelling* demo:** M0 → M1 → M3 → M4 → M7. That alone
  demonstrates the unoccupied differentiator (economic attrition) without any
  kernel work.
- **M2 (baseline) and M5 (eBPF containment)** are the technical-credibility
  beats — "kernel-enforced, precise, low-FP by construction." Add them next.
- **M6 (Envoy)** hardens the demo to production-real.
- **M7 (front-end)** can begin as soon as M1 emits verdicts and run in parallel
  with M4/M5.

```
local  ──► M1 ──► M2
            │      │
            └► M3 ─┴► M4 ─────────────► M7 ─► M8
AWS    ──► (M0 box) ──► M5 ──► M6 ─────┘
```

---

## 5. How we build (discipline that keeps the demo honest)

- **Tests encode the invariants.** Each `CLAUDE.md` core rule gets a test that
  fails if violated — scope isolation, the guardrail (`base=0 ⇒ score=0`),
  refuse-to-start, fail-open/closed, attrition budget ceiling. The demo is only
  as trustworthy as these.
- **Respect the seams.** The engine never imports an adapter or proxy SDK; the
  contract never imports outward. The reference dataplane talks only to the
  contract, exactly like a real adapter.
- **Smallest change that satisfies the milestone.** No speculative generality.
- **Update docs with intent changes.** New learned parameter ⇒ documented
  uncalibrated default + feedback loop + evidence floor, here and in the layer
  doc.

---

## 6. Open decisions (need a call before or during M0)

1. **Remote.** GitHub org/name, private. (Proposed: private repo under a
   `canarysting` org.)
2. **Reference dataplane first, or Envoy first?** Recommended: reference
   dataplane first (fastest to a real signal; keeps the engine honest), Envoy as
   M6. The alternative is more upfront integration cost before anything demos.
3. **Front-end stack** for the product dashboard: Next.js (matches the house
   style of `canarysting-www`, reusable by the future team) vs. a lighter
   Go-served dashboard (fewer moving parts for the demo).
4. **LLM-attacker:** a scripted client (deterministic, simple) vs. a real
   agent harness (maximum why-now impact, more setup). Could do scripted for M4
   and a real agent for M7.
5. **AWS specifics:** account, region, instance type/size, access method (SSM vs
   SSH), and how I connect to drive the box with you.

---

## 7. Status log

- **2026-06-03** — M0 started. Repo initialized; scaffold committed as baseline;
  this roadmap added. Next: remote + Makefile + CI + AWS dev box.
