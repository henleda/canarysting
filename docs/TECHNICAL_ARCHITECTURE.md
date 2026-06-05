# docs/TECHNICAL_ARCHITECTURE.md — CanarySting Technical Architecture & Differentiated Technology

Read `CLAUDE.md` first. This is the deep technical architecture document. It explains the full system, the technology that makes CanarySting defensible, and the baseline-learning capability that sharpens the engine. For layer-level build rules, see the companion docs: `ENGINE.md`, `CANARY.md`, `STING.md`, `SCOPE.md`, `IDENTITY.md`, `ADAPTERS.md`. Where this document and a layer doc overlap, this document explains the why and the layer doc governs the how.

---

## 1. The differentiated technology, stated plainly

Most of the deception market stops at detection. A decoy gets touched, an alert fires, and a human decides what to do inside a window that is now measured in minutes. CanarySting is built around three technical bets that, taken together, are hard to copy and address that gap directly.

1. **Proxy-attached deployment.** We attach at the proxy (Envoy and nginx first) instead of shipping endpoint agents or network appliances. This removes the deployment friction that held the deception category back, and it puts us on the path that real east-west traffic already takes.

2. **Kernel-coupled enforcement.** We close the loop from decoy interaction to action in the kernel using eBPF, attributed to the exact offending flow. Detection and response live in the same system, so response does not wait for a human.

3. **Aggressive economic attrition.** Beyond containment, we impose real cost on automated and AI-driven attackers by making them burn time, compute, and tokens against deception engineered to be expensive to process. This is the offensive-economic edge, and it is the part of the product that is genuinely new.

This document adds a fourth piece of differentiated technology that strengthens the first three rather than standing apart from them: **a baseline-learning phase, built on eBPF, that observes east-west traffic before any enforcement is turned on, and then uses what it learns to make detection sharper and deployment safer.**

The moat is not any single one of these. The attrition idea on its own is not protectable, and eBPF is available to everyone. The defensibility is the integration: proxy signal plus kernel enforcement plus a learned, per-deployment model of normal traffic plus economic attrition, all keyed to a single flow identity and isolated per scope. Copying one layer is easy. Reproducing the whole loop, tuned and safe, is the hard part.

---

## 2. The observation substrate: eBPF

eBPF is the technology that lets us watch the east-west fabric cheaply and precisely, at the kernel, without sitting inline on every connection.

### 2.1 Why the kernel, and why not just the proxy

The proxy adapters see L7 traffic that passes through the proxy. That is rich (mTLS identity, headers, request semantics) but partial. It does not see the full east-west fabric, and it cannot enforce after a flow has been released.

eBPF programs attached at the TC and cgroup hooks see the actual traffic between workloads: the connection five-tuple, byte and packet counts, connection lifecycle, and the kernel-side identity of each flow. They observe everything on the host, not only what the proxy proxied. And they can act on a flow at the kernel after the proxy has let it go, which is what makes asynchronous enforcement possible.

So the two observation points are complementary. The proxy supplies L7 meaning. eBPF supplies complete, low-level flow truth and the ability to enforce. CanarySting uses both.

### 2.2 Low overhead is a requirement, not a nice-to-have

A security control that taxes the workloads it protects will be turned off. The eBPF observation path must run continuously at a small, predictable cost (single-digit percent CPU, modest memory), the way a well-built continuous profiler does. Sampling and aggregation happen in kernel space where possible, and only summarized flow records cross into user space. The baseline learning described in Section 4 rides on this same cheap observation path, so learning does not add a second, heavier pipeline.

### 2.3 The identity join is the load-bearing primitive

Everything downstream depends on one fact: the same flow can be recognized at both the L7 layer and the kernel layer. The **socket cookie** is that join key. Both a proxy adapter and an eBPF program at the cgroup or TC hook can read the socket cookie for the same connection. This is what lets an L7-derived verdict enforce precisely in the kernel, and it is why containment can target the offending flow rather than guessing from logs and risking a jailed bystander. See `IDENTITY.md` for the rules. No second join mechanism is permitted.

---

## 3. System shape, in brief

Three layers, with the proxies kept thin and the engine kept proxy-agnostic. Full detail is in the layer docs; this is the map.

- **Canary layer** generates decoys, places them within reach of east-west traffic, and emits a signal event whenever a flow interacts with one. It carries no scoring logic. See `CANARY.md`.
- **Decision engine** ingests signals, scores intent, decides a response tier, calibrates from analyst feedback, and isolates all learned state per scope. It talks only to the contract, never to a proxy. See `ENGINE.md`.
- **Sting layer** acts on the engine's verdict: containment in the kernel and attrition that imposes economic cost. Attributed by socket cookie. See `STING.md`.

The contract between layers is simple and stable: a flow identity plus a signal event in, a verdict out. The baseline capability described next plugs into this shape without changing that contract.

---

## 4. Baseline mode: learn before you enforce

Baseline mode is a first-class operating mode, not a background feature. When CanarySting first attaches to a proxy fleet in a scope, it does nothing punitive. It watches, using the eBPF substrate, and builds a per-scope model of what normal east-west behavior looks like. Only after the operator reviews what was learned, and chooses to, does enforcement turn on.

### 4.1 Why a learning phase exists

Three reasons, in order of importance.

**It de-risks deployment.** The single biggest reason deception and active-defense tools failed to reach broad adoption is fear of blocking legitimate traffic. A control that can jail an east-west flow has to earn trust before it is allowed to act. Baseline mode is how it earns that trust: it shows the operator what it sees before it is permitted to do anything about it.

**It is the natural sales and onboarding motion.** "Run us in observe-only for two weeks, here is what we found, now you decide what to turn on" is exactly the design-partner pilot. Baseline mode is that pilot, made into a product capability.

**It makes the engine sharper.** This is the technical payoff, covered in 4.4 and 4.5. A model of normal traffic lets the engine auto-derive which flows are benign and lets the canary layer place decoys where they will be most diagnostic and least likely to be touched by accident.

### 4.2 What the baseline captures

During the learning window the eBPF path records summarized flow features per scope. The baseline is a statistical model of these, not a packet log. Representative features:

- Which workloads talk to which (the east-west adjacency graph), keyed by cgroup and, where available, workload identity.
- Ports, protocols, and the direction of initiation for each adjacency.
- Cadence and volume: how often a pair of workloads communicates, and the typical byte and packet envelope.
- Connection lifecycle norms: durations, churn, and connection counts.
- Identity context from the proxy where the flow is L7-visible (for example the SPIFFE identity initiating a connection), joined to the kernel flow by socket cookie.

The baseline is a profile of the negative space as much as the positive space. Knowing which paths carry no legitimate traffic at all is as useful as knowing which paths are busy, and Section 4.5 explains why.

### 4.3 The learning lifecycle, and the evidence floor

The baseline follows the same lifecycle as every other learned parameter in the engine, which keeps the whole system predictable. See `ENGINE.md` for the general pattern.

- **Uncalibrated (cold start).** At first attach, there is no baseline. The engine runs on documented defaults, and canary scoring uses uniform weights (raw count of distinct touches). Nothing about the baseline is trusted yet.
- **Learning window.** The eBPF path accumulates flow features. The operator sets the window length; a few weeks is typical, long enough to capture weekly cycles such as batch jobs, backups, and scheduled tasks.
- **Calibrated.** Once enough evidence accrues to cross the floor, the baseline is considered usable. The engine surfaces this state to the operator. The same evidence floor gates every learned parameter, so the baseline does not go live while canary weights are still cold, or vice versa.

The window length and the evidence floor are inputs the operator and the engine expose, not hidden constants. A scope that has not gathered enough traffic stays uncalibrated and says so. This matters most for operators who carve many small trust zones, since each one learns independently and some may never reach the floor. See `SCOPE.md`.

### 4.4 Baseline auto-derives the benign-exclusion set

The engine already treats a benign-exclusion input as first-class: service accounts, monitoring systems, and scheduled tasks are the most likely benign flows to brush a canary, and they should be held to a higher bar or excluded from scoring. Without a baseline, that list is hand-maintained, which is tedious and goes stale.

The baseline derives it automatically. Flows that are present, periodic, and stable throughout the learning window are, by construction, the benign east-west fabric. The engine can propose them as the exclusion set for the operator to confirm, rather than asking the operator to enumerate them from memory. This is a direct, concrete way the eBPF baseline improves the model: it replaces a manual input with a learned one, per scope, and keeps it current as the environment changes.

The exclusion set adjusts scoring. It does not, by itself, ever trigger a sting. See the guardrail in Section 5.

### 4.5 Baseline informs canary placement: bait in the negative space

A blind minefield seeds canaries arbitrarily. A baseline-informed minefield seeds them where they are most diagnostic and least likely to be touched by accident.

The key idea is placement in the negative space of normal traffic. If the baseline shows that no legitimate flow ever traverses a given path, a port, or a workload adjacency, then a canary placed there has an extremely low false-positive rate by construction. A touch on that canary is almost certainly not benign, because benign traffic never goes there. The baseline tells the canary seeder exactly where those low-traffic and zero-traffic regions are.

This couples two of the layers through the baseline. The eBPF observation finds the negative space, the canary seeder places bait there, and the result is a decoy whose interaction signal is even cleaner than a generic canary. The seeder also uses the baseline to place decoys near the workloads and paths that an attacker performing lateral movement would plausibly probe, so the bait sits where it is both tempting to an attacker and avoided by legitimate traffic. See `CANARY.md` for seeder rules.

### 4.6 Baseline feeds scoring as weight context

When a canary is touched, the engine scores the interaction. The baseline enters here as context that shapes the weight of that touch, not as a separate signal.

Concretely, a canary touch from a flow that also looks abnormal against the baseline (an adjacency that never existed before, an identity that has never initiated this kind of connection, a volume far outside the envelope) is more suspicious than the same touch from a flow that otherwise looks like the established fabric. The baseline lets the engine say "this touch came from something that does not belong here" and weight it up, escalating it through the tiers faster. A touch from a flow that resembles normal still counts, because the touch itself is the signal, but it may escalate more cautiously.

This is the precise sense in which the baseline makes the model better: it adds context that sharpens how a real signal is weighted. It never manufactures a signal on its own. That boundary is the subject of the next section, and it is not negotiable.

---

## 5. The guardrail: deviation from normal is not the sting trigger

This is the most important rule in the document. Read it carefully and do not weaken it.

**The canary touch is the trigger. The baseline is weight context. Deviation from normal, on its own, never triggers a sting.**

### 5.1 The rule, stated exactly

- A sting, of any kind, containment or attrition, is only ever evaluated because a flow interacted with a canary. The interaction is the entry condition for the whole response pipeline.
- The baseline adjusts the suspicion score and informs placement and exclusion. It can make a real canary touch escalate faster or slower. It can move bait to better ground. It can mark a flow as part of the benign fabric.
- The baseline can never, by itself, cause a flow to be tagged, contained, tarpitted, or attrited. A flow that merely looks unusual against the baseline, and that has not touched a canary, is left alone.

If an engineer ever finds themselves writing code where "this flow deviates from baseline" is sufficient to take a punitive action, that is a bug, and it is the specific bug this section exists to prevent.

### 5.2 Why the asymmetry is correct, not arbitrary

A canary has no legitimate reason to be touched. We place it precisely so that nothing benign should ever interact with it, and Section 4.5 makes that even more true by putting it in the negative space of normal traffic. So a canary touch is a near-zero-false-positive signal of intent. Someone is poking at something that exists only to be poked at by an intruder.

Deviation from normal is a completely different kind of signal. Normal traffic deviates for many innocent reasons: a new service ships, a backup runs late, a batch job moves, an engineer runs a one-off, a workload scales, a dependency changes. Treating deviation as guilt is how anomaly-detection products generate the false-positive floods that bury SOC teams and that we are positioning against. Deviation is correlated with interesting, not with malicious.

The two signals are not equivalent and must not be treated as equivalent. One is intent. The other is novelty. We act on intent and we use novelty only to weight it.

### 5.3 The anomaly-detection trap, named

A learned model of normal is an anomaly detector. Anomaly detection in security has two well-known failure modes, both of which our own cold-start research calls out, and both of which the guardrail avoids.

**Poisoned baseline.** If an attacker is already present and active during the learning window, their activity is learned as normal. An anomaly detector would then never flag them. Under our design this is far less damaging, because the attacker still has to touch a canary to be acted on, and the canary does not care what the baseline learned. The worst a poisoned baseline can do is fail to weight a real canary touch upward. It can never suppress the touch itself as a trigger, and it can never the other direction either.

**Benign novelty.** Legitimate but rare or new behavior looks anomalous. An anomaly detector fires on it. Under our design nothing happens, because no canary was touched. The novel-but-benign flow is simply context the engine may note, not a target.

By keeping the canary touch as the sole trigger, we get the placement and weighting benefits of a learned baseline while structurally avoiding the false-positive behavior that makes pure anomaly detection unsafe to enforce on. The baseline is allowed to be wrong, because being wrong only costs us some weighting precision, never a wrongful sting.

### 5.4 What fires, and what shapes

A compact way to hold the rule:

- **Fires the pipeline:** a canary interaction, attributed to a flow by socket cookie.
- **Shapes the response:** the baseline (weight context), the per-scope canary weights, the strictness setting, the tier thresholds, the benign-exclusion set.
- **Never fires anything on its own:** baseline deviation, novelty, volume changes, new adjacencies, unfamiliar identities.

Containment and attrition both sit behind the same entry condition. There is no path to a sting that does not begin with a canary touch.

---

## 6. Scoring with baseline context

Putting Sections 4 and 5 together, here is how a single event flows through the engine.

1. A flow touches a canary. The canary layer emits a signal event carrying the canary type, the flow identity including the socket cookie, the scope, and a timestamp.
2. The engine confirms the event belongs to a scope and computes the suspicion score for that flow within that scope. The score is the windowed, weighted sum of distinct canary interactions. Weights start uniform and are learned per scope from analyst feedback. See `ENGINE.md`.
3. The baseline enters as weight context. If the flow looks abnormal against the scope baseline, the engine weights the touch upward, so the score crosses tier thresholds sooner. If the flow looks like the established fabric, the touch is scored without that boost. The benign-exclusion set, derived from the baseline, may hold a known-benign flow to a higher bar. The exact mechanism is a bounded, floored, multiplicative weight multiplier, specified in full in `BASELINE_MULTIPLIER.md`. In short: score = base (from the touch) times a multiplier in the range one to a small cap, so a normal touch scores its raw base, an abnormal touch escalates faster, and no touch scores zero regardless of deviation.
4. The score maps to a tier (0 through 3) under the operator's per-tier strictness setting. Tiers 0 and 1 are asynchronous and take no blocking action. Tiers 2 and 3 may contain or attrit, inline or asynchronously per configuration, fail-open at tier 1 and fail-closed at tier 3.
5. The verdict, carrying the flow identity and tier, goes to the sting layer, which acts in the kernel attributed by socket cookie.

At no point does step 3 become step 1. The baseline only ever participates once a touch has already occurred.

---

## 7. Scope isolation applies to the baseline too

The baseline is per-scope learned state, and it obeys every isolation rule that governs the rest of the engine. See `SCOPE.md`.

- A baseline learned in one scope describes that scope's normal and is never applied to another. A different cluster or trust zone has a different fabric, and importing one baseline into another would be both wrong and a cross-boundary leak.
- The baseline is keyed by the same scope key that keys canary weights, calibration status, and feedback labels. There is no separate sharding.
- Each scope cold-starts its own baseline. There is no borrowing a head start from a mature scope. The bootstrap path (no baseline, uniform weights, documented defaults) is the only way into a fresh scope.
- The baseline never aggregates upward across deployments. The only shared artifact in the whole system remains the static seed prior, which carries no environment-specific information.

This is what lets CanarySting promise a customer that their traffic structure, which a baseline necessarily encodes, never leaves their boundary.

---

## 8. The sting differentiation, at the technical level

Detection is table stakes. The sting is where the product imposes cost, and the attrition half is the part that is genuinely new. See `STING.md` for the build rules. The technical points worth stating here:

- **Containment** stops egress and holds the actor: rate-limit, hard deny, jail the socket or cgroup, all enforced in the kernel. It is the defensive half, fail-closed at the high-confidence tier, and it acts only on flows it can attribute precisely.
- **Attrition** imposes economic cost: tarpitting, serving plausible but endless fake resources, deep recursive fake structures, and bait crafted to trigger expensive parsing. Against a human this is an annoyance. Against a scripted or LLM-driven attacker it is a direct hit to a metered compute and token budget, which is why the timing of this product matters now in a way it did not when attacks were human-driven.
- **Attrition can begin earlier than containment** because the cost of attrition-stinging a false positive is small (a slightly slower response to one flow) while the cost of containment-stinging a false positive is severe (a jailed legitimate flow). This is why attrition can start at tier 2 and containment hard actions wait for tier 3.
- **Aggressive by brand, elective by deployment.** The platform ships the aggressive ceiling. The operator chooses the floor: passive, moderate, or full adversarial. The default is conservative, and the aggressive level is reached only by explicit configuration. The sting must also bound its own resource use, so that attrition burns the attacker's compute and never the defender's.
- **Attrition is not hack-back.** It imposes cost on traffic that is already inside the perimeter and is touching things it never should. It does not reach outward into an attacker's own systems.

Every sting action, containment or attrition, sits behind the canary-touch entry condition from Section 5. The baseline shapes how quickly a confirmed intruder escalates into the sting, never whether an unconfirmed flow gets stung.

---

## 9. Why this is hard to copy

The defensibility is layered, and each layer raises the cost of reproduction.

- **The integration, not the parts.** Honeytokens exist. eBPF exists. Tarpits exist. Anomaly detection exists. No competitor combines proxy-attached deception, kernel-coupled enforcement keyed to a single flow identity, a per-deployment learned baseline used as weight context, and aggressive economic attrition, as one safe and tuned loop.
- **The identity join.** Making an L7 verdict enforce precisely in the kernel, via the socket cookie, so that the right flow is jailed and not a bystander, is fiddly engineering that has to be correct or the product is dangerous. Getting it right is a barrier.
- **The safety model.** The guardrail in Section 5, keeping the baseline as weight context and the canary touch as the sole trigger, is what lets us enforce automatically without the false-positive behavior that sank prior active-defense tools. That design judgment is part of the moat.
- **The economic-attrition catalog.** Building fake structures that maximize an automated attacker's token and compute spend, while bounding the defender's own cost, is novel work with little prior art aimed at internal lateral movement. The web-edge tarpits that exist target crawlers, not east-west AI agents.
- **Per-scope isolation as a property.** The promise that learned state, including the baseline that encodes a customer's traffic structure, never crosses a trust boundary is both a technical design and a trust asset that a fast follower cannot bolt on after the fact.
- **The compounding intelligence asset.** The integration above is the wedge; what compounds is the proprietary adversary intelligence the wedge produces. We observe real attackers making real lateral-movement decisions against deception, in production, attributed to a flow — a vantage point no perimeter, endpoint, or honeypot tool has. Each deployment sharpens the intelligence, which improves detection and the bait model, which wins more deployments. That loop, built without ever moving raw data across a trust boundary, is the durable moat. See `docs/INTELLIGENCE.md`.

---

## 10. The operator lifecycle, end to end

The differentiated technology shows up as a clean operator experience:

1. **Attach** CanarySting to an existing Envoy or nginx fleet. No agents, no appliances.
2. **Baseline** runs in observe-only mode. eBPF learns the scope's east-west fabric. Nothing is blocked. The operator sees what we see.
3. **Review and seed.** The engine proposes the benign-exclusion set and the canary placement, both informed by the baseline. The operator confirms.
4. **Tag.** Enforcement turns on at the low tiers first. Canary touches are scored, with baseline weighting, and suspicious flows are tagged and fed richer decoys. Still no blocking.
5. **Contain and attrit.** At higher confidence and tiers, the sting acts in the kernel, at the floor the operator chose. Attrition imposes cost; containment stops exfiltration.
6. **Calibrate.** Analyst feedback on tier 2 and 3 actions tunes the canary weights and the strictness over time, per scope.

Throughout, the canary touch is the only thing that ever triggers a response, and the baseline only ever sharpens how that response is weighted and placed.

---

## 11. Open items to specify during implementation

- The concrete eBPF flow-feature schema for the baseline, and the in-kernel aggregation that keeps overhead low.
- The statistical representation of the baseline (how "abnormal versus baseline" is quantified) and how that quantity maps to a bounded weight multiplier on a canary touch — **now specified in full in `BASELINE_MULTIPLIER.md`** (bounded, floored-at-one, saturating, multiplicative). The remaining work there is empirical tuning of the defaults, not design.
- The default learning-window length and the evidence floor values, derived from the same published base rates that seed the other cold-start defaults.
- The operator review surface for the proposed benign-exclusion set and canary placement.
- Bounds and a kill switch on attrition resource use, so the sting cannot exhaust the host.
- The freedom-to-operate review noted in `ARCHITECTURE.md`, kept current as the baseline and attrition mechanisms are detailed.
