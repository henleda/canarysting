# CanarySting

**Company:** CanarySting.ai
**Product:** CanarySting, a proxy-attached deception and active-response platform
**Document:** Architecture and product definition
**Status:** Working draft

---

## 1. What CanarySting is

CanarySting is a deception and active-response platform that attaches to a network proxy. It places harmless decoy resources within reach of east-west traffic, watches how traffic interacts with those decoys, and then acts on traffic that behaves like an attacker. Action ranges from quiet containment to aggressive economic attrition designed to make automated and LLM-driven attackers burn time, compute, and tokens against deception that produces nothing of value.

The product has two named components.

**Canary** is the detection surface. It generates and places decoy objects (fake secrets, buckets, credentials, files, endpoints), seeds them where east-west traffic can reach them, and observes every interaction. Canary answers one question: who is touching things they should never touch, and how.

**Sting** is the response. It takes the verdict produced from canary interaction and acts. Sting spans blocking, rate-limiting, tarpitting, token-wasting, and adversarial time-wasting. Sting is where CanarySting stops being a detector and becomes a control that imposes cost on the attacker.

The core thesis: detection alone is a commodity, and containment alone is defensive. The differentiated value is the ability to impose asymmetric economic cost on automated attackers. Against a human that is a delay. Against a script or an LLM agent it is a direct hit to the attacker's operating budget.

---

## 2. Why this is a category product, not a feature

CanarySting is built proxy-agnostic from day one. The first two integrations are Envoy and nginx, the two proxies that carry the largest share of real east-west and north-south traffic. The platform treats each proxy as a thin adapter and keeps all detection and decision logic in a separate engine behind a stable contract. This is a deliberate architectural bet: the product is a deception-and-response category platform that integrates many dataplanes over time, not an accessory to any single proxy or vendor.

The buyer is the CISO, and in many organizations the application teams and the SecOps team are co-buyers or the day-to-day operators. The CISO buys the outcome: earlier breach detection with low false positives, plus an active response that reduces dwell time and raises attacker cost. App teams and SecOps own the deployment and tuning.

---

## 3. The two-mode detection model

CanarySting runs two complementary detection modes against the same decision engine.

**Active deception (targeted).** The proxy classifies a flow as suspicious based on signals and tags it. Once tagged, the flow is selectively exposed to a richer canary surface to confirm intent. This is depth-first: it concentrates deception on flows that already look wrong.

**Minefield (passive).** Canaries are seeded broadly across the environment. Any flow may encounter them. A single interaction is a weak signal. A flow that keeps interacting with canaries, especially across distinct canaries, is a strengthening signal that feeds the decision engine. This is breadth-first: it covers the whole environment and lets attacker behavior surface itself.

The two modes are complementary, not alternatives. The minefield provides broad passive coverage. Active deception provides targeted depth on flows worth confirming. Both feed one engine and one scoring model.

---

## 4. Escalating response: the four tiers

Response escalates with confidence. Each tier carries its own cost-of-error profile, which is why the strictness required to enter a tier rises as the action gets more aggressive.

**Tier 0 — Observe.** A flow touched a canary. Log, attribute, raise a suspicion score. No action. This tier absorbs the benign case where legitimate traffic brushes a canary path.

**Tier 1 — Tag and deceive.** Score crosses a threshold, or active mode flags intent. The proxy marks the flow suspicious and begins feeding it richer canary surface to confirm. Still no blocking. This tier gathers corroboration.

**Tier 2 — Contain (and begin attrition).** Repeated or higher-confidence canary interaction. The kernel enforcement layer restricts egress for the offending socket or cgroup using rate-limiting or tarpitting rather than a hard drop, so the actor stays unaware. Attrition sting can begin here, because wasting a suspicious flow's time is low-risk even at moderate confidence.

**Tier 3 — Jail or adversarial.** Confirmed malicious. Hard egress deny, redirect into an isolated environment, or full adversarial attrition. Whether the action stays covert or goes loud is an operator policy choice.

Tier thresholds are data-driven from the suspicion score, not hardcoded, so operators tune sensitivity without redeploying.

---

## 5. The Sting taxonomy: containment vs attrition

Sting splits into two intents that share mechanisms but differ in purpose.

**Containment sting.** Goal: stop egress and hold the actor. Mechanisms: rate-limiting, hard egress deny, jailing the socket or cgroup. Purpose: defensive, prevent exfiltration and lateral progress. This is the fail-closed, high-confidence Tier 3 work, enforced in the kernel.

**Attrition sting.** Goal: impose cost. Mechanisms: tarpitting, adversarial slow responses, and plausible-but-endless fake resources engineered to make an automated or LLM-driven attacker burn time, compute, and tokens chasing nothing. Purpose: economic, raise the attacker's cost per operation. Attrition can begin at Tier 2 because the cost of attrition-stinging a false positive is small (a slightly slower response to one legitimate flow), whereas containment-stinging a false positive is severe (jailed real traffic).

Attrition is the competitive differentiator and ships aggressive-capable from day one. Operators may dial it down to passive (slow responses only) or moderate (serve plausible fake resources that keep a crawler looping), but the platform sells the aggressive ceiling: responses crafted to maximize an LLM agent's token consumption through deep fake directory trees, recursive fake structures, and bait that triggers expensive parsing. Against scripted and model-driven attackers, this is a direct cost imposed on the adversary's compute budget.

| Sting type | Goal | Mechanisms | Earliest tier | Error cost |
|---|---|---|---|---|
| Containment | Stop egress, hold actor | Rate-limit, hard deny, jail socket/cgroup | Tier 2 (limit), Tier 3 (deny/jail) | High |
| Attrition | Impose economic cost | Tarpit, adversarial responses, token-burning fake resources | Tier 2 | Low |

---

## 6. The decision engine

The engine is a policy surface, not a fixed pipeline. Detection and the trapping decision live here, separate from any proxy. The contract is simple: a flow identity plus a signal event in, a verdict out. Each proxy is an adapter to this contract.

### 6.1 The strictness control

Operators set a single per-tier strictness value from 0.01 (permissive, more false positives accepted) to 1.00 (strict, minimal false positives). Named `confidence_required` rather than "tolerance" so the number's direction matches its meaning.

The control expresses a target false-positive rate, which is what operators actually want, and the engine calibrates its internal thresholds to hold the observed rate at or below the setting. This requires a feedback signal to measure against. The engine is explicit about its state: in **calibrated mode** it honors the target using learned thresholds; in **uncalibrated mode** it falls back to a documented static threshold map derived from published base rates, and surfaces that it is uncalibrated rather than implying a guarantee it cannot keep.

Strictness is per-tier, not global. A baseline value carries a tier multiplier so a Tier 0-to-1 transition tolerates more false positives than a Tier 2-to-3 transition. This also makes low tiers cheaply reversible and high tiers strict by construction.

### 6.2 Inline vs asynchronous scoring

How the engine sits relative to the dataplane is configurable, and the modes are different operating contracts, not interchangeable per flow.

- **Tier 0 and 1: asynchronous only.** These tiers block nothing, so the engine is never on the hot path just to observe and tag. No added latency for the high-volume cheap transitions.
- **Tier 2 and 3: operator-chosen inline or async.** This is where the latency-versus-detection-gap tradeoff actually matters.

**Inline** holds the request for a verdict (Envoy ext_proc/ext_authz blocking, nginx auth subrequest). Cost: per-flow latency and a hard liveness dependency on the engine. **Async** emits the signal and proceeds; enforcement applies to subsequent packets via the kernel layer. Cost: a detection-to-enforcement gap where the first requests of a malicious flow complete before containment lands.

A coupling to document explicitly: inline can enforce at the proxy or the kernel; **async must enforce at the kernel**, because the proxy already released the flow. The kernel enforcement layer is what makes async viable.

### 6.3 Fail-open vs fail-closed

For inline mode, behavior on engine timeout or outage is an explicit per-tier setting, not an accident of timeout handling.

- **Tier 1: fail-open.** An engine problem must not block legitimate traffic at a low-confidence tier.
- **Tier 3: fail-closed.** A confirmed-malicious tier must not let an actor through because the engine is degraded. This also denies an attacker the strategy of degrading the engine to escape containment.

### 6.4 The feedback loop

The strictness calibration requires ground truth, and it is per-deployment and never available in advance. The product ships the loop that collects it, not the data. An analyst marks a Tier 2 or 3 action as correct or wrong; that label calibrates the engine in place. Three sources of confidence, in sequence:

1. **Interaction depth (bootstrap).** Available day one, needs no benign baseline. Repeated and escalating interaction across distinct canaries is a strong intent signal with low benign collision by construction. This carries the engine until real feedback accrues.
2. **Feedback labels (calibration).** Analyst confirmations accrue per deployment and calibrate thresholds once an evidence floor is met.
3. **Published base rates (cold start).** Static defaults so nothing ships at zero (see Section 8).

### 6.5 The scoring model

Scoring is one weighted function whose weights start uniform. Raw count of distinct canary touches is the special case where every canary type has weight 1.0. As the engine learns which canary types correlate with confirmed-malicious flows, weights diverge from uniform. There is no "count mode" and "weighted mode," only the weighted model whose weights evolve.

- Weight learning is gated by the same evidence floor that flips the engine to calibrated mode. Below the floor: uniform weights, raw count, documented as such. Above it: learned weights, surfaced to the operator.
- Initial intent-strength ordering (a planted credential outranks a fake bucket listing) is a seed prior, a cold-start default only. Learned weights override the seed once calibrated, and nothing downstream hardcodes the ordering.
- The score is **windowed.** Repeated touches inside a short correlation window (minutes) count more than the same touches spread over hours. Lateral movement happens fast; tight windows reduce false positives.
- A **benign-exclusion input** is first-class. Service accounts, monitoring systems, and scheduled tasks are the most likely benign canary-brushers and can be excluded from scoring or held to a higher bar.

---

## 7. Scope and isolation

All learned state (weights, calibration status, evidence counts, feedback labels) is **isolated per deployment** and never aggregates across deployments. Isolation is a security, correctness, and governance feature: it prevents one environment's traffic structure from leaking into another, prevents importing weights that are wrong for a different benign baseline, and gives each customer a clean answer about where their telemetry goes.

Isolation is implemented as a single **scope key**, not as separate cluster-mode and zone-mode code paths.

**Scope key resolution order:**

1. Operator-defined trust zone, if the flow matches one.
2. Else derived cluster identity. In a service mesh this is the SPIFFE trust domain (which already encodes a trust boundary); in Kubernetes, the cluster UID; this also serves as the catch-all scope for unzoned traffic in a cluster that has zones defined.
3. Else, where no cluster identity is derivable (for example standalone nginx on bare VMs), an operator-defined boundary, which is **required**.
4. Else hard fail with a clear error. The system refuses to start rather than silently defaulting to a global scope, because a silent merge of trust boundaries is the exact leak isolation exists to prevent.

Derived cluster identity serves double duty as both the zero-config default and the catch-all under named zones, so the fallback bucket is free and needs no separate config.

**Constraints on operator-defined scopes** (they attach to the key regardless of how it was populated):

- Scopes must partition cleanly. A flow belongs to exactly one scope. Overlapping definitions are rejected, or a deterministic precedence assigns the flow to exactly one.
- Each scope needs enough traffic to calibrate. Per-scope calibration status is surfaced, so an operator who carved many small zones can see which remain uncalibrated and why.
- The seed prior is the only shared artifact and ships as static config. A new zone cold-starts exactly like a new cluster, then diverges on its own feedback.

---

## 8. Cold-start defaults from published research

Uncalibrated-mode defaults rest on published numbers rather than intuition.

- **Single-signal honeytoken detection** runs around a 3% false-positive rate in measured peer-reviewed work, not the near-zero that vendor material claims. The near-zero figure is a design aspiration assuming flawless placement. The uncalibrated single-touch threshold assumes roughly 3% FP, not zero.
- **Lateral-movement detectors** span roughly 0.9% to 10% false positives to catch 80–90% of attacks. This range scaffolds the strictness knob: the permissive end maps toward 10%, the strict end toward sub-1%, with single-honeytoken 3% as a reasonable mid-default.
- **Multi-signal correlation is the published state of the art**, which validates the tiered depth-of-interaction model directly. The strongest result in the literature reached a 94.5% detection rate at under nine alerts per day on a 15-month, 780-million-login enterprise dataset, where prior single-event systems needed roughly eight times the false positives to catch the same attacks. The mechanism behind that gain is exactly correlating a sequence of actions rather than scoring an isolated event.
- **Short correlation windows and benign exclusion** are established FP-reduction techniques, which is why both are first-class in the scoring model.
- **The cold-start problem is real and named** in the anomaly-detection literature: too little benign data raises the false-positive rate, and malicious activity hidden in assumed-clean training data teaches bad baselines. This is why the depth-of-interaction bootstrap, which needs no benign baseline, is the day-one signal rather than early anomaly scoring.

---

## 9. Kernel enforcement and the identity join

Enforcement for async mode and for containment happens in the kernel via eBPF (TC/XDP and cgroup hooks), because by the time the engine decides, the proxy may have already released the flow.

The hard problem this solves is identity. The proxy sees L7 identity (mTLS SPIFFE ID, headers, JWT). The kernel sees kernel identity (socket cookie, cgroup, netns). A verdict from one layer cannot enforce in the other without a shared join key. **The socket cookie is the join key**: both an Envoy filter and an eBPF program at the cgroup or TC hook can observe it for the same connection. Attribution by socket cookie, cgroup, or PID is also why containment can target an offending flow precisely rather than guessing from L7 logs and risking a jailed legitimate flow.

---

## 10. Architecture layers

Three logical layers, with the proxies kept thin.

1. **Canary layer.** Proxy adapters (Envoy first, nginx second) plus canary object generation and seeding. Emits signals; carries no detection logic.
2. **Decision engine.** Scoring, tiering, strictness calibration, scope-keyed isolated state, the feedback loop. Proxy-agnostic, behind a stable contract.
3. **Sting layer.** Response keyed off the engine's tier verdict, attributed by socket cookie. Split into containment (kernel-enforced) and attrition (tarpit and token-burning, aggressive-capable).

The contract between layers is a flow identity plus a signal event in, a verdict out. Each new proxy is one adapter against that contract. Kernel enforcement is independent of which proxy fired the signal.

---

## 11. IP considerations (freedom-to-operate)

One known item for patent counsel, flagged as due diligence rather than a blocker. A granted US patent (10,623,442, originally filed 2015) covers a specific chained-honeytoken method: planting decoy credentials in one resource that unlock specifically enumerated downstream resources, and alerting only after the attacker traverses that exact credential chain.

CanarySting's design differs in mechanism: it scores continuous interaction depth across heterogeneous canary types, keys decisions on a learned calibrated suspicion score rather than a fixed credential traversal, and its novel layer (the attrition sting) is not a detection method at all. Infringement turns on practicing every element of a claim, and "require multiple interactions before acting" as a general concept is not what is claimed. Two design and business actions follow:

1. Do not build canary placement around the specific chained-decoy-credential mechanism (canary A exists to hand out credentials that unlock canary B in a fixed chain). The depth-of-interaction model does not need it and works on independent canaries scored by count and weight.
2. Commission a proper freedom-to-operate search before raising or shipping, and file a provisional on the genuinely novel work: the aggressive attrition sting and the token-economic-cost mechanism against LLM-driven attackers, which appears unoccupied.

---

## 12. Open items

- Freedom-to-operate search and provisional filing (Section 11).
- Concrete default threshold values per tier, derived from the Section 8 ranges, to be fixed during engine implementation.
- The specific canary object catalog and their seed intent-strength weights.
- The aggressive attrition response catalog (fake structure generators) and safety bounds on resource consumption by the sting itself.
