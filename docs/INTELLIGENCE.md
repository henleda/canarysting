# docs/INTELLIGENCE.md — The Intelligence Layer (Specification)

Read `CLAUDE.md`, `docs/TECHNICAL_ARCHITECTURE.md`, `docs/BASELINE_MULTIPLIER.md`, and `docs/SCOPE.md` first. This document specifies the intelligence layer: how CanarySting turns its observation vantage point into a proprietary, compounding data asset, and the streams built on top of it. It is a buildable spec. Where it touches scope isolation, `SCOPE.md` and the hard rule in Section 2 govern and cannot be relaxed.

The one-sentence summary: CanarySting is not only a control that acts on attackers, it is a system that produces proprietary adversary intelligence and acts on it in the kernel in real time. The intelligence is the asset. The sting is how we act on it and how we improve it.

---

## 1. Why this layer exists

Every other security tool watches the perimeter or the endpoint. CanarySting sits on the east-west fabric, behind the proxy, with kernel-level flow truth, and it watches attackers interact with deception engineered to provoke them. That vantage point produces a data stream nobody else can produce: real adversaries, in real environments, making real lateral-movement decisions against decoys, attributed to a precise flow.

The intelligence layer is the set of components that capture, derive, and operationalize that stream. It exists for three reasons:

1. **It is the durable moat.** The wedge (proxy-attached, kernel-coupled, attrition) gets us in. What compounds is the intelligence: each deployment makes it sharper, which improves detection and the bait model, which wins more deployments. That loop is the asset investors price.
2. **It closes the AI-versus-AI loop.** The adversarial-bait research model (`AI_MODELS` / Model 2, see Section 6) is trained on the behavior this layer captures. Better intelligence makes better bait, which extracts more behavior, which makes better intelligence.
3. **It produces a customer-facing proof.** The attacker-cost metric (Section 5.3) turns attrition into a number a customer reports to their board. Nobody else can produce it because nobody else imposes the cost.

---

## 2. The hard rule: intelligence never crosses a trust boundary as raw data

This is the most important rule in the document. The cross-customer network (Section 5.4) is the one place where the intelligence layer can break the promise the whole product is sold on. Do not break it.

**Only derived, anonymized adversary patterns may leave a deployment. Customer traffic, baselines, scope state, decoy contents, and any environment-identifying detail never leave the deployment boundary.**

Concretely:

- A behavioral fingerprint of an attacker tool (its probing sequence, its reaction to a tarpit, its token-burn signature) is derived intelligence. It may be shared across deployments after anonymization and aggregation.
- A scope baseline, a flow record, an adjacency graph, a decoy's contents, an IP, a hostname, an identity, or anything that could re-identify a customer or their environment is raw data. It never leaves.
- The cross-customer network ships patterns, not data. If an engineer cannot state, for a given field, why it cannot re-identify a customer, that field does not leave the boundary.

This rule sits on top of the scope-isolation model in `SCOPE.md`. Scope isolation governs learned state within a deployment. This rule governs what derived intelligence may cross between deployments, and the answer is: only anonymized patterns, never raw or scope-identifying data. Code that exfiltrates raw data, baselines, or scope state across a deployment boundary is a critical bug.

---

## 3. The vantage point (SHIPPED tier)

This tier is inherent in the architecture and exists the moment CanarySting is attached. It is the foundation the other tiers build on.

### 3.1 What is captured

For every canary interaction and the flow that produced it, the system already has, from the engine and the eBPF substrate:

- The flow identity (socket cookie), the scope, the canary type touched, and the timestamp.
- The flow's features against the scope baseline (adjacency, identity, port, volume, cadence; see `BASELINE_MULTIPLIER.md` Section 3).
- The tier reached, the verdict, and any sting applied.
- For attrition events, the attrition mechanism used and the cost-proxy measures (time held, bytes served, requests absorbed; see Section 5.3).

The intelligence layer's job in this tier is to record these as structured **adversary-interaction events**, per scope, in a form the higher tiers consume. It does not change engine behavior.

### 3.2 The adversary-interaction event

Define one canonical event type (see `internal/intelligence/event.go`, to be built). It is the join of: the canary signal, the flow's baseline-feature vector at interaction time, the engine verdict and tier, and the sting outcome with cost-proxy measures. It is scope-keyed and carries no raw payloads, only structured features and identifiers internal to the deployment.

### 3.3 Lifecycle and storage

Events are retained per scope under the same isolation rules as all learned state. Retention windows are an operator input. The store is local to the deployment. Nothing in this tier emits across a boundary.

---

## 4. Adversary profiling (NEAR-TERM tier)

This tier derives reusable structure from the raw events. It is buildable now and is the input to both the customer-facing metric and the cross-customer network.

### 4.1 Tool and technique fingerprints

From sequences of adversary-interaction events, derive a **behavioral fingerprint**: the ordered pattern of how an actor probes, which canary types it touches in what order, how it reacts to tagging and to tarpitting, and its timing signature. A fingerprint is a derived, structural object. It must be constructed so it carries no environment-identifying detail (no decoy contents, no addresses, no identities), because fingerprints are the unit the cross-customer network may share.

### 4.2 AI-attacker behavioral profiling

Because the attacker is increasingly an autonomous agent, the most valuable profiling is of agent behavior: how an LLM-driven actor probes, how it reacts to fake structures, where it gets stuck, which bait wastes the most of its compute and tokens. This profile is what trains the adversarial-bait model (Section 6). Build the profiler so its output is a clean training signal for that model: structured, labeled by observed reaction, and quantified by cost imposed.

### 4.3 The loop

Profiling feeds the bait model; the bait model extracts more distinctive behavior; that behavior sharpens the profiles. Build the interfaces so this loop is explicit: the profiler consumes adversary-interaction events and emits training-ready profiles; the bait model consumes profiles and emits bait; the bait's effect returns as new events. Keep each arrow a clean, testable boundary.

---

## 5. Operationalized streams (NEAR-TERM and UPSIDE tiers)

### 5.1 Reconnaissance signal (NEAR-TERM)

Because the system sits in the east-west path and knows the negative space of normal traffic, it can surface the quiet probing that precedes the loud part of an attack. Build this as a distinct, low-tier signal derived from canary touches in the negative space combined with baseline deviation as context (never as a trigger; the guardrail in `BASELINE_MULTIPLIER.md` Section 5 still holds). Surface it to the operator as an early-warning feed, not as an enforcement action.

### 5.2 Detection sharpening within a deployment (NEAR-TERM)

Profiles derived in a scope sharpen detection in that scope: a known fingerprint raises the weight of a matching interaction (within the bounds of the multiplier in `BASELINE_MULTIPLIER.md`; a fingerprint match is weight context on a canary touch, never an independent trigger). This stays within the deployment and obeys scope isolation.

### 5.3 Attacker-cost metric (NEAR-TERM)

Operationalize the attrition cost-proxy measures into a reported metric: time imposed, compute and token cost extracted, requests absorbed, per period, per scope, aggregated for the operator. This is a customer-facing KPI and a renewal lever. It is derived entirely from the deployment's own events and never leaves the boundary unless the operator chooses to export their own number. Build it as a clean reporting view over the event store.

### 5.4 Cross-customer intelligence network (UPSIDE)

The compounding asset. Anonymized fingerprints (Section 4.1) from many deployments aggregate into a shared adversary-pattern set that sharpens detection for all deployments. This tier is buildable, but it is governed entirely by the hard rule in Section 2.

Build constraints, all mandatory:

- Only fingerprints and derived patterns are eligible to leave a deployment. Run every candidate through an **egress filter** that drops anything carrying raw or environment-identifying data. Default deny: a field leaves only if explicitly marked safe and justified.
- Anonymize and aggregate before sharing. A pattern that could be traced to one customer's environment is not eligible.
- The shared set returns to deployments as detection context (matching the local-fingerprint path in Section 5.2), never as an enforcement trigger.
- The operator can opt out of contributing and still consume the shared set, and vice versa. Make participation a per-deployment input.

If any of these cannot be satisfied for a given pattern, that pattern stays local.

### 5.5 Threat-intelligence feed (UPSIDE)

Package the shared adversary-pattern set as a feed external systems consume (SIEMs, other tools, an industry ISAC). This is a second product line. It is built on top of 5.4 and inherits all of its constraints: the feed carries derived patterns only, never customer data. Build it as a read view over the anonymized, aggregated set, with its own access control and rate limiting.

---

## 6. Relationship to the AI models

The two models in the deck (`AI in CanarySting`) are this layer in motion:

- **Model 1 (shipping):** the adaptive scoring engine and baseline. It consumes events and feedback and sharpens detection. Specified in `ENGINE.md` and `BASELINE_MULTIPLIER.md`.
- **Model 2 (research direction):** the generative adversarial-bait model. It consumes AI-attacker profiles (Section 4.2) and emits bait tuned to be maximally expensive for an LLM agent to process. It is forward-looking R&D, not shipped. When it is specified for real, it gets its own doc (`AI_BAIT.md`) and its own freedom-to-operate review, since adversarial content generation against AI agents may have emerging prior art.

The intelligence layer is what makes both models improve over time. Build the event and profile interfaces (Sections 3.2 and 4) so both models are clean consumers of them.

---

## 7. Where this lives in the code

To be built. Suggested structure, consistent with the existing monorepo:

- `internal/intelligence/event.go` — the adversary-interaction event type (Section 3.2) and the per-scope event store interface.
- `internal/intelligence/profile/` — fingerprinting and AI-attacker profiling (Section 4). Emits training-ready profiles.
- `internal/intelligence/recon/` — the reconnaissance early-warning signal (Section 5.1).
- `internal/intelligence/cost/` — the attacker-cost metric and its reporting view (Section 5.3).
- `internal/intelligence/network/` — the cross-customer network: the **egress filter** (Section 5.4) is the critical component here, default-deny, plus the anonymize/aggregate path and the shared-set consumer.
- `internal/intelligence/feed/` — the external threat-intel feed read view (Section 5.5).

All of it is scope-isolated learned state except the explicitly-anonymized patterns that the egress filter clears for the network. The egress filter is the single chokepoint through which anything crosses a deployment boundary. Keep it that way: one chokepoint, default deny, fully tested.

---

## 8. Build order and tiering

For Claude Code, build in this order. Each tier is buildable; later tiers depend on earlier ones.

1. **Vantage point (shipped):** the event type and per-scope event store (Section 3). Everything depends on this.
2. **Profiling (near-term):** fingerprints and AI-attacker profiles (Section 4).
3. **Attacker-cost metric (near-term):** reporting view over events (Section 5.3).
4. **Reconnaissance signal (near-term):** early-warning feed (Section 5.1).
5. **Detection sharpening (near-term):** local fingerprint match as weight context (Section 5.2), within the multiplier bounds.
6. **Cross-customer network (upside):** the egress filter first and most carefully (Section 5.4), then anonymize/aggregate, then the consumer.
7. **Threat feed (upside):** the external read view (Section 5.5).

The guardrails never relax across tiers: the canary touch is the only trigger (`BASELINE_MULTIPLIER.md`), learned state is scope-isolated (`SCOPE.md`), and only anonymized patterns cross a boundary (Section 2). Any tier that appears to require relaxing one of these is mis-designed; stop and reconsider rather than relaxing the rule.

---

## 9. Open items

- The concrete schema of the adversary-interaction event and the fingerprint, validated against real design-partner data.
- The anonymization method for fingerprints and the formal definition of "cannot re-identify," reviewed before the network ships.
- The cost-proxy model that converts attrition measures into a credible dollar and token figure for the attacker-cost metric.
- The `AI_BAIT.md` spec for Model 2, when that research is ready to build, with its own FTO review.
