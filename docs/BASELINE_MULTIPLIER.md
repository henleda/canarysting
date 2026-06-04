# docs/BASELINE_MULTIPLIER.md — The Baseline Weight Multiplier (Specification)

Read `CLAUDE.md`, `docs/TECHNICAL_ARCHITECTURE.md` (especially sections 4, 5, and 6), and `docs/ENGINE.md` first. This document specifies exactly how the per-scope eBPF baseline enters the suspicion score, as a bounded multiplier on a canary touch. It is both an implementation spec and the reference for the freedom-to-operate and provisional-patent work. Where this document and a layer doc overlap, this document governs the multiplier.

The one-sentence summary: a canary touch produces a base score, the baseline produces a bounded multiplier on that base, the two are combined multiplicatively, and because the form is multiplicative with a multiplier floor of one, a flow that never touches a canary scores zero no matter how abnormal it looks.

---

## 1. Design principles (the invariants)

These five invariants are the contract. Everything in this spec exists to satisfy them, and no implementation may break them.

1. **Touch is the trigger.** The base score comes only from canary interactions. The multiplier shapes a base score that already exists. It never creates one.
2. **Multiplicative, so zero is zero.** Score is the base times the multiplier. If the base is zero (no touch), the product is zero regardless of the multiplier. This is the guardrail expressed in arithmetic.
3. **Multiplier floor of one.** The multiplier ranges from one (neutral) upward to a cap. It can amplify a real touch. It can never suppress one below its base. This is what protects against a poisoned baseline: the worst a corrupted baseline can do is fail to amplify, never hide.
4. **Bounded above, so the baseline never dominates.** The multiplier is capped at a small constant. A single touch from a maximally abnormal flow scores at most that cap times a normal touch. The touch count still drives the score. The baseline tunes the rate of escalation, not the existence of suspicion.
5. **Saturating and per-feature bounded, so no single outlier blows up the score.** The deviation quantity that feeds the multiplier is built from feature contributions that are each individually capped, then passed through a saturating function. This is the bounded-influence property from robust statistics, applied so that one extreme feature cannot run the multiplier to its cap on its own.

If a proposed change to the engine would violate any of these, it is wrong. Surface it rather than working around it.

---

## 2. Composition: how the multiplier enters the score

The engine's base score is the windowed, weighted sum of distinct canary interactions for a flow within a scope (see `ENGINE.md`). Call that base `B`:

```
B(flow, scope, t) = Σ over distinct canary types c touched in the window   w_c
```

where `w_c` is the learned per-scope weight for canary type `c` (uniform at cold start, learned from feedback once calibrated).

The baseline contributes a single per-flow multiplier `M`:

```
Score(flow, scope, t) = B(flow, scope, t) × M(flow, scope, t)
```

`M` is a property of the flow, not of any one canary, so it multiplies the whole sum. Key consequences, which are the invariants made concrete:

- If `B = 0` (no canary touched), `Score = 0` for any `M`. No touch, no score.
- `M ∈ [1, M_max]`. A normal-looking flow scores its raw base. An abnormal flow scores up to `M_max` times its base.
- `M_max` is small (default below) so the base, driven by touch count and canary weight, remains the dominant term.

`M` is evaluated at scoring time from the flow's observed features in the current window against the scope baseline. It is recomputed when the flow accrues a new interaction. Cache it per flow per window to avoid recomputation on the hot path.

---

## 3. The deviation quantity `d`

`M` is a function of a single scalar deviation quantity `d ≥ 0` that measures how far the flow sits from the scope baseline. `d` is built to be bounded by construction.

### 3.1 Features

`d` is computed from a fixed set of flow features compared against the per-scope baseline. The initial set:

- **Adjacency novelty.** Has this source-to-destination workload pair been seen in the baseline. A never-before-seen adjacency is the strongest single feature.
- **Identity novelty.** Has this initiating identity (SPIFFE identity or workload identity, joined by socket cookie) initiated this kind of connection before.
- **Port and protocol novelty.** Is this port and protocol normal for this adjacency.
- **Volume deviation.** How far the byte and packet envelope sits from the baseline envelope for this adjacency, as a normalized distance.
- **Cadence deviation.** How far the connection timing and frequency sit from the baseline cadence.

Each feature produces a contribution `c_i ≥ 0`.

### 3.2 Per-feature bounding

Each contribution is individually capped at `c_max` before combination:

```
c_i = min(raw_i, c_max)
```

This is invariant 5 at the feature level. A single feature, no matter how extreme, can contribute at most `c_max` to `d`. Without this cap, one wild feature (a single enormous transfer, say) could drive the whole multiplier, which is exactly the outlier-domination failure that bounded-influence estimation exists to prevent.

### 3.3 Combination

The capped contributions combine into `d`. Use a bounded combination. The default is the Euclidean norm of the capped contributions:

```
d = sqrt( Σ c_i² )
```

The norm is itself bounded because every `c_i` is bounded. An alternative is a weighted sum with per-feature weights learned from feedback, also over the capped contributions. Do not use an unbounded combination.

### 3.4 Time awareness

Real east-west traffic has diurnal and weekly cycles, so a stationary baseline produces false deviation (a nightly batch job looks anomalous at 3am only because the baseline was not conditioned on time). The baseline is therefore conditioned on a time bucket (default: day-of-week crossed with an hour band, configurable). `d` is always computed against the baseline slice for the current time bucket. This is why the learning window must span at least one full weekly cycle (see Section 6).

---

## 4. The multiplier map `M(d)`

`d` maps to `M` through a saturating function bounded to `[1, M_max]`:

```
M(d) = 1 + (M_max − 1) · g(d)
```

where `g(d) ∈ [0, 1]` is saturating, with `g(0) = 0` and `g(d) → 1` as `d → ∞`. The default `g` is a saturating Hill form:

```
g(d) = d / (d + k)
```

with `k` the deviation value at which `g = 0.5` (a moderately abnormal flow). Properties that matter:

- `g(0) = 0`, so a flow that matches the baseline gets `M = 1` (neutral). The touch still scores its full base. The baseline simply does not amplify.
- `g` saturates, so beyond the knee, more deviation adds diminishing multiplier and never exceeds `M_max`. This is the bounded-influence property at the multiplier level. A maximally abnormal flow and a merely very abnormal flow both land near `M_max`, which is correct: past a point, more strangeness should not keep multiplying suspicion without bound.
- `M` is continuous and monotonic in `d`, so small changes in the flow do not cause large jumps in the score.

A Huber-style clamp (linear up to a knee, flat after) is an acceptable alternative to the Hill form. Both give the bounded, saturating shape. Do not use an unbounded map such as a raw exponential.

---

## 5. Worked examples

Assume defaults: `M_max = 3.0`, single canary weight `w_c = 1.0`.

**Normal flow, one touch.** A flow that looks like the established fabric touches one canary. `d ≈ 0`, so `g(d) ≈ 0`, so `M ≈ 1.0`. `Score = 1.0 × 1.0 = 1.0`. The touch scores its raw base. The baseline did nothing.

**Abnormal flow, one touch.** A flow on a never-before-seen adjacency, from an identity that has never initiated this connection, touches the same canary. `d` is large, `g(d) ≈ 0.8`, so `M = 1 + 2.0 × 0.8 = 2.6`. `Score = 1.0 × 2.6 = 2.6`. The same single touch escalates about 2.6 times faster through the tiers. The baseline sharpened a real signal.

**Maximally abnormal flow, no touch.** A flow that is wildly off baseline in every feature, but that never touches a canary. `B = 0`. `Score = 0 × M = 0`. Nothing happens. No tag, no containment, no attrition. This is the guardrail. Deviation alone, at any magnitude, triggers nothing.

**Poisoned baseline, real attacker.** An attacker present during the learning window taught the baseline that their behavior is normal. When they touch a canary, `d ≈ 0` for them, so `M ≈ 1.0`. They still score the full base from the touch, `Score = B × 1.0`. The poisoning cost us the amplification, not the detection. The touch still triggers and still scores. This is invariant 3 doing its job.

---

## 6. Calibration lifecycle and defaults

The multiplier follows the same lifecycle as every learned parameter (see `ENGINE.md`).

- **Uncalibrated (cold start).** `M = 1.0` for every flow, forced. The baseline is not trusted, so the engine behaves exactly as the touch-only engine: raw count scoring with uniform canary weights. This is the safe default and the cold-start behavior.
- **Learning window.** The eBPF path accumulates the per-scope, time-bucketed baseline. The window must span at least one full weekly cycle. Default minimum two weeks.
- **Calibrated.** Once the baseline crosses the evidence floor, `M` is computed from `d` as specified. The same floor that gates canary weight learning gates the multiplier, so the two go live together, never one without the other.

The multiplier is forced to `1.0` any time the scope is uncalibrated, the baseline is stale, or the current time bucket has insufficient baseline data. When in doubt, the multiplier is neutral. Neutral is always safe because it reduces the engine to touch-only scoring.

### Default parameters

| Parameter | Symbol | Default | Notes |
|---|---|---|---|
| Multiplier cap | `M_max` | 3.0 | Range 1.0 to 3.0. Higher lets the baseline matter more. Keep conservative. |
| Saturation knee | `k` | tuned per scope | The `d` value at which `g = 0.5`. Set so a moderately abnormal flow maps near the middle of the range. |
| Per-feature cap | `c_max` | tuned | Caps any one feature's contribution to `d`. |
| Time bucket | — | day-of-week × hour band | Configurable granularity. |
| Learning window | — | ≥ 2 weeks | Must span a full weekly cycle. |
| Evidence floor | — | shared | The same floor that gates all learned parameters. |

All of these are inputs, not hidden constants. `M_max`, `k`, and the per-feature weights are learnable from analyst feedback once calibrated, within their bounds.

---

## 7. Failure-mode analysis

- **Poisoned baseline.** Worst case `M = 1.0` for the attacker (fails to amplify). Never suppresses the base score, never hides a touch. Mitigated further by estimating the baseline with high-breakdown, bounded-influence estimators so a contaminated window shifts the model less.
- **Benign novelty.** A new but legitimate service deviates from baseline. With no canary touch, `B = 0` and nothing happens. If it does happen to touch a canary, it is amplified, which is acceptable, because a benign service touching a decoy is exactly the rare event the benign-exclusion set and analyst feedback are there to correct, and the cost of an over-weighted touch is bounded by `M_max`.
- **Single extreme feature.** Capped at `c_max`, so it cannot run `d` to its maximum alone. Bounded influence at the feature level.
- **Baseline drift.** The environment changes legitimately over time. The baseline is refreshed on a rolling basis per scope. Stale baseline forces `M = 1.0` rather than producing wrong amplification.
- **Time-bucket sparsity.** A time bucket with little baseline data forces `M = 1.0` for that bucket rather than guessing.

In every failure mode the degradation is toward neutral (`M = 1.0`, touch-only scoring), never toward a wrongful trigger. That asymmetry is deliberate and is the safety argument for the whole mechanism.

---

## 8. Guardrail invariants, restated for implementers

- **Fires the response pipeline:** a canary interaction, attributed by socket cookie. Nothing else.
- **Shapes the score:** the multiplier `M` (bounded, floored at one), the per-scope canary weights `w_c`, the strictness setting, the tier thresholds, the benign-exclusion set.
- **Never triggers anything on its own:** `d`, `M`, baseline deviation, novelty, volume or cadence changes, new adjacencies, unfamiliar identities.
- **Forbidden code:** any path where `d`, `M`, or a baseline deviation, absent a canary touch, causes a tag, containment, tarpit, or attrition. Any place `M` can fall below 1.0. Any unbounded contribution to `d` or unbounded map to `M`. Any use of `M ≠ 1.0` while the scope is uncalibrated.

---

## 9. Novelty and IP framing

This section supports the freedom-to-operate and provisional-patent work. It is not legal advice. Counsel should confirm against a full search.

### 9.1 What is and is not novel

Not novel on their own, and not the basis of any claim:
- Using eBPF to build a behavioral baseline of network traffic. Done widely in network behavior analysis and detection-and-response products.
- Bounding a score so one input does not dominate. Known robust-statistics math (bounded influence functions, Huber estimators).
- Combining multiple anomaly signals multiplicatively or by weighted geometric mean. Published in the composite-anomaly-score literature.

The novel combination, and the intended point of novelty:
- A deception interaction (a canary touch) as the **sole** trigger for any response, combined with a kernel-derived per-scope behavioral baseline used **exclusively as a bounded, non-triggering multiplier** on that trigger, where the multiplier is floored at one (cannot suppress), capped (cannot dominate), and multiplicative (zero touch yields zero score).

The distinguishing constraint is the **non-triggering role** of the baseline. In the prior art the anomaly or baseline-deviation signal is the detector: it crosses a threshold and fires an alert or a block. Here the baseline-deviation signal is structurally barred from firing anything and serves only to weight an independent, near-zero-false-positive deception trigger. That inversion is the claim.

### 9.2 Claim elements to draft around

1. A high-confidence trigger consisting of an interaction with a deception object (canary), attributed to a network flow by a shared kernel and L7 identity (the socket cookie).
2. A per-scope behavioral baseline of east-west traffic derived from kernel-level (eBPF) observation, conditioned on a time bucket.
3. A bounded deviation quantity computed from per-feature contributions that are each individually capped, then combined by a bounded function.
4. A multiplier derived from that deviation through a saturating map bounded to a range whose floor is one and whose cap is a small constant.
5. A suspicion score formed by the product of a base score (from the deception trigger) and the multiplier, such that the absence of a trigger yields a zero score irrespective of the deviation.
6. Per-deployment isolation of the baseline and all derived state.

Dependent elements worth including: the bounding method (Huber-style or saturating Hill), the time-aware baseline, the auto-derived benign-exclusion set from the same baseline, and the negative-space canary placement informed by the same baseline.

### 9.3 Prior art to distinguish, and how

- **Entity risk-score patents (for example US 10,878,102 and US 10,015,185).** These combine weighted anomaly and impact scores and then act on the combined anomaly score. Distinguish on the non-triggering role of the baseline here and on the deception interaction being the independent trigger. These are the closest references and the specification should address them directly.
- **OWASP CRS collaborative detection.** Accumulates rule-match scores additively toward a block threshold, where every contributing rule is itself a trigger. Distinguish on additive-accumulation-of-triggers versus a single non-triggering context multiplier on a separate trigger.
- **Threshold-firing anomaly products (for example Elastic anomaly rules).** Fire actions when an anomaly score crosses a threshold. Distinguish on the anomaly signal being barred from firing anything here.

Counsel should foreground the non-triggering constraint as the point of novelty, since the prior art is dense on anomaly-as-detector and that constraint is the cleanest distance from all of it.

---

## 10. Where this lives in the code

- `internal/engine/scoring/` owns `B`, the windowed weighted base, and applies `M` at scoring time.
- A baseline component (new, under `internal/engine/` and fed by `bpf/loader/`) owns the per-scope baseline, computes `d` for a flow, and exposes `M`. It holds only scope-isolated learned state, with the standard uncalibrated-default and evidence-floor lifecycle.
- `bpf/loader/` feeds the baseline from the same low-overhead observation path used for enforcement, kept distinct from the enforcement path (observation never enforces).
- The multiplier defaults (`M_max`, `k`, `c_max`, time-bucket granularity, window, floor) live in `config/` as documented inputs.

---

## 11. Open tuning items

These are values to calibrate during implementation, not open design questions. The design is fixed by the invariants in Section 1.

- Empirical defaults for `M_max`, `k`, and `c_max`, validated against design-partner traffic so a normal touch and an abnormal touch separate cleanly without the baseline dominating.
- The exact feature set for `d` and the per-feature weights, learned from feedback.
- Time-bucket granularity that captures real cycles without fragmenting the baseline into sparse buckets.
- The rolling-refresh cadence for the baseline and the staleness threshold that forces `M = 1.0`.
