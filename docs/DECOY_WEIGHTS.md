# Decoy Weights — severity-aware scoring (intent × maliciousness)

Status: accepted (2026-06-14). Implements "Option Y" from the decoy-weights design
investigation. Read alongside `docs/BASELINE_MULTIPLIER.md` (the per-flow multiplier
M) and `docs/CANARY.md` (the catalog intent ordering).

## The score, in one line

A flow's base is the windowed sum of the weights of the **distinct canary types** it
touched, and the score is that base times the per-flow baseline multiplier:

```
B(flow)   = Σ over distinct canary types c touched in-window  weight(c, scope)
Score     = B × M        (M ≥ 1, per-flow baseline anomaly context — never a trigger)
```

`B` is computed in `internal/engine/scoring/scoring.go` (the `WindowedScorer.Score`
loop: `base += s.weights.Weight(scope, ct)`). `weight(c, scope)` is resolved
engine-side via the `Weights` interface, satisfied by
`internal/engine/calibration/Store.Weight`. The wire (`SignalEvent`) carries only the
canary **type**, never a weight — the type is the key the engine weights against.

## Problem: intent strength washes out with evidence

Two things should make a touched **planted-credential** decoy count for more than a
touched **fake-endpoint** decoy:

1. **Product:** severity-aware scoring — grabbing the crown jewels is worse than
   poking a static asset, and the response should escalate accordingly.
2. **Legibility:** without it, every single-decoy touch scores the *same* number, so
   the dashboard's live-attacker feed looks fake (one repeated value).

The catalog already encodes the ordering as `SeedWeight` (planted credential 1.8 ›
fake secret 1.5 › decoy file 1.2 › fake bucket 1.1 › fake endpoint 1.0), but it only
fed scoring as an **additive prior pseudo-count** in the old learned weight:

```
old:  weight = 2p ,  p = (mal + seed) / (mal + ben + seed + 1) ,  clamp [0.1, 2.0]
```

**Verified on the live demo (2026-06-14):** the scope is calibrated
(`evidence_seen = 10,692`, floor 50), yet the learned per-type weight is pinned at
~2.0 **uniformly** (backed out as `score ÷ touches ÷ M`: 1.999 / 2.06 / 2.14). The
reason is structural: every decoy is touched *only* by the labeled attacker
(`ben = 0`; benign flows are path-disjoint from canaries by Rule 8), so `p → 1` and
`2p → 2.0` for **every** type, and as `mal` grows the additive `seed` term is swamped
(at `mal=200`, seed 1.8 and seed 1.0 both give p ≈ 0.995). An additive prior cannot
preserve intent once a scope has plentiful evidence.

## Design: make intent a multiplicative factor

Separate the two things the weight was conflating and multiply them:

```
weight(c, scope) = clamp( intentNorm(c) × malFactor(c, scope) ,  MinWeight, MaxWeight )

  intentNorm(c)   = SeedWeight(c) / mean(SeedWeights)
                    relative intent strength, centered on 1.0 (documented default;
                    the AVERAGE decoy is unchanged, so the scoring scale — and the
                    tier thresholds tuned against it — are preserved). PERSISTENT.

  malFactor(c,s)  = 2 × (mal + 0.5) / (mal + ben + 1)
                    learned maliciousness from confirmed labels in THIS scope, with a
                    neutral Jeffreys prior: no evidence → 1.0, confirmed-malicious → 2.0,
                    confirmed-FP → 0. (This is the old "2p" with the intent removed from
                    the prior and replaced by a neutral prior; intent now lives in
                    intentNorm.) LEARNED.
```

**Cold start (below the evidence floor):** unchanged — `weight = 1.0`
("uniform weights ARE the raw count of distinct touches"). Severity applies only once
a scope is calibrated, i.e. once we have the evidence to combine intent with learned
maliciousness. This preserves the documented cold-start invariant and keeps the
production blast radius minimal. (Applying `intentNorm` at cold start too — severity
from day one — is a one-line follow-up if we decide we want it; deferred.)

**Clamp:** `MinWeight = 0.1`, `MaxWeight` raised **2.0 → 3.0** so a high-intent decoy
can sit above a low-intent one at full maliciousness (max `intentNorm` 1.36 ×
`malFactor` 2.0 = 2.73).

### Worked example — the five shipped decoys, calibrated + all-malicious (the demo)

`mean(SeedWeights) = (1.8+1.5+1.2+1.1+1.0)/5 = 1.32`; `malFactor → 2.0`.

| decoy type        | SeedWeight | intentNorm | weight (×2.0) |
|-------------------|-----------:|-----------:|--------------:|
| planted credential| 1.8        | 1.36       | **2.73**      |
| fake secret       | 1.5        | 1.14       | 2.27          |
| decoy file        | 1.2        | 0.91       | 1.82          |
| fake bucket       | 1.1        | 0.83       | 1.67          |
| fake endpoint     | 1.0        | 0.76       | **1.52**      |

Average = 2.0 — exactly the prior uniform weight, so the *average* escalation cadence
is preserved. The spread (1.52 → 2.73) de-quantizes the score and makes escalation
**severity-driven**: a credential-grabber climbs to the kernel jail in fewer touches
than an endpoint-poker.

## Rule compliance

- **Rule 7 (learned-parameter shape):** `intentNorm` is the documented uncalibrated
  default (the intent ordering in `docs/CANARY.md`); `malFactor` is calibrated by the
  single existing feedback loop and gated by the existing 50-label evidence floor. No
  new parameter, no new floor.
- **Rule 8 (touch is the only trigger):** only a real canary touch contributes to B;
  M is floored at 1 and can never suppress B; the `[0.1, 3.0]` clamp bounds any single
  decoy so none can dominate or be gamed (repeat touches of one type still count
  once — map dedup in the scorer); a non-touch scores 0, so
  false-positives-by-construction is untouched.
- **Honesty:** this is genuine severity-aware scoring, not demo dressing. The reason
  the demo previously read uniform — "perfectly clean malicious separation, so every
  decoy maxes out" — is itself true and worth saying.

## Blast radius

- **Cold-start scopes (below floor):** unchanged (weight 1.0).
- **Calibrated scopes:** per-type weights become severity-spread instead of
  uniform-at-ceiling. Because the mean is preserved, static tier thresholds hold *on
  average*; flows weighted toward high-intent decoys escalate faster (intended). The
  demo-escalation climb is re-validated after deploy; thresholds are tuned only if the
  Tag→Contain→Jail cadence visibly drifts.
- **Demo:** de-quantizes the live-attacker strip and makes escalation severity-driven.
  Requires an engine rebuild + restart; in-memory calibration evidence resets and
  re-accrues from the labeled attacker in ~minutes (baseline.db / M persist).
- **Config:** `DefaultMaxWeight` 2.0 → 3.0.

## Tunable knobs

- `SeedWeight` values in `internal/canary/catalog/catalog.go` — the intent ordering
  (single source; the seeder's placement-density `Mix` still duplicates the ordering
  by hand — single-sourcing it from `SeedWeights` is a follow-up).
- `malFactor` shape (currently `2 × Jeffreys`) — how far evidence boosts/suppresses
  around intent.
- `MaxWeight` clamp.
