# docs/ENGINE.md — Decision engine guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This document governs everything under `internal/engine/`.

The engine is the brain. It ingests signal events (a flow touched a canary), maintains a per-flow suspicion score, decides a response tier, and emits a verdict. It is **proxy-agnostic** and talks only to `internal/contract/`. It never imports an adapter or a proxy SDK.

## Subpackages

- `scoring/` — the suspicion score. One weighted function over canary interactions.
- `tiers/` — maps score + config to a tier (0–3) and the inline/async decision.
- `calibration/` — turns feedback labels into calibrated thresholds and weights.
- `scope/` — resolves the scope key and isolates all learned state. See `docs/SCOPE.md`.
- `feedback/` — intake of analyst labels; the single calibration signal.

## The scoring model (`scoring/`)

One weighted function. **There is no "count mode" and "weighted mode"** — only the weighted model whose weights evolve.

- Score = windowed, weighted sum of distinct canary interactions for a flow within a scope.
- Weights start **uniform** (every canary type = 1.0). Uniform weights make the score equal to a raw count of distinct touches — that is the cold-start behavior, by construction.
- As calibration accrues, weights diverge from uniform to reflect which canary types correlate with confirmed-malicious flows in *this* scope.
- **Windowed:** repeated touches inside a short correlation window (minutes) count more than the same touches spread over hours. Implement the window as config, default to a few minutes.
- **Benign exclusion is first-class.** Service accounts, monitoring, scheduled tasks are the most likely benign canary-brushers. Accept an exclusion input and either drop their events or hold them to a higher bar. Do not bury this in scoring internals — make it an explicit, configurable input.

Canary interaction events carry the canary type and the flow identity. The score is always computed *within a scope* — never across scopes.

## Tiers (`tiers/`)

Four tiers (see `docs/ARCHITECTURE.md` §4). The engine maps the current score to a tier using thresholds that come from `calibration/`.

- **Tier 0–1: async only.** The engine is never on the request hot path for these. Observe, tag, feed richer decoys — none of it blocks.
- **Tier 2–3: operator-chosen inline or async.** Honor the operator's setting. Inline holds the request for a verdict; async applies enforcement to subsequent packets via the kernel layer.
- **Coupling rule:** inline can enforce at the proxy or the kernel; **async must enforce at the kernel** (the proxy already released the flow). Encode this so an operator cannot configure async with proxy-only enforcement.
- **Strictness is per-tier.** A baseline strictness with a per-tier multiplier. Low tiers tolerate more false positives; high tiers less. The Tier 0→1 transition is cheap and reversible; the Tier 2→3 transition is strict by construction.

## Strictness control

- Operator-facing knob named `confidence_required`, range `0.01` (permissive, more FP accepted) to `1.00` (strict, minimal FP). Direction must match the name — higher value = stricter.
- It expresses a **target false-positive rate**, not a raw threshold. The engine calibrates internal thresholds to hold the observed FP rate at or below the target.
- The engine is explicit about its mode:
  - **Calibrated mode:** enough feedback labels exist (evidence floor met); honor the target with learned thresholds.
  - **Uncalibrated mode:** fall back to the documented static threshold map (see Cold-start) and **surface that it is uncalibrated**. Never imply a guarantee the engine cannot keep.

## Calibration (`calibration/`)

- Single feedback loop. An analyst marks a Tier 2/3 action correct or wrong (see `feedback/`). That label calibrates both the strictness thresholds and the canary weights.
- **Evidence floor:** below a minimum confirmed-label count, stay uncalibrated (uniform weights, static thresholds, documented). Above it, switch to learned and surface the switch to the operator.
- The same floor gates *all* learned parameters. Do not let one parameter go learned while another is still in cold start under a different rule.
- Weight learning: a canary type seen often in confirmed-malicious flows and rarely in false positives earns higher weight, within the current scope only. The seed intent-strength ordering (see `docs/CANARY.md`) is a prior that learned weights override once calibrated. Do not hardcode the ordering downstream.

## Inline fail behavior

For inline mode, behavior on engine timeout/outage is an explicit **per-tier** setting:
- **Tier 1: fail-open.** A low-confidence tier must not block legitimate traffic if the engine is degraded.
- **Tier 3: fail-closed.** A confirmed tier must not release an actor because the engine is degraded — this also denies an attacker the strategy of degrading the engine to escape.
- Make these defaults explicit in config, never an accident of timeout handling.

## Cold-start defaults (uncalibrated mode)

From published research (see `docs/ARCHITECTURE.md` §8). Encode as the documented static map:
- Single-touch honeytoken FP assumption ≈ 3% (not the vendor near-zero claim).
- Lateral-movement FP band ≈ 0.9%–10% to catch 80–90% of attacks — map the strictness knob across this band (permissive → ~10%, strict → sub-1%, mid ≈ 3%).
- Multi-signal correlation is the state of the art; the tier escalation *is* the correlation mechanism. Favor depth-of-interaction over single-event scoring.

## What the engine must never do

- Import an adapter or proxy SDK.
- Share or aggregate learned state across scopes.
- Put Tier 0–1 work on the request hot path.
- Add a learned parameter without an uncalibrated default + feedback loop + evidence floor.
- Claim calibrated behavior while in uncalibrated mode.

## Baseline context (the guardrail)

The engine may consume a per-scope **baseline** of normal east-west traffic (built via eBPF; see `TECHNICAL_ARCHITECTURE.md`). Its only roles in scoring are:
- **Weight context:** a canary touch from a flow that looks abnormal against the baseline is weighted upward, so it escalates through the tiers faster. The mechanism is a bounded, floored-at-one, saturating, multiplicative multiplier `M`, specified in full in `BASELINE_MULTIPLIER.md`: `Score = base × M`, `M ∈ [1, M_max]`. A normal touch scores its raw base (`M = 1`); an abnormal touch escalates faster; no touch scores zero regardless of deviation.
- **Benign-exclusion source:** flows that are present, periodic, and stable across the learning window are proposed as the benign-exclusion set (operator confirms).

The baseline is scope-isolated learned state with the standard uncalibrated-default + evidence-floor + feedback lifecycle.

**Hard rule:** the baseline NEVER triggers a tier transition or a sting on its own. The canary touch is the sole entry condition for the response pipeline. Deviation from normal is not a trigger. Code that lets baseline deviation tag, contain, or attrit a flow is a bug. See `TECHNICAL_ARCHITECTURE.md` §5.

## Implementation status (M1)

The engine core is implemented and tested end-to-end in-process (`internal/engine`, ROADMAP M1):

- **scope** — `StaticResolver`: the documented resolution order with deterministic zone precedence and a refuse-to-start (`ErrUnresolved`) path; never a global scope.
- **scoring** — `WindowedScorer`: windowed weighted sum over *distinct* canary touches per (scope, flow), weights supplied by calibration, benign-exclusion as a first-class drop. Uniform weights = raw count (cold start), by construction.
- **tiers** — `StaticDecider`: the static threshold map keyed by `confidence_required` over the §8 FP bands; async-only for tiers 0–1; `Config.Validate` encodes the async-only and Tier 1 fail-open / Tier 3 fail-closed rules so config cannot violate them.
- **calibration** — `Store`: per-scope evidence counts, one floor gating uncalibrated→calibrated for all learned params, seed-prior-regularized learned canary weights, no cross-scope aggregation.
- **engine / feedback** — `Service` (implements `contract.Engine`) composes the above and reports `Calibrated`; `Intake` is the single feedback seam into calibration.

**Scoped for a later increment (documented, not done):** in calibrated mode M1 learns per-scope *weights* (which sharpen the score); it does not yet solve internal *thresholds* to hold an observed FP rate at the `confidence_required` target — thresholds remain the static map keyed by the knob. `Calibrated=true` therefore means "evidence floor met, learned weights active," which is accurate and surfaced honestly; it is not an FP-rate guarantee. The baseline multiplier `M` (`Score = base × M`) is M2; until then `M = 1`.
