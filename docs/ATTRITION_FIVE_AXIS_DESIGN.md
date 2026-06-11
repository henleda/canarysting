# Five-Axis Attrition — Design + Engineering Build Plan

**Status:** ✅ FOUNDER-CONFIRMED 2026-06-10 — §0 decisions accepted; cleared to build the AX0 spine. Deferred items are tracked in §15. Built from an assembled current-state map of `internal/sting/attrition` + the cross-layer contract + intelligence/dashboard, and five verified per-workstream designs each passed through an adversarial reviewer (4 minor, 1 major verdict). **All verifier corrections are FOLDED IN below — where a reviewer flagged a core-rule violation or a wrong code claim, the design here is the corrected version, not the original proposal.** Read order: §0 (decisions needing signoff) → §1 (executive summary) → §2 (the integration spine) → §3–§7 (per-axis) → §8 (engagement contest + dashboard reframe) → §9 (cross-cutting contract/architecture) → §10 (refactors to delivered code) → §11 (milestones) → §12 (test/verification) → §13 (risks) → §14 (axis-5 no-hack-back / rule-9 constraints).

**Repo:** `/Users/danielhenley/projects/canary-sting/canarysting-repo` · Go 1.24.
**Authoritative spec:** `docs/STING.md` §Attrition (five axes, framing shift, engagement contest, "must never do") + `docs/ARCHITECTURE.md` §5. **Rules:** `CLAUDE.md` 1–9, most load-bearing here: rule 8 (canary touch is the ONLY trigger), rule 9 (only anonymized derived patterns cross a boundary, via the single egress filter), rule 3 (one reviewed contract), the attrition import-graph constraint, fail-closed at Tier 3, and `docs/STING.md` "Reach back into the attacker's own systems" (no hack-back).

**Framing shift (overarching, governs every axis + the dashboard):** attrition is "**opportunity cost on a velocity-dependent adversary**," NOT "make them pay a cloud bill." Every axis must justify itself as imposing cost that lands whether the attacker is metered, self-hosted, or on stolen compute. The dollar/metered framing is the weakest and must never lead.

---

## 0. Decisions needing founder signoff (read first)

Defaults are chosen so the build can proceed; the founder should confirm the load-bearing ones (★). Resolved decisions adopt the corrected verifier positions.

> **✅ CONFIRMED by founder 2026-06-10 — all recommended defaults accepted.** Load-bearing confirmations:
> - **D1 — spine-first.** Build the **AX0 spine alone** first; the axis-4 and axis-5 generators are DEFERRED to their own milestones (register §15: F1, F2).
> - **Egress filter = its OWN milestone** (not folded into D6). `internal/intelligence/network` (the rule-9 default-deny chokepoint, currently a `doc.go` stub) is a standalone deliverable that gates D6, D7, AND AX4/AX5 cross-boundary use (§15: F3).
> - **D8 — live-window flip APPROVED, deployed consciously.** The Tier-2 `fake_tree`→`poison_field` change ships to the live M7 window only deliberately, WITH Daniel (recon-feed / by-mechanism rollup / saved screenshots key on `fake_tree`).
> - **Axis 5 (operational exposure) — passive in-perimeter design APPROVED.** The new in-perimeter harmlessness predicate is a separate, founder-reviewed deliverable required before any AX5 code (§14; §15: F4).
> - **D2, D3, D4, D5, D6, D7, D9, D10 — accepted as written.** The optional dashboard `views/fingerprint.go` per-axis reframe is DEFERRED (kept as the separate flowID-bearing derivation for now — §15: F9).
>
> The table below is retained as the rationale of record.

| # | Decision | Default / recommendation | Why it matters |
|---|----------|--------------------------|----------------|
| **★ D1** | **Ship axes 4 & 5 generators now, or only the contract spine + seams (generators deferred)?** | **Ship the SPINE now** (axis enum, floor→axis map, new `Outcome`/`StingOutcome` fields, `internal/harmless/decoy` pkg, axis-aware selection, no-op `Observe` seam). DEFER the exploit-burn (axis 4) and operational-exposure (axis 5) GENERATORS to their own milestones — they additionally block on building `internal/intelligence/network` (the rule-9 egress filter, currently a `doc.go` stub) before any cross-boundary use. | Axes 4/5 are the highest-risk (no-hack-back, egress). The spine is the only contract change and unblocks everything; landing it first de-risks the rest. |
| **★ D2** | **The single rule-3 `StingOutcome` change — who owns it and what fields?** | **One coordinated rule-3 change owned by the SPINE (Milestone M0).** Add to `StingOutcome` (all four mirrors + proto): `Axes uint32` (bitset), `TimeToDisengageSec float64`, `PoisonClass string`, `PoisonReached int`, `ExploitsObserved int64`, `ExposureSignals int64`, `DisengageReason int`. Every other milestone DEPENDS on M0; nobody re-bumps the proto. | The drift-guard + proto/convert lockstep make uncoordinated additions expensive. One review, one `make proto`, one gob-forward-safe migration on the live M7 window. |
| **★ D3** | **Compose multiple axes on one flow — how?** | **Rotate generators per `cursor.chunkIdx` on the EXISTING single stream**, sharing ONE cursor and ONE per-flow `Budget` envelope. Not Budget-per-axis; not a multi-stream model; not per-chunk concatenation. | Preserves the proven O(1)/clock-free/single-`ImmediateResponse` transport and the live window. Revisit richer composition only if a demo needs simultaneous axes in one chunk. |
| **★ D4** | **Axis attribution — authoritative at capture, or derived from the `Mechanism` string?** | **HYBRID:** ship the authoritative `Axes` bitset (set at `Open` from `AxesForMechanism(mech)`) so composition is expressible AND the intelligence/dashboard layer reads it directly; KEEP `Mechanism` (frozen strings) as the dominant/first-active axis for the D3 KPI + `ByMechanism` drill-down. Never repurpose a shipped `Mech*` string; only ADD labels. | A single string cannot express composition; a bitset can. Keeping `Mechanism` keeps the KPI/drill-down stable. |
| **★ D5** | **Adaptive-latency ramp shape + visibility on the only delivered transport.** | **Bounded LINEAR ramp** from `MinDelay` to `MaxDelay` over `RampSaturate` chunks. **Default `RampSaturate` SMALL (8–12)**, NOT 64 — the only delivered transport is the inline `ImmediateResponse` (8 s hold, 0.5–1 s drip ⇒ ~8–16 chunks), so a 64-chunk ramp is unreachable. Do NOT cite a 120 s async path; no async attrition driver exists. | The visible-escalation story must fit the real transport budget, or the demo shows no escalation. |
| **★ D6** | **`TimeToDisengageSec` / engagement-duration SOURCE.** | **Derive from `Sting.TimeHeldSec` (real imposed hold) + the persisted disengage classifier**, NOT from event-timestamp `LastSeen−FirstSeen`. For a single-touch tarpitted flow `LastSeen−FirstSeen ≈ 0` even after minutes of hold; that measures inter-touch spread, a SEPARATE "persistence" metric. | The spec names time-to-disengage a CORE metric; sourcing it wrong silently zeros it on the common case. |
| **★ D7** | **Disengage classification — where, and what buckets?** | Classify in the ADAPTER (`pump.go`/`verdict.go`), not in `attrition.stream.Next`. Split into ≥3 buckets: **attacker-disengaged** (`holdCtx.Err()==context.Canceled` before any defender bound), **generator-exhausted** (`DoneComplete`), **defender-capped** (`DoneFlowBudget`/`DoneGlobalCeiling`/deadline). `TimeToDisengageSec` is non-zero ONLY for attacker-disengaged. | `stream.Next` sees only `ctx.Done()` and cannot tell a client disconnect from the 8 s `AttritionMaxHold` deadline; only the adapter holds `holdCtx`. Defender-stops must never be mislabeled an attacker disengage. This is a transport-fact mapping, not detection logic (rule 1 safe). |
| **★ D8** | **Tier-2 LIVE-window demo mechanism flips from `fake_tree` to `poison_field`.** | **Confirm with Daniel.** At `FloorModerate`+`TierContain` (the common inline-attrition path on the live prober) the headline mechanism changes from `fake_tree` to the new `poison_field`. The dashboard recon-feed, by-mechanism rollup, and saved screenshots key on `fake_tree`. | This is a visible behavioral change to the live M7 demo posture, not a silent internal refactor. |
| **D9** | **Shared decoy-generation package home/name.** | `internal/harmless/decoy` (subpackage of `harmless`). `harmless` is the VALIDATION source-of-truth; `harmless/decoy` is the GENERATION source-of-truth. Must import ONLY stdlib (optionally `internal/contract`), so attrition's allowed import set `{contract, harmless, stdlib}` is preserved and the import-graph test stays green. | Closes the confirmed duplication of `exampleKeyID`/`exampleSecret`/`envLeaf` (attrition) vs `exampleAWSKeyID`/`exampleAWSSecret`/`reservedHost` (catalog). |
| **D10** | **`believed-longer-than-detect` threshold source.** | **Static documented views constant** (mirroring `tarpitPersistSec=30.0`) or operator config — NEVER derived from "median legit think-time." Legit traffic produces no `AdversaryInteractionEvents` (rule 8), so the event store has no legit sample. | A presentation threshold, not a learned engine parameter; rule 7 does not bind, but the source must be honest. |

**Locked (no signoff — carried from the rules):** aggressive is never the silent default (3 structural guards preserved); attrition imports only `{contract, harmless, stdlib}`; every generator O(1)/chunk, iterative-not-recursive, `harmless.CrossScan`-clean, self-tested at construction; attrition is clock-free (delay is data); per-flow `Budget` under host `Governor` + single kill switch; `Open` is a no-op below `TierContain` and on `SocketCookie==0`; Tier 3 fail-closed; no hack-back; `Mech*` strings frozen (ADD only); only derived/anonymized scalars cross a boundary, via the single egress filter.

---

## 1. Executive summary

`internal/sting/attrition` ships (M6, proven on the live M7 window) a pull-based, clock-free, delay-as-data attrition stream with **three** generators on a single linear intensity ladder: `tarpit` (velocity, `FloorPassive`), `fakeMaze` (information poisoning + opportunity cost, `FloorModerate`), `tokenBait` (opportunity cost, `FloorAggressive`). Selection is `selectGenerator = gens[min(tierIntensity(tier), floorMax(floor))]` — exactly ONE generator per flow. The attacker-cost meter `Outcome{Mechanism, TimeHeldSec, BytesServed, RequestsAbsrb, TokenCostProxy, DepthReached, Reason}` is copied at the composition root onto `contract.StingOutcome` → `rpc ReportOutcome` → `boltevents.AmendOutcome` → `cost.Rollup` → dashboard.

The new spec reframes attrition into **five axes**: (1) velocity disruption, (2) information poisoning [core differentiator], (3) opportunity-cost injection [subsumes token-burning], (4) exploit-inventory burn, (5) operational exposure — plus an **engagement contest** (time-to-disengage as a core metric) and a framing shift away from dollars toward velocity-dependent opportunity cost.

**What is true today vs. what the spec requires:**

| Axis / metric | Shipped | Gap |
|---|---|---|
| 1 Velocity | `tarpit` + delay-as-data; FIXED band (`dripDelay` keyed on `(seed,chunkIdx)` only) | **Adaptive latency** that grows with persistence; first-class **time-to-disengage** |
| 2 Info poisoning | `fakeMaze` (per-page-independent maze + one hardcoded `envLeaf`) | A **first-class, internally-consistent fabricated-environment** generator distinct from the maze; a per-axis reaction signal |
| 3 Opportunity cost | `tokenBait` + `tokenProxy` + correct "defer $ to D3" comment | **Reframe** (labels/comments/dashboard lead with dollars); optional axis attribution |
| 4 Exploit-inventory burn | none | **NEW**: attractive decoys + capture the fired exploit as intelligence |
| 5 Operational exposure | none | **NEW, Tier-3 only**: in-perimeter callback sinks + tooling/C2 fingerprint — sharpest no-hack-back tension |
| Engagement | `DoneReason` computed but DROPPED at the durable boundary; `PersistsTarpit` binary | **Per-axis cost attribution**, **time-to-disengage** persisted + rolled up; plausibility proxy |

**Strategy (founder accepts refactoring delivered code → prefer the correct design):**
- **M0 — the spine** (this is the only contract change, owned once): axis bitset + floor→axis map in `internal/contract`; the new `internal/harmless/decoy` shared package; the rule-3 `StingOutcome` field additions threaded through all six real sites; the axis-aware selection (`selectAxes` returning a SET, rotated per chunk on the existing stream); the no-op `Stream.Observe` seam; `cost.Rollup` per-axis subtotals. **Refactor**, not minimal patch: `selectGenerator/tierIntensity/floorMax` and the index-identity guard tests are RETIRED, not patched.
- **M1 — velocity adaptive latency + time-to-disengage** (shares the stream/cursor M0 touches; sequenced alongside M0).
- **M2 — information poisoning generator** (`poison_field`, `FloorModerate`, consumes `internal/harmless/decoy`).
- **M3 — opportunity-cost + engagement/dashboard reframe** (mostly presentation + rollups; consumes M0/M1 fields).
- **M4 — exploit-inventory burn** (axis 4; blocked on the egress filter for any cross-boundary use).
- **M5 — operational exposure** (axis 5; Tier-3 only; blocked on the egress filter; the no-hack-back redesign in §7/§14).

Net-new vs refactor is called out per section and consolidated in §10.

---

## 2. The integration spine (M0) — contract, floor ladder, axis-aware selection, shared decoy generation

**Verdict folded in:** the spine workstream's reviewer returned **major** for two reasons, both corrected here: (a) the original cited `harmless.AllHostsReserved` as the axis-5 callback safety basis — WRONG (see §7/§14); (b) `DriverObservation` was unconstrained. Both are fixed below. Additional verifier corrections (set-composition cursor/Budget sharing, `stream.gen → stream.gens`, per-chunk `tokenProxy` keying, retire index-identity tests, deployment-local-only guard on axes 4/5 fields) are incorporated.

### 2.1 `internal/harmless/decoy` (NEW, stdlib-only) — close the generation duplication

`internal/harmless` is the VALIDATION single-source-of-truth (`CrossScan`, `IsExampleAWSKeyID`, `AllHostsReserved`, …). It only validates; it does not generate. Today the harmless decoy-BODY templates are duplicated: catalog has `exampleAWSKeyID`/`exampleAWSSecret`/`reservedHost` (rng-driven); attrition independently re-implements `exampleKeyID`/`exampleSecret`/`envLeaf` (uint64-seed-driven). Confirmed against code.

Create `internal/harmless/decoy/decoy.go` holding pure **deterministic-seed** (`uint64 → string`, NOT rng) body builders:
- `AWSCredentialStanza(seed uint64) string` — `~/.aws/credentials` stanza, `AKIA…EXAMPLE` / `…EXAMPLEKEY`.
- `EnvFile(seed uint64) string` — `.env` block, EXAMPLE keys + reserved-host DSN.
- `S3Listing(seed uint64) string` — `ListBucketResult` XML, owner `000000000000`, reserved endpoint.
- `ServiceLocator(seed uint64) string` — internal locator over an RFC-2606/5737/3849 reserved host/IP.
- `InertPEM(seed uint64) string`, `UnsignedJWT(seed uint64) string` — structurally invalid (DER body unparseable; `alg:none`).
- `ReservedHost(seed uint64) string` / `ReservedIP(seed uint64) string` — the shared realism-in-envelope/harmless-in-contents helpers.

Constraints: imports ONLY stdlib (optionally `internal/contract`); **every builder passes `harmless.CrossScan` by construction**, asserted in `decoy_test.go` over sampled seeds (mirrors the `genSelfTest` discipline). Because `{contract, harmless, stdlib}` is exactly attrition's allowed set and `harmless/decoy` sits inside it, both `internal/canary/catalog` and `internal/sting/attrition` may import it without breaking `TestAttritionImportsOnlyContractAndHarmless` or `catalog_test.go:TestCanaryDoesNotImportEngine` (verified: that test only forbids `internal/engine`). The seed-driven signature preserves attrition's clock-free determinism; catalog adapts via a tiny rng→seed shim.

### 2.2 `internal/contract` — axis enum + floor→axis map (no engine change)

```go
type AttritionAxis uint32
const (
    AxisVelocity     AttritionAxis = 1 << iota // 1
    AxisPoison                                  // 2
    AxisOppCost                                 // 4
    AxisExploitBurn                             // 8
    AxisOpExposure                              // 16
)
// Axes returns the axis set an operator floor unlocks. Single source of truth for
// the floor->axis map; kept OUT of the engine (rules 1/2 — engine emits only Tier).
func (f StingFloor) Axes() AttritionAxis {
    switch f {
    case FloorAggressive: return AxisVelocity|AxisPoison|AxisOppCost|AxisExploitBurn|AxisOpExposure
    case FloorModerate:   return AxisVelocity|AxisPoison
    default:              return AxisVelocity // FloorPassive (zero value)
    }
}
```

`contract` imports only `time`; this adds zero imports (a `uint32` bitset + a switch). `StingFloor` is still NOT a field on `Verdict` — it is bound into the `Attritor` at the composition root; the engine never sees it (rule 1/2 preserved).

**`DriverObservation` (constrained):** a `contract.DriverObservation` struct fed by the driver (`pump.go`) into the no-op `Stream.Observe` seam, for future axis-4/5 reaction signals. **MUST be a structured digest — counts/bools/enums ONLY, no `[]byte`, no addresses, no headers, no decoy/payload bytes.** A static reflection test (`TestDriverObservationCarriesNoRawData`) asserts it has no byte-slice or address-shaped field, mirroring the `Outcome` "no raw payload" invariant (rule 9). It ships as a defined-but-unused seam in M0; populated only at M4/M5.

### 2.3 axis-aware selection (`selectAxes`) — replace the linear ladder

Extend the generator interface (`generators.go`):
```go
type generator interface {
    mechanism() string
    axis() contract.AttritionAxis     // NEW
    minTier() contract.Tier           // NEW
    next(cur *cursor, p genParams) (data []byte, delay time.Duration, ok bool)
    selfTest(samples int, p genParams) error
}
```
- `tarpit`: `AxisVelocity`, `minTier=TierContain`.
- `fakeMaze`: `AxisPoison|AxisOppCost`, `minTier=TierContain` (kept; the maze is the directory-tree opportunity-cost flavor).
- `tokenBait`: `AxisOppCost`, `minTier=TierJail`.
- `poisonField` (M2): `AxisPoison`, `minTier=TierContain`.
- (M4) exploit-bait, (M5) op-exposure: `AxisExploitBurn`/`AxisOpExposure`, `minTier=TierJail`.

Replace `selectGenerator`/`tierIntensity`/`floorMax` with:
```go
func (a *BoundedAttritor) selectAxes(floor contract.StingFloor, t contract.Tier) []generator
```
which intersects `floor.Axes()` with the tier-permitted generators (`g.minTier() <= t`) and returns the SET of active generators. `New()` constructs only generators whose `axis()` is in `floor.Axes()` (so the 3 structural "aggressive never silent" guards hold: `FloorPassive` is the zero value; higher generators are not even constructed; `selectAxes` has no upward default arm).

**Composition (D3):** `stream` changes from a single `gen generator` to `gens []generator`; it rotates the active generator per `cursor.chunkIdx` (`gens[chunkIdx % len(gens)]`). All generators share ONE `cursor` and ONE per-flow `Budget` envelope (NOT Budget-per-axis), so composition does not multiply defender bytes/hold. Per-chunk `tokenProxy(...)` MUST key off the CURRENTLY-active generator's `mechanism()`, not a frozen `Outcome.Mechanism`. `Outcome.Mechanism` is set at `Open` to the dominant/first-active generator (D4) for KPI stability; `Outcome.Axes` is set to the union of the active set's axes. Re-assert `BenchmarkNextAllocsFlat` across rotation (still O(1) allocs/chunk).

### 2.4 the FloorAggressive+TierContain cell

The original (floor,tier) table left this undefined. **Define it:** `FloorAggressive+TierContain` selects `{tarpit, fakeMaze, poisonField}` (velocity + poison; opportunity-cost generators gate at `minTier=TierJail`). `tokenBait`/exploit-bait/op-exposure remain Tier-3-only via `minTier`.

### 2.5 deployment-local-only guard on axes 4/5 fields

`ExploitsObserved`/`ExposureSignals` may be persisted to the LOCAL durable store (rule 5) but must NOT reach any cross-boundary path until `internal/intelligence/network` (the default-deny egress filter) ships and clears them (rule 9). Add a comment + a guard test mirroring the "`DoneReason` not persisted" discipline. M0 ships the fields zero-valued (no generator populates them yet).

---

## 3. Axis 1 — Velocity disruption (adaptive/escalating latency)  [M1]

**Spec:** "Adaptive latency that increases the more a flow probes, so persistence is punished … self-hosting-proof because it costs the attacker wall-clock time no matter who owns the GPU."

**Current state (verified):** `dripDelay(seed, idx, d)` = `MinDelay + h%(MaxDelay-MinDelay)`, `h = mix(seed, idx+0xd31)` — keyed only on `(seed, chunkIdx)`, ignores `cursor.depth` and any persistence counter. All three generators call it. `cursor.chunkIdx` increments unconditionally and is never reset (depth resets at `MaxDepth`, chunkIdx does not) — so **`chunkIdx` is already a monotonic per-flow probe counter**; no new cursor field needed (O(1)/fixed-size cursor preserved).

**Design:**
- **Adaptive delay** — `adaptiveDelay(seed uint64, idx int, d DripParams, persist int) time.Duration`. A bounded LINEAR ramp (D5): `lo := MinDelay + ramp(persist, d.RampSaturate, MaxDelay-MinDelay)`, then jitter deterministically within `[lo, MaxDelay]` via the existing `mix()`. `ramp` is pure, O(1), `ramp(0)=0`, `ramp(persist>=saturate)=span` exactly, **division-safe** (`RampSaturate` normalized to a positive default before any `*min(persist,sat)/sat`). All three generators switch from `dripDelay` to `adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)` so velocity escalation is the shared substrate that composes with the other axes.
- **`RampSaturate`** — new `DripParams` field, `Normalized()` floors zero/negative to a SMALL conservative default (D5: 8–12, NOT 64), so escalation is visible within the inline 8 s / 0.5–1 s budget and a misconfig can never mean 0-escalation or a divide-by-zero. Exposed in `config/canarysting.example.yaml` `sting_drip.ramp_saturate`; wired in `cmd/envoy-adapter/main.go`'s `DripParams` literal. `Drip` is bound at the composition root and never on the wire — **NOT a proto change.**
- **Time-to-disengage** — see §8 (engagement). M1 lands the `adaptiveDelay` mechanism that MAKES disengage-time meaningful; the metric field + classifier are M0/M8.

**Honest framing of escalation visibility (verifier correction):** on the ONLY delivered transport (inline `ImmediateResponse`, 8 s `AttritionMaxHold`, 0.5–1 s drip), effective ramp spans ~8–16 chunks; a 64-chunk saturate is unreachable. Ship `RampSaturate` default small (D5). Do NOT cite a 120 s async path as if it exists — there is no async attrition driver in the codebase (only the inline pump and the clock-free selfcheck harnesses). A future async/streamed transport is where wide escalation becomes visible; ship the mechanism as correct-and-forward-looking.

**Detectability note (verifier):** monotonically increasing per-chunk delay is exactly the signal a capable agent uses to DETECT a tarpit and disengage early — escalation may REDUCE time-to-disengage rather than raise total cost. Interpret the time-to-disengage metric as a believability KPI as well as a cost KPI; the ramp shape is a future D2-profiler tuning dial.

**Net-new:** `adaptiveDelay`, `ramp`, `RampSaturate`. **Refactor:** the three `dripDelay` call sites; `TestDelayIsClamped` updated to sweep `adaptiveDelay` across `persist∈[0,>saturate]` (keep `dripDelay` only as a `persist=0` wrapper if needed for compile, preferred is to update the test).

**Effort: M.**

---

## 4. Axis 2 — Information poisoning (core differentiated mechanism)  [M2]

**Spec:** "Serve plausible-but-false environmental state: fake credentials, fabricated internal hostnames, bogus network topology, decoy secrets that look real, fake 'successful' results … the agent acts on bad intelligence … Treat this as the core differentiated mechanism." Plausible under inspection (engagement contest). Natural Tier-2 action at `FloorModerate`.

**Current state (verified):** `fakeMaze` is the only axis-2 generator; its pages are idempotent per `(seed,path)` but there is no stable host/credential set to pivot within — `mazePathFor` derives a fresh random path each chunk, and `envLeaf` emits one hardcoded `postgres://db.payments.example` + EXAMPLE creds identical on every page. Not a coherent environment.

**Design — `poisonField{}` generator (`MechPoison="poison_field"`, `AxisPoison`, `FloorModerate`, `minTier=TierContain`):** renders a SINGLE internally-consistent fabricated environment per flow, keyed by `cursor.seed`: a small fixed set of fabricated reserved hosts (via `internal/harmless/decoy`), a credential set (EXAMPLE namespace) that references those same hosts, a topology/inventory page listing those same hosts, and a fake-success result page — so re-fetching any part is consistent with the rest (the "plausible under inspection" requirement). Iterative, O(1)/chunk, depth-bounded by an explicit `cursor.poisonStage int` (fixed-size cursor preserved), every chunk `truncateAtLine` + `harmless.CrossScan`-clean.

**Consistency without breaking O(1) (verifier correction):** the fabricated host set is **recomputed deterministically per chunk from the seed** (`hosts[i] = decoy.ReservedHost(mix(seed, i))`), NEVER stored as a per-flow slice — the cross-page-consistency requirement must not silently grow the fixed-size cursor. `genSelfTest` adds a no-heap-growth/alloc assertion across the stage walk. `poisonField` has a NATURAL END (bounded N-page set): it returns `ok=false` at the end of the stage walk, so the stream reports `DoneComplete`, not `DoneFlowBudget`.

**Reaction signal (cost-meter peer of `DepthReached`):** `Outcome.PoisonClass string` (`"" | "credential" | "topology" | "success"`) + `Outcome.PoisonReached int` (deepest stage consumed), set at stream construction/advance, copied at the composition root. This is how axis 2 "composes with the intelligence layer" WITHOUT attrition importing intelligence — the reaction travels out as a plain contract value. **`PoisonReached` is NOT time-to-disengage** and must not be sold as such on the dashboard; it only measures how far the linear stage walk advanced (an indifferent crawler also advances it). Known measurement gap: true plausibility/efficacy stays unmeasured until the engagement metric (§8) lands.

**Keep `fakeMaze` AND `poisonField`:** two small bounded generators self-test/reason more cleanly than one large one; `selectAxes` picks `poisonField` for `AxisPoison` at Tier 2 while `fakeMaze` carries `AxisPoison|AxisOppCost`.

**LIVE-window flip (D8):** at `FloorModerate`+`TierContain` the rotated active set now includes `poison_field`, so the headline Tier-2 demo mechanism changes from `fake_tree`. Get Daniel's signoff; the recon-feed/by-mechanism rollup/screenshots key on `fake_tree`.

**Net-new:** `internal/harmless/decoy` (shared with M0), `poisonField`, `cursor.poisonStage`, `MechPoison`, `PoisonClass`/`PoisonReached` (carried by the M0 contract change). **Refactor:** `fakeMaze`/`envLeaf` consume `internal/harmless/decoy`; catalog consumes it too; the selection/floor guard tests updated to the axis-set model (see M0).

**Effort: L.**

---

## 5. Axis 3 — Opportunity-cost injection (reframe of token-burning)  [M3]

**Spec:** "Consume the attacker's finite capacity … subsumes the original token-burning mechanism but frames it correctly: opportunity cost on constrained capacity, which lands against metered, self-hosted, and stolen-compute attackers alike. Against a metered attacker it is also a direct dollar cost; do not lead with that, since it is the weakest framing." `tokenBait`/`fakeMaze` escalate at Tier 2→3, FloorAggressive.

**Current state (verified):** the MECHANISM is shipped and correct — `tokenBait` (parser-hostile bait), `fakeMaze` (recursive structure), `tokenProxy` (chars/4 plain, ×3 bait) with the "Pricing → dollars is D3's job … never over-claims" comment. The gap is purely FRAMING/METRIC/LABELING: `cost.go:42` literally says tiers 0–1 "impose no economic cost"; `AttackerCost.tsx:62` tag is `'attrition · economics'`; `IntelKPIView` and `CostView` lead with tokens.

**Design — reframe-first, minimal generation, ZERO new contract change beyond M0:**
- **No generator rewrite.** Keep `tokenProxy` math and `TokenCostProxy`/`TokensBurned` field names UNCHANGED — a rename is a non-forward-safe gob migration + a 6-place proto/convert lockstep that would zero live-M7-window cost. ADD-only + comment/UI relabel (adopt D3=KEEP, D4=REUSE as mandatory).
- **Axis attribution is the M0 `Axes` bitset**, read directly by intelligence/dashboard (D4). `fakeMaze` carries `AxisPoison|AxisOppCost`; `tokenBait` carries `AxisOppCost`; `tarpit` carries `AxisVelocity`. The per-axis breakdown is INTENTIONALLY OVERLAPPING (a mechanism can land on multiple axes) and must NEVER be rendered as a partition that sums to the flat total — bake this into the view doc + frontend copy.
- **Reframe (presentation + comments):** `cost/cost.go:42` "impose no economic cost" → "impose no opportunity/attrition cost" (REQUIRED test, not optional — a guard so the framing cannot silently regress). `AttackerCost.tsx` tag `'attrition · economics'` → `'attrition · opportunity cost'`; relabel "tokens burned" with an explicit PROXY/ESTIMATE qualifier and demote it below time-imposed; reword the cost-note to the velocity-dependent-adversary framing (kept as the intended cost MODEL, not a measured fact — the platform cannot observe the attacker's real allocation). Subordinate the M9 `RealMeter` ($) visually but keep it (it is the only ground-truth number; proxy and real stay SEPARATE, never merged).
- **`cost.Summary` per-axis subtotals** (`AxisTimeSec[5]`/`AxisTokens[5]`/`AxisCount[5]`) computed by classifying each event's `Axes` bits, folded into the EXISTING event pass (no extra full scan). Pure intelligence-side, single-scope.

**Net-new:** none in attrition generation. **Refactor:** comment/label reframes; `cost.Summary` subtotals; `views`/`types.ts` per-axis + lead-metric reorder (Go + TS in lockstep, `make check` + `tsc/lint/build`).

**Effort: M.**

---

## 6. Axis 4 — Exploit-inventory burn  [M4 — net-new, gated on egress filter]

**Spec:** "Make decoys attractive enough that the attacker spends real exploits on them … A fresh exploit fired at a fake service is both intelligence (the platform learns it) and a forced choice … independent of compute entirely."

**Design:**
- **Attractive decoy services** in the negative space, generated via `internal/harmless/decoy` (`ServiceLocator`, fake endpoints/buckets) so a touch is the trigger (rule 8 — the fake service is reachable, a touch escalates). Exploit-bait generator at `FloorAggressive`/`minTier=TierJail` (`MechExploitBait`, `AxisExploitBurn`). Bounded/harmless/iterative exactly like the others; self-tested at construction.
- **Capture the fired exploit as intelligence** — the driver (`pump.go`) digests the inbound request shape (method, declared content-type, structural markers) into a `contract.DriverObservation` (counts/bools/enums ONLY — no raw bytes/addresses, §2.2) and feeds it via the no-op `Stream.Observe` seam. The reaction surfaces as `Outcome.ExploitsObserved int64` (a count), copied at the composition root. **Capture is observation INSIDE the perimeter; the platform NEVER fires the exploit back, never reaches the attacker's systems** (no hack-back).
- **Cross-boundary use is BLOCKED** on `internal/intelligence/network` (the default-deny egress filter, currently a `doc.go` stub). `ExploitsObserved` is deployment-local-only until that filter ships and clears it (rule 9; §2.5 guard).

**Net-new:** exploit-bait generator, `MechExploitBait`, `ExploitsObserved`, the `Observe`→digest path. **Depends on:** M0 (fields/seam/decoy pkg) + a built egress filter for any feed use.

**Effort: L.**

---

## 7. Axis 5 — Operational exposure  [M5 — net-new, Tier-3 only, sharpest no-hack-back tension]

**Spec:** "When a flow is confirmed hostile, raise the attacker's operational risk: force infrastructure to reveal itself (callbacks to controlled endpoints), fingerprint the tooling, capture C2 patterns."

**CORE-RULE CORRECTION (verifier major finding — the original safety story was WRONG):** the spine design claimed `harmless.AllHostsReserved` "enforces" axis-5 callback safety. That conflates two unrelated things. `harmless.AllHostsReserved` only scans SERVED PAYLOAD bytes to assert embedded URL hosts are RFC-2606/5737/3849 NON-ROUTABLE; it has zero bearing on any outbound connection and cannot make a routable C2-capture sink "safe." Worse, a real callback-capture sink must be ROUTABLE to receive a callback — directly contradicting `AllHostsReserved`.

**Corrected axis-5 design — PASSIVE, in-perimeter only:**
- Operational exposure is **PASSIVE intelligence capture**, gated to **Tier-3 confirmed-hostile** flows only (`minTier=TierJail`, `FloorAggressive`). The defender NEVER initiates an outbound connection toward attacker infrastructure (`docs/STING.md` "Reach back into the attacker's own systems … is not outbound retaliation / hack-back").
- "Callbacks to controlled endpoints" means: attrition serves bait whose embedded locators point at **defender-owned, in-perimeter decoy sinks** that the attacker's OWN tooling may connect INTO. The defender owns and observes the sink; it never dials out.
- A real capture sink is routable and therefore CANNOT pass `harmless.AllHostsReserved`. **Axis-5 bait that embeds a live in-perimeter capture host must use a DIFFERENT, explicitly-reviewed harmlessness basis** (in-perimeter + defender-owned + not-attacker-reachable), NOT `CrossScan`'s reserved-host rule. This is a deliberate, separately-signed-off safety predicate (a new milestone deliverable), distinct from the universal `CrossScan` gate the other axes use.
- Tooling/C2 fingerprint capture is the `DriverObservation` digest (counts/bools/enums) feeding `Outcome.ExposureSignals int64`. Captured raw locally (rule 5); any cross-boundary form is anonymized through the egress filter (rule 9). **Cross-boundary use is BLOCKED** on `internal/intelligence/network` (unbuilt).
- Tier-3 fail-closed preserved: an engine outage must not release a confirmed-malicious flow.

**Net-new:** op-exposure generator, the in-perimeter-sink harmlessness predicate (separate review), `MechOpExposure`, `ExposureSignals`. **Depends on:** M0 + the egress filter + the new harmlessness predicate's review. See §14 for the full no-hack-back / rule-9 treatment.

**Effort: XL** (the new harmlessness basis + in-perimeter sink infrastructure + egress filter dependency make this the heaviest, riskiest axis).

---

## 8. Engagement contest + cost-meter / dashboard reframe  [M8 metric carrier in M0; presentation in M3]

**Spec:** "measure time-to-disengage as a core attrition metric"; fake state "internally consistent and plausible under an agent's inspection." Five-axis cost attribution.

**Current state (verified):** `DoneReason` is computed (and travels on `contract.StingOutcome`/proto) but `boltevents.AmendOutcome` DROPS it and `intelligence.StingOutcome` omits it — the one disengage signal is lost at the durable boundary. No engagement/time-to-disengage/plausibility/per-axis field anywhere. Correction to a verifier-flagged overstatement: the `AttackerCost` hero is NOT $-led today (its lead is the active-flow COUNT; time-imposed already renders first in cost-metrics) — the $-framing is in the tag, the `RealMeter`, and the `cost.go:42` comment, NOT the hero number; `doc.go` does NOT contain "economic cost."

### 8.1 Engagement / time-to-disengage (corrected)

- **Source (D6, verifier correction):** derive from `Sting.TimeHeldSec` (REAL imposed hold, post-`43102ab`) summed across the session's outcomes + the persisted disengage classifier — NOT from `LastSeen−FirstSeen` of event timestamps. For a single-touch tarpitted flow `LastSeen−FirstSeen ≈ 0` even after minutes of hold (events are written only on canary TOUCHES, rule 8). Keep `LastSeen−FirstSeen` as a SEPARATELY-labelled "session span / persistence" metric.
- **Persist the classifier:** `boltevents.AmendOutcome` (which today copies only 6 cost fields) gains `Axes` + `DisengageReason int` (gob-forward-safe, old blobs zero-fill, no schema bump, no `OutcomeAmendmentMarker` collision).
- **Classify in the adapter (D7):** `holdCtx.Err()==context.Canceled` (before any defender bound) ⇒ attacker-disengaged ⇒ `TimeToDisengageSec = TimeHeldSec`. `DoneComplete` ⇒ generator-exhausted ⇒ 0. `DoneFlowBudget`/`DoneGlobalCeiling`/deadline-cap ⇒ defender-capped ⇒ 0 (honest empty). NEVER mislabel a defender-stop as an attacker disengage. `stream.Next` cannot do this (only sees `ctx.Done()`); the adapter holds `holdCtx`. This is a transport-fact mapping, not detection (rule 1 safe).
- **Rollups:** `cost.Summary` gains `EngagementMedianSec`, `EngagementP90Sec`, `DisengagedEarly`, `GeneratorExhausted`, `DefenderCapped` (≥3 buckets, not a single "defender released" bucket — verifier correction). `views.EngagementView{MedianSec, P90Sec, LongestSec, DisengagedEarlyFraction, BelievedFraction}` derived in a new `buildEngagement`. Median/p90 make `Rollup` O(N log N) with a per-session duration slice — state the bound, keep it allocation-conscious.

### 8.2 Plausibility proxy (corrected)

`DepthReached` is idempotent per-path (cookie-seeded `mazeNode`) — "re-fetches the same path and goes deeper" is contradictory. **Corrected definition:** a session that reached `DepthReached >= k` via DEEPER fetches AND was NOT attacker-disengaged-early is evidence the deception held. No new attrition field beyond `DepthReached` (exists) + `DisengageReason` (added).

### 8.3 Drift-guard naming (build-breaking — resolve concretely)

`TestOutcomeMapsToStingOutcome` reflects over `intelligence.StingOutcome` and fails if any field lacks a SAME-NAMED field on `attrition.Outcome`. So `Axes` and the disengage field MUST exist by the same name on `attrition.Outcome`. **Resolution:** add `DisengageReason int` to BOTH `attrition.Outcome` and `intelligence.StingOutcome` (set `DisengageReason = int(Reason)` at finish; leave `attrition.Outcome.Reason` as the internal control-flow field), and `Axes uint32` to both. Without this the build fails. Note: `convert.go` is NOT reflection-guarded (it threads fields by hand + a literal-DeepEqual round-trip test that PASSES when both sides are zero) — so the new fields MUST be added explicitly to the proto, `convert.go` both directions, AND the `convert_test.go` literals, or they silently zero over gRPC.

### 8.4 Dashboard reframe (presentation)

`AttackerCost.tsx` tag → `'attrition · opportunity cost'`; add an engagement stat (median time-to-disengage / longest-held) and a per-axis OVERLAPPING bar set; subordinate `RealMeter`; honest empty states ("ATTRITION READY" / "—" / "single-axis attrition", no fake bars). `types.ts` mirrors `EngagementView`/`AxisCostView` 1:1 (Go + TS together).

**Detect-threshold (D10):** the `BelievedFraction` "believed-longer-than-detect" threshold is a static documented views constant or operator config — NEVER "median legit think-time" (legit traffic produces no events, rule 8).

**Effort: L** (carrier in M0; presentation/rollups here).

---

## 9. Cross-cutting contract & architecture

### 9.1 The single rule-3 `StingOutcome` change (M0-owned)

Four lockstep mirror sites + the gob store + the composition-root copy. Verified the exact six real sites a field must thread through:
1. `internal/sting/attrition/cost.go` — `Outcome`.
2. `cmd/envoy-adapter/main.go` `OnOutcome` — the `attrition.Outcome → contract.StingOutcome` copy (the original spine refactor list OMITTED this; ADD it — a missed field silently drops here).
3. `internal/contract/contract.go` — `StingOutcome`.
4. `internal/intelligence/event.go` — `StingOutcome` (mirror; drift-guard).
5. `api/proto/contract.proto` — `StingOutcome` fields 8+ (proto 1–7 used, `done_reason=7`; next free is 8) + `make proto` regen of `api/gen/*.pb.go`.
6. `api/convert/convert.go` — `StingOutcomeToProto`/`FromProto` BOTH directions + `convert_test.go` literals; AND `boltevents.AmendOutcome` (must add the new fields to the persisted `intelligence.StingOutcome` literal or they never reach `cost.Rollup`/dashboard).

Fields added (D2): `Axes uint32` (8), `TimeToDisengageSec double` (9), `PoisonClass string` (10), `PoisonReached int32` (11), `ExploitsObserved int64` (12), `ExposureSignals int64` (13), `DisengageReason int32` (14). All additive ⇒ gob-forward-safe (old blobs zero-fill, live-M7-window-safe) and proto3-forward-safe. None named `OutcomeAmendmentMarker` (static guard preserved). The four new fields go on the EXISTING `AmendOutcome` gob struct, NOT a new discriminated blob type, so `TestEventTypeHasNoOutcomeDiscriminatorField` stays green.

### 9.2 Import-graph & layer seams (unchanged)

`attrition` still imports ONLY `{internal/contract, internal/harmless, internal/harmless/decoy, stdlib}` — `harmless/decoy` is inside the allowed set, so `TestAttritionImportsOnlyContractAndHarmless` stays green (update it to permit the `harmless/decoy` subpath if it pins exact strings). Axis classification (`AxesForMechanism`) lives in attrition (pure, stdlib + contract). Per-axis/engagement signals flow OUT only as plain `contract` values copied at the composition root — attrition NEVER imports intelligence (the intelligence-side classifier, if any, must never be imported by attrition). `DriverObservation` enters via the no-op `Stream.Observe` seam; the adapter stays thin (a transport-fact digest, no decision logic). Engine unchanged (emits only `Tier`; `StingFloor` stays composition-root-bound).

### 9.3 Dashboard wire contract

`views.*` + `dashboard/app/lib/types.ts` is a strict 1:1 snake_case mirror; every Go view-struct change ships with the TS edit and the frontend gate (`npx tsc --noEmit` / `npm run lint` / `npm run build`). New `Mech*` labels flow into `drilldown.ByMechanism` automatically (groups by the `Sting.Mechanism` string).

---

## 10. Refactors to already-delivered code (consolidated; net-new vs refactor)

| File | Change | New / Refactor |
|---|---|---|
| `internal/harmless/decoy/decoy.go` (+`_test.go`) | NEW stdlib-only deterministic-seed harmless body builders + CrossScan-by-construction self-test | NEW |
| `internal/contract/contract.go` | `AttritionAxis` bitset + `StingFloor.Axes()` + `DriverObservation` (raw-free) + 7 new `StingOutcome` fields | NEW + Refactor |
| `internal/sting/attrition/generators.go` | `generator.axis()/minTier()`; `tarpit/fakeMaze/tokenBait` implement them; `envLeaf/exampleKeyID/exampleSecret` → `internal/harmless/decoy`; `dripDelay`→`adaptiveDelay`+`ramp`; add `poisonField`+`cursor.poisonStage` (M2) | Refactor + NEW |
| `internal/sting/attrition/attrition.go` | retire `selectGenerator/tierIntensity/floorMax` → `selectAxes` (returns SET); `stream.gen`→`stream.gens` (rotate per chunkIdx, shared cursor+Budget); set `Outcome.Axes`; no-op `Stream.Observe` | Refactor |
| `internal/sting/attrition/budget.go` | `DripParams.RampSaturate` + `Normalized()` floor (small default, division-safe) | NEW field |
| `internal/sting/attrition/cost.go` | new `Outcome` fields + `DisengageReason`; `MechPoison/MechExploitBait/MechOpExposure` (ADD); `AxesForMechanism`; per-chunk `tokenProxy` keyed off active gen; reframe doc comments | Refactor + NEW |
| `internal/sting/attrition/attrition_test.go` | RETIRE `TestFloorMaxMatchesConstructedGenerators` (index-identity dies under the set model) + rewrite `TestGeneratorSelectionTable/TestFloorIsRespected/TestTokenBaitNotConstructedBelowAggressive` to assert per-floor axis SETS; keep `TestAggressiveIsNeverSilentDefault`/`TestNoTierAloneRaisesFloor` re-expressed against axes; extend `TestOutcomeMapsToStingOutcome`; re-assert `BenchmarkNextAllocsFlat` across rotation | Refactor |
| `adapters/envoy/pump.go` | classify disengage from `holdCtx.Err()` (Canceled vs DeadlineExceeded); feed `DriverObservation` digest into `Stream.Observe` | Refactor |
| `cmd/envoy-adapter/main.go` | `RampSaturate` in `DripParams`; copy ALL new fields in `OnOutcome` | Refactor |
| `internal/intelligence/event.go` | mirror new `StingOutcome` fields + `DisengageReason` | Refactor |
| `internal/intelligence/boltevents/store.go` | `AmendOutcome` persists `Axes`/`DisengageReason`/poison/exploit/exposure fields; legacy-blob zero-fill test | Refactor |
| `api/proto/contract.proto` + `api/gen/*` + `api/convert/convert.go` (+`_test.go`) | fields 8–14; thread BOTH directions; explicit round-trip literals | Refactor |
| `internal/intelligence/cost/cost.go` (+`doc.go`) | reframe "economic cost"→"opportunity/attrition cost" (REQUIRED guard test); per-axis subtotals; engagement aggregates (O(N log N) bound) | Refactor + NEW |
| `internal/dashboard/backend/views/{views,drilldown}.go` | `EngagementView`/`AxisCostView`; lead-metric reorder; overlapping per-axis (never a partition) | Refactor + NEW |
| `internal/canary/catalog/generators.go` | consume `internal/harmless/decoy` (kill duplication); keep `TestCanaryDoesNotImportEngine` green | Refactor |
| `dashboard/app/components/{AttackerCost,CostView,AdversaryIntelligence}.tsx` + `lib/types.ts` | tag/label reframe; engagement + per-axis render; 1:1 TS mirror | Refactor |
| `cmd/sting-selfcheck` / `cmd/envoy-selfcheck` | update to the axis-aware API; per-axis ledger | Refactor |
| `config/canarysting.example.yaml` | `sting_drip.ramp_saturate` documented default | NEW |

---

## 11. Sequenced milestone plan

**Milestone-label namespacing (read first):** the `M0`–`M5` (and the `M8` engagement-carrier reference in §8) labels in THIS document are **attrition-internal** and refer ONLY to the attrition build sequence below. They are **not** the ROADMAP milestones — `docs/ROADMAP.md` already uses `M0`–`M11` for delivered/forward roadmap work (e.g. ROADMAP `M0` = repo/dev infra DONE, ROADMAP `M8` = the Next.js dashboard DONE). To avoid that collision, ROADMAP carries this build as **Track E, namespaced `AX0`–`AX5`** (1:1 with `M0`–`M5` here: `M0`→`AX0` spine, `M1`→`AX1` velocity, `M2`→`AX2` poison, `M3`→`AX3` opportunity-cost/reframe, `M4`→`AX4` exploit-burn, `M5`→`AX5` op-exposure). When citing this plan from ROADMAP / `docs/D2_D5_DESIGN.md` / the dashboard plan, use the `AX*` names; this doc remains the authoritative source for the build content.

| Milestone | Summary | Depends on | Effort |
|---|---|---|---|
| **M0 — Integration spine** | `internal/harmless/decoy`; `AttritionAxis`+`StingFloor.Axes()`+raw-free `DriverObservation`; the single rule-3 `StingOutcome` change (7 fields, 6 sites); `selectAxes` (SET, rotate per chunk, shared cursor+Budget); no-op `Stream.Observe`; `cost.Summary` per-axis carriers; retire/rewrite the guard tests. The ONLY contract change. | — | L |
| **M1 — Velocity adaptive latency** | `adaptiveDelay`+`ramp`+`RampSaturate` (small default); apply to all generators; `TimeToDisengageSec` populated via the M0 carrier + D7 adapter classify. | M0 (shares stream/cursor; sequence alongside) | M |
| **M2 — Information poisoning** | `poisonField` (consistent fabricated environment, recompute-not-store hosts, natural-end `DoneComplete`); `PoisonClass`/`PoisonReached`; D8 live-flip signoff. | M0 (decoy pkg + fields + selectAxes) | L |
| **M3 — Opportunity-cost + reframe** | No generator rewrite; axis attribution via `Axes`; reframe comments/labels/dashboard (lead time/engagement, demote tokens, subordinate `RealMeter`); per-axis OVERLAPPING bars; engagement rollups + views; required anti-regression framing test. | M0, M1 (engagement fields) | M |
| **M4 — Exploit-inventory burn** | Attractive decoy services (negative space, rule-8 touch trigger); exploit-bait generator (FloorAggressive/Tier3); `ExploitsObserved` via `Observe` digest; NEVER fire back. | M0; egress filter for any cross-boundary use | L |
| **M5 — Operational exposure** | PASSIVE Tier-3-only capture; defender-owned IN-PERIMETER sinks (never dial out); NEW separately-reviewed in-perimeter harmlessness predicate; `ExposureSignals`; fail-closed at T3. | M0; `internal/intelligence/network` egress filter; new harmlessness predicate review | XL |

**Egress-filter prerequisite (rule 9):** axes 4 and 5 produce intelligence (exploit signatures, tooling/C2 fingerprints). `internal/intelligence/network` (the single default-deny egress chokepoint) does NOT exist (it is a `doc.go` stub). M4/M5 may persist these signals LOCALLY (rule 5) but NOTHING may cross a deployment boundary until that filter is built, default-deny, per-field-justified. Building it is an implicit prerequisite of any axis-4/5 feed use and should be its own scoped task.

---

## 12. Test / verification plan

**Spine (M0):**
- `TestStingFloorAxesMap` (passive=velocity / moderate=+poison / aggressive=+oppCost+exploit+opExposure).
- `TestSelectAxesComposition` (FloorAggressive+TierJail accrues multiple axes across chunks; FloorPassive only velocity); `BenchmarkNextAllocsFlat` re-asserted O(1) across rotation; shared-cursor/shared-Budget assertion (composition does not multiply defender bytes/hold).
- Rewrite `TestGeneratorSelectionTable`/`TestFloorIsRespected`/`TestTokenBaitNotConstructedBelowAggressive` to the axis-set model; RETIRE `TestFloorMaxMatchesConstructedGenerators`; keep `TestAggressiveIsNeverSilentDefault`/`TestNoTierAloneRaisesFloor`.
- `TestDriverObservationCarriesNoRawData` (no `[]byte`/address field — rule 9).
- `internal/harmless/decoy`: `TestDecoyBuildersHarmlessByConstruction` + stdlib-only import guard.
- `api/convert` round-trip + explicit `convert_test.go` literals for ALL new fields (no reflection guard catches a missed proto field).
- `boltevents`: legacy-blob zero-fill decode test; `TestEventTypeHasNoOutcomeDiscriminatorField` stays green.
- `TestOutcomeMapsToStingOutcome` extended for the new same-named fields.

**Velocity (M1):** `TestAdaptiveDelayEscalatesWithPersistence`; `TestAdaptiveDelayStaysWithinBand` (escalation never exceeds `MaxDelay`); `ramp(0)==0`, `ramp(>=saturate)==span`, division-safe; `TestAdaptiveLatencyKeepsDefenderFlat` (TimeHeld climbs faster late-flow, allocs flat); `TestDisengageRecordsTimeToDisengage` (attacker-disconnect ⇒ `TimeToDisengageSec==TimeHeldSec>0`; `DoneFlowBudget`/deadline/governor-kill ⇒ 0).

**Info poisoning (M2):** `TestPoisonFieldIsInternallyConsistent` (diff the host SET extracted from each stage's bytes across a multi-stage walk of one cursor — equality, not single-page); `TestPoisonFieldSelectedAtModerateTier2`; `TestPoisonFieldBoundedAndHarmless` (CrossScan every chunk, marker present, natural-end `DoneComplete`); no-heap-growth across the stage walk.

**Opportunity-cost / reframe (M3):** `AxesForMechanism` table; `Summary` per-axis subtotals (overlapping, NOT summing to total); REQUIRED guard test that `cost.go` no longer contains "no economic cost"; frontend fixture render shows `'opportunity cost'` tag + tokens not the lead.

**Engagement (M8 in M0/M3):** `buildEngagement` from `TimeHeldSec`+`DisengageReason` (NOT timestamp span); 3-bucket classification; honest empty state; plausibility proxy (deeper fetches + not-disengaged-early).

**Axes 4/5 (M4/M5):** bounded/harmless exploit-bait + op-exposure generators self-test; `ExploitsObserved`/`ExposureSignals` populated from `Observe` digest; deployment-local-only guard (no cross-boundary read until egress filter); op-exposure in-perimeter harmlessness predicate test; Tier-3-only + fail-closed.

**Gates:** `make check` (fmt-check vet build test selfcheck) EXIT=0 per milestone; frontend `tsc/lint/build` green when `types.ts` changes; `make proto` regen committed with the contract change.

---

## 13. Risks

- **LIVE M7 window (highest):** M0 + M1/M2 touch the engine + adapter + durable store. Additive gob/proto3 is forward-safe (old blobs zero-fill), but engine + envoy-adapter must redeploy in LOCKSTEP, and the known **adapter-restart breaks cross-host socket-cookie resolution** (eBPF attach lifecycle) — a full box REBOOT is currently required for clean re-attach. Sequence every on-box deploy WITH Daniel; never hot-restart the adapter alone. The proper fix (idempotent eBPF detach/re-attach) is an out-of-band follow-up.
- **D8 demo flip:** Tier-2 mechanism changes `fake_tree`→`poison_field` on the live window — recon-feed/by-mechanism/screenshots key on `fake_tree`. Founder signoff required.
- **Escalation visibility:** on the only delivered transport (inline 8 s hold), ramp headroom is ~8–16 chunks; default `RampSaturate` small or escalation is invisible. Do NOT promise the (nonexistent) async path.
- **Drift-guard naming is build-breaking:** `Axes`/`DisengageReason` must be same-named on `attrition.Outcome` AND `intelligence.StingOutcome` or the build fails. `convert.go` has NO reflection guard — a missed proto/convert field silently zeros over gRPC; explicit round-trip literals are mandatory.
- **Per-axis attribution is COARSE at first** (which-axes-active, not exact byte/token split per axis, since one stream runs one generator per chunk) — label the dashboard "axes active," NEVER a 100% partition; overlapping by design.
- **Field-rename trap:** renaming `TokenCostProxy`/`TokensBurned` is a non-forward-safe gob migration + 6-place lockstep that would zero live cost — ADD-only, never rename.
- **Over-claiming the reframe:** "compute burned"/"every cycle on fake state" is the intended cost MODEL, not a measured fact; keep proxy/estimate qualifiers; `RealMeter` ($) stays the only ground-truth number, separate, subordinated.
- **Axis-5 no-hack-back (see §14):** the single most dangerous design surface; the original safety rationale was wrong; the corrected passive/in-perimeter design + a new reviewed harmlessness predicate are mandatory before any axis-5 code.

---

## 14. Axis 5 (operational exposure) — explicit no-hack-back & rule-9 constraints

This section is load-bearing; axis 5 carries the sharpest tension with `docs/STING.md` "What the sting layer must never do."

1. **No hack-back (hard line).** `docs/STING.md`: "Reach back into the attacker's own systems. Attrition imposes cost on traffic *inside your perimeter that is touching things it never should* — it is not outbound retaliation / hack-back." Axis 5 is therefore **PASSIVE intelligence capture only**: the defender NEVER initiates an outbound connection toward attacker infrastructure, never fires a probe/exploit back, never beacons.

2. **"Callbacks to controlled endpoints" — the only compliant reading.** Attrition serves bait whose embedded locators point at **defender-owned, in-perimeter decoy sinks**. The attacker's OWN tooling may connect INTO those sinks; the defender observes the inbound connection. The defender owns the sink, inside the perimeter, and never dials out. There is no enumerated chained-credential mechanism (ARCHITECTURE §11 / `docs/CANARY.md` — the patent path); placements stay FLAT.

3. **`harmless.AllHostsReserved` does NOT govern axis 5 (corrected).** `AllHostsReserved`/`CrossScan` only validate that hosts embedded in SERVED PAYLOAD are RFC-reserved/non-routable; they govern nothing outbound and cannot make a routable capture sink "safe." A real in-perimeter capture sink is routable and therefore CANNOT pass `AllHostsReserved`. Axis-5 bait that embeds a live in-perimeter capture host MUST be validated by a **NEW, separately-reviewed harmlessness predicate** asserting the host is (a) inside the defender's own perimeter, (b) defender-owned, (c) not attacker-reachable/not the attacker's system, (d) never a prompt-injection/beacon to a third party. This predicate is a distinct M5 deliverable with its own founder review — it does NOT reuse the universal `CrossScan` gate, and the other four axes continue to use `CrossScan` unchanged.

4. **Rule 9 (egress).** Tooling/C2 fingerprints and exploit signatures are captured RAW only LOCALLY (rule 5, scope-isolated). They become `Outcome.ExposureSignals`/`ExploitsObserved` (structured COUNT scalars — no raw bytes/addresses, no decoy contents) on the durable event. They may cross a deployment boundary ONLY after `internal/intelligence/network` (the single default-deny egress filter — currently unbuilt) is built and per-field-justifies each crossing. M0's deployment-local-only guard (§2.5) enforces this until then.

5. **Rule 8 + Tier discipline.** Axis 5 is gated to Tier-3 confirmed-hostile flows only (`minTier=TierJail`, `FloorAggressive`), reached only via `attrition.Open` (Tier≥Contain + non-zero socket cookie) — i.e. off a canary-touch-derived verdict, NEVER off baseline deviation/novelty/recon. No new non-canary trigger path. Tier 3 stays fail-closed: an engine outage must not release a confirmed-malicious flow.

6. **Defender-cost bound.** The capture path must not buffer attacker traffic unbounded; it consumes only the `DriverObservation` digest (counts/bools/enums), under the shared `Governor` + kill switch, O(1)/chunk like every other axis.

---

## 15. Deferred / follow-up work register (don't lose track)

Everything this plan pushes to later, with why it's deferred, what unblocks it, and where it's tracked. Confirmed by founder 2026-06-10 (§0). **Each `F#` should be opened as a tracked task/issue when its milestone is scheduled.**

### Deferred build items (sequenced after the AX0 spine — decision D1)

| # | Deferred item | Why deferred | Prerequisite / unblocked by | Tracked in |
|---|---|---|---|---|
| **F1** | **AX4 — exploit-inventory-burn generator** | Spine-first (D1); net-new, higher risk | AX0 spine; **F3** egress filter for any cross-boundary use of `ExploitsObserved` | ROADMAP Track E AX4; §6 |
| **F2** | **AX5 — operational-exposure generator** | Spine-first; riskiest axis (no-hack-back) | AX0 spine; **F4** predicate review; **F3** egress filter | ROADMAP Track E AX5; §7 / §14 |
| **F3** | **Egress filter `internal/intelligence/network`** — now its OWN milestone (decision A2) | Rule-9 default-deny chokepoint; currently a `doc.go` stub | Standalone build, default-deny, per-field-justified | ROADMAP D6 + Track E deps; §2.5 / §11 |
| **F4** | **Axis-5 in-perimeter harmlessness predicate** (NEW, separate founder review) | `CrossScan` cannot govern a routable capture sink; needs its own safety review | Founder review BEFORE any AX5 code | §7 / §14.3 |
| **F5** | **D5 Phase 2+** (per-axis profiling + jail-fed matching) | The per-axis engagement signature has no source until AX0's `StingOutcome` fields land AND are persisted | AX0 spine (the 7 fields + `AmendOutcome` persistence + drift-guard same-naming) | `docs/D2_D5_DESIGN.md` §1.5 / §2 |

### Deferred design / measurement gaps (ship the mechanism now, sharpen later)

| # | Gap | Note | Tracked in |
|---|---|---|---|
| **F6** | **Async / streamed attrition transport** | Only the inline ~8 s `ImmediateResponse` exists today, so adaptive-latency escalation is visible over ~8–16 chunks (`RampSaturate` small). Wide escalation needs a future async driver — ship the ramp now as correct-and-forward-looking; do NOT promise the async path until it exists. | §3 / §0 D5 / §13 |
| **F7** | **Per-axis cost attribution is COARSE** | One stream runs one generator per chunk → "which axes active" (overlapping), NOT an exact byte/token split per axis. Dashboard renders overlapping bars, never a partition. Exact per-axis split is future work. | §2.3 / §8.4 / §13 |
| **F8** | **Information-poisoning plausibility/efficacy unmeasured** | `PoisonReached` only measures how far a linear walk advanced (an indifferent crawler advances it too). True plausibility / time-to-disengage efficacy stays unmeasured until the engagement metric matures and D2 profiling correlates it. | §4 / §8.2 |
| **F9** | **Dashboard `views/fingerprint.go` per-axis reframe** (optional — decision 13) | Kept as the separate flowID-bearing derivation for now; reframing the screenshot-verified live fingerprint to the per-axis engagement signature is a separate later edit to the dashboard wire contract. | §0 (decision 13) / `docs/D2_D5_DESIGN.md` decision E |
| **F10** | **Profile struct field-name finalization** | `AxesEngaged`, the time-to-disengage bucket type, the opportunity-cost proxy band, and `DisengageReason`'s role in the D6 export transform are described semantically — pin the exact Go names when `profile.go` is written against the LANDED AX0 contract. | `docs/D2_D5_DESIGN.md` §2 |

### Pre-existing operational follow-up that gates live deploys of AX0–AX2

| # | Item | Note |
|---|---|---|
| **F11** | **Adapter restart currently needs a full box REBOOT** (eBPF attach lifecycle) | A `systemctl restart` of the adapter alone breaks cross-host socket-cookie resolution; the proper fix is clean detach-on-exit / idempotent re-attach. Until then, every on-box AX0–AX2 deploy that restarts the adapter needs a reboot — sequence WITH Daniel. Not introduced by this plan, but it gates its live deploys. | §13 |
