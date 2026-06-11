# Intelligence MOAT — Comprehensive Deep Build Plan (D2 keystone · D4 · D5-Phase-2 · D6 remainder · D7)

**Status:** ✅ FOUNDER-APPROVED 2026-06-11 — all §0 decisions (D2-1, D2-2, D6-1, D6-2, D6-3, D6-4, D5-1, D5-2, D7-1, UI-1) approved as recommended. Sequence locked: **D2 (keystone) → D4 ∥ → D5-Phase-2 → D6 → D7**, the cross-customer/threat-feed UI scoped separately (UI-1). Building D2 first. Rule-9/rule-5/dependency reviewed SOUND (severity minor; corrections folded in). Verified against the repo at HEAD `aa895f2` (`go build ./internal/intelligence/...` clean; `go test ./internal/intelligence/network/` ok — 12 invariant tests green). This is the build plan for the proprietary, compounding data asset (`docs/INTELLIGENCE.md`), the founder-locked critical path: ROADMAP **Decision 9** (line 681) puts the full intelligence track **D1–D7** in demo #1, **including the cross-customer network demonstrated with a real second deployment**.

**Read order:** §0 (decisions needing signoff) → §1 (executive summary + state correction) → §2 (dependency graph) → §3 (per-track: D2, D4, D5-P2, D6, D7) → §4 (rule-9/5/8 guarantees + the cross-boundary path) → §5 (D6 second-scope topology) → §6 (dashboard-unblock map) → §7 (sequenced milestone plan) → §8 (test/verification plan) → §9 (risks) → §10 (deferred-work cross-reference).

**Authoritative inputs (verified to exist):** `docs/INTELLIGENCE.md` (§2 hard rule, §4 profiling, §5.1/5.4/5.5, §7 code map, §9 RESOLVED), `docs/EGRESS_FILTER_DESIGN.md` (the built `Clear()` chokepoint, §0 D0–D10, §5 predicate, §7.2 deferred, D6 known-gap), `docs/D2_D5_DESIGN.md` (decisions A–K + the 0b verdicts, §1.5 AX0 dependency, §2 phased build, §3 files), `docs/ATTRITION_FIVE_AXIS_DESIGN.md` (§15 deferred register F1–F11), `docs/ROADMAP.md` (D2 ~423, D4 ~475, D5 ~488, D6 ~504, D7 ~547, Decision 9 ~681), `CLAUDE.md` rules 1/5/8/9.

---

## 0. Decisions needing founder signoff (read first)

Defaults are chosen so the build can proceed; the founder should confirm the load-bearing ones (★). Items D2-1 / D6-1 / D6-2 are the leak-boundary decisions — they are the only ones where a wrong call is a critical (rule-9) bug.

| # | Decision | Default taken (recommendation) | Why it matters |
|---|----------|--------------------------------|----------------|
| **★ D2-1** | **The D2 `Profile` local-vs-export split + the exact exportable Go field names** (deferred F10). | The local `Profile` stays rich. The exportable subset is a **near-identity projection** mirroring `network.referenceExport` (candidate.go) **field-for-field**: `ReachedContain bool`, `EngagedVelocity bool`, `EngagedPoison bool`, `HeldBand int` (`band=0..3`), `DisengagedEarly bool`, `PoisonClass string` (closed enum). Richer local-only fields (full ordered sequence, MAD/jitter, `ExploitsObserved`/`ExposureSignals`) live on `Profile` but **never** in `ExportForm`. Founder confirms the split before `profile.go` is written. | Rule 9 leak boundary. The exportable field names are **load-bearing**: the gate registers the string-enum key `poisonclass` only (justify.go:124), so the exported field MUST be named exactly `PoisonClass` with value in `{"",credential,topology,success}` or `Clear` hard-denies it. |
| **★ D2-2** | **The `DisengageReason → DisengagedEarly` coarsening mapping** (the subtle semantic leak the review flagged). | `DisengagedEarly` is `true` **only** for `DisengageReason == DisengageAttacker (1)`, read jointly with `TimeToDisengageSec`. A `DisengageGeneratorDone (2)` or `DisengageDefenderCapped (3)` session **never** sets `DisengagedEarly`. | A defender max-hold cap mislabeled as an attacker disengage **corrupts the cross-customer signal** — exactly the kind of semantic leak that passes a field-name test. Must be pinned in the per-field coarsening table. |
| **★ D6-1** | **The per-field coarsening table** (`profile.ToExportForm` — how each rich field becomes a coarse scalar). | Coarsen to the `referenceExport` shape only: cadence→bands, sequence→**dropped** (not even unordered set in MVP), tier→`reached T2+` bool, `Axes`→per-axis engaged booleans (never the raw bitset — it leaks floor config), `TimeToDisengageSec`→`HeldBand 0..3`, `PoisonClass`/`PoisonReached`→coarse class + (optional) bucketed depth. No floats, no sequence, no hash. Founder signs the table before D6 transport is enabled. | This is the producer half of the rule-9 path. It must be auditable field-by-field; producer and gate distrust each other (two independent failures must both occur to leak — EGRESS_FILTER_DESIGN §1.3). |
| **★ D6-2** | **The cross-scope ledger that computes `SeenInScopes`** (closes the egress filter's documented known-gap). | Build it **inside** `internal/intelligence/network` as the package's own single trusted source. Until it lands, **fail closed** on any producer-asserted `SeenInScopes` (EGRESS_FILTER_DESIGN D6/risk-5). `aggregationK` stays a package constant (=3), never producer-supplied. | k-anonymity is only as sound as the count's provenance. A wrong ledger silently breaks k-anonymity even though the gate looks enforcing. |
| **★ D6-3** | **Second-scope topology for the demo.** | Stand up a **dedicated 3rd box** as scope-2 (its own `ScopeKey`, bbolt store, baseline) rather than reusing one of the two live M7 boxes — so the M7 learning window is not contaminated. Sequence the bring-up + adapter wiring with Daniel (F11: adapter restart needs a full reboot). | A real second scope is the Decision-9 requirement (no mock). M7 is a live ~2-week window; contaminating it loses the moat's real adversary history. |
| **★ D6-4** | **k-anonymity vs a small demo.** | **Do NOT lower `aggregationK`.** Drive the real ledger to k≥3 via deliberately staged repeated exhibition across the standing scopes, and **demo the gate REJECTING a sub-k pattern** as proof the guarantee is enforcing. | Lowering k is a critical anonymity regression — it is the guarantee the product is sold on. With only 2–3 boxes the demo must be staged honestly, not by weakening k. |
| **D5-1** | **D5 `Matcher` emerging-flow event source** (the wiring gap — the `Match(scope,flow,at)` signature carries no events). | Construct `MaliciousProfileStore` with a handle to the emerging flow's event source (the `observebaseline.Aggregator` per-flow buffer, or `boltevents.Store`). `Match` internally fetches the scope+flow events, runs `DeriveProfile`, then computes `Similarity` vs the stored set. | `baseline.Matcher.Match(scope, flow, at) float64` (baseline.go:270) receives only scope/flow/at — it has **no** event/profile handle. Without specifying where the emerging flow's events come from, D5 cannot be built as written. |
| **D5-2** | **The jail-detection predicate + jailed-flow event fetch.** | In `capturingEngine` (internal/boot/boot.go), detect a jail via `v.Tier == contract.TierJail` (=3) on the verdict; on that event fetch the **jailed flow's full accumulated event slice** from `boltevents` (by scope + socket cookie) and pass it to `DeriveProfile` → `store.RecordJail(scope, profile)`. Wire on the `ReportOutcome` path (the OutcomeRecord carries scope + SocketCookie); `Submit` alone sees only one `SignalEvent`+`Verdict`, not the flow's history. | Neither `capturingEngine.Submit` (:247) nor `ReportOutcome` (:267) currently has any jail detection. The predicate and the event-fetch are both currently unspecified and load-bearing. |
| **D7-1** | **Is D7 in this phase or deferred?** | Keep D7 **in-phase** (Decision 9) but build it **last** and time-box it as a thin read-view + access-control/rate-limit layer over D6. It is the safe cut line if D6 overruns (it adds no new moat data, only a consumer surface). | Honest demo-#1 scope. |
| **UI-1** | **Cross-customer + threat-feed dashboard PANELS.** | Estimate the **UI build separately** from the D6/D7 data-layer estimates — these panels **do not exist today** (grep-confirmed). | Demo-#1 honesty: the two money-shot panels are unscoped additional UI work on top of the data layer. |

**Locked (no signoff — carried from the rules):** rule 9 (only `Clear()`-cleared anonymized patterns cross; raw-data exfil = critical bug); rule 5 (scope isolation absolute; learned state never aggregates); rule 8 (canary touch is the only trigger; shared set = detection context, never inbound trigger); rule 1 (engine proxy-agnostic — `Matcher`/`FeatureSource` are interfaces so `baseline` takes no dependency on `intelligence/profile`); `M ∈ [1, M_max]`, `base=0 ⇒ Score=0`; `aggregationK` is a network-package constant; **AX4/AX5 (`ExploitsObserved`/`ExposureSignals`) stay hard-blocked from any export this entire phase** (see §4).

---

## 1. Executive summary + verified-state correction

The moat's foundation is **further along than the ROADMAP text claims**. Of the seven tracks, four are done and the trust-critical chokepoint is built:

- **D1 events — DONE.** `internal/intelligence/event.go` (`AdversaryInteractionEvent` + `StingOutcome` with all seven five-axis fields + `EventStore`) + `internal/intelligence/boltevents/store.go` (per-scope bbolt store).
- **D3 attacker-cost KPI — DONE.** `internal/intelligence/cost/cost.go` (`Summary` + `Rollup`, per-axis overlapping subtotals, engagement percentiles, AX2/AX4/AX5 reaction counts), incl. the AX3 dashboard reframe.
- **AX0 five-axis spine — LANDED.** `contract.go` carries the overlapping `AttritionAxis` bitset (lines 99–107), `StingFloor.Axes()` (114–123), the `Disengage*` consts (`DisengageAttacker=1`, `DisengageGeneratorDone=2`, `DisengageDefenderCapped=3`, lines 208–213), and `OutcomeRecord`/`StingOutcome` with the seven fields (`Axes`, `TimeToDisengageSec`, `PoisonClass`, `PoisonReached`, `ExploitsObserved`, `ExposureSignals`, `DisengageReason`, lines 176–183). `intelligence.StingOutcome` (event.go:56–62) and `attrition.Outcome` are same-named.
- **AX0 persistence — DONE (satisfies the F5 prerequisite).** `boltevents.AmendOutcome` persists **all** five-axis fields into the gob `outcomeRecord` (store.go:111–117); additive, gob-forward-safe (old blobs zero-fill); `DoneReason` intentionally not persisted. The live M7 store; `Query` merges outcomes into events by `(cookie, ts)`. **So `DeriveProfile` reading a scope's merged event slice will see the five-axis fields — the D2 data source is real.**

> ### ⚠️ STATE CORRECTION — the egress filter is BUILT (the ROADMAP/EGRESS_FILTER_DESIGN text is stale)
>
> `docs/ROADMAP.md` line 504 ("D6 … UNBUILT — the egress filter does not yet exist"), line 588 ("egress filter … currently a `doc.go` stub"), and the `EGRESS_FILTER_DESIGN.md` status line ("build target … today a `doc.go` stub") are **out of date**. As of HEAD `aa895f2`, **`internal/intelligence/network/` is fully built**: `filter.go`, `candidate.go`, `optin.go`, `block.go`, `reidentify.go`, `justify.go`, plus `filter_test.go` (12 invariant tests, all green). `Clear(c Candidate) (*Cleared, error)` is the single default-deny chokepoint; `Cleared` is an opaque carrier with **unexported** fields and `Clear` as its **only** constructor (the single-chokepoint invariant is enforced by the **Go type system**, not convention). The §5 3-part cannot-re-identify predicate is founder-approved (2026-06-11), resolving the INTELLIGENCE §9 open item. **A maintenance task should update ROADMAP D6/§E-deps and the EGRESS_FILTER_DESIGN status to "BUILT" to stop the stale claim propagating into the next plan.**
>
> **CRITICAL verified fact:** there is **zero** consumer/transport of `*Cleared` anywhere outside the network package (grep-confirmed — see §2). Nothing transmits a cleared pattern yet, so **no leak can occur today regardless**, and `*Cleared` is the clean seam D6 consumes.

This collapses the build to a dependency chain. **D2 is the keystone** — `internal/intelligence/profile/` is still a `doc.go` stub, and four consumers gate on it: D5-Phase-2 (its real `Matcher` is a `DeriveProfile` consumer), D6 export (its `ToExportForm` is the producer half of the cross-boundary path), Model-2 bait (future), and the dashboard fingerprint-enrichment panel. The build order is: **D2 → (D4 in parallel) → D5-Phase-2 → D6 remainder → D7.** The egress filter being built removes what the prior plan treated as the long-pole trust work, so D6 reduces to: the producer-coarsening body + the cross-scope ledger + a real 2nd scope + the transport + the shared-set consumer.

---

## 2. Dependency graph

```
D1 events (DONE) ─────────────┐
AX0 spine + persistence (DONE)─┤
                               ▼
                    ┌──────────────────────┐
                    │  D2  adversary profile│  ◄── THE KEYSTONE (profile/ is a doc.go stub)
                    │  DeriveProfile/Similarity/ToExportForm
                    └───────┬───────┬───────┘
                            │       │
              (parallel)    │       │
  D4 recon ◄── D1 + M7      │       │
  (recon/ stub; independent)│       │
                            ▼       ▼
                   D5-Phase-2     D6 export half
                   (Matcher = a   (ToExportForm
                    DeriveProfile  satisfies the
                    consumer; seam already-built
                    wired-but-nil) network.Candidate)
                            │       │
                            └───┬───┘
                                ▼
                    D6 remainder (chokepoint DONE)
                    = coarsening body + cross-scope LEDGER
                      + real 2nd scope + transport over *Cleared
                      + shared-set consumer → feeds D5's SAME
                      FingerprintMatch dimension (decision J)
                                ▼
                    D7 feed (read-view over D6's aggregated set;
                             + access control + rate limiting)
```

**Why this order (each edge verified):**
- **D2 first.** Its data source is live (AX0 persistence, store.go:111–117). It is the only artifact four downstream tracks consume.
- **D4 parallel.** D4 reads D1 events + baseline-deviation-as-context only; it has **no** D2 dependency. It is the one track that parallelizes with D2 to fill calendar time without adding to the critical path.
- **D5-Phase-2 after D2.** The engine `Matcher` seam exists wired-but-nil (Phase 1, commit `797e877`): `baseline.Matcher` interface (baseline.go:269–271), `Store.matcher` + `UseMatcher` (288, 341–348), the additive term `M = clamp(1 + (M_max−1)·g(d) + α·match, 1, M_max)` (`MFromFeatures`, 177–194), `DefaultParams` ships α=0 (99) so Phase 1 is a byte-identical no-op, and `fingerprint_match` round-trips through `FeaturesMap` (derive.go:104). The real `Matcher` **is** a `DeriveProfile` consumer, so it gates on D2.
- **D6 after D2 and D5-Phase-2.** D6's export half is `profile.ToExportForm` (gates on D2). D6's consumer feeds the **same single `FingerprintMatch` dimension** D5 just built (decision J) — building the consumer before that dimension exists would have nothing to feed.
- **D7 last.** A pure read-view over D6's aggregated ledger output; cannot exist before the aggregated set does.

**Verified grep — `*Cleared` has no consumers outside the network package:**
```
$ grep -rn "Cleared" --include=*.go internal/ | grep -v _test.go | grep -v internal/intelligence/network/
(no output)
```

---

## 3. Per-track build

### 3.1 D2 — adversary profiling (THE KEYSTONE) · ~2–3 days

**Scope.** Build `internal/intelligence/profile/` from the `doc.go` stub into the moat's load-bearing artifact: the **anonymized-by-construction** `Profile` carrying the **per-axis engagement signature** sourced from the now-persisted AX0 `StingOutcome` fields (D2_D5_DESIGN §1.1, decision D). `Profile` holds: ordered canary-type sequence, cadence/jitter (median/MAD), peak adjacency + identity novelty, tier/depth progression, a deterministic `BehavioralHash` (**fnv-64a over the behavioral pattern, never FlowID**), and the per-axis engagement signature:
- **`AxesEngaged`** — per-axis booleans derived from the OVERLAPPING `Axes` bitset (velocity/poison/oppCost/exploitBurn/opExposure), **not** the raw bitset (which leaks floor config).
- **time-to-disengage bucket + disengage class** — from `TimeToDisengageSec` + `DisengageReason`. A defender-cap (`DisengageDefenderCapped`) is **never** mislabeled an attacker disengage; time-to-disengage is the CORE engagement metric, sourced from the real held time, not `LastSeen−FirstSeen`.
- **poison reaction** — `PoisonClass`/`PoisonReached`, read **jointly** with the disengage class (a linear walk advances depth indifferently).
- **a DEMOTED opportunity-cost proxy band** — qualified estimate, never the lead.
- **`ExploitsObserved`/`ExposureSignals`** — flagged **deployment-local-only** (AX4/AX5; rule 9 — never enter `ExportForm`).

This `Profile` is **distinct** from the shipped dashboard `views/fingerprint.go` `FlowFingerprint` (which carries `FlowID`/`FlowIDHex` and hashes `(flowID|sequence)`). Per decision E / deferred F9, **do not unify the derivations** (the flowID hash would smuggle identity into the anonymized profile).

**API surface (`internal/intelligence/profile/`):**
- `profile.go` — `type Profile struct` (behavioral fields + per-axis engagement signature + `BehavioralHash uint64`). MUST NOT contain `ScopeKey`/`FlowID`/IP/decoy contents.
- `derive.go` — `func DeriveProfile(events []intelligence.AdversaryInteractionEvent) *Profile` — **pure**, single-scope, returns nil for empty. Mirrors `cost.Rollup` **exactly** (imports only `contract` + `intelligence`, **never** `attrition` or the engine — no import cycle, rule 1/5). Reads the AX0 fields off the merged event slice (the same `e.Sting.DisengageReason` switch `cost.Rollup` uses at cost.go:113–120).
- `features.go` — shared axis/threshold consts + the feature-key vocabulary.
- `match.go` — `func (p *Profile) Similarity(other *Profile) float64` in `[0,1]` — the behavioral-similarity kernel D5 consumes.
- `export.go` — `type ExportForm struct` (the coarsened, `egress:"safe,<reason>"`-tagged shape mirroring `network.referenceExport`); `func (p *Profile) ToExportForm() ExportForm`; `func ValidateProfileForSharing(p *Profile) error`. `ExportForm` implements `network.Candidate` (`EgressFields() (any, ContributionContext)`). `ExploitsObserved`/`ExposureSignals` **hard-blocked** (never a field on `ExportForm`).
- **Shared helpers — follow decision E as locked:** extract `median`/`mad`/sequence-sort into a new **`internal/intelligence/stats/`** package (D2_D5_DESIGN §3 file table line 129; the 0b verdict for E says *"share only low-level HELPERS … via a small shared package"*). `views/fingerprint.go` (median@111, mad@125) is refactored to consume `stats` behind its existing tests (no JSON drift). *(This corrects an earlier framing that said "copy into profile/"; the locked decision is extract-to-shared-package.)*

**Exportable field names (the F10 pin — must match the gate exactly).** `ExportForm` mirrors `network.referenceExport` (candidate.go:10–17) field-for-field:

| `ExportForm` field | kind | egress tag | gate rule it must satisfy |
|---|---|---|---|
| `ReachedContain` | bool | `safe,coarse tier bucket …` | bool kind allowed (filter.go:135) |
| `EngagedVelocity` | bool | `safe,per-axis engaged boolean …` | bool |
| `EngagedPoison` | bool | `safe,per-axis engaged boolean` | bool |
| `HeldBand` | int | `safe,band=0..3,…` | banded int, span ≤ `maxBandSpan=256`, value in range (filter.go:137–148) |
| `DisengagedEarly` | bool | `safe,attacker-disengaged-before-cap boolean` | bool; **set only for `DisengageAttacker`** (decision D2-2) |
| `PoisonClass` | string | `safe,coarse poison reaction class …` | **name must lowercase to `poisonclass`** (the only registered enum key, justify.go:124); value ∈ `{"",credential,topology,success}` |

Any other string field, any float, any sequence/hash/identity-named field, or any untagged field is **hard-denied** by `Clear`. A test asserts `network.Clear(profile.ToExportForm())` succeeds.

**Depends on:** D1 events (DONE) + AX0 persistence (DONE). No remaining blockers — the D2_D5_DESIGN §1.5 / F5 dependency is satisfied.
**Unblocks:** D5-Phase-2 (`DeriveProfile` + `Similarity`), D6 (`ToExportForm` → `Candidate`), the dashboard fingerprint-enrichment panel, future Model-2 bait.
**Effort:** ~2–3 days (D2_D5_DESIGN §2 Phase-2 step 5).

---

### 3.2 D4 — reconnaissance early-warning (intelligence pkg) · ~2–3 days · PARALLEL

**Scope.** Build `internal/intelligence/recon/` from the `doc.go` stub into the **real** D4 intelligence-layer early-warning signal — distinct from the existing dashboard `DeriveReconTimeline` (drilldown.go:532), which is a derived-from-events **view** (severities `"recon"`/`"surfaced"`, **never** `"detected"` — verified, drilldown.go:164,571,573). Real D4 (INTELLIGENCE §5.1) surfaces quiet pre-attack probing in the negative space — low-tier canary touches + baseline deviation **as CONTEXT only** — ahead of the loud part, **never as a trigger** (rule 8; the `docs/BASELINE_MULTIPLIER.md` §5 guardrail holds: deviation from normal can never tag/contain/attrit a flow).

Promote the dashboard's recon-cluster logic (`reconAdjacencyThreshold=0.8`, `reconClusterWindowSec=90`, `reconClusterMin=3`, views.go:50–56) into the intelligence package; the dashboard then becomes a thin view over it. Five-axis enrich: where a recon-flagged flow later escalates, attach the eventual per-axis engagement (still context, never a trigger).

**API surface (`internal/intelligence/recon/`):**
- `type ReconSignal struct` — negative-space probe clusters + baseline-deviation context; severity in `{recon, surfaced}`, never `detected`.
- `func DeriveReconSignal(events []intelligence.AdversaryInteractionEvent, now time.Time) []ReconSignal` — pure, single-scope, reads D1 events + `Features`-as-context. (Same pure/no-I/O discipline as `cost.Rollup` and `DeriveReconTimeline`.)
- Refactor `backend.serveReconTimeline` (backend.go:388, route `GET /api/recon` @281) to a thin view over `recon.DeriveReconSignal`.

**Depends on:** D1 events (DONE) + the M7 baseline for the deviation context. **INDEPENDENT of D2** — the only track that can run fully parallel.
**Unblocks:** the real recon early-warning dashboard panel (replaces the placeholder derived view).
**Effort:** ~2–3 days (ROADMAP D4 ~475).

---

### 3.3 D5 — Phase 2 detection sharpening · ~3–4 days

**Scope.** Implement the real `Matcher` behind the already-wired (nil) engine seam: a per-scope behavior-keyed `MaliciousProfileStore` fed by **JAIL OUTCOMES** (decision C / Option 3 — customer-reproducible confirmed-malice, **not** analyst labels), and flip `DefaultParams` α from 0 to `DefaultSharpeningAlpha` (0.5, documented at baseline.go). On a T3/jail, record the jailed flow's `DeriveProfile`; for a live emerging flow, `Match` returns the best `Similarity` vs the set, gated by `N≥3` confirmed jails + a freshness cutoff (~30d, decision G) + cold-start. Bounded circularity is intended **cross-flow** learning: the jailed flow sharpens **other** matching flows (capped by `M_max`); D5 moves M only and can never manufacture a jail (jail still requires `minTouches[T3]` distinct decoy touches — rule 8).

**API surface:**
- A new package (e.g. `internal/intelligence/maliciousprofile` or a sibling) implementing `baseline.Matcher`:
  `Match(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64`.
- `type MaliciousProfileStore` — per-scope, keyed by `profile.BehavioralHash`, each entry `{confirmed_jails int, last_jail_ts time.Time}`; `RecordJail(scope, *profile.Profile)`; bbolt-persisted (`mp:{scope}:{hash}`), rehydrated on boot.
- **(D5-1 — the Matcher data-path gap, RESOLVED here):** `baseline.Matcher.Match(scope, flow, at)` receives **only** scope/flow/at — it has **no** event/profile handle. Construct the store with a handle to the **emerging flow's event source** — the `observebaseline.Aggregator`'s per-flow buffer (preferred; it already owns the flow lifecycle and `flowReset`) or `boltevents.Store`. Inside `Match`: fetch the scope+flow events for `flow`, run `DeriveProfile(emergingEvents)`, then compute the best `Similarity` against the stored set. Without this handle, D5 cannot be built — the signature alone gives the store nothing to derive from.
- **(D5-2 — the jail-feedback predicate + event fetch, RESOLVED here):** wire `RecordJail` in `capturingEngine` at **`internal/boot/boot.go`** (NOT `cmd/engine` — verified: `capturingEngine` @241, `Submit` @247, `ReportOutcome` @267; reconciles with D2_D5_DESIGN lines 112/132's "OnVerdict/containment seam in `internal/boot`" — same composition point). Detect a jail via `v.Tier == contract.TierJail` (=3, contract.go:69). On the jail event, **fetch the jailed flow's full accumulated event slice** from `boltevents` (by scope + socket cookie) → `DeriveProfile(jailedEvents)` → `store.RecordJail(scope, profile)`. Prefer the **`ReportOutcome` path** (the `OutcomeRecord` carries `Scope` + `SocketCookie` + `Outcome` — the natural place a Tier-2/3 outcome lands and the flow's history is queryable). `Submit` alone sees only one `SignalEvent`+`Verdict`, not the flow's history.
- Wire `base.UseMatcher(store)` at boot (baseline.go:341) — currently **not** called; `base.UseFeatureSource(b.Aggregator)` already is (boot.go:156). Flip `DefaultParams` α to 0.5 (baseline.go:99).
- The emerging-profile match is set on `f.FingerprintMatch` in `observebaseline.Aggregator.Features`, honoring `flowReset`. (NB: this is a **different** concern from the existing `observebaseline.MaliciousSet` at exclusion.go, which is the baseline-of-normal *exclusion* set keyed by addr-hash — not the D5 profile store.)

**Depends on:** D2 (`DeriveProfile` + `Similarity`). Engine seam exists (Phase 1). AX0 persistence satisfied the data dependency (F5).
**Unblocks:** live local sharpening (the moat beat). Establishes the **single `FingerprintMatch` consumer dimension** that D6's shared set later **also** feeds (decision J).
**Effort:** ~3–4 days (D2_D5_DESIGN §2 steps 5–10).

---

### 3.4 D6 — cross-customer network (remainder; chokepoint DONE) · ~6–9 days

**Scope.** Build the five remaining pieces on top of the shipped egress filter. The chokepoint (`Clear`/`Cleared`, 12 green tests, founder-approved) needs **zero change** — D6 produces a `Candidate` and consumes a `*Cleared`.

1. **Producer coarsening body** — flesh out `profile.ToExportForm` to the real per-field coarsening (the D6-1 table): cadence→bands, sequence→**dropped**, tier→`reached T2+` bool, `Axes`→per-axis booleans, `TimeToDisengageSec`→`HeldBand`, `PoisonClass`/`PoisonReached`→coarse class + bucketed depth; `ExploitsObserved`/`ExposureSignals` **never** in the export. This is the producer half that distrusts `Clear` (EGRESS_FILTER_DESIGN §1.3 — two independent failures must both occur to leak).
2. **The cross-scope ledger** (D6-2) — `internal/intelligence/network/ledger.go`: the network package's **own** trusted source that computes the **real** `SeenInScopes` per `BehavioralHash` across scopes. `Clear` consults the ledger (the count must originate **inside** the chokepoint). This closes the documented known-gap (optin.go:11–16; EGRESS_FILTER_DESIGN D6/risk-5: **fail closed on a self-asserted count** until the ledger exists). `aggregationK` stays a package constant (=3).
3. **A real second scope/deployment** (D6-3) — a dedicated 3rd box as scope-2; see §5.
4. **The transport** — accepts **only** `*network.Cleared` and consumes **only** `Cleared.Marshal()` bytes (which re-validates every payload entry's dynamic kind, filter.go:179–189), never raw `payload` access. `*Cleared` is consumed **nowhere** today (grep-confirmed) — this is a clean new seam.
5. **The shared-set consumer** — returns aggregated patterns as **DETECTION CONTEXT** into D5's `FingerprintMatch` dimension (decision J; rule 8 — never an inbound trigger). Feeds the **same** `baseline.Matcher`/`FingerprintMatch` dimension from both local AND shared profiles.
6. **Per-deployment opt-in config** — wire `ContributionContext.Contribute` to a single operator-config source of truth (zero-value denies, EGRESS_FILTER_DESIGN risk-6). `config/` has no such field today (verified).

**API surface:**
- `profile.ToExportForm` real coarsening body + a test asserting `network.Clear(ToExportForm())` succeeds and the on-screen `Cleared.Fields()` shows raw/identifying candidates dropped.
- `internal/intelligence/network/ledger.go` — the trusted cross-scope `SeenInScopes` ledger; `Clear` consults it.
- transport accepting only `*network.Cleared`, sending only `Marshal()` bytes.
- shared-set consumer feeding the `baseline.Matcher`/`FingerprintMatch` dimension.
- config: a per-deployment `Contribute` opt-in.
- demo path: a fingerprint leaving scope A through `Clear()` with identifying candidates DROPPED ON SCREEN, sharpening detection in scope B.

**Depends on:** D2 (`ToExportForm`/`Candidate`) + D5-Phase-2 (the `FingerprintMatch` consumer dimension to feed). Egress filter chokepoint DONE.
**Unblocks:** the cross-customer dashboard panel (does not exist yet — genuinely blocked here) and D7. Delivers the Decision-9 cross-customer money-shot.
**Effort:** ~6–9 days (data layer; the dashboard panel UI is **separate** unscoped work — UI-1). The egress-filter being done removes the trust-critical sub-piece this estimate would otherwise have carried.

> **D6 sub-design note.** The cross-scope ledger (D6-2) and the per-field coarsening table (D6-1) are the rule-9 leak boundary. They warrant a short focused sub-design (a ledger schema + a per-field coarsening table with each `<reason>` string) before code, signed off like the egress filter was — this is the single remaining trust-critical decision and the founder must sign it (per EGRESS_FILTER_DESIGN §1.3 the producer transform is the deferred piece that lands with D6).

---

### 3.5 D7 — threat-intelligence feed (read-view over D6) · ~3–5 days

**Scope.** Build `internal/intelligence/feed/` from the `doc.go` stub into a **READ VIEW** over D6's anonymized aggregated cross-scope set — five-axis-derived patterns (per-axis engagement bands, disengage-reason mixes, coarse poison signals), all **already-`Clear()`-ed/aggregated**, inheriting every D6/rule-9 constraint. The feed is **never** a second egress surface: it reads only data that already passed `Clear()`. It **adds** its own ACCESS CONTROL + RATE LIMITING (the new attack surface vs D6). Framed as a second product line (SIEM/ISAC consumer; INTELLIGENCE §5.5). Follows the dashboard read-view handler pattern (`cost.Rollup`/`DeriveReconTimeline` → handler).

**API surface (`internal/intelligence/feed/`):**
- `type FeedView` / `type FeedEntry` over D6's ledger output (anonymized aggregated patterns only).
- `func BuildFeed(...) FeedView` — read-only over already-`Cleared` data; performs **no** egress itself.
- an HTTP handler with its **own** auth + rate limiter, mirroring `backend.serveReconTimeline` (backend.go:388).

**Depends on:** D6 (the aggregated set + ledger). Strictly last.
**Unblocks:** the threat-feed dashboard/product panel (does not exist yet — genuinely blocked on D6/D7; UI is **separate** unscoped work — UI-1).
**Effort:** ~3–5 days (data/read layer; ROADMAP D7 ~547).

---

## 4. Rule-9 / rule-5 / rule-8 guarantees

### 4.1 Rule 9 — the cross-boundary path (the load-bearing seam)
Only anonymized derived patterns cross, via the **single** `Clear()`. The exact path:

```
D2 Profile (rich, local)
   → profile.ToExportForm()           # UPSTREAM coarsening to the egress:"safe,<reason>"-tagged ExportForm (the producer)
   → network.Clear(ExportForm)        # the INDEPENDENT second gate (producer + gate distrust each other)
   → *network.Cleared                 # opaque carrier; unexported fields; Clear is the ONLY constructor (Go-type-enforced)
   → Cleared.Marshal() bytes          # re-validates every payload entry's dynamic kind before wire bytes
   → D6 transport                     # accepts ONLY *Cleared, consumes ONLY Marshal bytes
```

- **`ExportForm` becomes a `network.Candidate`.** It must implement `EgressFields() (any, ContributionContext)` and produce **exactly** the `network.referenceExport` shape (candidate.go:10–17). The comment there states it *"slots in with zero network change."* D2 ships a test asserting `network.Clear(profile.ToExportForm())` succeeds.
- **The gate's rules `ExportForm` must produce-clean-to** (filter.go `clearStruct` + justify.go + reidentify.go): no untagged fields (default-deny); **floats denied outright**; numeric fields must declare a coarse `band=LO..HI` (span ≤ `maxBandSpan=256`) with the value in range — so `HeldBand` is an int band 0..3, not a raw duration; strings only against the registered closed enum (only `poisonclass`); no identity-named fields (reidentify.go denylist — scope/flowid/ip/host/asn/tenant/decoy/baseline/sequence/hash/exploit/exposure/timestamp/…); `AxesEngaged` exported as per-axis **booleans**, never the raw `Axes` bitset.
- **The `DisengageReason → DisengagedEarly` mapping (D2-2).** `DisengagedEarly` is set `true` **only** for `DisengageAttacker (1)`, read jointly with `TimeToDisengageSec`. A `DisengageGeneratorDone (2)` or `DisengageDefenderCapped (3)` session must **not** set it — else a defender cap is mislabeled an attacker disengage in the shared set (a subtle semantic leak). This belongs in the D6-1 coarsening table the founder signs.

### 4.2 Rule 9 — AX4/AX5 stay home (this phase does NOT touch the export block)
`ExploitsObserved`/`ExposureSignals` are deployment-local-only and **hard-blocked** from any export by **three** shipped layers: (a) the candidate-type denylist (block.go `denylistedType` rejects `cost.Summary`, `intelligence.{AdversaryInteractionEvent,StingOutcome}`, the `contract` carriers, and **any** `internal/engine/` type, recursing embedded fields so wrapping can't launder); (b) the `*exploit*`/`*exposure*` name tokens in reidentify.go (catches a renamed same-valued field); (c) the `egress:"blocked,…"` marker (defense-in-depth, not the sole barrier). **This entire phase keeps them blocked.** Any future unblock is a **founder-signed compile-time edit to block.go AFTER** percentile/boolean coarsening exists — **never** a runtime flag — and the AX5 path additionally gates on the F4 in-perimeter harmlessness predicate sub-design. **F4 does not gate D6/D7** (this phase blocks AX4/AX5 anyway); stated here so no one tries to soften the block as part of D6/D7.

### 4.3 Rule 5 — scope isolation absolute
Every new pure function — `DeriveProfile`, `DeriveReconSignal`, the `MaliciousProfileStore` — operates on a **single** scope's already-isolated event slice and never aggregates learned state across deployments. `MaliciousProfileStore` is keyed per-scope (`mp:{scope}:{hash}`). The **only** thing that ever leaves a scope is an egress-`Clear()`-ed anonymized pattern. block.go denylists every `internal/engine/` type so scope-local learned state can't even be field-inspected by the gate. `DeriveProfile` mirrors `cost.Rollup`'s verified import discipline (`contract` + `intelligence` only) so there is no import cycle and no scope-state coupling.

### 4.4 Rule 8 — canary touch is the only trigger; shared set is context only
D4's recon signal and D6's shared-set consumer both feed **context**, never triggers. The shared set returns into the **same** bounded `baseline.Matcher`/`FingerprintMatch` additive term D5 wired (decision J) — capped by `M_max`, and `B=0 ⇒ Score=0` arithmetic means it cannot fire on a flow with no canary touch (the `FingerprintMatch` field is deliberately excluded from `contributions()`, baseline.go:65–77). D5 moves M only and can never manufacture a jail (jail still requires `minTouches[T3]` distinct decoy touches). D4's baseline-deviation stays context-only (`BASELINE_MULTIPLIER.md` §5). `Clear` gates OUTBOUND patterns; it never creates an inbound trigger (EGRESS_FILTER_DESIGN §6.3).

### 4.5 Rule 9 — the D6 ledger fills the `SeenInScopes` known-gap
Today `optin.go` `ContributionContext.SeenInScopes` is **producer-asserted** and the k=3 gate is encoded but only **advisory** (EGRESS_FILTER_DESIGN D6/risk-5 recommends fail-closed on a self-asserted count). D6 builds the network package's **own** cross-scope ledger as the single trusted source that **computes** `SeenInScopes`; `Clear` consults the ledger so the k-anonymity guarantee becomes real (k is only as sound as the count's provenance). `aggregationK` stays a package constant (a producer-supplied k=0 would invert the gate — EGRESS_FILTER_DESIGN D5).

---

## 5. D6 second-scope topology

**Recommended (D6-3): extend the live M7 AWS environment with a dedicated 3rd box as scope-2** rather than mocking. The current M7 window is a two-box AWS topology (server box + client box) running ~2 weeks from 2026-06-09. Standing up a **third box** as a genuinely separate deployment (its own `ScopeKey`, its own bbolt store, its own baseline) gives a real second scope to cross **to** without contaminating the M7 learning window's two boxes (which carry the real adversary history the moat sells).

**Cross-direction for the demo (one way):**
```
scope A (an M7 box): a jailed flow → profile.DeriveProfile → profile.ToExportForm
   → network.Clear() → *Cleared.Marshal() bytes
   → transport
   → scope B (the 3rd box): ingest the cleared pattern into the shared-set consumer
      → feeds B's FingerprintMatch dimension (decision J)
   ⇒ the SAME behavioral signature is detected harder/faster in B, no analyst in the loop.
```
The money-shot (ROADMAP ~141): a fingerprint learned in deployment A is anonymized, passed through the single default-deny `Clear()` with the **identifying candidate fields DROPPED ON SCREEN** (`Cleared.Fields()`), and sharpens detection in deployment B.

**Two real-deployment constraints to plan around:**
- **(a) k-anonymity (D6-4).** The k=3 `SeenInScopes` gate needs ≥3 distinct scopes exhibiting a pattern to actually cross. With only 2–3 boxes the demo must drive the **real** ledger to k=3 via deliberately staged repeated exhibition across the standing scopes — **never** by lowering `aggregationK`. Demo the gate **rejecting** a sub-k pattern as part of the show (it proves the guarantee is enforcing).
- **(b) F11 — adapter restart needs a full box reboot** (eBPF attach lifecycle). Standing up the 3rd box and any adapter re-wiring requires full reboots and **must be sequenced with Daniel during a controlled window**, against the LIVE M7 window — risk of disrupting M7 data collection.

---

## 6. Dashboard-unblock map

| Track | Panel | Today | After |
|---|---|---|---|
| **D2** | fingerprint-enrichment | `views/fingerprint.go` `FlowFingerprint` is flowID-bearing **presentation**, not the real D2 profile | D2's per-axis engagement signature enriches it. Per **deferred F9**, keep the two derivations **separate** (share only `median`/`mad`/sort via `internal/intelligence/stats`, decision E) — the panel reframe is itself deferred. |
| **D4** | recon early-warning | `DeriveReconTimeline` (drilldown.go:532) / `serveReconTimeline` (backend.go:388, `/api/recon`) is a derived-from-events **placeholder** (severities recon/surfaced) | the real D4 intelligence pkg replaces the derivation; the dashboard becomes a thin view over `recon.DeriveReconSignal`. |
| **D5-P2** | (indirect) | `FeaturesMap` round-trips `fingerprint_match` (derive.go:104); the value is 0 in Phase 1 | no dedicated blocked panel, but it makes the fingerprint panel's match value **live**. |
| **D6** | cross-customer | **does NOT exist** (grep-confirmed) — genuinely blocked | D6 is the prerequisite. The on-screen "what crossed" demo (`Cleared.Fields()`) is the panel's data source. **UI is separate unscoped work (UI-1).** |
| **D7** | threat-feed | **does NOT exist** (grep-confirmed) — genuinely blocked | D7 is the prerequisite. **UI is separate unscoped work (UI-1).** |

The existing dashboard `AxisReactionView` (AX2/AX4/AX5, drilldown.go:150) is deployment-local-only and unaffected.

---

## 7. Sequenced milestone plan

| Milestone | Track | Work | Effort | Gates on |
|---|---|---|---|---|
| **MOAT-1** | D2 (keystone) | `profile/` package (profile/derive/features/match/export) + `internal/intelligence/stats` extraction + tests (determinism, hash-ignores-FlowID, no-forbidden-field, `Clear`-able export, per-axis coarsening, exploit/exposure export-blocked) | ~2–3d | nothing (data source live) |
| **MOAT-2** | D4 (parallel) | `recon/` package + `DeriveReconSignal` + refactor `serveReconTimeline` to a thin view + tests (never-emits-a-trigger, deviation-stays-context) | ~2–3d | D1 + M7 baseline (runs **parallel** to MOAT-1) |
| **MOAT-3** | D5-Phase-2 | `MaliciousProfileStore` (with the emerging-flow event-source handle, D5-1) + jail-feedback wiring in `internal/boot` (`v.Tier==TierJail`, fetch jailed-flow events, `RecordJail`, D5-2) + `UseMatcher` + α=0.5 + tests | ~3–4d | MOAT-1 (D2) |
| **MOAT-4** | D6 sub-design | short focused design: the cross-scope ledger schema + the per-field coarsening table (each `<reason>`) — founder signoff (D6-1, D6-2) | ~0.5–1d | MOAT-1 |
| **MOAT-5** | D6 remainder | `ToExportForm` coarsening body + `network/ledger.go` (real `SeenInScopes`) + transport over `*Cleared` + shared-set consumer (feeds D5 dimension) + opt-in config | ~5–7d | MOAT-3 + MOAT-4 |
| **MOAT-6** | D6 second scope | dedicated 3rd box as scope-2; one-direction cross demo; staged k≥3 exhibition (sequence with Daniel — F11) | ~1–2d (operational; with Daniel) | MOAT-5 |
| **MOAT-7** | D7 | `feed/` read-view + access control + rate limiting over the aggregated set + tests | ~3–5d | MOAT-5 |
| **MOAT-UI** | dashboard | cross-customer + threat-feed panels (do not exist today) | **unscoped — estimate separately** | MOAT-5 / MOAT-7 |

**Critical path:** MOAT-1 → MOAT-3 → MOAT-5 → (MOAT-6, MOAT-7). MOAT-2 (D4) and MOAT-4 (D6 sub-design) run off the critical path. **D7 is the safe cut line** if D6 overruns (it adds no new moat data). Each milestone ships green with `make check`, built design → implement → adversarial review → fixes (like M8/M9, AX0).

---

## 8. Test / verification plan

**D2 (`internal/intelligence/profile/`):**
- `DeriveProfile` deterministic; `BehavioralHash` **ignores FlowID**; `Profile` has **no** forbidden field (scope/flow/IP/decoy).
- per-axis signature: `AxesEngaged` from `Axes` (OVERLAPPING, never a partition); time-to-disengage bucket from `TimeToDisengageSec`/`DisengageReason` (not `LastSeen−FirstSeen`); **never** mislabels a `DisengageDefenderCapped` stop as an attacker disengage.
- `ExportForm` coarsening: `Axes`→engaged booleans, `TimeToDisengageSec`→`HeldBand`, `PoisonClass`/`PoisonReached`→coarse class + bucketed depth; **`ExploitsObserved`/`ExposureSignals` NEVER appear in `ExportForm`**.
- **`network.Clear(profile.ToExportForm())` succeeds** (the contract assertion); `ValidateProfileForSharing` rejects identity-bearing fields.

**D4 (`internal/intelligence/recon/`):** never-emits-a-trigger; baseline-deviation-stays-context; cluster thresholds preserved (0.8 / 90s / min-3); severities stay `{recon, surfaced}`.

**D5-Phase-2:**
- gate forces `match=0` under N<3 / stale / cold-start; cross-flow-not-self-amplification; M stays within the `M_max` clamp; **jail still requires `minTouches[T3]`** (D5 can't manufacture a jail).
- `cookie=0`/lookup-miss/`flowReset` ⇒ neutral, never suppress/fabricate/crash.
- scope isolation: a profile recorded in scope A never affects scope B's M.
- demo honesty: sharpening in the staged window is driven by **real** jail outcomes (customer-reproducible).

**D6:** the filter drops every raw/identifying field by default (re-run the 12 network invariants + new ones); `Clear(ToExportForm())` succeeds and drops identifying candidates on screen; an un-opted-in scope neither contributes nor is identifiable; the ledger computes `SeenInScopes` (a self-asserted count is fail-closed); the consumer feeds only the `FingerprintMatch` context dimension (rule-8 invariant: no inbound trigger).

**D7:** feed contains patterns only; never re-derives from raw; access control + rate limit enforced; reads only already-`Cleared` data (no second egress).

**Regression guards already in the tree (keep green):** `boltevents` `TestEventTypeHasNoOutcomeDiscriminatorField` (the gob-discriminator trap), `contract_test.go` `TestDriverObservationCarriesNoRawData` (scalar-allowlist discipline), the AX0 drift-guard (same-naming on `attrition.Outcome`/`intelligence.StingOutcome`), and the 12 network invariants.

---

## 9. Risks

1. **k-anonymity demo tension (D6-4).** The shipped k=3 gate is hard to satisfy with only 2–3 real scopes; mishandling could tempt lowering `aggregationK` — a **critical anonymity regression**. *Mitigation:* stage real repeated exhibition, never lower k, demo the rejection path.
2. **The `SeenInScopes` ledger is the single remaining trust-critical piece** (the egress filter's documented known-gap). A wrong ledger silently breaks k-anonymity even though the gate looks enforcing. *Mitigation:* build it inside the network pkg as the single trusted source; fail-closed on any producer-asserted count until it lands (D6-2).
3. **F10 field-name drift.** If `profile.go` field names/types don't exactly match the LANDED AX0 contract and the `network.referenceExport` shape, `ExportForm` won't satisfy `Candidate` — and in particular the string field MUST be named `PoisonClass` (lowercases to the only registered enum key) with value in `{"",credential,topology,success}`. *Mitigation:* pin names against contract.go + candidate.go + justify.go before writing; ship the `Clear`-ability assertion test with D2.
4. **D5 wiring gaps (D5-1/D5-2).** The `Matcher` signature carries no events, and there is no jail detection in `capturingEngine` today. *Mitigation:* construct the store with an emerging-flow event-source handle; detect `v.Tier==TierJail` on the `ReportOutcome` path and fetch the jailed flow's events from `boltevents`.
5. **F11 operational.** Standing up scope-2 and any adapter re-wiring needs full box reboots and must be sequenced with Daniel against the LIVE M7 window — risk of disrupting M7 data collection.
6. **Bounded circularity in D5.** A too-low N or too-long freshness could let a single/stale jail over-amplify. *Mitigation:* keep N≥3 and the ~30d cutoff (decision G); test cross-flow-not-self-amplification.
7. **AX4/AX5 export is hard-blocked by design.** Any future move to export `ExploitsObserved`/`ExposureSignals` needs a founder-signed compile-time edit to block.go AFTER percentile coarsening exists, and the AX5 in-perimeter harmlessness predicate review (F4) is a **sub-design that must precede any AX5 generator/export code**. Not in scope for D6/D7 — stated to prevent anyone softening the block.
8. **Dashboard cross-customer + threat-feed panels do not exist at all yet.** Their UI build is additional **unscoped** work beyond the D6/D7 data layer and must be estimated separately so demo-#1 scope is honest (UI-1).
9. **Stale-doc propagation.** The ROADMAP/EGRESS_FILTER_DESIGN status text still calls `network/` a stub. *Mitigation:* update those lines to "BUILT" so the next plan does not inherit the wrong claim.

---

## 10. Deferred-work cross-reference (`docs/ATTRITION_FIVE_AXIS_DESIGN.md` §15 register, verified)

| F# | Item | This-phase status |
|---|---|---|
| **F3** | Egress filter `internal/intelligence/network` | **DONE** (12 green tests, founder-approved 2026-06-11) — the prerequisite this whole plan builds on. |
| **F5** | D5 Phase 2+ (per-axis profiling + jail-fed matching) | **Unblocked** — AX0 persistence (store.go:111–117) satisfies its hard prerequisite. Built in MOAT-3. |
| **F10** | Profile struct field-name finalization (`AxesEngaged`, time-to-disengage bucket type, opp-cost proxy band, `DisengageReason`'s export role) | Pinned in MOAT-1 against the LANDED AX0 contract + the `referenceExport`/`poisonclass` shape (D2-1). |
| **F9** | Dashboard `views/fingerprint.go` per-axis reframe (optional) | **Deferred** — keep the separate flowID-bearing derivation; D2 shares only `median`/`mad`/sort helpers. |
| **F7** | Per-axis cost attribution is COARSE (overlapping, not an exact split) | Holds — `AxesEngaged` is overlapping booleans, never a partition. |
| **F1/F2/F4** | AX4/AX5 generators + the AX5 harmlessness predicate review | Deferred and **out of scope this phase**; AX4/AX5 export stays hard-blocked. F4 does not gate D6/D7. |
| **F11** | Adapter restart needs a full box reboot | A live operational constraint the D6 second-deployment demo (MOAT-6) must sequence around with Daniel. |
