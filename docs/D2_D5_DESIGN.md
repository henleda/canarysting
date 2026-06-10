# D2 (Adversary Profiling) + D5 (Detection Sharpening) — Design

**Status:** FINALIZED 2026-06-10 (founder-approved). Built from a 3-lens research pass + a 9-decision adversarial review of §0. **Read order: §0b (verdicts — what changed and why) → §1 (final architecture) → §2 (phased build).** The §0 table is the *original* proposal, superseded by §0b/§1 where they revise it. Grounded in `docs/INTELLIGENCE.md`, `docs/BASELINE_MULTIPLIER.md`, `docs/ENGINE.md`, `CLAUDE.md` rules 5/7/8/9, and the engine seams (`internal/engine/{baseline,scoring,calibration,tiers}`, `internal/intelligence/{event,cost,profile,recon,network,feed}`).
**Repo:** `/Users/danielhenley/projects/canary-sting/canarysting-repo` · Go 1.24.
**Why now:** the moat. ROADMAP §6 Decision 9 puts the full intelligence layer in demo #1. D2+D5 are the "the control *learns* and sharpens locally" beat; they also produce the anonymized profiles D6/D7 later share. Sequenced after the bystander proof (done), before D6.

---

## 0. DECISIONS NEEDING SIGN-OFF (read first)

Defaults are chosen so the build can proceed; the founder should confirm the load-bearing ones (★).

| # | Decision | Default taken | Why it matters |
|---|----------|---------------|----------------|
| **★ A** | **D5 integration mechanism.** | **A sixth `baseline.Features` dimension `FingerprintMatch ∈ [0,1]`**, fed through the *existing* `FeatureSource → MFromFeatures → M∈[1,M_max]` path — NOT a new/wrapping `MultiplierSource`. | Makes rule 8 **arithmetic** (M only ever multiplies the canary-touch base B; B=0 ⇒ Score=0 regardless of match) and bounds M by construction (the 6th feature is capped at `CMax=1.0` like the others). Zero changes to `scoring`, `tiers`, or `boot.Build()` — the `Aggregator` already implements `FeatureSource`. |
| **★ B** | **Match-strength source.** | **Pre-computed lookup**: D5 calls `FingerprintStore.LookupMatch(scope, cookie) → (strength float64, ok bool)`. D2 maintains the store; D5 only consumes. | Decouples D2 (profiling) from D5 (consumption); keeps `Aggregator.Features()` cheap (one map read, no live similarity math on the scoring hot path). |
| **★ C** | **Evidence floor / gating.** | **Reuse the SINGLE calibration floor** (`DefaultEvidenceFloor=50` analyst labels/scope) — the same 3 gates (`calibrated ∧ live ∧ bucket-sufficient`) that force `M=1.0` also force `FingerprintMatch=0` below the floor. **Plus** a per-fingerprint min-evidence `N=3` confirmed-malicious labels before it can match. | Rule 7 ("default + one feedback loop + evidence floor; learned params go live together, never one without the other"). No second calibration system. The per-fingerprint `N` stops a single label minting a matcher. |
| **★ D** | **Profile schema + anonymization.** | Behavioral-only fields: ordered canary-type sequence, cadence/jitter, peak adjacency/identity novelty, tarpit-persistence, tier/depth progression, and a cost signature (tokens/time/bytes from `StingOutcome`). A deterministic **`BehavioralHash`** (fnv-64a over the *behavioral pattern*, **not** FlowID). **NO** ScopeKey, FlowID, IPs, identities, or decoy contents. | Rule 9 — the profile is the unit D6 may share, so it must carry zero environment-identifying detail by construction (INTELLIGENCE.md §4.1). A static "no-forbidden-field" test gates D6 eligibility. |
| **★ E** | **Unify with the existing `views/fingerprint.go`.** | **Yes — extract the shared derivation** (sort, cadence/jitter, novelty-max, persistence) into the `profile` package; the dashboard `FlowFingerprint` becomes a thin presentation wrapper over `profile.DeriveProfile`. Keep the dashboard JSON contract stable (it's committed + screenshot-verified). | Avoids two divergent fingerprints drifting apart. Carries refactor risk on already-shipped code → done carefully, behind the existing fingerprint tests. |
| **F** | **Hash secrecy.** | **Plain deterministic fnv-64a** (no HMAC/deployment-salt). | A salted hash would break cross-deployment matching (the whole point of D6). The canary-type sequence space is small and non-secret; document the re-identification analysis. Sign off if you want salted-local + unsalted-export instead. |
| **G** | **Confidence decay over time.** | **None in MVP** — match strength is evidence-based (confirmed-malicious count, bounded). Time-decay is a fast-follow tuning dial. | Keeps the first cut simple and explainable; decay tuning needs real data. |
| **H** | **Profiling granularity.** | **Per-flow/session** (one profile per flow-session, same granularity as today's fingerprint), scope-isolated. Cross-flow "coordinated campaign" aggregation = later. | Scope isolation (rule 5) is simplest per-flow; cross-flow aggregation risks intra-scope leakage and needs care. |
| **I** | **Benign-exclusion interaction.** | **No special handling** — rely on the existing benign-exclusion set + rule 8 (a benign flow that never touches a canary already scores 0). Track a fingerprint-collision metric for observability. | A benign flow touching a decoy is already anomalous; D5 only adds *weight context*, never a trigger. |
| **J** | **Shared (D6) profiles.** | **Out of scope** for D2/D5 (local-only). The `FingerprintMatch` dimension is designed so D6 can later feed it from *both* local and anonymized-shared profiles via the same single dimension. | Keeps this pass local; D6 is a separate, trust-critical chokepoint (egress filter). |
| **★ K** | **Build phasing.** | **Two phases.** Phase 1: wire the 6th `FingerprintMatch` dimension end-to-end with strength **always 0** (zero behavioral change) + prove the rule-8/bounds/gate invariants as tests. Phase 2: implement D2 (`DeriveProfile` + store + feedback loop) so strength becomes real, behind the floor. | De-risks the engine change (Phase 1 is provably a no-op behaviorally); Phase 2 is pure-intelligence + a store. Each phase ships green with `make check`. |

**Locked (no sign-off — carried from the rules):** M ∈ [1, M_max], `base=0 ⇒ Score=0`, scope isolation absolute, tiers/thresholds untouched by D5 (it only moves M → score → tier naturally), async-only T0–1, fail-safe (any fingerprint-lookup failure → neutral, never suppresses or fabricates detection), every learned param obeys rule 7.

---

## 0b. Adversarial review verdicts (2026-06-10)

Each §0 decision was independently challenged against the code + rules. Result: **1 confirm, 6 revise, 2 reject-default.** The design *direction* holds; several *mechanisms* changed. Revised positions below supersede the table above.

- **A → REVISE (was: 6th Euclidean-norm feature).** The norm DILUTES confirmed-malice: a strong fingerprint match with low novelty barely moves M (`d=√1→M≈1.6`) while novelty alone moves it more (`d=√5→M≈2.6`) — backwards for an intelligence layer. It also double-counts (the profile *is* adjacency/identity behavior) and pushes max `d` √5→√6, shifting M for all active flows. **REVISED: a separate, bounded ADDITIVE sharpening term** — `M = 1 + (M_max−1)·g(d) + α·min(match,1)`, `α ≤ (M_max−1)`, final `M` clamped to `M_max`. Keeps rule 8 arithmetic (still inside M, so `B=0⇒Score=0`), stays bounded, and decouples threat-evidence from anomaly. (The spec's own §3.3 weighted-sum is the alternative.) `FingerprintMatch` stays a `Features` field; only the *combination* changes.
- **B → REVISE (was: per-(scope,cookie) stored strength).** Socket cookies are kernel-recycled (`aggregator.go` fold/prune + `flowReset` on reuse); a reused cookie would inherit the prior socket's strength → stale/mis-attributed, and it never reflects THIS flow's emerging behavior. **REVISED: match on the live flow's DERIVED behavior** — `LookupMatch` derives the flow's emerging profile (its sequence-so-far) and matches it against the per-scope known-malicious profile set by behavioral similarity; anchored to the same `flowReset` lifecycle so cookie reuse starts fresh. Key the malicious-profile store by `BehavioralHash`, not cookie.
- **C → RESOLVED (locked 2026-06-10, founder): Option 3 — jail-outcome is the feedback source.** The trap was the *feedback source*, not D5 itself: gating D5 behind the 50-analyst-label calibration floor means it would activate in the M7 demo via the **staged labeler** (auto ground truth) — real in the demo, NOT reproducible at a customer. **FIX: D5 learns from JAIL OUTCOMES, not analyst labels.** A flow that reaches **T3/jail** is a high-confidence, **customer-reproducible** confirmed-malicious signal (it required `minTouches` distinct decoy touches — rule 8 fully honored). On jail, the jailed flow's derived `Profile` is recorded/strengthened in the per-scope malicious-profile store. D5 is therefore gated by its **own** evidence floor (per-fingerprint `N` confirmed jails + freshness), **NOT** the 50-analyst-label calibration floor — so it is honest and demoable *even in the staged window* (jail outcomes there are genuinely real). Analyst confirmation may *additionally* strengthen a profile, but is not required. The moat beat becomes the honest, automatic: *"this attacker got jailed → we profiled it → a returning attacker with the same signature is hit harder/faster, no analyst in the loop."* **Circularity is bounded** (see §1).
- **D → REVISE (was: static no-forbidden-field test).** Rule 9's bar is *semantic*, not field-names: cadence/jitter leaks target RTT + tarpit delays; the canary-type SEQUENCE leaks decoy taxonomy/placement; the cost signature leaks attrition payload size/config; tier/depth leaks escalation thresholds — all pass a field-name test. **REVISED: the LOCAL profile stays rich (for D5 matching + Model 2); the D6 EXPORT form is a deliberate, per-field-justified, COARSENED transform** (cadence→bands, sequence→unordered set or drop, cost→percentile buckets/booleans, tier→"reached T2+"). Bake the boundary now; the transform itself lands with D6.
- **E → REVISE (was: unify the derivation).** The dashboard `DeriveFingerprint(flowID, …)` hashes `(flowID|sequence)` and carries `FlowID` — unifying risks smuggling identity into the anonymized profile (or stripping identity the dashboard needs). **REVISED: share only low-level HELPERS** (`median`, `mad`, sequence-sort) via a small shared package; keep the two derivations separate (dashboard hashes with flowID; profile hashes sequence-only, no flowID). Lower risk on the shipped, screenshot-verified fingerprint.
- **F → REJECT-DEFAULT (was: plain fnv, export-ready).** A plain fnv over the 5-type vocab is fully enumerable (~9.7M for len≤10, <1s) → a D7-feed recipient could reverse a shared hash to learn another customer's probe sequence/decoy taxonomy. **REVISED: local hash is fine (plain or salted); the cross-boundary form is NOT a raw hash** — it's an aggregated/justified export (e.g. "seen in ≥3 scopes" before sharing, or stats only). Folds into D (export transform) and defers to D6.
- **G → REVISE (was: no decay).** The baseline already staleness-gates (`SetLive`→M=1 when stale), but a stored fingerprint would keep amplifying — an asymmetry that (with cookie reuse) is a latent false-amplification path. **REVISED: add a freshness CUTOFF** to stored malicious profiles (`last_evidence_ts`; `LookupMatch`→0 beyond a threshold, e.g. 30d), mirroring `SetLive`. Not a full decay curve — just a staleness gate. (B's behavior-keying also removes the cookie-reuse leg.)
- **H → REVISE.** Per-flow misses coordinated multi-flow campaigns (real attackers split across identities; the moat sells exactly this). **MVP stays per-flow/session but the claim is scoped explicitly**, and cross-flow aggregation is a named fast-follow; validate against M9's agent.
- **I → REVISE (consistency with the bystander proof!).** D5 adds a NEW bounded amplification path: a benign-but-canary-touching flow (scanner/misconfig) that matches a *mislabeled*-malicious fingerprint gets M amplified — it still requires a canary touch (so "0 legitimate flows actioned" holds for non-touching traffic), but it can push a borderline touch tag→contain. **REVISED: tighten label validation before a profile enters the malicious store, make the per-fingerprint `N` semantics explicit, add a collision metric, and keep the bystander-proof wording precise** (the guarantee is "no action without a decoy touch," which D5 preserves; D5 changes *how hard* a confirmed attacker's touch is hit, within bounds).
- **J → CONFIRM.** D6 out of scope; the additive `match` term + behavior-keyed store leave a clean seam for shared profiles later (via the D/F export transform).
- **K → CONFIRM.** Phase-1 neutrality is mathematically sound (a zero additive term / zero norm component is a true no-op). Implementation: `contributions()`→6 elements (or the additive term), fix positional struct literals in `baseline_test.go`, update `FeaturesMap`.

**Net design change:** D5 = a **bounded additive sharpening term** (not a norm dimension), driven by **behavior-keyed** matching of a flow's emerging profile against a per-scope **freshness-gated** malicious-profile set, **disabled during the staged window** and activated only on genuine feedback, with the **D6 export form** a deliberate coarsened transform (deferred). Phasing (K) unchanged.

---

## 1. Architecture (finalized)

### 1.1 D2 — adversary profiling (`internal/intelligence/profile/`, pure, mirrors `cost.Rollup`)
```
profile.DeriveProfile(events []AdversaryInteractionEvent) *Profile   // caller guarantees one scope; nil for empty
```
`Profile` is **anonymized-by-construction** (decision D): behavioral fields only (ordered canary-type sequence, cadence/jitter, peak adjacency/identity novelty, tarpit-persistence, tier/depth progression, cost signature) + a deterministic `BehavioralHash` over the *behavioral pattern* (NOT FlowID). No ScopeKey/FlowID/IP/decoy contents. It is the input to D5 matching (local), Model 2 bait (future), and D6 (shared, future).

**Local vs export (decisions D, F):** the *local* `Profile` is rich. The *cross-boundary* form is a **separate, deliberate transform** (`profile.ExportForm` / `ValidateProfileForSharing`) that coarsens per rule 9 (cadence→bands, sequence→unordered set or dropped, cost→percentile buckets, tier→"reached T2+" bool) and aggregates ("seen in ≥k scopes") — built with **D6**, not now. The boundary is baked in; the transform is stubbed + tested to reject identity-bearing fields.

**Reuse (decision E):** share only low-level helpers (`median`, `mad`, sequence-sort) via a small shared package; the dashboard `views/fingerprint.go` keeps its own flowID-bearing hash. No unification of the two derivations (avoids identity smuggling into the anonymized profile).

### 1.2 D5 — detection sharpening (a bounded ADDITIVE term in M)
**Mechanism (decision A — additive, NOT a 6th norm dimension):**
```
M = clamp( 1 + (M_max − 1)·g(d)  +  α · match , 1, M_max )
      └─ baseline-novelty term ──┘   └ sharpening ┘
```
where `d` is the existing 5-feature bounded Euclidean norm, `g` the saturating Hill function, `match ∈ [0,1]` the fingerprint-match strength, and `α ≤ (M_max − 1)` a documented sharpening constant (default e.g. `0.5`). This **decouples** threat-evidence from anomaly (no sqrt-dilution, no double-counting, no √5→√6 scale shift), stays bounded by the final `clamp`, and keeps rule 8 arithmetic (the term lives *inside* M; `B=0 ⇒ Score = 0 × M = 0`). `FingerprintMatch` stays a field on `baseline.Features`; only the *combination* in `MFromFeatures` changes.

**Matching (decision B — behavior-keyed, not cookie-keyed):** on each scoring event, `match` = similarity of the live flow's **emerging** `DeriveProfile(events-so-far)` against the per-scope malicious-profile set (keyed by `BehavioralHash`), anchored to the aggregator's existing `flowReset` lifecycle so a recycled cookie starts fresh. `cookie=0`/lookup-miss/error → `match=0` (fail-safe). The store is per-scope, bbolt-persisted, rehydrated on boot.

**Feedback source (decision C — Option 3, jail outcomes):** the per-scope malicious-profile set is built from **T3/jail outcomes** — when a flow is jailed, its `DeriveProfile` is recorded/strengthened (per-fingerprint confirmed-jail count, capped). This is the single rule-7 feedback loop for D5: documented default (`match=0`), one loop (jail outcomes), evidence floor (`N` confirmed jails per fingerprint + a **freshness cutoff** `last_jail_ts`, decision G). Customer-reproducible (no analyst required); analyst "malicious" labels may *additionally* strengthen a profile.

**Gating:** the `α·match` term is forced to 0 unless (a) the matched fingerprint has ≥`N` confirmed jails, (b) it is fresh, and (c) the scope is past cold-start (the same readiness the baseline term uses). Below any gate → `match` contributes nothing → `M` is the unchanged baseline multiplier.

### 1.3 Bounded circularity (the Option-3 safety analysis)
D5 raises M → score → could push a flow toward T3 → whose profile then sharpens future flows. This is **bounded and intended** (cross-flow learning, not self-amplification):
- A flow can only be jailed by reaching the **`minTouches[T3]` distinct decoy touches** (tier decider floor) — D5 changes M, never the touch requirement (rule 8). D5 cannot manufacture a jail without real escalation.
- `M` is hard-clamped to `M_max`, so per-touch amplification is capped.
- The freshness cutoff + per-fingerprint `N` prevent a single or stale jail from minting a strong matcher.
- The profile recorded is of the *jailed* flow; it sharpens *other* matching flows (cross-flow), not itself.

### 1.4 Guardrail summary
- *Rule 8:* match only moves M; `B=0 ⇒ Score=0`. Arithmetic.
- *Rule 7:* `match` = learned param with default 0, one feedback loop (jail outcomes), evidence floor (`N` jails + freshness).
- *Rule 5:* malicious-profile set keyed per scope; never aggregated across scopes.
- *Rule 9:* local Profile carries no env-identifying field; the cross-boundary form is a separate coarsened/aggregated transform (deferred to D6).
- *Bounds:* final `clamp(·,1,M_max)`.
- *Fail-safe:* any match/lookup failure → neutral, never suppress or fabricate.

---

## 2. Phased build (decision K — Phase-1 neutrality is a true no-op)

**Phase 1 — the seam, behaviorally neutral (engine) — ✅ DONE (uncommitted):**
1. `FingerprintMatch float64` added to `baseline.Features` but **excluded from `contributions()`** (the norm stays 5 → `d` unchanged); `MFromFeatures` adds `+ α·clamp(match,0,1)` then `clamp(·,1,M_max)`. `Params.SharpeningAlpha` clamped to `[0,M_max−1]` in `Normalized`. **`DefaultParams` ships α=0 in Phase 1** (D5 off everywhere — engine *and* the dashboard's M reconstruction, which both use `DefaultParams`); `DefaultSharpeningAlpha=0.5` documents the Phase-2 value.
2. `baseline.Matcher` interface (`Match(scope, flow, at) float64`) + `Store.matcher` + `UseMatcher` + `Multiplier` folds the strength into `f.FingerprintMatch` **outside the Store lock** (same B→A deadlock discipline as `fs.Features()`), then defers to `s.M`'s readiness gate. Nil matcher (the default, all of Phase 1) ⇒ no sharpening.
3. **Persistence forward-safety (review fix):** `FeaturesMap` + `featuresFromMap` carry `fingerprint_match` (0 in Phase 1) so a Phase-2 non-zero match round-trips through the event store and the dashboard's M reconstruction matches the engine.
4. `boot.go` unchanged (no `Params` ⇒ α=0). **Tests** (all green) prove: byte-identical no-op at `match=0` *and* `α=0`; anti-dilution (a low-novelty match still raises M — the property the norm approach failed); match & α clamped, M ≤ M_max; readiness gate forces M=1.0 even with a full match; nil-matcher / unready-scope neutral. `make check` EXIT=0; **zero behavioral change.** Reviewed (feature-dev:code-reviewer): 2 findings (DefaultParams α; FeaturesMap round-trip) applied.

**Phase 2 — D2 profiling + jail-fed matching (intelligence + engine; ~2–3 days):**
5. `internal/intelligence/profile/`: `profile.go` (the anonymized `Profile`, decision D), `derive.go` (`DeriveProfile`, pure, mirrors `cost.Rollup`), `features.go` (shared feature-key + tarpit-threshold consts), `match.go` (behavioral similarity → `[0,1]`), `export.go` (`ExportForm`/`ValidateProfileForSharing` — coarsen + reject identity-bearing fields; transform deferred to D6 but the gate ships), tests (determinism, hash-ignores-FlowID, no-forbidden-field, export-rejects-identity).
6. Extract shared low-level helpers (decision E); leave `views/fingerprint.go`'s derivation separate, behind its existing tests (no JSON drift).
7. `MaliciousProfileStore` real impl: per-scope set keyed by `BehavioralHash`, each entry `{confirmed_jails, last_jail_ts}`; `Match` = best similarity of the emerging profile vs the set, gated by `N` jails + freshness + cold-start; bbolt-persisted (`mp:{scope}:{hash}`), rehydrated on boot.
8. **Wire the jail-outcome feedback (Option 3):** at the T3/jail composition point (the existing `OnVerdict`/containment seam in `internal/boot` / `cmd/*`), on a jail, `DeriveProfile(jailed flow's events)` → `store.RecordJail(scope, profile)`. (Optionally also strengthen on analyst `WasMalicious` Tier≥2 labels via `feedback.Intake`.)
9. `docs/FINGERPRINT_MATCH.md` + update `docs/INTELLIGENCE.md`: the match metric, `α`, the gates, the jail-feedback loop, the bounded-circularity analysis.
10. End-to-end tests: a *jailed* flow's profile sharpens a **subsequent matching flow's** touch (M higher, ≤ M_max, after `N`); a benign/no-touch flow is unaffected; scope-isolated; stale/under-`N` profile ⇒ no sharpening; **demoable in the staged window honestly** (jail outcomes are real ground truth there).

Built design → implement → adversarial review → fixes, like M8/M9. **D5 ships ENABLED** (Option 3 feedback is customer-reproducible) — no "disabled in staged window" caveat needed.

---

## 3. Files

| File | Action | Phase |
|------|--------|-------|
| `internal/engine/baseline/baseline.go` | MODIFY — `FingerprintMatch` field; **additive `α·match` term + `clamp(·,1,M_max)`** in `MFromFeatures` (NOT a norm dimension); `α` documented const | 1 |
| `internal/engine/baseline/baseline_test.go` | MODIFY — additive-term invariants: no-op at `match=0`, bounded at `match=1`, rule-8, gates | 1 |
| `internal/engine/observebaseline/aggregator.go` | MODIFY — `Features()` derives emerging profile + sets `FingerprintMatch` via the store (no-op default); honor `flowReset` | 1 |
| `internal/intelligence/profile/{profile,derive,features,match,export}.go` | CREATE — anonymized `Profile`, pure `DeriveProfile`, similarity `Match`, `ExportForm`/`ValidateProfileForSharing` (D6 gate) | 2 |
| `internal/intelligence/profile/*_test.go` | CREATE — determinism, hash-ignores-FlowID, no-forbidden-field, export-rejects-identity | 2 |
| `internal/intelligence/stats/` (or similar) | CREATE — shared `median`/`mad`/sequence-sort helpers (decision E) | 2 |
| `internal/engine/.../maliciousprofilestore.go` | CREATE — per-scope `BehavioralHash`-keyed set `{confirmed_jails,last_jail_ts}`; `Match`; `RecordJail`; bbolt-persisted (`mp:{scope}:{hash}`); freshness + `N` gates | 2 |
| `internal/dashboard/backend/views/fingerprint.go` | MODIFY — use shared helpers only; derivation + JSON contract unchanged | 2 |
| `internal/boot/boot.go` / `cmd/*` (jail seam) | MODIFY — on T3/jail (`OnVerdict`/containment), `RecordJail(scope, DeriveProfile(events))`; wire store onto aggregator | 2 |
| `docs/FINGERPRINT_MATCH.md`, `docs/INTELLIGENCE.md` | CREATE/UPDATE — match metric, `α`, gates, jail-feedback loop, bounded-circularity | 2 |

---

## 4. Test invariants (encoded as failing-if-violated, per build discipline §5)
- **match-alone-no-touch ⇒ Score 0** (rule 8, arithmetic — `B=0 ⇒ Score=0`).
- **adding the additive term with `match=0` ⇒ M byte-identical** for all existing flows (Phase-1 no-op proof).
- **match-with-touch ⇒ M strictly higher but ≤ M_max** (final clamp); **no-match touch ⇒ baseline M unchanged**; **a fingerprint match with LOW novelty still raises M** (the anti-dilution test that the norm approach failed).
- **gates:** under-`N` jails / stale fingerprint / cold-start ⇒ `match` contributes 0.
- **`cookie=0` / lookup-miss / store-error / `flowReset` ⇒ neutral**, never suppress, never crash, never fabricate.
- **bounded circularity:** a flow below `minTouches[T3]` is never jailed regardless of `match` (D5 can't manufacture a jail).
- **`DeriveProfile` deterministic**; **`BehavioralHash` ignores FlowID**; **`Profile` has no forbidden (scope/flow/IP/decoy) field**; **`ExportForm` rejects identity-bearing fields** (rule 9 / D6 gate).
- **scope isolation:** a profile recorded in scope A never affects scope B's `M`.
- **demo honesty:** D5 sharpening in the staged window is driven by real jail outcomes (customer-reproducible), not synthetic analyst labels.
