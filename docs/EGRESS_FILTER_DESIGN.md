# docs/EGRESS_FILTER_DESIGN.md — The Egress Filter (Design)

**Status:** ✅ FOUNDER-APPROVED 2026-06-11 — all §0 decisions (D0–D10) approved as written, including the §5 formal "cannot re-identify" definition (the INTELLIGENCE.md §9 open item, now recorded there as RESOLVED). Implementing per §10. The build target is `internal/intelligence/network/` (today a `doc.go` stub). Built from the authoritative specs (`docs/INTELLIGENCE.md` §2/§5.4/§7/§8/§9, `CLAUDE.md` rule 9, `docs/SCOPE.md`, `docs/D2_D5_DESIGN.md` decisions D/F, `docs/ATTRITION_FIVE_AXIS_DESIGN.md` §2.5/§14/§15, `docs/ROADMAP.md` D6/D7) plus a 3-lens research pass and an adversarial **leak review** whose findings are folded in throughout (every place a correction lands is marked **[leak-review]**).
**Repo:** `/Users/danielhenley/projects/canary-sting/canarysting-repo` · Go 1.24.

> **This document IS the `docs/INTELLIGENCE.md` §9 open item** — *"the anonymization method for fingerprints and the formal definition of 'cannot re-identify,' reviewed before the network ships."* §5 below is that formal definition, surfaced for founder review. Nothing crosses a boundary until §0 is signed off and §5 is recorded in `docs/INTELLIGENCE.md` §9 as resolved.

---

## The one paragraph

The egress filter is the **single default-deny chokepoint** through which any derived intelligence may cross a CanarySting deployment boundary (`CLAUDE.md` rule 9; `INTELLIGENCE.md` §2). It is the most security-critical component in the product: a single leaked field breaks the promise the whole product is sold on. This milestone (founder **decision A2**, 2026-06-10) is a **standalone prerequisite** gating three consumers — (a) D6 cross-customer sharing, (b) the D7 threat feed, (c) the cross-boundary use of Track E AX4 `ExploitsObserved` / AX5 `ExposureSignals`. The MVP is the **GATE + the field-justification model + the formal cannot-re-identify definition + the AX4/AX5 hard block + the full invariant test suite**. It is **NOT** a live network transport, the real coarsening transform body, the aggregation computation, or a second deployment — those are D6/D7. Default-deny means: **a field crosses only if it is explicitly marked safe AND carries a per-field justification AND survives the structural checks; anything unmarked, untagged, wrong-kind, or identity-named is dropped and the candidate is rejected whole.**

---

## 0. Decisions needing founder signoff (read first)

Defaults are chosen so the build can proceed; the ★ rows are load-bearing and must be confirmed. Every row reflects a **[leak-review]** correction where marked.

| # | Decision | Default taken | Why it matters |
|---|----------|---------------|----------------|
| **★ D0** | **The formal "cannot re-identify" definition (§5).** Adopt the 3-part predicate: no singling-out (k-anonymity) / no linkability (quasi-identifier denylist) / no inference (no raw enumerable hash, no raw counts). | **Adopt as written**, and record it in `INTELLIGENCE.md` §9 as RESOLVED + cross-link from `reidentify.go`. | This is the explicit §9 open item that MUST be reviewed before the network ships. It is conservative, testable, and mapped to our known small vocabularies (≈5 canary types, 5 axes). |
| **★ D1** | **Default-deny is a KIND ALLOWLIST with a `default:` terminal-deny arm — not a denylist of known-bad kinds. [leak-review]** | Safe kinds = `{Bool, Int…Int64, Uint…Uint64, Float32, Float64}` (already-coarsened scalars) **plus** `String` ONLY when validated against an explicit closed enum value-set. **Every other `reflect.Kind` hits `default:` and ERRORS.** | The original denylist (`[]byte/string/ptr/slice/map/time.Time`) left ~20 kinds (`Struct`, `Array`, `Complex`, `Chan`, `Interface`, `Uintptr`, `UnsafePointer`…) falling through to an implicit pass — and `time.Time`'s kind IS `Struct`, so a "forbid time.Time by type" rule is leaky against a generic struct. Mirror the existing `TestDriverObservationCarriesNoRawData` switch (scalar allowlist + `default:` fatal). |
| **★ D2** | **The reflection walk is RECURSIVE and denies unregistered structs. [leak-review]** | `Clear` recurses into every nested/embedded struct and applies the per-field allowlist+tag+name+predicate **at every level**. No struct is ever "opaque-safe". `time.Time` rejected by KIND (`Struct`) AND by an explicit type check. | A non-recursive walk would treat a nested per-axis-signature struct (or a nested `ScopeKey`) as one opaque, passable field. Embedded/anonymous fields are walked; unexported fields are unreadable and therefore irrelevant (a producer must export to share). |
| **★ D3** | **The carrier's serialization is itself gated — not just the candidate. [leak-review]** | `Cleared` holds only value-copied scalars (the D1 safe kinds), never a boxed pointer/slice/map/aliased reference. `Cleared.Marshal()` re-validates every payload entry's dynamic kind against the D1 allowlist before producing wire bytes; D6 transport consumes ONLY those bytes, never raw `Cleared` internals. | Boxing into `any` can carry a mutable pointee. The carrier is a second egress surface unless its serialization is part of the chokepoint. |
| **★ D4** | **AX4/AX5 hard block is anchored to TYPE + SEMANTIC NAME, not a producer-written marker. [leak-review]** | Permanent deny via three layers: (a) the candidate-type denylist rejects any `StingOutcome`/`AdversaryInteractionEvent`-bearing type outright; (b) `ExploitsObserved`/`ExposureSignals` and any `*exploit*`/`*exposure*` field name are on the identity/semantic denylist, so a *renamed same-valued* field is still caught; (c) the `egress:"blocked,…"` marker remains as defense-in-depth but is **NOT** the sole barrier. Unblockable only by a founder-signed edit to `block.go` (compile-time), never a runtime flag. | A marker the producer controls can be renamed/omitted to route around the block. The block must survive a malicious or careless producer renaming the field. A runtime config toggle is exactly the silent-relax path rule 9 forbids. |
| **★ D5** | **k for "seen in ≥k scopes" is a NETWORK-PACKAGE CONSTANT, never producer-supplied. [leak-review]** | `optin.go` `const aggregationK = 3` (must be ≥2; k=1 is singling-out). `Clear` compares `SeenInScopes` against this const. `AggregationK` is **removed** from the producer-supplied `ContributionContext`. | A producer-supplied `AggregationK=0` makes `SeenInScopes(0) ≥ K(0)` TRUE, inverting the fail-closed gate on a zero value. k must originate inside the chokepoint. |
| **★ D6** | **The k-gate is ADVISORY until D6 computes `SeenInScopes` from a real cross-scope ledger. [leak-review]** | Document this as a KNOWN GAP. MVP recommendation: **fail closed on any candidate that supplies its own count** — `Clear` rejects a self-asserted `SeenInScopes` until the network package's own ledger exists (D6). The gate is encoded now; its *enforcement* is honest only once the ledger lands. | Until D6 computes the count, a producer could assert any `SeenInScopes ≥ k` over a single-scope (singling-out) pattern. Do not let the MVP imply the k-gate is enforcing when nothing computes the count. |
| **D7** | **The justification marker lives as a struct TAG on the producer's export struct, validated by `Clear` via reflection — not a separate table in `network`.** | `egress:"safe,<non-empty-reason>"`. The tag keeps the justification next to the field so it cannot drift; `Clear`'s independent re-check + the denylist means the producer cannot grant itself trust the gate doesn't separately confirm. | Two independent checks (producer's `ExportForm` coarsening + `Clear`'s structural re-verification) must both fail to leak. |
| **D8** | **`Clear` is ALL-OR-NOTHING: error naming the first bad field, no `*Cleared`. [leak-review]** | Fail closed; no partial passing / field-stripping. The producer must hand `Clear` a fully-clean candidate. | Partial passing invites a producer to lean on the gate to strip fields, eroding the two-independent-checks property. |
| **D9** | **No raw `BehavioralHash` crosses in any form.** | The cross-boundary matching unit is the aggregated coarse pattern gated at k scopes, never a hash. A plain fnv over the ≈5-type vocab is enumerable in <1s (D2_D5 decision F). | Salted-local + a privacy-preserving set-membership scheme for cross-deployment hash matching is a separate future signoff, deferred to D6. Flag now, do not invent. |
| **D10** | **All feature/cost maps are flattened to individually-tagged banded scalars; no map (and no map KEY) ever crosses. [leak-review]** | `map` kind is denied by D1. Each coarsened feature becomes a named struct field with its own `egress:"safe,<reason>"` tag and band value; feature key names (e.g. `adjacency_novelty`) are baseline-schema taxonomy and are never emitted. | A map leaks both raw float values (singling-out) and the baseline feature schema (the key taxonomy). |

**Locked (no signoff — carried from the rules):** single chokepoint, default deny, fully tested (`INTELLIGENCE.md` §7); only derived/anonymized patterns cross (rule 9 / §2); scope state never leaves (rule 5 / SCOPE.md, stricter rule wins); the shared set returns as detection context only, never a trigger (rule 8 / §5.4); per-deployment opt-in to contribute and to consume, independent toggles (§5.4); if any constraint cannot be satisfied for a pattern, it stays local (§5.4 closing line).

---

## 1. Architecture — the single chokepoint

### 1.1 The entire public surface

`internal/intelligence/network` is the **only** package that may produce a value destined to cross a deployment boundary. Its public surface is exactly one function and one opaque carrier:

```go
// Clear is the single default-deny egress chokepoint (rule 9, INTELLIGENCE.md §2/§7).
// It returns (nil, err) on ANY untagged, wrong-kind, identity-named, blocked, denylisted,
// un-opted-in, or sub-k candidate. A non-nil *Cleared is the ONLY value any future
// cross-boundary transport (D6) may accept.
func Clear(c Candidate) (*Cleared, error)

// Cleared is an opaque carrier with UNEXPORTED fields only. Its sole constructor is Clear().
// No other package can construct one. Marshal re-validates before producing wire bytes (D3).
type Cleared struct {
    payload map[string]scalar // value-copied scalars only — never a boxed ptr/slice/map (D3 [leak-review])
    meta    clearMeta
}
func (c *Cleared) Marshal() ([]byte, error) // re-checks every payload entry's kind (D3)
```

Because `Cleared` has no exported fields and no alternate constructor, **"everything crossing must call `Clear`" is enforced by the Go type system, not by convention**: if you don't hold a `*Cleared`, you have nothing to put on the wire (D6 transport's send signature takes `*Cleared`). There is no second path. This is the §7 *"one chokepoint, default deny, fully tested"* mandate made structural.

### 1.2 Default-deny by construction

`Clear` does **not** transform or coarsen. It is the GATE. It walks the candidate field-by-field, **recursively** (D2), and a field passes only if **all** of the following hold:

1. it carries an `egress:"safe,<reason>"` struct tag with a non-empty engineer-written `<reason>` (D7);
2. its `reflect.Kind` is in the **closed safe allowlist** (D1) — a scalar, or a `String` validated against an explicit closed enum value-set; **every other kind hits the `default:` arm and errors** (D1 [leak-review]);
3. its field name is **not** on the identity/semantic denylist (§5.2);
4. it passes `canReIdentify(field, value) == false` at runtime (§5).

Any field failing any of these → `Clear` returns a non-nil error naming the field and a nil `*Cleared` (D8, all-or-nothing). **A new field added to a candidate struct that nobody tagged is, by default, untagged → it hits the gate → `Clear` errors.** That is the load-bearing property: **adding a field can never silently leak; it fails the gate until an engineer tags and justifies it.** This is the `INTELLIGENCE.md` §2 per-engineer test — *"if an engineer cannot state, for a given field, why it cannot re-identify a customer, that field does not leave"* — promoted to a compile-and-test-time obligation: the `<reason>` string IS the stated justification, and the test suite (§8) fails if any reference-candidate field reaches `Clear` without one.

### 1.3 Separation of powers — coarsening lives UPSTREAM, the gate lives here

Per `INTELLIGENCE.md` §8 build order (*"egress filter first and most carefully, then anonymize/aggregate, then the consumer"*), the **coarsening transform** is `profile.ExportForm` / `profile.ValidateProfileForSharing` (D2_D5 decision D; built when D2 lands), NOT this package. `network.Clear` is an **independent second check** over whatever `ExportForm` produced — a producer and a gate that **distrust each other**:

- `profile.ExportForm` coarsens: cadence → bands; canary-type sequence → unordered set or dropped; tier → "reached T2+" bool; cost → percentile buckets; `Axes` bitset → per-axis engaged booleans; `TimeToDisengageSec` → bands; `PoisonClass`/`PoisonReached` → coarse class + bucketed depth (stage taxonomy dropped).
- `network.Clear` re-verifies every field is tagged-safe and is actually a coarse scalar, AND enforces the cross-cutting rules `ExportForm` cannot (k-anonymity, opt-in, the AX4/AX5 hard block, the candidate-type denylist).

**Two independent failures must both occur to leak; neither alone suffices.** The MVP ships a hand-written reference `Candidate` (the shape D2 must satisfy) so the gate is exercised today; when `profile.ExportForm` lands it slots into `Candidate` with zero filter change.

### 1.4 Candidate-level preconditions the field walk cannot see

Before field inspection, `Clear` enforces:

- **(a) Candidate-type denylist (D4 [leak-review]).** A `reflect` type-identity switch (plus an embedded-type scan, so wrapping a denylisted type in a new struct does not launder it) hard-rejects: `cost.Summary` and `cost.Rollup` output (rule-5 local-only CISO KPI; `cost.go`: *"never reaches across a scope boundary"*), `intelligence.AdversaryInteractionEvent` and `intelligence.StingOutcome` / `contract.StingOutcome` (carry `ScopeKey`+`FlowID`+`Features` and the AX4/AX5 fields), and any baseline / scope-state type. These can never even be field-inspected.
- **(b) Contribute opt-in.** An explicit per-deployment `Contribute bool` (default false). An un-opted-in scope produces nothing and is therefore unidentifiable. A zero-value `ContributionContext` denies.
- **(c) Aggregation k-gate (D5/D6 [leak-review]).** `Clear` rejects anything with `SeenInScopes < aggregationK` where `aggregationK` is a **network-package const** (default 3, ≥2). Until D6's ledger computes the count, recommendation D6: fail closed on a self-asserted count.
- **(d) AX4/AX5 hard block (D4).** See §6.

### 1.5 What it gates NOW vs defers — see §7.

---

## 2. Package and file layout

```
internal/intelligence/network/
  doc.go         UPDATE — point at Clear() as the single chokepoint; cite §5 predicate
  filter.go      Clear(Candidate) (*Cleared, error); the recursive default-deny walk; Cleared + Marshal (D2,D3,D8)
  candidate.go   type Candidate interface{ EgressFields() (any, ContributionContext) }; the reference candidate
  justify.go     tag parsing (const tagKey="egress"); the SAFE-KIND ALLOWLIST + default-deny arm (D1); enum value-sets
  reidentify.go  canReIdentify(field, value) — the executable §5 predicate; identity/semantic NAME denylist (D4 §5.2)
  optin.go       type ContributionContext{ Contribute bool; SeenInScopes int }; const aggregationK=3 (D5)
  block.go       denylistedType(any) bool (D4a); the AX4/AX5 permanent block (D4b/D4c)
  filter_test.go the invariant suite (§8) — the rule the whole product is sold on
```

`Candidate.EgressFields()` returns the tagged export struct + its opt-in/aggregation context. The export struct's fields carry the `egress:"safe,<reason>"` tags `Clear` validates.

---

## 3. The field-justification model (default-deny by explicitly-marked-and-justified FIELD)

A field crosses **iff**:

```
tagged egress:"safe,<non-empty-reason>"        (D7 — the justification, next to the field)
  AND reflect.Kind ∈ safe allowlist             (D1 — allowlist with default-deny arm)
  AND String-typed fields validate vs a closed enum value-set   (D1 — no free strings)
  AND field name ∉ identity/semantic denylist   (§5.2 / D4)
  AND canReIdentify(field, value) == false       (§5 — runtime predicate)
```

The default — no tag, an unrecognized tag, a non-allowlisted kind (`Struct`/`Array`/`Slice`/`Map`/`Ptr`/`Interface`/`Chan`/`Func`/`Complex`/`Uintptr`/`UnsafePointer`/**`Float32`/`Float64`**/a string not in any enum set), a denylisted name, or a `canReIdentify==true` value — is **DENY**. Marking is **never** by struct, by omission, or by field-name-pattern alone: it is per FIELD, explicit, and justified. The bar is **semantic, not field-name-based** (D2_D5 decision D): cadence leaks target RTT + tarpit delays; the canary-type sequence leaks decoy taxonomy/placement; the `Axes` composition maps 1:1 to `StingFloor.Axes()` and so leaks the floor/posture config; tier/depth leak escalation thresholds; `PoisonClass` stage taxonomy leaks the poison generator config — every one passes a naive no-forbidden-name test, so the structural allowlist + the predicate + k-anonymity together are what make it sound. **The `<reason>` string is necessary but never sufficient** (a lazy `safe,because` passes the non-empty check) — a bad reason on a raw field still fails the kind allowlist, the name denylist, and the predicate.

### 3.1 Coarseness is enforced, not just scalar kind (leak-review round 2)

The first implementation's allowlist proved a field was a SCALAR but not that it was COARSE — a red-team passed a raw `float64` RTT (`0.0034219`), a raw maze byte-count (`8054`), and a raw second-count disguised as a "0..3 band" (`987654`) through the gate, because all are allowlisted kinds and `canReIdentify` ignored the value. Closed by two structural rules in `clearStruct`, so the gate enforces coarseness WITHOUT trusting the (unbuilt) upstream `ExportForm`:

- **Floats are denied outright.** A continuous value singles out (§5.1.1); a coarse value must be an int BUCKET or a bool. `Float32`/`Float64` are off the kind allowlist.
- **Every numeric field MUST declare a coarse band** `egress:"safe,band=LO..HI,<reason>"`, and `Clear` validates BOTH that `HI-LO <= maxBandSpan` (256 — a band, not a raw count) AND that the actual value is in `[LO,HI]`. A raw `8054`/`987654` in a `0..3` band fails the range check; a `band=0..1000000` declared to launder a count fails the span check.

Also expanded the §5.2 identity-name denylist after the round-2 red-team passed int fields named `Region`/`Asn`/`Tenant`: it now covers network/org/location/time/config quasi-identifiers (region, geo, country, asn, org, tenant, customer, account, cluster, namespace, spiffe, cert, serial, domain, fqdn, url, uri, port, mac, vlan, subnet, cidr, sequence, order, signature, fingerprint, digest, checksum, token, …).

**Acknowledged limit (documented, not silently implied):** the gate enforces per-FIELD coarseness + justification + k-anonymity; it does NOT enforce a global information budget. A producer encoding data across MANY individually-bounded, individually-justified fields is a covert channel bounded by the small field count, human review of each `<reason>`, and the k-anonymity gate — not by `Clear`. `canReIdentify` checks the NAME (linkability); coarseness lives in the band gate; the two are separate and run together.

---

## 4. The carrier and its serialization (D3 [leak-review])

`Clear` copies each passing field's **value** (not a reference) into `Cleared.payload`, a `map[string]scalar` where `scalar` is a closed sum of the safe kinds — never `any` boxing a pointer/slice/map/aliased reference. `Cleared.Marshal()` re-walks `payload` and re-validates every entry's dynamic kind against the D1 allowlist before emitting wire bytes; an entry whose box somehow holds a pointer/slice fails `Marshal`. **D6 transport consumes the bytes from `Marshal`, never raw `payload` access** — documented in `doc.go` and enforced by `payload` being unexported. The carrier is thus inside the chokepoint, not a second egress surface.

---

## 5. The formal definition of "cannot re-identify" (the §9 open item, for founder signoff)

A field **"cannot re-identify a customer or their environment"** iff it satisfies **all three** classical de-identification tests against the product's KNOWN small, closed vocabularies (the ≈5-type canary taxonomy and the 5 attrition axes):

### 5.1 The three tests

1. **No singling-out.** The field's value, alone or combined with other cleared fields, cannot isolate one deployment. *Operationally:* the value is drawn from a COARSE closed set whose cell never has fewer than **k** contributing scopes (the k-anonymity gate, D5). Raw floats (cadence seconds, time-to-disengage seconds), ordered sequences, and raw bitsets FAIL — they are continuous or high-cardinality over the small vocab and single out.
2. **No linkability.** The field cannot be joined to an external or other-deployment dataset to re-link. *Operationally:* NO direct identifiers (`ScopeKey`, `FlowID`/cookie, IP, host, identity); NO quasi-identifiers that pin an environment (decoy taxonomy/placement via the ordered canary-type sequence; the `Axes` composition which maps 1:1 to `StingFloor.Axes()` and leaks the floor/posture config; tier/depth which leak escalation thresholds; `PoisonClass` stage taxonomy which leaks the poison generator config); NO timestamps (environment-correlatable).
3. **No inference / not reversible.** A recipient cannot reverse the field to recover a per-customer secret. *Operationally:* NO raw deterministic hash over an enumerable space (a plain fnv-64a over the 5-type vocab is enumerable in <1s — D2_D5 decision F); NO raw count whose magnitude reveals payload sizing/config. Only bucketed/banded/boolean derivations cross; the cross-boundary unit is an AGGREGATE ("seen in ≥k scopes"), never a raw hash (D9).

### 5.2 The identity/semantic NAME denylist (necessary, not sufficient)

`Clear` hard-rejects any field whose name matches (case-insensitive substring): `ScopeKey`, `FlowID`, `Cookie`, `IP`, `Host`, `Addr`, `Identity`, `Timestamp`, `Features`, `Decoy`, `Baseline`, `Path`, `Content`, **`Exploit`**, **`Exposure`** (the last two per D4 so a renamed-but-same-valued AX4/AX5 field is still caught). This is necessary but the structural allowlist (§5.1, D1) is what makes the predicate **sound** — a denylist of names alone is bypassable by renaming, which is exactly why the kind allowlist + k-gate + recursion rule run together.

### 5.3 Why this is sound, not just a checklist

The predicate is enforced by the kind-allowlist + name-denylist + k-gate + recursion rule **together** (D1+D2+D4+D5). `canReIdentify()` running over a value is necessary; the structural allowlist is what makes it sound. A good `<reason>` string is never sufficient. **Recommendation D0:** record §5 verbatim in `docs/INTELLIGENCE.md` §9 as RESOLVED and cross-link `reidentify.go`. This closes the §8/§9 *"reviewed before the network ships"* open item.

---

## 6. The AX4/AX5 hard block (D4 [leak-review])

`ExploitsObserved` (int64, AX4) and `ExposureSignals` (int64, AX5) on `StingOutcome` are **deployment-local-only** (`ATTRITION_FIVE_AXIS_DESIGN.md` §2.5/§14; `contract.go:180-181` comments; `event.go:54-55,60-61`). They may persist to the local durable store (rule 5) but cross **NOTHING** until this filter ships AND per-field-justifies each. Even after this filter exists, they coarsen to percentile-bucket/boolean only.

The block is anchored to **three layers so it cannot be defeated by renaming a field or dropping a marker** (D4 [leak-review]):

1. **Type denylist (§1.4a):** any `StingOutcome`/`AdversaryInteractionEvent`-bearing type is rejected as a candidate outright — the fields' home types can never be field-inspected.
2. **Semantic name denylist (§5.2):** `*exploit*` / `*exposure*` names are denied, so a *renamed same-valued* field is still caught by the name check and the predicate.
3. **Blocked marker (defense-in-depth):** `egress:"blocked,ax4-exploits"` / `egress:"blocked,ax5-exposure"` is a HARD deny that overrides any `safe` tag. It is **not** the sole barrier (a producer controls it).

Unblocking is a **founder-signed compile-time edit to `block.go`** plus adding the percentile-bucket/boolean coarsening first — **never a runtime config flag** (a toggle is the silent-relax path rule 9 forbids).

---

## 7. Gates now vs defers

### 7.1 Ships in this MVP (the standalone milestone)

- The default-deny GATE — `network.Clear(Candidate)`; every field explicitly tagged-safe + justified or dropped; a new/untagged field can never silently cross (§1.2).
- The field-justification model — `egress:"safe,<reason>"` tags + the safe-kind ALLOWLIST with default-deny arm (D1) + identity/semantic name denylist + recursive walk (D2) (§3).
- The carrier-serialization gate — `Cleared.Marshal` re-validates (D3) (§4).
- The formal cannot-re-identify predicate — `reidentify.go`, the §9 open item encoded executably and surfaced for review (§5).
- The AX4/AX5 hard block — three-layer, compile-time unblockable only (§6).
- The candidate-type denylist — `cost.Summary`/`cost.Rollup`, `AdversaryInteractionEvent`, `StingOutcome`, baseline/scope-state hard-rejected (§1.4a).
- The Contribute opt-in + k-anonymity gate (k a network const) (§1.4b/c).
- The full invariant test suite (§8).
- A reference `Candidate` wired through `Clear` today, as the contract D2's `ExportForm` must satisfy.

### 7.2 Deferred (D6/D7)

- The cross-boundary TRANSPORT / network protocol / wire (= D6). `Clear` produces a `*Cleared`; nothing transmits it yet. `*Cleared` is the seam D6 consumes.
- The real body of `profile.ExportForm` / `ValidateProfileForSharing` coarsening (= D2 Phase 2 + D6).
- The aggregation COMPUTATION that populates `SeenInScopes` from a real cross-scope ledger (= D6). The gate CHECKS the count now; D6 computes it (D6 known-gap).
- A real second deployment/scope to cross TO, and the shared-set consumer returning patterns as detection context (= D6).
- The D7 threat-feed read view (access control + rate limiting over the aggregated set), built on D6, inheriting `Clear` unchanged.
- Flipping the AX4/AX5 block to allowed (§6) — behind explicit per-field founder signoff + the coarsening that must exist first.

The ROADMAP D6 demo is the gate *"dropping raw/identifying candidates on screen"* as they hit `Clear`.

---

## 8. Rule guarantees

- **Rule 9 — single default-deny chokepoint.** `Clear` is the only exported function and `*Cleared` the only opaque carrier with no alternate constructor; D6 transport accepts only `*Cleared`. *"Only through the single egress filter"* is type-enforced. Code that exfiltrates raw data across a boundary becomes either a compile error (no `*Cleared`) or a `Clear`-time error — the §2 *"critical bug"* surfaces loudly.
- **Rule 5 — scope isolation / local-only never exportable.** The candidate-type denylist hard-rejects `cost.Summary`/`Rollup` (the CISO KPI), `AdversaryInteractionEvent` (`ScopeKey`+`FlowID`+`Features`), `StingOutcome`, and any baseline/scope-state type. SCOPE.md §relationship: when both rules apply, the stricter (rule 9) wins — `Clear` is exactly that boundary. The opt-in + k-anonymity gates ensure no single scope's state is identifiable.
- **Single-chokepoint invariant (§7 of INTELLIGENCE.md).** Exactly ONE exported function and ONE opaque carrier; no second path. The recursive default-deny walk + the type denylist mean even a future careless caller cannot route around it — a non-`*Cleared` value has nowhere to go.
- **Rule 8 — canary touch is the only trigger** — honored by what the network does NOT do: the shared set returns as DETECTION CONTEXT only (D5's bounded `FingerprintMatch` weight term, capped by `M_max`), never as an enforcement trigger (`INTELLIGENCE.md` §5.4 bullet 3). `Clear` gates OUTBOUND patterns; it never creates an inbound trigger. Documented as a never-relax guardrail in `doc.go`.
- **Rule 7 / structural-anonymization precedent.** The invariant suite mirrors `TestDriverObservationCarriesNoRawData` (scalar allowlist + `default:` fatal) and the boltevents structural-anonymization discipline. Anonymization is structural (boltevents model) PLUS a runtime per-field justification check at the actual crossing (the new layer `Clear` adds).

---

## 9. Test plan — invariants (failing-if-violated; the rule the product is sold on)

Modeled on `TestDriverObservationCarriesNoRawData` and the boltevents reflection guard.

1. **default-deny:** an untagged field on the reference candidate ⇒ `Clear` errors.
2. **new-field-drops (reflection guard):** adding ANY untagged field to the reference candidate makes `Clear` error — *"unmarked = dropped"* proven by a failing test, not by review.
3. **kind allowlist, not denylist (D1):** a field of a non-allowlisted kind (`Struct`, `Array`, `Complex`, `Chan`, `Interface`, `Uintptr`, a free `String` not in any enum) ⇒ error via the `default:` arm. Explicit test for an `any`-typed field and a generic nested struct.
4. **recursive walk (D2):** a candidate whose nested/embedded struct hides a raw/identity field (a nested `ScopeKey`, a raw `Axes uint32`) ⇒ error. A `time.Time` field ⇒ error (by KIND and by type).
5. **export-rejects-identity:** every name on the §5.2 denylist + every forbidden kind ⇒ error.
6. **carrier serialization (D3):** a `payload` entry whose box holds a pointer/slice fails `Cleared.Marshal`.
7. **AX4/AX5 never cross (D4):** `ExploitsObserved`/`ExposureSignals` ⇒ error even if mistagged `safe`; a *renamed* same-valued field (e.g. `BurnCount`) is still caught by name+predicate; the blocked marker overrides a safe tag.
8. **candidate-type denylist (D4):** `cost.Summary` ⇒ error; `cost.Rollup` output ⇒ error; a struct EMBEDDING `cost.Summary` ⇒ error; a struct embedding baseline/scope-state ⇒ error; `AdversaryInteractionEvent`/`StingOutcome` ⇒ error.
9. **opt-in:** `Contribute:false` (and zero-value `ContributionContext`) ⇒ error / nothing produced.
10. **k-anonymity (D5):** `SeenInScopes < aggregationK` ⇒ error; `ContributionContext{Contribute:true, SeenInScopes:0}` ⇒ error; **no producer-supplied k can satisfy the gate** (assert `AggregationK` is not a `ContributionContext` field).
11. **no map / no map key (D10):** the reference candidate exposes no map; no raw float feature and no feature key name crosses.
12. **no raw hash (D9):** no `BehavioralHash`-shaped field crosses.
13. **happy path:** a fully-tagged, coarse, opted-in, k-satisfied reference candidate ⇒ non-nil `*Cleared`, and `Marshal` succeeds.
14. **no second constructor:** `Cleared` has only unexported fields (compile-time — no external literal).
15. **surface reflection-guard:** assert the reference candidate's exported fields are all in the safe-kind allowlist (mirrors `TestDriverObservationCarriesNoRawData`).

`make check` EXIT=0 with all of the above green is the milestone exit, alongside §0 signoff and §5 recorded in `INTELLIGENCE.md` §9.

---

## 10. Sequenced build plan (design → implement → adversarial review → fix, like M8/M9)

1. **Signoff §0** (especially ★ D0–D6) and record §5 in `INTELLIGENCE.md` §9 as resolved.
2. `justify.go` — tag parser + the safe-kind ALLOWLIST with `default:` deny arm (D1) + enum value-sets. Unit-test the allowlist in isolation first (the load-bearing primitive).
3. `reidentify.go` — `canReIdentify` predicate + the identity/semantic name denylist (§5.2, incl. `*exploit*`/`*exposure*`).
4. `optin.go` — `ContributionContext` (no `AggregationK`) + `const aggregationK=3` (D5).
5. `block.go` — `denylistedType` (type-identity + embedded scan, D4a) + the AX4/AX5 three-layer block (D4b/c).
6. `filter.go` — `Clear` recursive walk (D2) tying together 2–5; `Cleared` opaque carrier + `Marshal` re-validation (D3); all-or-nothing error (D8).
7. `candidate.go` — `Candidate` interface + the hand-written reference candidate (the D2 `ExportForm` contract).
8. `doc.go` — update to point at `Clear` + cite §5.
9. `filter_test.go` — the full §8 invariant suite.
10. Adversarial leak review (a fresh reviewer attempts to construct a leaking candidate); fix every finding; re-run.
11. `make check` EXIT=0; close the §9 open item.

When D2's `profile.ExportForm` lands, it implements `Candidate` and slots in with **zero `network` change** — and a test asserts `ExportForm`'s output is `Clear`-able (the contract the reference candidate stands in for until then).

---

## 11. Risks

1. **Reflection bypass via `interface{}`/`any` fields** — mitigated: the safe-kind allowlist forbids `Interface`/`Ptr`/`Slice`/`Map` outright (D1), so such a field fails; explicit test (§8.3).
2. **Lazy `<reason>` strings** — mitigated: the tag is necessary-not-sufficient; kind allowlist + name denylist + predicate must also pass. Do not rely on the string's quality for safety; a review checklist is advisory only.
3. **D2's `ExportForm` is unbuilt** — until then the gate is exercised only against the hand-written reference candidate; mitigated by shipping the reference as the contract D2 must satisfy + a test that fails if `ExportForm`'s output isn't `Clear`-able.
4. **k-anonymity with k=3 over a small closed vocabulary** may be weak against a determined recipient with side knowledge (homogeneity/background-knowledge attacks). Mitigated: the `Axes` composition and sequence are DROPPED/coarsened to booleans rather than k-anonymized sets where possible; flag l-diversity/t-closeness as a fast-follow if D7 productizes the feed.
5. **`SeenInScopes` is producer-asserted until D6's ledger (D6 known-gap)** — mitigated: documented loudly; recommendation is to fail closed on a self-asserted count until the ledger lands; the count must originate from the network package's own future ledger (single trusted source).
6. **Opt-in misconfiguration** (`Contribute:true` set by mistake) — mitigated: opt-in originates from one operator-config source of truth; `Clear` treats a zero-value `ContributionContext` as deny (both `Contribute:false` and `SeenInScopes:0 < k` fail).
7. **Existing in-deployment serializers** (dashboard tap, bbolt store) are rule-5-governed and NOT cross-boundary — mitigated: audit that `*Cleared` is the ONLY type any future egress/transport accepts; document the single-chokepoint invariant in `doc.go` and `CLAUDE.md`.
