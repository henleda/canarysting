# docs/D6_3_INGEST_DESIGN.md — The Cross-Scope Ledger Ingest (D6-3) (Design)

> **Sub-design for founder signoff BEFORE any code.** Modeled on `docs/D6_NETWORK_DESIGN.md` / `docs/EGRESS_FILTER_DESIGN.md`.
> D6-3 opens **exactly ONE new cross-scope data flow** (scope → aggregator). Everything downstream (aggregator → B) is the
> already-signed D6 path, byte-for-byte. A wrong call on the new wire is a **CRITICAL rule-9 bug**. Audited seam-by-seam
> against the **live code** (ledger.go, filter.go, shared.go, transport.go, aggregate.go, sharedset.go, reidentify.go, optin.go,
> boot.go), not against design prose. **This design folds in the full adversarial leak-review; the two CRITICAL findings
> (I3 token form, k-provenance enforcement boundary) reshaped the recommendations below.**
> **D6-3 ingest MUST NOT be enabled until §0/D63b and §0/D63e are signed.**

## The one paragraph

`D6_NETWORK_DESIGN §4` left a hole open verbatim: *"the exact cross-scope `Record` wire — who sends 'scope X confirmed tuple T'
to whom — is D6-3 transport, needs the 3rd box."* This is that resolution. The merged code records each deployment's OWN local
Tier-3 jails into ITS OWN in-memory ledger (`boot.go:419`, `Contribute`-gated), so a single ledger only ever reaches `distinctScopes==1`
per pattern, never `aggregationK=3`, so **nothing ever crosses**. D6-3 closes that with a **CENTRAL AGGREGATOR**: one operator-trusted
process holds THE ledger; the N contributing deployments file-spool **confirmations** `(opaque scope token, the already-cleared 7-field
coarse pattern)` to it; it re-validates each pattern through the UNCHANGED `ParseSharedPattern`, records it via the UNCHANGED
`RecordForm` keyed by the remote token bucketed under the aggregator's OWN salt, and when a cell reaches `k≥3` it runs the UNCHANGED
`ClearWithLedger` + `transport.Send` to deployment B's consume spool, where B's `sharedset` shows the cross-customer match and B
escalates faster. **The rule-9 crux is the scope token:** it is a **random, aggregator-issued, non-identifying 128-bit value with NO
derivable relationship to the `ScopeKey`** — never the raw `ScopeKey` (rule-5 leak), never a shared salt (D6i re-identification),
and never an HMAC OF the `ScopeKey` (a keyed hash of the protected identity inherits the `hash`-denylist low-entropy-brute-force risk
the moment the key leaks). **The aggregator adds NO egress path:** `ClearWithLedger` stays the only constructor of a transmittable
`*Cleared`, the `ledgerVerified` Marshal gate and the `SeenInScopes` tripwire are untouched, and the aggregator runs its own
independent field walk (EGRESS §1.3 two-walk distrust preserved).

---

## 0. Decisions needing founder signoff (read first)

> **✅ FOUNDER-SIGNED 2026-06-12.** All §0 decisions (D63a–D63j) approved as recommended — including the two rule-9-critical resolutions the leak-review forced: **D63b** (the scope identity on the wire is a RANDOM, aggregator-issued, non-identifying 128-bit token — never the raw ScopeKey, never a shared salt, never an HMAC-of-ScopeKey) and **D63e** (the gaming attack is closed at the PACKAGE BOUNDARY — an aggregator-scoped ledger that counts only ENROLLED tokens, via a constructor dependency). The honest k-provenance framing (**D63f**: k≥3 == 3 distinct enrolled tokens = 3 deployments the operator VOUCHES for; D6-3 is operator-trusted, NOT Sybil-resistant — true untrusted-contributor auth is D7) and the demo-honesty narration (**D63j**) are signed. The in-repo ingest code is cleared to build; the live 3-scope staged crossing is the AWS session.

Each row is a load-bearing choice. **Rule-9-critical** rows are 🔴. **k-anonymity-provenance** rows are 🟠. Sign or amend before code.

| id | Decision | Recommendation | Why load-bearing |
|----|----------|----------------|------------------|
| **D63a** | **Topology: CENTRAL AGGREGATOR, not gossip.** One thin process (`cmd/aggregator`) holds THE ledger; N deployments file-spool confirmations to it; it clears + sends. Two seams only: a confirmation spool **IN** (scope→aggregator), the existing cleared-pattern spool **OUT** (aggregator→B). | **Adopt central aggregator. Defer gossip (D63i).** | Thinnest honest option for a live 3-scope demo and the only one reusing the merged chokepoint unchanged. A sound distinct-scope count needs ONE counting authority and ONE comparable bucketing salt. Gossip makes every peer both emitter AND counter, multiplies the rule-9 surface by N², re-opens the comparable-bucket problem at every edge (I3b), and re-opens the D6e fan-out (one origin replayed via 3 peers reads k=3). The aggregator is the minimal realization of D7's deferred central tier — built here for cross-customer **SHARPENING**, not the feed. It is **operator-trusted infrastructure** (vendor- or design-partner-hosted), NOT attacker-reachable — same trust class as the file spool. |
| **D63b** 🔴 | **THE rule-9 crux — scope identity on the wire = a RANDOM, AGGREGATOR-ISSUED, NON-IDENTIFYING token** (≥128-bit `crypto/rand`, stored in the deployment's config, NO derivable relationship to the `ScopeKey`/customer). The aggregator buckets it with its OWN process-local salt via the UNCHANGED `RecordForm(token, …)`. **REJECT (a)** raw `ScopeKey` crosses. **REJECT (b)** a shared salt. **REJECT (c-variant)** `ScopeID = HMAC(per-deployment-secret, ScopeKey)`. | **Adopt the random issued token. BLOCK ingest until signed.** | **The critical decision; the three design inputs CONTRADICTED here and the leak-review forced the resolution.** (a) The raw `ScopeKey` is rule-5 identity / rule-9 scope-state and is `scope`-denylisted (reidentify.go:18); crossing it makes the aggregator a re-identification asset holding `(ScopeKey, pattern)` pairs — the exact leak rule 9 exists to prevent, regardless of recipient trust. (b) A shared salt is a network-wide secret whose leak lets anyone with the (low-entropy, operator-set) `ScopeKey` list recompute every bucket — a full break (D6i). (c-variant, the rejected HMAC-of-ScopeKey) is a **keyed hash of the protected `ScopeKey`**: it inherits exactly the `hash`-denylist rationale (reidentify.go:29 — *"a plain fnv over the small vocab is reversible"*), so the instant the per-deployment secret leaks to the aggregator or a spool reader, every past confirmation is re-linkable by recomputing the HMAC over the small `ScopeKey` vocabulary; it is also stable-derived-from-identity, so a non-rotated secret makes it a permanent pseudonym OF the identity. The **random** token has none of these inverses: it is not a function of the `ScopeKey` (nothing to brute-force), the raw `ScopeKey` never leaves the deployment, the token never enters `clearFields` and never crosses to B, and a dumped aggregator ledger stays a coarse-pattern→{opaque salted bucket} histogram answering only "how many." The token is a **deployment pseudonym, never a customer identifier.** |
| **D63c** | **The confirmation wire = an NDJSON `Confirmation{Scope: <opaque token>, Pattern: <the 7 cleared coarse fields>}`.** The pattern object is the same shape `ParseSharedPattern` validates (UNCHANGED, re-validated on ingest). The scope token rides as **envelope metadata OUTSIDE the cleared payload**, never inside `clearFields`. | **Adopt the envelope.** | The pattern is the already-cleared `ExportForm` shape — safe by construction (exactly what already crosses A→B). The ONLY new thing on the wire is the token, and it MUST sit outside `clearFields`: the substrings `scope`, `token`, AND `identity` are all on reidentify.go's denylist (lines 18), so a scope id inside the `clearStruct` walk is hard-denied **by name**. Carrying it as envelope metadata is the only way the aggregator can count distinctness without ever routing an identity through the egress gate. |
| **D63d** 🔴 | **Who clears + sends at k≥3 = the AGGREGATOR, reusing the chokepoint + transport BYTE-FOR-BYTE.** On a cell hitting `k≥3` it wraps the just-confirmed coarse pattern as a thin `network.Candidate` (`Contribute:true, SeenInScopes:0`), calls `ClearWithLedger(cand, ClearContext{Ledger})` UNCHANGED, and `transport.Send(*Cleared)` to B's consume spool UNCHANGED. | **Adopt; reuse the merged egress path verbatim.** | The aggregator holds the only ledger that reaches `k≥3`, so it is the only process that CAN clear. It adds NO new egress path: `ClearWithLedger` stays the sole constructor of a transmittable `*Cleared` (filter.go), the `ledgerVerified` Marshal gate is untouched (filter.go:250), the asserted-zero `SeenInScopes` tripwire still fires (filter.go:92), the count is still computed INSIDE the chokepoint from the ledger, and the aggregator runs its OWN independent `clearStruct` walk — preserving EGRESS §1.3 two-walk distrust (contributor coarsened; aggregator re-clears). The only genuinely new code is "build a `Candidate` from a coarse pattern the aggregator already counted." |
| **D63e** 🟠 | **k-provenance: count distinctness ONLY by issued token, AND move the token-authentication INTO the package boundary (not main.go).** Add an aggregator-scoped ledger constructor that takes the enrolled-token predicate as a **constructor-time dependency**, so an un-allowlisted token CANNOT reach `RecordForm` — making it as type-/constructor-enforced as the `ledgerVerified` Marshal gate. Drop unknown/empty tokens fail-closed; reject any pattern failing `ParseSharedPattern`. | **Adopt; the allowlist is a constructor dependency, NOT a main.go `if`.** | **The leak-review CRITICAL k-provenance finding.** In the reused ledger, `k=3` means literally "3 distinct STRINGS were `RecordForm`'d against this coarseKey" — `RecordForm` buckets ANY string and `distinctScopes` just counts buckets (ledger.go:88, 125). An allowlist in `cmd/aggregator/main.go` is the right control but lives OUTSIDE the type system: a bug, a refactor, or a second ingest path that calls `RecordForm` without the check silently re-opens fan-out (the D6e attack: one box sends the same pattern under 3 invented strings → k=3, singling-out wearing a k=3 mask). Binding the predicate to a constructor makes un-allowlisted tokens structurally unable to increment the count. **See D63f for the residual this control does NOT close.** |
| **D63f** 🟠 | **State the k-provenance guarantee PRECISELY, and carry Sybil-resistant authenticated enrollment to D7 as a SIGNED precondition for any untrusted contributor.** The doc must say: "`k≥3` == 3 distinct ENROLLED TOKENS recorded this coarse cell; it equals 3 INDEPENDENT deployments **only under the operator's one-token-per-independent-deployment issuance discipline**; a multi-token holder or token-sharer defeats it." | **Sign the precise wording + the D7 gate.** | **The leak-review residual the inputs overclaimed.** Issuance binds to a *token*, not to an *independent deployment*: one operator issued 3 tokens (or a compromised contributor holding its token + 2 leaked tokens) reaches k=3 on one box. The allowlist proves "3 distinct issued tokens," NOT "3 independent non-colluding deployments." For the **staged demo** this is a non-issue (one operator legitimately runs all three). For **production** the aggregator MUST issue/bind tokens (scopes cannot self-mint), bind each token to a per-token AUTH secret (constant-time compare, so a leaked spool line cannot replay a victim token), and rate-limit — all **D7 scope**. The aggregator prevents ONE scope counting as THREE; it does NOT adjudicate whether 3 real enrolled scopes share an owner. **Founder must sign that D6-3's aggregator is operator-trusted and NOT Sybil-resistant against an untrusted contributor.** |
| **D63g** | **Confirmation transport = a FILE spool (the D6f idiom), a SECOND spool distinct from the cleared-pattern spool.** Append-only NDJSON, `0o600`, the same 1 MiB scan cap + fail-closed framing as `transport.Spool`. For the demo it can be a shared volume / rsync / scp target. NO inbound listener. | **Sign the file spool for MVP.** | A listener adds inbound attack surface (access-control, rate-limiting, TLS) that transport.go's own comment and D7 explicitly assign to D7. A write into the k-count is MORE sensitive than the existing read spool, so the networked authenticated version is gated behind D7 auth and out of MVP. A file is the honest minimum and is `cat`-inspectable, which IS a privacy-proof demo beat (show the token is opaque and the pattern is 7 coarse fields). |
| **D63h** 🔴 | **Bound the aggregator's at-rest assets HONESTLY (two assets, not one) + DRAIN-AND-TRUNCATE the confirmation spool.** Document that the aggregator holds (1) a bucketed membership ledger `coarseKey → bucket-set` AND (2) the retained inbound confirmation spool of `(token, coarse pattern)` pairs. The aggregator MUST drain-and-truncate (or offset-advance + age-out) the spool after ingest, not retain it indefinitely. Keep the token→customer issuance map OFF the aggregator host. | **Sign the two-asset disclosure + spool age-out.** | **The leak-review concentration finding.** Unlike the single-deployment ledger (which only ever holds its OWN scope, capping at k=1), the aggregator ledger is a cross-scope **membership matrix**: for any pattern it records WHICH opaque buckets exhibited it, so a dump answers "do buckets X and Y co-occur across patterns" — a correlation fingerprint over the small live population the per-deployment ledger structurally cannot produce. The retained spool is a SECOND, finer at-rest asset (`(token, coarse pattern)` at full per-confirmation granularity, pre-bucketing). `RecordForm` idempotency makes re-reading safe but does NOT require indefinite retention; draining bounds a host compromise to the in-flight window. The salt is process-local and never co-persisted (D6i). Even a total compromise then yields only opaque buckets over k-gated coarse cells, never customers. |
| **D63i** | **Longitudinal correlation is an ACCEPTED residual the random token does NOT eliminate.** A stable token is a longitudinal pseudonym whose confirmation TIMELINE is observable to a spool/aggregator holder; an observer with side knowledge ("customer X was attacked Tuesday") can correlate. Bound it by: token→customer map OFF the aggregator, spool age-out (D63h), operator-trust on the host. | **Sign as accepted-and-bounded; aggregator is operator-trusted infra, never attacker-reachable.** | **The leak-review timing finding.** The random token removes the `ScopeKey`-derivation linkage, NOT the activity-timeline linkage. The aggregator sees the PRE-aggregation per-token stream, which is strictly MORE identifying than either read view — the internal sharpening ledger uses `aggregationK=3` while the external feed uses `FeedK=5` precisely for this small-population re-identification reason (aggregate.go:7-14). This is WHY the aggregator must be operator-trusted infra, not merely "no inbound listener." |
| **D63j** 🔴 | **Demo honesty: the 3-scope demo is 3 REAL scopes WE OPERATE, never "3 customers," on a CALIBRATED B, and it proves the THRESHOLD — NOT Sybil-resistance.** Three genuinely-separate deployments (distinct `ScopeKey`, store, ledger, issued token), each producing a REAL local Tier-3 jail of the same pattern; B is calibrated+live+bucket-sufficient (D6j); narrate as "three staged scopes we operate." | **Sign the exact narration (§7).** | Folds D6_NETWORK_DESIGN/D6j + the leak-review demo-honesty findings. Three traps: (1) **cold-B acceleration theater** — `baseline` returns M=1.0 ignoring `FingerprintMatch` until calibrated; narrating acceleration on a cold B is a lie. (2) **"3 customers"** — operator-controlled scopes are NOT customers. (3) **NEW/underweighted:** the demo CANNOT prove Sybil-resistance (one operator holds all three tokens), so the k=2→k=3 crossing proves the threshold is *enforced and not lowered* (real) but NOT that the three are *independent/non-colluding*. Narrating it as "one attacker can't fake the network" would be the subtle overclaim. This UPGRADES the signed DEMO_ARC beat-6 honesty contract (forward-look diagram → live staged demo) and needs explicit re-signoff that real-scopes/real-jails/staged-operators is NOT "mocking a second box." |

**Residual accepted (carry to D7), not a new defect:** the k-provenance guarantee is "k≥3 == 3 distinct enrolled tokens"; "3 independent
deployments" holds only under one-token-per-deployment issuance discipline (D63f). Authenticated enrollment + per-token auth + rate-limiting
+ the networked inbound listener are **D7**. Gossip topology (D63i-deferred) needs its own design — every peer becomes emitter AND counter,
re-opening D63b (comparable buckets without a shared salt) and D63e/f (distributed allowlist / Sybil-resistance).

---

## 1. The gap, confirmed in code

`RecordForm` is called from EXACTLY ONE place — `capturingEngine.ReportOutcome` on a LOCAL Tier-3 jail, gated on `Contribute`
(`boot.go:418-419`). So each deployment records ITS OWN scope's jails into ITS OWN in-memory ledger; a single ledger only reaches
`distinctScopes==1` per pattern, `1 < aggregationK=3` (optin.go:23), and `ClearWithLedger` denies every crossing (filter.go:106-107).
**Nothing crosses.** D6-3 is the ingest that lets ≥3 DISTINCT scopes confirm the SAME coarse pattern into ONE ledger so a cell reaches
k=3 → the UNCHANGED `ClearWithLedger` → `transport.Send` → B's `sharedset`.

**The structural insight:** there are now TWO opposite cross-scope wires. The merged `transport.go`/`sharedset` path is **OUTBOUND**
(a `Cleared` crosses A→B). D6-3 is the **INBOUND** confirmation wire (scope→aggregator). **D6-3 reuses the entire outbound path
UNCHANGED and adds exactly ONE new surface: a confirmation receiver that only ever calls `RecordForm`.**

---

## 2. Topology (D63a): CENTRAL AGGREGATOR

A single process (`cmd/aggregator`), operator-trusted infrastructure (vendor- or design-partner-hosted, NOT attacker-reachable —
same trust class as the file spool). Two seams: a confirmation spool **IN** (scope→aggregator), the existing cleared-pattern spool
**OUT** (aggregator→B). Gossip is deferred (D63i): it makes every peer both emitter and counter, multiplying the rule-9 surface by N²
and re-opening the shared-salt problem at every edge. The aggregator is the minimal realization of D7's deferred central tier — built
here for cross-customer SHARPENING, not (yet) the feed.

The aggregator loop (sketch; the only new binary):

```go
func run(confirmInPath, clearedOutPath string, enrolled func(token string) bool) error {
    ledger, _ := network.NewAggregatorLedger(enrolled)        // D63e: allowlist is a CONSTRUCTOR dependency, not a main.go if
    confs, _  := transport.NewConfirmSpool(confirmInPath).ReceiveConfirmations()
    out       := transport.NewSpool(clearedOutPath)           // existing aggregator->B cleared-pattern spool (UNCHANGED)
    for _, c := range confs {
        sp, err := network.ParseSharedPattern(c.Pattern)      // UNCHANGED inbound mirror; fail-closed
        if err != nil { continue }
        n, err := ledger.IngestConfirmation(c.Scope, sp)      // un-enrolled token CANNOT reach RecordForm (D63e); idempotent per (token,coarseKey)
        if err != nil { continue }
        if n >= 3 {                                            // aggregationK; the gate re-checks authoritatively inside ClearWithLedger
            cleared, err := network.ClearWithLedger(network.SharedCandidate(sp), network.ClearContext{Ledger: ledger.Ledger()}) // UNCHANGED chokepoint
            if err == nil { _ = out.Send(cleared) }            // UNCHANGED transport -> B's sharedset
        }
    }
    // D63h: drain-and-truncate (or offset-advance) the confirmation spool after ingest.
    return nil
}
```

---

## 3. The confirmation wire (D63c) and the scope-identity resolution (D63b)

### 3.1 The wire

A new NDJSON `Confirmation` envelope, carried by a SECOND file spool mirroring the existing `transport.Spool`:

```go
// internal/intelligence/transport/confirm.go (NEW) — the scope->aggregator wire
type Confirmation struct {
    Scope   string          `json:"scope"`   // opaque RANDOM aggregator-issued token (D63b); NEVER raw ScopeKey, NEVER a hash of it
    Pattern json.RawMessage `json:"pattern"` // exactly the 7-field cleared coarse shape; re-validated by ParseSharedPattern
}
type ConfirmSpool struct{ path string }
func NewConfirmSpool(path string) *ConfirmSpool
func (s *ConfirmSpool) SendConfirmation(scopeToken string, clearedPatternBytes []byte) error // producer half (contributing deployment, on local jail)
func (s *ConfirmSpool) ReceiveConfirmations() ([]Confirmation, error)                        // consumer half (aggregator); 1 MiB cap, over-long terminates scan, malformed line skipped
```

The pattern object is the already-cleared `ExportForm` shape, re-validated on ingest by the UNCHANGED `ParseSharedPattern` (fail-closed:
rejects unknown/missing/duplicate keys, out-of-band ints, non-enum `PoisonClass`). The token rides as envelope metadata **OUTSIDE the
cleared payload** — critical, because `scope`/`token`/`identity` are all on reidentify.go's denylist (line 18), so a scope id inside the
`clearStruct` field walk is hard-denied by name.

### 3.2 THE rule-9 crux (D63b): the random issued token, and why the other three options are rejected

The ledger buckets scope with a process-local salt; for ONE aggregator to count distinct scopes the inbound identities must be
**comparable AT the aggregator**. Four options were weighed; the three design inputs CONTRADICTED on this and the leak-review forced the
resolution:

- **(a) raw `ScopeKey` → aggregator buckets it: REJECTED.** The raw `ScopeKey` is rule-5 identity / rule-9 scope-state and is
  `scope`-denylisted; crossing it is the leak rule 9 exists to prevent, and it makes the aggregator a re-identification asset holding
  `(ScopeKey, pattern)` pairs. "Acceptable to a trusted aggregator" is the wrong frame — rule 9 says the identity never leaves,
  regardless of recipient.
- **(b) shared salt, scopes pre-bucket: REJECTED.** The shared salt becomes a network-wide secret (D6i); its leak lets anyone with the
  low-entropy operator-set `ScopeKey` list recompute every bucket — a full re-identification break, and a single compromised scope
  de-anonymizes all the others.
- **(c-variant) `ScopeID = HMAC(per-deployment-secret, ScopeKey)`: REJECTED** (this was one input's proposal; the leak-review flagged it
  CRITICAL). It is a **keyed HASH of the protected `ScopeKey`** and inherits exactly the `hash`-denylist rationale (reidentify.go:29):
  the moment the per-deployment secret reaches the aggregator or a spool reader, every past confirmation is re-linkable by recomputing
  the HMAC over the small `ScopeKey` vocabulary. It is stable-derived-from-identity (a permanent pseudonym OF the identity) and a secret
  rotation silently breaks idempotency. A keyed hash of a low-entropy protected value is precisely what D9 forbids crossing.
- **(d) random aggregator-issued token: RECOMMENDED.** Each deployment is issued once a ≥128-bit `crypto/rand` token, stored in config,
  with NO derivable relationship to the `ScopeKey`/customer. The aggregator buckets the token with its OWN process-local salt via the
  UNCHANGED `RecordForm(token, …)`. Comparable (distinct tokens→distinct buckets), stable (idempotent per `(token, coarseKey)`), and
  non-identifying: the token is **random, not a hash** (nothing to brute-force over the small vocab); the raw `ScopeKey` never leaves the
  deployment; the token never enters `clearFields` and never crosses to B; a dumped aggregator ledger stays a
  coarse-pattern→{opaque salted bucket} histogram answering only "how many." A structural test must pin that the on-wire token is NOT a
  function of `ScopeKey` (two deployments with the same `ScopeKey` get different tokens; the `ScopeKey` is not recoverable).

---

## 4. Who clears + sends (D63d): the aggregator, reusing the chokepoint UNCHANGED

The aggregator holds the only ledger that reaches `k≥3`, so it is the only process that CAN clear. On a cell hitting `k≥3` it wraps the
just-confirmed coarse pattern as a thin `network.Candidate` (`Contribute:true, SeenInScopes:0`) via a new `SharedCandidate` helper,
calls `ClearWithLedger(cand, ClearContext{Ledger})` byte-for-byte unchanged, and `transport.Send(*Cleared)` to B's consume spool
unchanged.

This is **NOT a second egress path:** `SharedCandidate` produces a `Candidate`, not a `*Cleared`; `ClearWithLedger` stays the only
constructor of a transmittable carrier (the `ledgerVerified` Marshal gate is untouched, filter.go:250), still runs the full field walk,
still computes `n` from the ledger, still trips on a non-zero `SeenInScopes` (filter.go:92), still denies `n<3`. The aggregator runs an
independent second field walk on the pattern — preserving EGRESS §1.3's two-walk distrust (contributor coarsened; aggregator re-clears).

The two genuinely new network helpers:

```go
// internal/intelligence/network/shared.go (EDIT)
func ExportFormFromShared(sp SharedPattern) any  // rebuild the TAGGED 7-field ExportForm-shaped value so coarseKeyFromExport == contributor's coarseKey (see §4.1)
func SharedCandidate(sp SharedPattern) Candidate  // EgressFields => (the 7 coarse fields, ContributionContext{Contribute:true, SeenInScopes:0}); NOT a *Cleared
```

### 4.1 Coarse-key parity (D63d, leak-review medium finding)

`coarseKeyFromExport` runs the FULL `clearFields` reflect walk (ledger.go:139), which requires `egress:"safe,band=..."` tags and band
declarations on every numeric field (clearStruct denies an untagged or unbanded numeric field, filter.go:197-208). Therefore
`ExportFormFromShared` MUST return a **fully egress-TAGGED struct** with band tags identical to `profile.ExportForm`, and the aggregator
MUST derive the coarseKey by running it through the SAME `clearFields` walk `RecordForm` uses — **never a hand-built coarseKey from raw
`SharedPattern` fields** (which would lose the two-walk distrust and let an out-of-band value `ParseSharedPattern` happened to accept key
a cell). Note `profile.ExportForm` and `network.SharedPattern` have a DIFFERENT field ORDER and `SharedPattern` has NO egress tags; place
the tagged mirror INSIDE package `network` (so `network` does not import `profile`) and keep it unexported beyond the two helpers.

**Required tests:** (1) `coarseKeyFromExport(profile.ExportForm) == coarseKeyFromExport(ExportFormFromShared(ParseSharedPattern(Cleared.Marshal())))`
— pin the round-trip. (2) Neither `ExportFormFromShared` nor any contributor form-walk emitter can produce a `*Cleared` or anything
Marshalable — assert the only constructor of a `ledgerVerified` carrier remains `ClearWithLedger`.

### 4.2 The contributor's pattern bytes (Q1)

A contributor's LOCAL ledger is at k=1, so it cannot produce a `ledgerVerified` `Cleared.Marshal()`. The contributor emits its coarse
pattern bytes by running the FORM walk (`clearFields`, **no ledger gate**) over its `ExportForm` and JSON-encoding the 7-field result —
field-validated coarse bytes WITHOUT faking k. The aggregator's `ParseSharedPattern` re-validates on ingest (defense-in-depth: both ends
form-walk). Such an emitter must NOT be able to produce a transmittable `*Cleared` (asserted by the test in §4.1).

---

## 5. Rule guarantees (the contract D6-3 must keep)

- **Rule 9** (only `Clear`-cleared anonymized patterns cross): D6-3 introduces exactly one new data flow (scope→aggregator); everything
  downstream (aggregator→B) is the already-signed D6 path, byte-for-byte. **Aggregator→B is UNCHANGED:** only the 7-field coarse
  `Cleared.Marshal()` tuple crosses, via the existing transport, gated by the existing `ledgerVerified` Marshal gate;
  `ClearWithLedger` remains the sole constructor of a transmittable `*Cleared`; the `SeenInScopes` tripwire is intact; the aggregator
  runs the full `clearStruct` walk independently. **The NEW scope→aggregator wire** carries `(opaque random token, coarse pattern)`. The
  PATTERN is the already-cleared `ExportForm` shape, re-validated by the UNCHANGED `ParseSharedPattern` (fail-closed) — exactly what
  already legitimately crosses A→B, no new field class. The TOKEN is resolved safely by D63b (random `crypto/rand`, NO `ScopeKey`
  derivation, not a hash, not the raw `ScopeKey`); the raw `ScopeKey` NEVER leaves the deployment; the token never enters `clearFields`
  (where `scope`/`token` hard-deny by name) and never crosses to B. At rest, the aggregator buckets the token with its own process-local
  salt, so a dumped ledger is a coarse-pattern→{opaque salted bucket} histogram answering only "how many," never "which" — identical to
  the single-deployment ledger's safety property.
- **Rule 5** (scope isolation absolute; the ONLY sanctioned cross-scope structure is the coarse-pattern→distinct-scope-COUNT ledger): the
  aggregator is that sanctioned structure lifted into its own process — a COUNT, not learned state. No weights/calibration/evidence/feedback
  ever reaches it. Scope identity is double-decoupled (`ScopeKey` → issued token → HMAC-salted bucket). **Concentration residual
  (D63h):** the aggregator additionally holds a cross-scope membership matrix (`coarseKey → bucket-set`, a co-occurrence fingerprint the
  per-deployment ledger cannot produce) and the retained confirmation spool (`(token, coarse pattern)` pre-bucketing) — both disclosed,
  bounded by spool age-out, the process-local non-co-persisted salt, the token→customer map kept off the host, and the operator-trust
  class. Even a total compromise leaks only opaque buckets over k-gated coarse cells.
- **k-anonymity provenance** (D63e/f): distinctness is bound to ISSUED tokens, authenticated at the **package boundary** (constructor
  dependency, not a main.go `if`), idempotent per `(token, coarseKey)` so one scope re-confirming cannot inflate k; `aggregationK=3` stays
  a const computed inside the chokepoint, never producer-supplied (tripwire intact). **Precise guarantee:** `k≥3` == 3 distinct ENROLLED
  TOKENS recorded this cell; it equals 3 INDEPENDENT deployments only under one-token-per-independent-deployment issuance discipline. A
  multi-token holder/token-sharer defeats it — **Sybil-resistant authenticated enrollment is a SIGNED D7 precondition for any untrusted
  contributor.** The longitudinal-timeline residual (D63i) survives even a perfect token and is bounded the same way.
- **Rule 8** (canary touch is the only trigger; a shared set is detection context, never an inbound trigger): UNCHANGED. D6-3 is upstream
  of the consumer; B's inbound path is the merged `sharedset.Match` → `FingerprintMatch`, on a base that is 0 without a local canary touch
  (`FromSharedPattern` zeroes the hash → no self-match fast-path; the inbound match is `typeSim==0`, deliberately weaker, ceiling ~0.60).
  The ingest adds NO path from a confirmation to a verdict/tier/attrition/jail-floor; `Match` never records and `MinConfirmedJails` never
  counts an inbound pattern (D6h/§5.4 of the network design).
- **Rule 1** (baseline takes no dep on intelligence/profile): UNCHANGED; the consumer reaches baseline only through the `baseline.Matcher`
  interface wired at boot; no new import edge.

---

## 6. The honestly-staged 3-scope demo (D63j / D6-4)

### 6.1 REAL vs STAGED (the honesty spine)

- **REAL:** three distinct scope deployments, each with its own `ScopeKey`, store, baseline, ledger, and issued token; each independently
  produces a **real local Tier-3 jail** of the same attacker tooling (the D5 ground truth — `boot.go:412-419` records only on a real
  jail, never a synthetic `RecordForm`); the egress chokepoint (`ClearWithLedger`) and transport (`Send`) are the merged production code,
  unchanged; B is a real calibrated, live scope that recognizes a pattern it never itself confirmed; the k=3 gate machinery is real and
  not lowered.
- **STAGED:** the three scopes are all operated by us, not three separate customers; they may be co-located (the live M7 server hosts
  scope-1; one dedicated 3rd box hosts scope-2/B and scope-3 as two separate OS processes — distinct ledgers/salts/stores per process);
  the same demo cassette is replayed against each scope's engine so all three derive the IDENTICAL coarse tuple and the ledger keys
  collide to k=3; the aggregator is an operator-trusted network-tier process (may co-locate on the 3rd box, disclosed as the network
  tier); confirmations are moved by rsync'd file spools rather than an authenticated push.
- **Boxes:** 3 REAL scopes on FEWER BOXES is the honest unit — what makes k=3 honest is three DISTINCT scope identities each producing a
  REAL jail, NOT three physical machines. Keep scope-1 on the live M7 server (untouched, no F11 reboot contamination); stand up ONE
  dedicated 3rd box for scope-2/B + scope-3 as separate processes. **Do NOT collapse to "one process, three scope-keys"** — a single
  process shares one salt and one ledger, making the k=3 a single-binary fiction (exactly the gap D6-2 closed). Multi-token-on-one-box is
  a last-resort fallback, narrated as such.

### 6.2 The on-screen beats (the money-shot, gate visibly enforcing)

1. **Three real jails, three independent confirmations.** Replay the demo cassette against scope-1, scope-3, and a third staged scope.
   Each escalates to a real Tier-3 jail (verify all three hit T3 — `RecordForm` only fires on a jail; a T2 would make k=3 fake) and emits
   a `Confirmation` `(opaque token + coarse tuple)` to its confirmation spool. On screen: three panels each showing a kernel jail +
   "contributed 1 pattern" (`Ledger.Patterns()` — a cardinality, never the pattern).
2. **The gate REJECTS at k=2.** With only scope-1 + scope-3 ingested, run the aggregator's clear attempt: the literal `ClearWithLedger`
   error `egress: pattern seen in 2 scope(s) < k=3 (singling-out risk)` (filter.go:107). **Nothing crosses.** The guarantee enforcing,
   live.
3. **The gate CROSSES at k=3.** Ingest the third scope's confirmation. `ClearWithLedger` returns a `ledgerVerified` `*Cleared`; `cat` the
   consume-spool NDJSON on screen — the only bytes that crossed are the 7 coarse bands/bools/one enum. `transport.Send` drops it to B's
   spool.
4. **B recognizes and escalates faster (the money-shot).** B = scope-2, **calibrated + live + bucket-sufficient** (show `baseline.State`
   on screen — D6j; never narrate this on a cold B). The same attacker tooling touches a canary in B → `FingerprintMatch` lifts M
   (~1.0 → ~1.30) → B contains on fewer touches, carrying a non-identifying "recognized by the cross-customer network" tag (never a source
   `ScopeKey`). **Closing side-by-side:** a parallel flow in B with the maxed cross-customer match but ZERO canary touches sits at
   `Score = 0 × M = 0` — no tier, no verdict (rule 8, the load-bearing arithmetic). B is the CONSUMER for the money-shot pattern (it never
   itself confirmed it) — that asymmetry IS the cross-customer story.

### 6.3 Narration the founder must approve VERBATIM

> *"We staged three scopes that we operate, each independently confirming this same attacker pattern with a real kernel jail. In
> production, these are three different customers. Watch the gate: at two confirmations it refuses to let anything cross — singling-out
> risk. The moment a third independent scope confirms, the pattern crosses, and a fourth deployment that never caught this attacker itself
> now recognizes it and contains faster. Because we operate all three scopes here, this demo proves the k=3 threshold is enforced and
> never lowered — it does NOT prove resistance to a single adversary minting three tokens; authenticated enrollment that prevents
> self-minting is the production precondition (D7)."*

**Honesty guardrails (priority order):** (1) Don't narrate acceleration on a cold B (M=1.0; the match does nothing) — show
`baseline.State`; keep the labeled forward-look DIAGRAM as the documented FALLBACK if B is cold by demo day. (2) Say "three staged scopes
we operate," NEVER "three customers." (3) Frame the k=2→k=3 crossing as "the THRESHOLD is enforced," NOT "one attacker can't fake the
network" (the demo can't prove Sybil-resistance). (4) The cross-customer match is STRICTLY WEAKER than a local jail (ceiling ~0.60;
`FromSharedPattern` zeroes the hash → `typeSim==0`) — "sharpened detection of a repeat pattern," never "caught a novel attacker." (5)
Verify all three staged scopes hit a real T3, not T2.

---

## 7. Build sequence

Design → implement → adversarial review → PR; founder merges. "Needs the 3 boxes" = the live staged demo (with Daniel); everything else
is in-repo unit-testable now.

**In-repo (buildable + testable now):**

1. **Confirmation wire + spool** — `internal/intelligence/transport/confirm.go` (NEW): `Confirmation` envelope, `ConfirmSpool` with
   `SendConfirmation` / `ReceiveConfirmations`, mirroring `transport.Spool` (append-only NDJSON, `0o600`, 1 MiB cap, fail-closed framing,
   drain-and-truncate per D63h). Tests (`confirm_test.go`): round-trip; reject malformed/oversized pattern; over-long line fails closed;
   missing spool → empty.
2. **Network re-entry helpers + parity** — `internal/intelligence/network/shared.go` (EDIT): `ExportFormFromShared` (returns the tagged
   internal mirror), `SharedCandidate`, and the contributor form-walk emitter. Tests (`ingest_test.go`): coarse-key parity round-trip
   (§4.1); `SharedCandidate`/emitter cannot Marshal without the ledger gate (only `ClearWithLedger` constructs a `ledgerVerified`
   carrier).
3. **Aggregator-scoped ledger with boundary-enforced allowlist** — `network` (EDIT): `NewAggregatorLedger(enrolled func(string) bool)` +
   `IngestConfirmation(token, SharedPattern)` so an un-enrolled token CANNOT reach `RecordForm` (D63e). Tests: 3 distinct enrolled tokens
   → k=3 → Clear+Marshalable; 2 tokens → reject; unknown/empty token does NOT increment; one token re-confirming does NOT inflate k
   (idempotency); structural test that the on-wire token is NOT a function of `ScopeKey`.
4. **`cmd/aggregator/main.go`** (NEW): the central loop — `NewAggregatorLedger`, ingest, `RecordForm` via `IngestConfirmation`,
   `ClearWithLedger` at k≥3, `transport.Send`; flags `--confirm-in` / `--cleared-out` / `--token-allowlist`; drain-and-truncate the
   confirmation spool after each cycle. Test: end-to-end 3-confirmation → crossing; un-allowlisted token never crosses.
5. **boot.go emit + config** (EDIT): alongside the existing local `RecordForm` on `ReportOutcome` (Contribute-gated, boot.go:418-419),
   ALSO emit a `Confirmation` when `confirmSpool != nil` — `SendConfirmation(scopeToken, coarseBytes)`. New `boot.Options`:
   `ScopeToken string`, `ConfirmSpoolPath string`; new `config/` fields `intel.scope_token`, `intel.confirm_spool_path`. Test: a jail
   emits a confirmation; an export attempt does NOT; an inbound pattern does NOT.
6. **Adversarial review pass** against this doc + live code: no raw `ScopeKey`/hash/HMAC-of-ScopeKey on the wire; token not derived from
   `ScopeKey`; allowlist enforced at the package boundary; tripwire fires; coarse-key parity holds; `ClearWithLedger` remains the sole
   transmittable-carrier constructor; aggregator never retains the spool indefinitely. Then PR.
7. **Cross-link** `docs/D6_NETWORK_DESIGN.md` §4 (the deferred cross-scope `Record` wire) to this resolution.

**Needs the 3 boxes (live staged demo, D6-4, with Daniel; D63j/D6j):** stand up scope-1 (M7 server, untouched), scope-2/B + scope-3 on a
dedicated 3rd box as separate processes; issue + allowlist 3 tokens out-of-band (token→deployment map kept OFF the aggregator); accrue
scope-2/B to Calibrated+Live+BucketSufficient (its own accrual window, sequenced against M7's F11 reboot constraints); replay the one
demo cassette against each scope so all three derive the identical coarse tuple and reach a real T3; demo the gate REJECTING at k=2 then
CROSSING at k=3; revert all three scopes to `default` posture afterward. Do NOT lower `aggregationK`.

**Deferred (tracked, NOT in D6-3 MVP):** authenticated scope enrollment + per-token auth secret + rate-limiting + the networked inbound
listener (D7 — the precondition for ANY untrusted contributor; D63f); bbolt persistence of the aggregator ledger (D6i salt constraint);
gossip topology (D63i); splitting the token's bucketing-identity from a separate bearer auth credential (open question, founder call).

---

## 8. Open questions (carry into review / sequencing with Daniel)

- **OQ1 — token vs auth credential:** the issued token is both the pseudonymous bucketing identity and (if used as a bearer) the auth
  credential. Split into a non-secret participant id + a separate secret auth token so a leaked credential does not also leak the stable
  bucketing identity? Cleaner but adds an enrollment field; founder call (D7-shaped).
- **OQ2 — aggregator custody:** who operates the central aggregator — CanarySting (the token→customer issuance map is our custodial
  liability) vs the customer's own central tier? Shapes whether the D63h partition is across processes or across organizations.
- **OQ3 — confirmation transport for the live demo:** file spool rsync'd to the aggregator (honest: "in production this is an
  authenticated push; here we rsync three files") vs a live authenticated POST (would pull D7 inbound-WRITE controls into D6-3 scope).
  Recommend rsync'd file spools for the demo; flag the rsync as the staged glue.
- **OQ4 — M7 contamination / sequencing:** which boxes back the 3 enrolled scopes; scope-2/B accrual lead time; do NOT contaminate M7's
  two boxes (F11 reboot windows). Sequence with Daniel before the demo.
- **OQ5 — idempotency across restarts:** the confirmation spool is append-only; re-ingesting after a restart is safe (`RecordForm`
  idempotent per `(token, coarseKey)`). Confirm the MVP re-reads the whole spool each cycle (recommended) and DRAINS it (D63h) vs tracking
  an offset.
- **OQ6 — cassette → 3 real T3 jails:** confirm the replayed run reaches a real Tier-3 jail in EACH scope (not just T2) so `RecordForm`
  fires in all three; if any scope only reaches T2 the k=3 is fabricated and the demo is a lie.