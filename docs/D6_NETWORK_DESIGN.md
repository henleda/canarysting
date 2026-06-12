# docs/D6_NETWORK_DESIGN.md — The Cross-Customer Network (Design)

> **Sub-design for founder signoff BEFORE any code.** Modeled on `docs/EGRESS_FILTER_DESIGN.md`.
> D6 is **THE rule-9 leak boundary**: the single place anonymized adversary patterns may cross
> between deployments. A wrong call here is a **CRITICAL bug**. Audited field-by-field and
> seam-by-seam against the **live code** (filter.go, justify.go, reidentify.go, candidate.go,
> optin.go, block.go, profile.go, export.go, features.go, match.go, derive.go, sharpen.go,
> baseline.go, contract.go, boot.go), not against design prose.

## The one paragraph

D6 turns the built egress chokepoint into a real cross-customer network. The **producer half** (D6-1)
coarsens a `profile.Profile` into the already-shipped 6-field `ExportForm` and hands it to the single
`network.Clear` gate. A new in-package **ledger** (D6-2) becomes the network package's own trusted
source of "seen in ≥k distinct scopes," replacing today's producer-asserted `SeenInScopes` (the
known-gap, optin.go:11-16). A thin **transport** (D6-3, needs the 3rd box) moves only `Cleared.Marshal()`
bytes A→B. A **consumer** reconstructs a deliberately-poorer coarse pattern and feeds it into the SAME
single `FingerprintMatch` dimension D5-Phase-2 built — as DETECTION CONTEXT ONLY, never an inbound
trigger (rule 8). The producer and the gate distrust each other; so do the two ends of the wire.
**Critical correction folded in from leak-review:** the cross-scope count is keyed on the **coarse
cleared tuple**, never the raw `BehavioralHash` — shipping the fnv-64a hash between deployments is
exactly the D9-forbidden reversible-hash crossing and would re-encode every dropped field. **D6 transport
MUST NOT be enabled until §0/D6c is signed.**

---

## 0. Decisions needing founder signoff (read first)

Each row is a load-bearing choice. **Rule-9-critical** rows are marked 🔴. Sign or amend before code.

> **✅ FOUNDER-SIGNED 2026-06-11.** All §0 decisions approved. **D6a amended:** the export carries the 6 fields **plus `CadenceBand`** (7 total) — the one honest match-strength refactor. The compelling demo is built on the **trust story** (§8), not on a stronger match (which is rule-9-capped). Demo refactors signed alongside: the cadence-honesty handling (§5.1), the `Consume` toggle into the MVP (D6g), keep the file spool (D6f), and a **calibrated scope-2** for the acceleration beat (D6j). `PoisonDepthBand` and the live A→B push are deferred.

| id | Decision | Recommendation | Why load-bearing |
|----|----------|----------------|------------------|
| **D6a** | **SIGNED: the 6-field shape PLUS `CadenceBand int` (0..3)** = 7 fields (`ReachedContain, EngagedVelocity, EngagedPoison, HeldBand, DisengagedEarly, PoisonClass, CadenceBand`). `PoisonDepthBand`/`DisengageBand`/`EngagedOppCost` stay deferred. | **Add `CadenceBand`; defer the rest.** | The egress filter enforces per-FIELD coarseness, not a global budget — but each added field multiplies the joint-cell count (homogeneity). `CadenceBand` is the single field worth its cost: it turns the kernel's 0.15 `cadSim` term from a luck-of-the-draw band-0 coincidence into EARNED evidence (automation-vs-human tempo across deployments), lifting the inbound Similarity ceiling ~0.45 → ~0.60 (M ~1.22 → ~1.30 — a visible vs invisible acceleration beat). Cost: 256 → 1024 joint cells (bought back by D6c coarse-tuple keying + staged k≥3). A richer match beyond this is **rule-9-capped**: the dominant `typeSim` (0.40) is the decoy SEQUENCE and can NEVER cross — that cap IS the privacy guarantee, reframed as the trust story (§8). |
| **D6b** 🔴 | **Pin the D2-2 `DisengagedEarly` semantic in code**, not just the table: add a `DeriveProfile` invariant test asserting `DisengagedEarly==false` for `DisengageReason ∈ {0,2,3}` even when `TimeToDisengageSec>0`. | **Yes — ship the test as part of D6.** | This is the ONE leak the table cannot delegate to `Clear`. A defender max-hold cap (reason 3) or generator-exhausted end (reason 2) mislabeled true would disguise OUR config as adversary behavior in the shared set. It passes every field-name/kind test, so derive.go:76 (`DisengageReason==DisengageAttacker` only) + this test are the sole guards. |
| **D6c** 🔴 | **Key the cross-scope ledger on the COARSE CLEARED TUPLE, not the raw `BehavioralHash`.** The hash stays strictly in-process (local Similarity/dedup); it NEVER leaves a deployment. | **Adopt coarse-tuple keying. BLOCK transport until signed.** | **The critical leak-review finding.** A hash-keyed ledger is single-binary (counts cap at 1), so reaching k≥3 forces the raw fnv-64a hash across the deployment boundary in the cross-scope ingest — the **D9-forbidden reversible-hash crossing**. `behavioralHash()` (derive.go:116-128) is fnv over `Join(OrderedTypes)+cadenceBand+ALL FIVE AxesEngaged bits+PoisonClass+PoisonReached+DisengagedEarly`; brute-forcing it over the tiny vocab recovers the dropped decoy SEQUENCE, the full 5-axis bitset (floor config), AND the AX4/AX5 exploit/exposure bits. Coarse-tuple keying makes the counted unit == the wire unit (correct k-granularity) and the hash-key-vs-hash-crossing tension moot. |
| **D6d** 🔴 | **Chokepoint signature change:** add `ClearWithLedger(c Candidate, lc ClearContext) (*Cleared, error)`; the old `Clear` becomes fail-closed/reference-only; `ContributionContext.SeenInScopes` is **rejected as a tripwire** (assert-zero, error if a producer set it non-zero). | **Adopt (a): ledger-aware chokepoint + tripwire.** | The count must be computed INSIDE the chokepoint from the package's own state via an UNEXPORTED reader; a producer-supplied count is the fox counting the henhouse (EGRESS §5.1.1, optin.go known-gap). Turning the old field into a tripwire permanently closes the producer's ability to re-supply the count. |
| **D6e** | **`Record` fires ONLY on a LOCAL Tier-3 jail** (the D5 confirmed-malice ground truth, boot.go:336 ReportOutcome path), gated on `Contribute` opt-in, idempotent per (scope,pattern). It NEVER fires on an export attempt and NEVER on **inbound** pattern receipt. | **Sign jail-only + no-receive-feedback.** | Two circular-self-attestation paths re-open the gap if missed: (1) recording on export = "I tried to share it inflates its own k"; (2) recording on receive = a single originating scope A fanned out to B and C reads k=3 for a pattern only A confirmed (k=1 reality in a k=3 mask). |
| **D6f** | **Transport seam = a FILE/spool drop, not a network service.** `transport.Send(*network.Cleared)` consumes ONLY `Marshal()` bytes; receiver parses into a NEW narrow `SharedPattern`, never back into `*Cleared`. | **Sign file drop for MVP.** | A file is the honest minimum that satisfies "move opaque bytes A→B." A listener adds inbound attack surface + access-control + rate-limiting — that is **D7's** scope (MOAT §3.5); putting it in D6 smears D7's surface into the rule-9 review. File is reboot-tolerant (F11) and the bytes are `cat`-inspectable for the demo. |
| **D6g** | **Add a `Consume` opt-in toggle** to operator config, independent of `Contribute` (zero-value denies). **Signed INTO the MVP** (not deferred) so the demo can narrate per-deployment consent ("A contributes; B consumes"). | **Add it now; same config source of truth as `Contribute`.** | EGRESS locks "per-deployment opt-in to contribute AND to consume, independent toggles." A `Consume` toggle **does not exist in `config/` today** (verified — grep is empty). The consumer must gate on it so a deployment can contribute without consuming or vice-versa. Trivial, additive, default-deny. |
| **D6j** 🔴 | **Demo honesty: the acceleration beat REQUIRES scope-2 (B) to be CALIBRATED + live + bucket-sufficient.** Stand up scope-2 with an accrued baseline (not a cold box) and surface its `baseline.State` (Calibrated/Live/BucketSufficient) on screen. | **Stand up a calibrated scope-2; show its gate-state.** | `baseline.go:417-419` returns M=1.0 (ignoring `FingerprintMatch`) until the scope is calibrated+live+bucket-sufficient. Narrating "B escalated faster because of the network" on a **cold** B is staged-misleading — the match would do nothing. This is the most common way the demo would otherwise lie. **Tied to the M7 baseline-accrual long-pole**: scope-2 needs accrual time before demo day. |
| **D6h** | **Inbound is detection CONTEXT only**, held in a SEPARATE bucket that `Match()` scans but `RecordJail` never writes and `MinConfirmedJails` never counts. A sparse-lifted inbound profile MUST leave `BehavioralHash==0` so the `Similarity` self-match fast-path (match.go:21) can never fire for it. | **Sign separate-bucket + zero-hash invariant.** | Letting an inbound pattern increment the local jail-floor would launder a remote signal into local confirmed-malice B never observed (rule 5). Letting a forged/colliding hash trip `Similarity==1.0` would drive the local sharpening term to its ceiling from a cross-deployment input, sidestepping the deliberately-weaker evidence kernel. |
| **D6i** | **MVP persistence = in-memory** (mirrors sharpen.go:19-24 deferral). bbolt is a tracked fast-follow; when it lands, the ledger is the ONE sanctioned cross-scope artifact at rest and **MUST NOT co-persist the bucketing salt with the buckets**. | **Sign in-memory MVP; pin the salt constraint now for the deferred bbolt work.** | Losing the ledger only LOWERS counts ⇒ denies more ⇒ fails CLOSED (same safety logic as sharpen). But a persisted ledger with co-located salt becomes a re-identification asset ("which deployment exhibited which pattern"). Pin the constraint before an implementer can casually persist salt+buckets together. |

**Residual accepted (carry to D7), not a new defect:** k-anonymity with k=3 over the small closed
vocabulary (the **7-field** joint space is 2·2·2·4·2·4·**4** = **1024 cells** with the D6a-signed
`CadenceBand`; 256 without it) is weak against a determined
recipient with side knowledge (homogeneity/background-knowledge). EGRESS risk #4 already flagged
l-diversity/t-closeness as a fast-follow. D6c (coarse-tuple keying) materially helps: k≥3 then means
≥3 scopes share the **exact cell that crosses**, restoring true k-anonymity of the wire unit. Document
as accepted-and-bounded.

---

## 1. The five D6 pieces and their dependency order

1. **D6-1 producer coarsening** (§2) — flesh out `ToExportForm` per the signed table. **In-repo testable now.**
2. **D6-2 ledger** (§3) — `network/ledger.go`, the package's own trusted count. **In-repo testable now** (single-binary counts cap at 1 by design).
3. **Clear consults the ledger** (§3.3) — `ClearWithLedger` + tripwire. **In-repo testable now.**
4. **D6-3 transport seam** (§4) — file spool A→B. **Needs the 3rd box (with Daniel)** for the live A→B demo; the Send/Receive units are in-repo testable now.
5. **D6 consumer** (§5) — sparse-lift → composite Matcher → `FingerprintMatch`. **In-repo testable now**; the cross-deployment money-shot needs the 3rd box.

---

## 2. D6-1 — The per-field coarsening table (the producer half)

`profile.Profile → profile.ToExportForm → network.ExportForm → network.ClearWithLedger`. The producer
coarsens; the independent gate re-verifies (EGRESS §1.3). The signed MVP shape is **exactly the 6 fields
already shipped**; every other rich field is **DROPPED**.

### 2.1 The exported fields (the 6-field MVP)

| rich field (Profile) | coarse field | kind | transform | egress tag / why safe |
|---|---|---|---|---|
| `PeakTier int (0..3)` | `ReachedContain` | bool | `PeakTier >= int(contract.TierContain)` i.e. `>= 2`. NOT the raw tier, NOT a 0..3 band. | `safe,coarse tier bucket (reached T2+)`. The raw tier / any tier threshold is scope-local floor policy; one "reached T2+" bool says "escalated to a real response somewhere" without revealing the floor. |
| `AxesEngaged[0]` (velocity) | `EngagedVelocity` | bool | `AxesEngaged[0]` (axisBits[0]==AxisVelocity). Per-axis bool read out of the bitset; the raw `Axes` bitset is NEVER exported. | `safe,per-axis engaged boolean; not the raw Axes bitset (which leaks floor config)`. The bitset is the union of active generators' axes = the enabled attrition floor; one bool is an adversary-reaction fact, and you cannot reconstruct the floor from one axis. |
| `AxesEngaged[1]` (poison) | `EngagedPoison` | bool | `AxesEngaged[1]` (axisBits[1]==AxisPoison). Never the raw bitset. | `safe,per-axis engaged boolean`. Velocity+poison are FloorModerate's two axes; axes 2/3/4 are excluded (see §2.3). |
| `HeldSec float64` | `HeldBand` | int 0..3 | `heldBand(HeldSec)`: `{<=0→0; <4s→1; <30s→2; >=30s→3}` (features.go). NO float ever crosses. | `safe,band=0..3,imposed-hold band 0..3`. A raw duration singles out (continuous) AND leaks the tarpit/max-hold cap. Band span 3 ≪ maxBandSpan=256; the gate range-checks the value (filter.go:145). Float is denied outright by the kind allowlist, so the band int is mandatory. |
| `DisengagedEarly bool` (joint w/ `DisengageReason`+`TimeToDisengageSec`) | `DisengagedEarly` | bool | **PINNED D2-2 SEMANTIC:** true ONLY when `DisengageReason == DisengageAttacker (1)`, read jointly with non-zero `TimeToDisengageSec`. Reasons 2/3 NEVER set it. `Profile.DisengagedEarly` is already defined this way (derive.go:76); `ToExportForm` passes it straight through. The producer must NOT recompute it from a looser predicate. | `safe,attacker-disengaged-before-cap boolean`. **The load-bearing row (see §0/D6b).** A field-name test passes either way; only the pinned derivation rule (+ the D6b invariant test) catches a semantic mislabel. |
| `PoisonClass string` | `PoisonClass` | string (closed enum) | `clampPoisonClass(p.PoisonClass)`: pass through iff in `{"",credential,topology,success}`, else coarsen to `""`. The clamp is REQUIRED because `contract.StingOutcome.PoisonClass` is a free string; a malformed value would fail Clear's closed-enum check and, because Clear is all-or-nothing (D8), silently drop the WHOLE candidate. | `safe,coarse poison reaction class from the closed vocab`. The name must lowercase to exactly `poisonclass` — the only registered enum key in `justify.go enumValues` — or Clear denies it. Value is checked against the closed set. The stage TAXONOMY is dropped. |
| `CadenceSec float64` | `CadenceBand` | int 0..3 | `cadenceBand(p.CadenceSec)` (features.go:36 — already computed for the local hash). The BAND is exported, NEVER the float. **D6a-signed addition.** | `safe,band=0..3,coarse inter-arrival tempo band (automation vs human-paced); NOT raw cadence seconds`. The band is the same 0..3 bucket `HeldBand` uses (span 3 ≪ maxBandSpan=256, range-checked at filter.go:145). It is the ATTACKER's own probe inter-arrival (attacker-controlled tempo), not environment RTT. Float is denied by the kind allowlist, so the int band is mandatory. **Earned `cadSim` evidence** (vs today's coincidental band-0 match). Homogeneity cost: ×4 cells — accepted, carry to D7's l-diversity (EGRESS risk-4). |

### 2.2 DROPPED fields (each drop is explicit and auditable)

| rich field | why dropped |
|---|---|
| `OrderedTypes []string` (decoy-type touch sequence) | The probe SEQUENCE is the decoy-placement signature. Dropped entirely — not even an unordered set or length band (D6-1). Slice kind is non-allowlisted; the name carries `sequence`/`order` tokens (reidentify.go:28). |
| `Touches int` (total interaction count) | Raw interaction-volume is a singling-out quasi-identifier (a campaign's volume). Not in `referenceExport`; a raw count fails the band requirement. Behavioral signal is carried by the bool/band fields. |
| `DepthReached int` (deepest maze/nesting level) | Bounded by THIS deployment's maze topology, so it discloses decoy/maze structure (same family as `OrderedTypes`). Engagement-depth is carried by `ReachedContain` + (optional future) `PoisonDepthBand`. |
| `CadenceSec float64` (median inter-arrival) | The continuous timing **float** is dropped (singles out; float denied by the kind allowlist). **The coarse `CadenceBand` 0..3 IS exported (D6a-signed)** — see the §2.1 table. Only the band crosses, never the seconds. |
| `CadenceJitter float64` (MAD of inter-arrivals) | Continuous timing-variance float tied to an environment; float denied by kind allowlist. Dropped entirely. |
| `AdjacencyNov float64` (peak adjacency novelty) | Baseline-relative learned state (rule 5) — defined against the local baseline, uninterpretable cross-scope. Float denied; nearby `baseline`/`features` names also denylisted. |
| `IdentityNov float64` (peak identity novelty) | Baseline-relative learned state (rule 5); the substring `identity` is itself on the reidentify denylist (reidentify.go:18). Hard-denied by name AND kind. |
| `PersistsTarpit bool` | Double-encodes the `tarpitPersistSec=30` config that `HeldBand`'s `>=30s→band 3` boundary already sits on; a separate "persisted past 30s" bool would confirm the exact cap. Subsumed by `HeldBand==3`. |
| `TimeToDisengageSec float64` (standalone) | Continuous disengage-time float (singles out; correlatable jointly with held time). Folded into the `DisengagedEarly` bool. A future disengage-speed signal must be a 0..3 band, never seconds. |
| `PoisonReached int` (raw poison-stage depth) | Dropped in the signed MVP (`referenceExport` has none). D6-1 permits an OPTIONAL bucketed `PoisonDepthBand 0..3` if the founder opts in (D6a) — never the raw stage count, never the stage taxonomy. |
| `AxesEngaged[2]` (opportunity-cost) | Not in the audited two-axis MVP shape; oppCost is a DEMOTED proxy "never the lead" (MOAT §3.1). Clean to add later as `EngagedOppCost` bool (name passes the denylist), but out of MVP scope. |
| `BehavioralHash uint64` | Reversible fnv-64a over a tiny vocab (brute-forceable) AND a stable cross-scope correlation key (linkability). `hash`/`fingerprint`/`digest` tokens hard-deny it (reidentify.go:28-29); uint64 cannot satisfy a band. **Local-only key; per D6c it NEVER crosses, not even to the ledger ingest.** |
| Raw timestamps / FirstSeen / LastSeen / decoy contents / paths | Environment-correlatable / rule-9-critical raw content. `isTimeType` + the name denylist hard-deny. The core engagement metric is sourced from real held time, never wall-clock timestamps. |

### 2.3 `never_exported` (the hard-block set — exhaustive)

- **`ExploitsObserved int64` (AX4)** and **`ExposureSignals int64` (AX5)** — triple-blocked: structurally absent from `ExportForm`; the `exploit`/`exposure` name tokens hard-deny (reidentify.go:31-32); int64 needs a band it is denied; carrier types (`intelligence.StingOutcome`) on the candidate-type denylist (block.go:40-45). AX5 additionally gates on the F4 in-perimeter-harmlessness predicate. **HARD-BLOCKED this entire phase.** Any future unblock is a founder-signed compile-time edit to block.go, never a runtime flag.
- **`AxesEngaged[3] / AxesEngaged[4]` as engaged-booleans** — **CRITICAL STRUCTURAL FINDING:** even the coarse per-axis bool for axes 3/4 can NEVER cross, because the only sensible field name (`EngagedExploitBurn` / `EngagedExposure`) contains the `exploit`/`exposure` denylist tokens and is hard-denied **by name**. This is why the per-axis engaged-boolean export is structurally limited to axes 0 (velocity) and 1 (poison) — exactly the shipped `referenceExport`. **Sign this constraint as intentional.**
- **`ScopeKey`** (rule 5 identity), **`FlowID`/`SocketCookie`** (rule 4 join key), any **IP/host/addr/port/mac/vlan/subnet/cidr/domain/fqdn/url/region/geo/asn**, any **org/tenant/customer/account/cluster/namespace/spiffe/cert/agent** — all on the reidentify name denylist; never Profile fields by construction.
- **baseline / learned-state / `Features` / calibration / scope-state** (rule 5) — every `internal/engine/` type is on the candidate-type denylist (block.go:47).
- **`BehavioralHash` / any hash / fingerprint / digest / checksum / signature** — denylisted by name (D9); reversible; stable correlation key.
- **`cost.Summary`** and any raw event / `StingOutcome` / `OutcomeRecord` / `Verdict` / `SignalEvent` / `FeedbackLabel` — candidate-type denylist (block.go).

---

## 3. D6-2 — The cross-scope ledger (`internal/intelligence/network/ledger.go`)

The package's OWN single trusted source of "seen in ≥k distinct scopes," replacing the producer-asserted
`SeenInScopes` known-gap. **Not yet written** (confirmed no `ledger.go` exists).

### 3.1 What it stores — exactly one thing

A map from the **coarse cleared tuple** (per D6c, NOT the raw hash) to a set of distinct scope buckets:

```go
// internal/intelligence/network/ledger.go — the network package's OWN trusted source

// coarseKey is the canonical, stable encoding of the SIX coarse cleared fields — the
// SAME tuple that crosses the wire — so the count's granularity == the wire unit's.
// It is NOT the BehavioralHash (D6c): the hash never leaves a deployment.
type coarseKey struct {
    ReachedContain, EngagedVelocity, EngagedPoison bool
    HeldBand        int    // 0..3
    DisengagedEarly bool
    PoisonClass     string // closed enum
}

type scopeBucket [16]byte // HMAC(process-local salt, ScopeKey) truncated; distinct iff scopes distinct

type Ledger struct {
    mu   sync.RWMutex
    seen map[coarseKey]map[scopeBucket]struct{} // coarse pattern -> set of distinct scope buckets
    salt []byte                                 // process-local; never crosses, never persisted as plaintext
}

func NewLedger() *Ledger

// Record is the ONLY mutation. A scope "exhibits" a pattern => bump its distinct-scope set.
// Idempotent per (scope, key): re-exhibition by the same scope does NOT inflate the count
// (the whole k-anonymity guarantee). Returns the new count for observability only.
func (l *Ledger) Record(scope contract.ScopeKey, key coarseKey) int

// distinctScopes is the count the chokepoint reads. UNEXPORTED on purpose: only Clear
// (same package) may read it. Returns 0 for an unknown key (fail-closed: unknown => sub-k => deny).
func (l *Ledger) distinctScopes(key coarseKey) int
```

- It stores **NO** Profile, ExportForm, raw events, baselines, scope-state, decoy contents, IPs/cookies/FlowIDs, cadence/timing-as-data, or behavioral fields beyond the coarse tuple. The only value ever READ is the set's cardinality.
- It does **NOT** store the raw `ScopeKey`: `Record` reduces it to `scopeBucket = HMAC(salt, ScopeKey)` truncated, so even a dumped ledger is an opaque histogram (coarse-pattern → opaque-bucket-set) that cannot answer "which deployment exhibited X," only "how many." This keeps the ledger itself rule-5/rule-9-clean.

### 3.2 The record path — WHO calls `Record` and WHEN

Tie `Record` to the **D5 jail signal** — the existing customer-reproducible ground truth, NOT an export
attempt. At the boot composition root, the SAME place that calls `sharpen.Store.RecordJail` on a Tier-3
jail (boot.go:336, the `ReportOutcome` path), ALSO derive the jailed flow's Profile (already derived
inside `RecordJail`), coarsen it to the `coarseKey`, and call `ledger.Record(scope, key)`. A scope
"exhibits" a pattern when it **independently confirms** that behavior as malicious in its own deployment.

`Record` gating: (a) the scope has opted in to **`Contribute`** (zero-value denies — an un-opted-in
scope must not even appear in the count, else its participation is inferable); (b) a real confirmation
event (a jail), **never** a mere observation, **never** an export attempt (D6e), **never** an inbound
shared pattern (D6e — see §5.4). Idempotent per (scope, key).

**MVP is single-deployment-local:** in one binary the ledger only sees ITS OWN scope confirm patterns, so
counts max out at 1 ⇒ the gate denies everything (n=1 < k=3). That is correct and **fail-closed**. D6-4's
staged k≥3 demo drives `Record` from each of the ≥3 standing scopes' real confirmations once the cross-scope
ingest (D6-3) feeds remote `Record` calls in.

### 3.3 How `Clear` consults the ledger — the hash-lookup resolution

```go
type ClearContext struct {
    Ledger *Ledger
    Key    coarseKey // the coarse tuple of THIS pattern; lookup index only
}

func ClearWithLedger(c Candidate, lc ClearContext) (*Cleared, error)
```

Flow:
1. `lc.Ledger == nil` → **ERROR** (fail closed: no trusted source ⇒ nothing crosses; the ledger is MANDATORY for a real crossing — you cannot get a `*Cleared` without one).
2. `n := lc.Ledger.distinctScopes(lc.Key)` — the count is **COMPUTED HERE**, from the package's own state, via the unexported reader. The producer cannot supply, override, or even read `n`.
3. The candidate's `ContributionContext.SeenInScopes` is **no longer consulted** and is asserted-zero as a **tripwire** — error if a producer set it non-zero (turns the old known-gap field into a leak detector). `ContributionContext.Contribute` IS still consulted (opt-in stays producer-config-sourced).
4. `n < aggregationK` → **ERROR** (the SAME `aggregationK=3` package constant, now backed by real provenance).
5. else run the existing `clearStruct` field walk **unchanged**; payload NEVER contains the key or any hash.

**The hash-as-key tension, RESOLVED (D6c):** there is no raw `BehavioralHash` anywhere in this path. The
lookup index is the **coarse tuple itself**, derived from the candidate's already-cleared fields, so (a)
nothing reversible is constructed, (b) the index can never hit reidentify.go's `hash` token, (c) it is
never copied into `Cleared.payload`, (d) it never appears in `Marshal` bytes, and (e) the cross-scope
ingest (§4) ships only the coarse tuple — which is exactly what already legitimately crosses. **D6-1's
"no hash crosses" holds by construction.** The `BehavioralHash` remains the local key for `sharpen.Store`
and `Similarity` dedup only.

### 3.4 Concurrency

`sync.RWMutex` on `Ledger`. `Record` write-locks (mutates the set); `distinctScopes` read-locks (returns
`len`). Reads (clears) dominate writes (jails are rare), so RWMutex is right. **Leaf lock, B→A discipline**
(mirrors `sharpen.Store`): scope-bucketing happens BEFORE the lock; no call-out under the lock;
`ClearWithLedger` calls `distinctScopes` (brief RLock, returns int), releases, THEN runs `clearStruct`
outside any ledger lock. No lock held across reflection/I/O; no nested ledger locks. Go maps require the
lock on every access.

### 3.5 Persistence

**MVP: in-memory only**, mirroring `sharpen.go:19-24`'s already-accepted deferral. Losing the ledger can
only LOWER counts ⇒ `n < k` more often ⇒ the gate DENIES more ⇒ fewer patterns cross. Forgetting the
ledger fails **CLOSED**, never open — the signature of a guardrail. The live M7 window runs passive (no
jails), so there is nothing to lose there yet.

**bbolt fast-follow constraints (sign D6i now, code later):** (1) the ledger is the ONE sanctioned
cross-scope structure and MUST live in its own DB/bucket, never inside a per-scope store; (2) persist ONLY
coarse-tuple → bucket-set, never the raw `ScopeKey` and never any profile/event field; (3) **NEVER
co-persist the bucketing salt with the buckets** — persisting the salt next to the buckets would let an
attacker with the deployment's scope-key list re-identify which scope exhibited what. Add a test at the
bbolt stage that the persisted file contains no `ScopeKey` and no salt.

---

## 4. D6-3 — The transport seam (file/spool drop)

**Recommendation (D6f): the thinnest honest seam = a FILE drop, not a network service.** New package
`internal/intelligence/transport`.

**Producer side (deployment A):**
1. `p := profile.DeriveProfile(jailedEvents)` (already built).
2. `cand := p.Candidate(ctx)` (export.go:70 — `Candidate(ctx network.ContributionContext)`).
3. `cleared, err := network.ClearWithLedger(cand, network.ClearContext{Ledger: l, Key: coarseKeyOf(cand)})` — the single chokepoint; fail-closed on err.
4. `b, err := cleared.Marshal()` — the ONLY bytes that may leave (payload is unexported; `Fields()` is a screen-demo copy, NOT a transport path, so the transport MUST consume `Marshal()` bytes to run the D3 re-validation, filter.go:179-189).
5. `transport.Send(*network.Cleared) error` writes `b` to an append-only NDJSON spool. It accepts **ONLY** `*network.Cleared` (Go-type-enforced: you cannot call `Send` without having passed `Clear`) and internally calls `.Marshal()`. It NEVER takes raw bytes or a `Candidate`.

**Cross-scope ingest of `Record` (the k≥3 enabler):** what crosses is the **coarse tuple** (the same
`Marshal` bytes), NOT a hash (D6c). On receipt, B records "remote scope exhibited this coarse pattern" into
B's ledger via the same buckized `Record` path — but see §5.4: **a received pattern must NOT feed B's OWN
`Record` as if B exhibited it.** The remote scope's bucket is what increments distinctness. The exact
cross-scope `Record` wire (who sends "scope X confirmed tuple T" to whom) is **D6-3 transport, needs the
3rd box.**

**Receiver side (deployment B):**
1. Read the spooled file → `[]byte` per record.
2. Parse into a NEW exported `network.SharedPattern` — **NOT back into `*network.Cleared`** (Cleared has unexported fields and no inbound constructor by design; reconstructing one would be a second constructor and break the single-chokepoint invariant). Shape mirrors `ExportForm` exactly: `ReachedContain, EngagedVelocity, EngagedPoison bool; HeldBand int; DisengagedEarly bool; PoisonClass string`.
3. **Validate on ingest** (the inbound mirror of `Clear`, fail-closed; the two ends distrust each other): `json.Decoder.DisallowUnknownFields`; reject any unknown key, `HeldBand` outside 0..3, `PoisonClass` not in the closed enum, any non-bool bool. **Coerce JSON numbers safely:** `Marshal` emits `json.Marshal(map[string]any)`, so `HeldBand` arrives as `float64 1.0` — validate it is integral and in-band, then store as `int`; this must NOT reintroduce a float anywhere.
4. Hand the validated `SharedPattern` to the consumer (§5).

**Key asymmetry:** a `*Cleared` is marshaled at A but is NOT un-marshaled back into a `*Cleared` at B. The
inbound type is a separate, narrower receiver struct — this preserves "Clear is the only constructor of
Cleared" and keeps the inbound path from masquerading as an egress path.

---

## 5. The consumer + the rule-8 inbound argument

### 5.1 Sparse-lift into the existing kernel

The validated `SharedPattern` is lifted into a **deliberately SPARSE** `profile.Profile`:
`AxesEngaged[0]=EngagedVelocity`, `AxesEngaged[1]=EngagedPoison`, `PoisonClass`, `DisengagedEarly`,
`PeakTier from ReachedContain (>=TierContain ? 2 : 0)`; `HeldSec` unset (HeldBand is the export); `OrderedTypes`
EMPTY (sequence DROPPED, D6-1); **`BehavioralHash` = 0 (D6h — MUST stay zero)**.

**Cadence (D6a-signed + the honesty handling).** Because `CadenceBand` IS exported, the consumer reproduces
the band on the lifted profile so `cadSim` becomes EARNED evidence — set `CadenceSec` to the band's
representative value (so `cadenceBand(CadenceSec)` round-trips to the exported band) OR compare the bands
directly; never reconstruct a float that didn't cross. **The honesty rule (folds in the rule-check
finding):** the kernel must NEVER score a `cadSim` match from an UNSET/unknown cadence — only from a real
exported `CadenceBand`. A `SharedPattern` whose cadence is unknown contributes **0** to `cadSim` (treated as
unknown, never a coincidental band-0 hit). Pin this in the consumer similarity path + a test.

So `typeSim` is **structurally 0** (the decoy sequence is rule-9-dropped and can never cross — §8), and
`cadSim` is earned only when `CadenceBand` is present. The realistic inbound ceiling is `axisSim(0.30) +
reactSim(0.15) + cadSim(0.15)` ≈ **0.60** (≈0.45 without cadence). **That is the honest consequence:** a
cross-customer pattern is a STRICTLY WEAKER match signal than a local confirmed profile — correct, because
we deliberately know less about it.

**D6h hard invariant:** the lifted profile's `BehavioralHash` MUST be 0, and the `Similarity` self-match
fast-path (`match.go:21`, `p.BehavioralHash == o.BehavioralHash → return 1`) MUST never fire for an inbound
pattern. Either (preferred) compute a dedicated coarse-only similarity over the 6 fields, or guard the
fast-path so two zero hashes do NOT short-circuit to 1.0. Test: an inbound `SharedPattern` can never
produce `Similarity==1.0` against any local profile via the hash path.

### 5.2 It feeds the SAME single `FingerprintMatch` dimension (decision J)

No new term, no new field, no new math:
- `baseline.Store.Multiplier` (baseline.go:430) snapshots `mt := s.matcher` (line 439) and sets `f.FingerprintMatch = mt.Match(scope, flow, at)` (line 455) OUTSIDE the store lock (B→A).
- `MFromFeatures` (baseline.go:177-188) composes `M = clamp(1 + (M_max−1)·g(d) + α·match, 1, M_max)`. The shared set reaches M through the SAME `Match()` return ⇒ the SAME `α·match` additive term — never a second term.
- **Recommended wiring (D6 open, lean composite):** a thin composite Matcher wrapping `{sharpen.Store local, sharedset.Store shared}` returning `max(local.Match, shared.Match)`. `baseline` still sees ONE Matcher. The composite keeps local-jail logic and shared-pattern logic in separate packages (cleaner rule-5/rule-9 separation, easier to prove the jail-floor is untouched). The emerging flow's `Similarity` vs a shared pattern uses the SAME `profile.Similarity` kernel.

### 5.3 The rule-8 inbound argument (PROOF the shared pattern can NEVER trigger)

1. The shared pattern only ever sets `f.FingerprintMatch` (a [0,1] float). It enters M solely through the `α·match` additive term (baseline.go:181-188). It writes NO other `Features` field and NO other engine state.
2. `FingerprintMatch` is **DELIBERATELY EXCLUDED** from `contributions()` (baseline.go:66-69, "FingerprintMatch is intentionally excluded"), so it cannot move the novelty/deviation norm `d` either — it is purely the bounded sharpening weight, capped by `α` (DefaultSharpeningAlpha=0.5) and clamped into `[1, M_max]`.
3. M is a **MULTIPLIER on a base that is zero without a canary touch** (`Score = B × M`; rule 8). A shared pattern lifting M from 1.0 to 1.5 on a flow with base=0 yields `1.5 × 0 = 0`. No score, no tier, no verdict. **Weight context times zero is zero** — the load-bearing arithmetic.
4. The jail decision is independent of M's source: a jail still requires the engine's own Tier-3 decision on `minTouches[T3]` DISTINCT canary touches. The shared pattern feeds `Match()→FingerprintMatch→M`; it is NOT on the touch-count path.
5. `Clear` gates OUTBOUND only; it never creates an inbound trigger (EGRESS §6.3/§8). The receiver routes `SharedPattern` ONLY to the Matcher dimension — there is NO code path from `SharedPattern` to a verdict, tier, attrition action, or touch count.

### 5.4 Scope attribution + no back-contamination (the jail-floor answer)

The inbound shared pattern **MUST NOT count toward the local jail-floor.** Concretely: a `SharedPattern`
must NEVER be fed to `sharpen.Store.RecordJail`, NEVER increment any `entry.flows` / confirmed-jail count
(sharpen.go:99), and NEVER call `ledger.Record` (D6e — receiving ≠ exhibiting). It is held in a SEPARATE
store/bucket that `Match()` scans for best-`Similarity` but `RecordJail` never writes and
`MinConfirmedJails=3` never counts. The two never alias; only the local bucket carries a real flow-cookie set.

If a shared pattern could increment the local floor it would (a) launder a remote signal into a local
jail-floor (rule-5 violation — B's confirmed-malice set is B's own state) and (b) manufacture local
confirmed-malice B never observed. A shared match never back-contaminates: B jails only on its own Tier-3
decision; only THEN does the flow become B's own local profile via the normal `RecordJail` path, and only
THEN — if B opts in and the ledger reaches k≥3 — could B's OWN derived pattern be cleared outbound.
Shared-in and local-confirmed remain separate ledgers; one never silently promotes into the other.

**Invariant test:** a scope with only received shared patterns and zero local jails produces `Match()>0`
context but `RecordJail` is never called, `len(entry.flows)==0` for any local pattern, and the ledger
count for those patterns is 0.

**Provenance tagging** (for the dashboard money-shot "the cross-customer network detected this"): each
shared pattern carries a non-identifying provenance marker (an opaque "shared" flag + the `SeenInScopes`
band), never a source `ScopeKey` (that would re-introduce the linkability the egress filter dropped).

---

## 6. Rule guarantees (the §8-style contract D6 must keep)

- **Rule 9** (only `Clear`-cleared anonymized patterns cross): the ONLY thing on the wire is the 6-field coarse tuple via `Cleared.Marshal()`. Raw `BehavioralHash` NEVER crosses (D6c) — not on the export, not in the ledger ingest. Producer + gate distrust each other; the receiver re-validates. Raw data / baseline / scope-state / decoy exfil = critical bug, structurally blocked by the kind allowlist + name denylist + type denylist + the hash-never-crosses rule.
- **Rule 5** (scope isolation absolute; learned state never aggregates across scopes EXCEPT egress-cleared patterns): the ledger aggregates a **COUNT, not STATE**. Rule 5's protected state (weights/calibration/evidence/feedback) is exactly what never enters. The counted unit (the coarse tuple) is the already-anonymized export unit. Scope identity is buckized so the ledger cannot re-link. It EXISTS to make k-anonymity real (the protective direction), and it fails CLOSED. Inbound shared patterns are held in a separate bucket that never touches B's raw learned state and never back-contaminates the jail-floor.
- **Rule 8** (canary touch is the only trigger; a shared set is detection context, NEVER an inbound trigger): proven in §5.3 — `FingerprintMatch` is excluded from `contributions()`, enters only as `α·match` on a base that is zero without a canary touch, and there is no path from `SharedPattern` to a verdict/tier/attrition/touch-count.
- **Rule 1** (baseline takes no dep on intelligence/profile): the consumer reaches baseline ONLY through the `baseline.Matcher` interface, wired at the boot composition root (boot.go:158). No new import edge.

**k-anonymity provenance (why k is only sound from here):** EGRESS §5.1.1 grounds no-singling-out on
"the cell never has fewer than k contributing scopes." That is a fact about the world only a cross-scope
ledger can witness. Today's producer-asserted count is the fox counting the henhouse (optin.go:11-16). The
ledger turns the gate's k-comparison from advisory arithmetic into an enforced guarantee — and keying on
the coarse tuple (D6c) makes "k contributing scopes" refer to the EXACT cell that crosses.

---

## 7. Build sequence

Design → implement → adversarial review → PR; founder merges. Order respects dependencies; "needs 3rd
box" = D6-3 (with Daniel) for the live A→B demo; everything else is in-repo unit-testable now.

1. **D6-1 producer coarsening body + `CadenceBand` + D6b invariant test** (in-repo now). Flesh out `ToExportForm` to the signed 7-field table — **add `CadenceBand int` (0..3)** to `ExportForm` sourced from `cadenceBand(p.CadenceSec)` with the `egress:"safe,band=0..3,..."` tag (a new `<reason>` string for the adversarial re-review). Add the `DeriveProfile` test pinning `DisengagedEarly==false` for `DisengageReason ∈ {0,2,3}` even with `TimeToDisengageSec>0`. Confirm `ValidateProfileForSharing` still passes and `referenceCandidate` is still Clear-able.
2. **D6-2 ledger** `internal/intelligence/network/ledger.go` (in-repo now): `Ledger`, `coarseKey`, `scopeBucket`, `NewLedger`, `Record`, unexported `distinctScopes`, RWMutex leaf-lock. Tests: idempotency per (scope,key), unknown-key→0, single-binary count caps at 1, `Contribute` gating.
3. **Clear consults the ledger** (in-repo now): `ClearWithLedger` + `ClearContext{Ledger, Key}`; demote `Clear` to fail-closed/reference-only; assert-zero tripwire on `ContributionContext.SeenInScopes`. Tests: nil ledger→error, sub-k→error, producer-set SeenInScopes→error, k≥3 happy path crosses, payload contains no key/hash, `Marshal` re-validates.
4. **`Record` wiring at the boot composition root** (in-repo now): alongside boot.go:336 `RecordJail`, coarsen the jailed profile to `coarseKey` and call `ledger.Record(scope, key)`, gated on `Contribute`. Test: a jail records; an export attempt does NOT; an inbound pattern does NOT.
5. **D6-3 transport seam** `internal/intelligence/transport` (Send/Receive units in-repo now; **live A→B needs the 3rd box**): `Send(*network.Cleared)` consumes only `Marshal()` bytes; `Receive() → []network.SharedPattern` with `DisallowUnknownFields` + band/enum validation + safe float64→int coercion. Tests: round-trip the **7 fields**, reject unknown key / out-of-band / bad enum, never reconstruct a `*Cleared`.
6. **D6 consumer + the cadence-honesty handling + `Consume` toggle** (in-repo now; cross-deployment money-shot needs the 3rd box): sparse-lift with `BehavioralHash==0` invariant; reproduce `CadenceBand` on the lifted profile so `cadSim` is earned (and contributes **0** when cadence is unknown — §5.1); composite Matcher `max(local, shared)`; `Consume` opt-in (D6g, new config field, into the MVP). Tests: rule-8 base=0 ⇒ Score=0 with a maxed shared match; jail-floor untouched (shared-only scope ⇒ `RecordJail` never called, `len(entry.flows)==0`, ledger count 0); `Similarity` never 1.0 for an inbound pattern; an unset-cadence inbound pattern contributes 0 `cadSim`.
7. **D6-4 staged k≥3 demo on a CALIBRATED scope-2** (**needs the 3rd box, with Daniel; D6j**): stand up scope-2 with an accrued baseline (calibrated+live+bucket-sufficient — tied to the M7 accrual long-pole), surface its `baseline.State`; drive `Record` from each of ≥3 standing scopes' real confirmations; DEMO the gate REJECTING a sub-k pattern and then crossing at k=3. Do NOT lower `aggregationK`.
8. **Adversarial review pass** against this doc + the live code, then PR. Re-run the leak-review checklist: no raw hash on any wire, tripwire fires, base=0⇒Score=0, jail-floor untouched, the new `CadenceBand` `<reason>` clears + does not leak the tarpit/cap config.

**Deferred (tracked, NOT in D6 MVP):** bbolt ledger persistence (D6i salt constraint); l-diversity/t-closeness for the **1024-cell** homogeneity residual (carry to D7); the D7 inbound listener + access-control + rate-limiting + the optional live authenticated A→B push (replaces the file spool, behind the four rule-8/9 invariant tests); optional `PoisonDepthBand`/`DisengageBand`/`EngagedOppCost` fields (only on a demonstrated need, D6a).

---

## 8. The compelling demo — the trust story, not a stronger match

> **Founder-confirmed framing (2026-06-11):** a dramatically stronger cross-customer match is **rule-9-capped** — the dominant matching signal (`typeSim`, 0.40) is the decoy-touch SEQUENCE, which IS the customer's decoy-placement map and can never cross. The inbound Similarity ceiling is ~0.60 (with `CadenceBand`), lifting M to ~1.30 — a real but modest acceleration. **That cap is not a weakness to hide; it is the privacy guarantee, and the demo is built around it.** A block-averse CISO trusts "sharpens your own detection, never acts on another customer's say-so" far more than a magic auto-block they'd never run in production.

**Three live beats, all provable on shipped code + the signed refactors:**

1. **The privacy proof, shown literally.** Deployment A jails an attacker on *its own* Tier-3 decision (rule 8 — a real local touch, not the network, triggers it). A coarsens the `Profile` to the `ExportForm`; **`cat` the NDJSON spool on screen**: the only bytes that ever left customer A are 7 coarse bands/bools/one-enum. Point at what is **absent** — no IP, no hostname, no decoy names, no raw timing, no hash, no exploit/exposure axes. *"We deliberately throw away our single strongest matching signal — your decoy layout — rather than risk leaking it."*

2. **The k-gate enforcing anonymity, live.** Feed a pattern only **2** scopes have independently confirmed; the chokepoint returns, on screen, `egress: pattern seen in 2 scope(s) < k=3 (singling-out risk)` and **nothing crosses**. Then a real 3rd customer independently confirms the same attacker → it crosses. k=3 is enforced machinery, never a lowered constant.

3. **The rule-8 trust beat (the money-shot).** B is a **CALIBRATED, live** deployment (show `baseline.State`: Calibrated + Live + BucketSufficient — D6j, so the audience knows the multiplier *can* move) that has simply never seen this attacker. The same adversary tooling touches a canary in B → `FingerprintMatch` lifts M ~1.0 → ~1.30 and **B escalates to containment on fewer touches than a cold B would need**, carrying a non-identifying *"recognized by the cross-customer network"* provenance tag (never a source `ScopeKey`). **Closing beat, side by side:** a parallel flow in B with the **maxed** cross-customer match but **zero** canary touches sits at `Score = 0 × M = 0` — no tier, no verdict. *"The network made us sharper on a real attacker, and it cannot act on anyone we haven't independently caught ourselves."*

**Honesty guardrails (the demo must not overclaim):**
- The acceleration only manifests on a **calibrated** B (D6j) — never narrate it on a cold box (M=1.0 there, the match does nothing).
- The cross-customer match is and stays **strictly weaker** than a local jail (ceiling ~0.60); frame it as "sharpened detection of a *repeat* pattern," not "caught a novel attacker."
- k=3 over the 1024-cell space remains homogeneity-weak to a recipient with side knowledge; l-diversity/t-closeness is an honest D7 fast-follow.
