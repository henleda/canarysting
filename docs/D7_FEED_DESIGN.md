# docs/D7_FEED_DESIGN.md — The Threat-Intel Feed (Design)

> **Sub-design for founder signoff BEFORE any code.** Modeled on `docs/D6_NETWORK_DESIGN.md` /
> `docs/EGRESS_FILTER_DESIGN.md`. D7 is the **LAST moat track and the "safe cut line"**: it adds **no new
> moat DATA**, only a *consumer surface* over D6's already-`Clear()`-ed, already-aggregated set. Audited
> field-by-field and seam-by-seam against the **live code** (filter.go, shared.go, ledger.go, optin.go,
> transport.go, backend.go, ledger_test.go), not against design prose. Three parallel design pieces
> (read-view, access-control, l-diversity) were adversarially reviewed; every finding is folded in below
> as either a **corrected choice** or an **open §0 decision**.

## The one paragraph

D7 packages the cross-customer aggregated set (D6's ledger) as a feed external systems consume (SIEMs,
ISACs) — INTELLIGENCE.md §5.5, "a SECOND PRODUCT LINE … the feed carries DERIVED PATTERNS ONLY, never
customer data … a READ VIEW over the anonymized, aggregated set, with its OWN ACCESS CONTROL and RATE
LIMITING." It is **never a second egress surface** (rule 9): every byte it serves already passed
`clearFields`/aggregation inside the network package, because the feed's *only* input is the ledger's
`seen` map, whose keys are `coarseKey` — the exact already-cleared 7-field tuple that crosses the wire.
The feed adds exactly **one** new derived scalar — a **bucketed prevalence band**, computed *inside*
package `network` behind the unexported distinct-scope count — and exactly **one** genuinely new attack
surface: an authenticated, rate-limited HTTP **read** endpoint, the FIRST attacker-reachable inbound code
in the whole intelligence layer (transport.go's own comment defers access-control + rate-limiting to D7).
The security bound that makes D7 the safe cut line: even a **total auth bypass** discloses only coarse,
**k≥feedK**, suppressed, banded patterns — no customer traffic, baseline, scope identity, or raw count.
In the current single-/few-deployment reality every cell is at k=1, so the feed is correctly **EMPTY
(fail-closed)**; it is fully testable now with a ledger seeded to k≥feedK and populates live with the 3rd
box.

---

## 0. Decisions needing founder signoff (read first)

> **✅ FOUNDER-SIGNED 2026-06-11 — LEAN SCOPE.** Build the **read-view DATA layer only** now: the ledger
> `Aggregated()` (D7a `feedK=5`, **presence-only** — no prevalence band, sparse-cell suppression, all inside
> package `network`), `feed.BuildFeed` + `FeedView`/`FeedEntry`, full tests. **DEFER the entire
> attacker-reachable consumer surface** — the HTTP handler + auth (D7e) + rate-limit/budget (D7f/g) + TLS
> (D7d) + revocation (D7i) + audit (D7j) — to **when there is a real external consumer** (clean
> `Source`-interface seam; the full security design below is captured for that day). Rationale: D7 is the
> safe cut line, the feed is **honestly empty at demo #1** (`feedK=5` over 2–3 boxes), and there is no
> external consumer yet — so shipping a consumer-less endpoint, or over-building production auth for it, is
> premature. D7b stands: **no l-diversity/t-closeness** (theater for this data shape; the residual is
> raised-and-bounded by `feedK`, not closed). The 🟠 new-attack-surface rows (D7c–D7j) are **design-captured,
> not built** in this PR. Next after the D7 read-view lands: the five-axis demo wiring.

Each row is a load-bearing choice. **Rule-9-critical** rows are 🔴; **new-attack-surface** rows are 🟠. Sign or amend before code.

| id | Decision | Recommendation | Why load-bearing |
|----|----------|----------------|------------------|
| **D7a** 🔴 | **The feed threshold + prevalence shape.** Three sub-choices, signed together as ONE number set, pinned identically across `aggregate.go`, `feed.go`, and the demo script. | **(1) `feedK` = a package CONST ≥ `aggregationK`, floored, NEVER request-supplied; recommend `feedK = 5`. (2) Prevalence: SHIP PRESENCE-ONLY for the MVP (no band at all) — a cell's mere appearance asserts "≥ feedK deployments independently corroborated this." (3) If the founder wants a band anyway, the lowest emitted band MUST be genuinely WIDE (e.g. 5–19 / 20+), never `3–4`.** | **The biggest re-identification vector the review found.** The original read-view/access-control sketch set the floor at k≥3 with a `3–4`/`k3to5` bottom band. In the real 2–3-box world every released cell sits at *exactly* k=3, so a `3–4` band conveys the EXACT count (3) for essentially every entry — "bucketed, never the raw N" becomes theater at bucket width 1–2, and a recipient with side knowledge re-identifies the third contributor. `feedK=5` raises the corroboration floor for the *broader, less-trusted external* consumer; presence-only carries zero count signal. `feedK` is a const for the same reason `aggregationK` is (optin.go:20–23): a caller who could lower it to 1 re-enables singling-out. **Consequence to accept:** with only 2–3 live boxes, `feedK=5` means the feed stays **honestly empty** until the network is broad — the demo narrative is "conservatively empty until k≥feedK corroborate," not "populated on the 3-box demo." |
| **D7b** 🔴 | **l-diversity / t-closeness vs higher-k.** The D6 residual (D6_NETWORK_DESIGN §0: k=3 over the 1024-cell joint space is homogeneity-weak to side knowledge) was deferred to "lands HERE." | **Do NOT build l-diversity/t-closeness — they are theater for THIS data shape. Build `feedK` + sparse-cell suppression + (optional) wide bands instead. Document l-diversity/t-closeness as assessed-not-meaningful, plus an explicit "no per-cell sub-distributions in the feed, ever" invariant.** | l-diversity protects against homogeneity of a *sensitive attribute* inside a quasi-identifier class. That table model does not exist here: the released record IS the coarse pattern (QI and payload are the same 7 fields), the "individuals" (contributing deployments) are already opaque salted `scopeBucket`s that never appear in a feed entry, and there is no separate sensitive column to diversify. Forcing one (e.g. PoisonClass) just re-derives k-anonymity on a sub-tuple — strictly weaker than raising k on the whole tuple. t-closeness is even less applicable (no per-class distribution to measure against). The honest residual is re-identification of a *contributing deployment*, which `feedK` + suppression attack head-on. The read-view sketch's vague "suppress a degenerate all-equal cell" predicate is **rejected** as undefined hand-waving that would give false assurance. **Claim "raised-and-bounded," never "closed."** |
| **D7c** 🟠 | **Transport: in-process HTTP read handler vs separate service.** | **In-process `feed.Handler() http.Handler`, mounted by the engine/control-plane on its own listener, mirroring `backend.Backend.Handler()` (mux + `writeJSON`/`writeErr`). NOT a separate daemon.** | A separate service needs either its own at-rest copy of the aggregated set (a SECOND moat replica with weaker access control — a rule-9 own-goal) or a new internal RPC back to the engine (a brand-new transport to review). In-process keeps the new attack surface to exactly ONE thing: the authenticated read endpoint over the same in-memory ledger. The upgrade path to a standalone service stays clean because the feed depends on a one-method `Source` interface. |
| **D7d** 🟠 | **TLS posture.** The access-control sketch *assumed* the feed sits behind "the same TLS front door as the dashboard." | **TLS is a HARD fail-closed precondition, enforced at startup — the feed REFUSES to serve if not behind TLS (operator-supplied cert in the feed listener, or a verified terminating front door). Do NOT inherit the dashboard's posture.** | Verified against the tree: there is **no** auth/TLS/`subtle`/`Bearer` precedent anywhere in `internal/`, `cmd/`, `adapters/` (grep is empty), and the dashboard backend (the cited read-view precedent) serves **plain HTTP, no auth** on localhost. A bearer-token feed over plaintext leaks every consumer's long-lived credential to any on-path observer on first use — a *valid-credential* bypass (worse than the bounded-disclosure bypass, because it grants budget too). The feed is the FIRST attacker-reachable inbound surface (transport.go), so it cannot reuse an internal-only front door. **Until TLS is confirmed, the feed must not expose a port.** |
| **D7e** 🟠 | **Auth model for the MVP.** | **Per-consumer opaque bearer tokens (≥256-bit CSPRNG, shown once at issuance), stored only as `sha256`, verified by hashing the presented token to a fixed 32-byte digest and `crypto/subtle.ConstantTimeCompare` against EACH stored digest with OR-accumulation (no early exit), resolving the matched `Consumer` by a constant-time scan — NEVER a `map[hash]Consumer` lookup. Default-deny: missing/empty/unknown ⇒ 401. NOT OAuth/OIDC/JWT/mTLS for MVP.** | A real secret, a real constant-time compare, a real default-deny allowlist is the honest minimum. The review tightened the compare: `subtle.ConstantTimeCompare` is constant-time only for equal-length inputs (it short-circuits on length) — comparing fixed-width sha256 digests makes the length-leak moot; and a `map[hash]Consumer` hit/miss after the compare reintroduces a timing oracle that undoes the constant-time work. OAuth/OIDC is the right long-term answer for a multi-tenant ISAC but is multi-week infra with zero rule-9 safety benefit for 1–2 design-partner consumers; flagged as the deferred upgrade path (clean seam = the `Authenticator`). |
| **D7f** 🟠 | **Rate-limit + anti-scrape, and where the limiter STATE lives.** | **Two per-consumer layers, both fail-closed: (1) a hand-rolled token bucket (refill QPS + burst) ⇒ 429 + `Retry-After`; (2) a hard MONTHLY QUERY BUDGET (the real anti-scrape control) ⇒ 429 once exhausted. Hand-rolled (no `golang.org/x/time/rate` — verified ABSENT from go.mod/go.sum). Limiter state is PER-CONSUMER-LOCKED (a `sync.Map` of `*consumerLimiter`, each with its own mutex), NOT one global mutex. Middleware order is PINNED: (i) cheap global/per-IP request ceiling to shed unauthenticated floods, THEN (ii) constant-time auth, THEN (iii) per-consumer bucket + budget.** | A token bucket alone lets a patient scraper at 1 req/sec pull the whole ≤1024-cell set forever and run the homogeneity attack; the monthly budget converts "scrape forever" into "N audited views/month" — it is the only control that bounds *total* disclosure, so it is MANDATORY, not deferred. The review found two more holes: (a) a single global mutex guarding all consumers' state lets one consumer's flood serialize everyone (cross-consumer DoS) and does per-request work under one lock; (b) leaving auth-vs-rate ordering unspecified means an unauthenticated flood either hits the expensive constant-time auth or is unbounded. |
| **D7g** 🔴 | **Monthly-budget restart semantics.** The budget is the anti-scrape control; an in-memory counter resets on restart. | **The budget MUST fail CLOSED on restart (match the ledger's posture, D6i: losing state only DENIES more). Either (a) persist it in bbolt — keyed by `consumerID + calendar-month`, NEVER co-located with the salt — OR (b) if MVP keeps it in-memory, treat a just-restarted/unknown counter as EXHAUSTED until loaded / cap per-process lifetime disclosure. Do NOT ship a fail-OPEN budget.** | The access-control sketch flagged in its own open questions that an in-memory budget "fails OPEN on restart." That is a self-acknowledged hole in the one control that bounds total disclosure: an attacker who induces or waits for a restart (crash, deploy, OOM, or a long scrape spanning a routine restart) resets their quota and resumes. This is the inverse of the ledger's deliberate fail-CLOSED-on-loss design. An anti-scrape control that resets on restart is not a control. If persistence is truly out of MVP, the founder must EXPLICITLY accept that the differential-membership residual (D7h) is correspondingly unbounded. |
| **D7h** 🔴 | **Differential-membership / scrape-over-time residual.** A consumer polling daily and diffing successive views learns the exact moment a cell crosses `feedK` (a new entry appears) — with a small known population that reveals WHICH deployment's confirmation pushed it over, plus a coarse incident-timing oracle. | **Accept-and-bound, not eliminate (full elimination needs DP noise = out of MVP). Bound it with: the MANDATORY monthly budget (D7g); `feedK=5` + presence-only/wide bands (D7a) so fewer single-deployment-attributable transitions exist; and serve the set at a coarse REFRESH CADENCE (recompute at most once per release window; byte-identical responses within a window) so intra-window polling yields no diff and only budgeted cross-window diffs carry signal. Document as an explicitly-accepted, budget-bounded residual.** | The access-control sketch named this but proposed day-granularity `GeneratedAt` as the fix — which does nothing, because the *membership transition itself* is the oracle, not the timestamp field. The read-view sketch only had a per-request rate bucket, which does not bound longitudinal diffing. This is a genuine rule-9-adjacent residual that the feed cannot fully close without differential privacy; it must be named, bounded, and signed, not hand-waved. |
| **D7i** 🟠 | **Token lifecycle / revocation.** Both sketches deferred issuance/rotation/revocation. | **MVP: load the hashed allowlist from config; support HOT-RELOAD (SIGHUP or file-watch) so a leaked token can be removed WITHOUT a restart (a restart would reset budgets, D7g); add an optional per-token `NotAfter` expiry. Full OAuth/OIDC issuance stays deferred. Revocation is REQUIRED-before-first-external-consumer, not nice-to-have.** | A static config allowlist with no revocation path means a leaked token (e.g. via the no-TLS hole, or consumer-side compromise) is valid forever, and removing it requires an operator edit + restart — which also resets the budget, a doubly-broken state. Hot-reload + expiry close this cheaply without the full issuance infra. |
| **D7j** | **Audit logging.** | **Append-only `(consumerID, path, decision, coarse timestamp)` per request, decision ∈ {allowed, 401-unauth, 429-rate, 429-budget}. NEVER log the served `FeedView`/entries (the product — a second weaker-protected at-rest copy of the moat) and NEVER log the bearer token or its hash.** | The audit log is for abuse detection (who is scraping, who is probing with 401s) and the trust story (per-consumer accountability), so it must capture WHO + WHICH-ENDPOINT + DECISION but not the payload or a credential. `consumerID` is a non-secret label, safe to log. |
| **D7k** | **Per-deployment Consume/Publish opt-in for the feed.** | **Likely a product/contractual question, not a rule-9 one — the ledger is already cross-scope-aggregated and anonymized. Recommend: the feed serves the full aggregated set by default for MVP; confirm whether a deployment may refuse to expose ITS contributions via the feed.** | The D6 `Consume` toggle (D6g) gates a deployment *consuming* inbound patterns into its own matcher; it does not govern the external feed. Worth confirming the feed is allowed to serve the full set, but it is not a rule-9 blocker because nothing un-anonymized is involved. |
| **D7l** | **Feed topology: per-deployment vs central aggregator.** | **Per-deployment for MVP (each box has its own ledger; the SIEM points at each box) — that is what the ledger supports today. A central aggregation tier is a much larger design, deferred.** | The moat framing is single-deployment (each box's ledger is empty until k≥3 cross-scope). Where a SIEM/ISAC points its client (each customer box vs a central set) shapes whether the feed is per-deployment or needs a central tier; confirm the MVP is per-deployment. |

**Residual accepted (carry forward, not a new defect):** even with `feedK` + suppression, the
differential-membership oracle (D7h) cannot be fully eliminated without DP noise; it is bounded by the
monthly budget and documented. The 1024-cell homogeneity residual is **raised-and-bounded** by `feedK`,
**not closed** — l-diversity/t-closeness are honestly assessed as not meaningful for this data shape (D7b).

---

## 1. The D7 pieces and their dependency order

1. **D7-1 the exported ledger read** (§2) — `network/aggregate.go`: `PrevalenceBand` (only if D7a keeps a band), `Aggregated(minScopes int) []AggregatedPattern`, the bucketing/thresholding/suppression INSIDE package `network`. **In-repo testable now** (seed a ledger to k≥feedK).
2. **D7-2 the read view** (§3) — `internal/intelligence/feed/{feed.go}`: `Source` interface, `FeedEntry`, `FeedView`, pure `BuildFeed`. **In-repo testable now.**
3. **D7-3 the handler + access-control + rate-limit** (§4) — `feed/handler.go`: auth, per-consumer limiter + budget, TLS precondition, audit. **In-repo testable now** (httptest); the new attack surface.
4. **Live-populated feed** (§7 demo) — **needs the 3rd box** to drive cells to k≥feedK across distinct scopes; everything else is unit-testable against a seeded ledger now.

---

## 2. D7-1 — The exported ledger read (`internal/intelligence/network/aggregate.go`)

The bucketing, thresholding, and suppression live **on the Ledger, inside package `network`** — beside the
unexported `distinctScopes` and `coarseKey` (ledger.go:122–132). This is the rule-9-load-bearing seam: the
one sensitive scalar (the exact distinct-scope count) is coarsened (or dropped) *at the trust boundary*, so
the `feed` package is, by Go visibility, **structurally incapable** of receiving a raw N or a `scopeBucket`.
This mirrors exactly why `distinctScopes` is unexported ("only the chokepoint may consult it, so the count's
provenance stays inside the package").

```go
// internal/intelligence/network/aggregate.go (NEW)
package network

// feedK is the FEED's own k threshold: the external feed is a broader, less-trusted
// consumer than the internal cross-deployment matcher, so it requires MORE corroborating
// scopes than aggregationK. A package CONST, never request-supplied (a caller-supplied k
// could invert the gate — the same reason aggregationK is a const, optin.go:20-23). The
// compile-time floor guarantees the feed can never be LESS anonymous than the internal gate.
const feedK = 5 // >= aggregationK (=3); raise, never lower. (D7a — founder-pinned)

// AggregatedPattern is ONE k-anonymous, cross-scope-confirmed cell, ready for a read view.
// It mirrors profile.ExportForm / network.SharedPattern FIELD-FOR-FIELD (the 7 already-cleared
// coarse fields — note CadenceBand, the D6a-signed 7th field) and adds NOTHING that can hold a
// pointer/slice/map/float/raw-count/hash/scope-id. A structural-guard reflect test pins this
// (mirrors TestCoarseKeyHasNoHashOrIdentity, ledger_test.go:119).
type AggregatedPattern struct {
    ReachedContain  bool
    EngagedVelocity bool
    EngagedPoison   bool
    DisengagedEarly bool
    HeldBand        int    // 0..3 band
    CadenceBand     int    // 0..3 band
    PoisonClass     string // closed enum
    // Prevalence is OPTIONAL per D7a. If presence-only is signed, this field does NOT exist.
    // If a band is signed, it is a closed enum (PrevalenceBand), NEVER an int N.
    // Prevalence PrevalenceBand
}

// Aggregated enumerates every ledger cell seen in >= max(minScopes, feedK) distinct scopes
// as an anonymized aggregated pattern. minScopes is FLOORED at feedK (a caller cannot ask for
// sub-feedK cells — fail-closed). Read-only: RLock, mutates nothing, allocates a fresh slice
// (no aliasing into seen). Cells below feedK are SUPPRESSED (absent — the homogeneity-weak
// sparse cells are exactly these). NEVER returns the raw distinct-scope count or a scopeBucket.
func (l *Ledger) Aggregated(minScopes int) []AggregatedPattern {
    if l == nil { return nil }
    if minScopes < feedK { minScopes = feedK } // floor; never below the internal gate
    l.mu.RLock(); defer l.mu.RUnlock()
    var out []AggregatedPattern
    for key, set := range l.seen {
        if len(set) < minScopes { continue } // sparse-cell suppression, fail-closed
        out = append(out, AggregatedPattern{
            ReachedContain:  key.ReachedContain,
            EngagedVelocity: key.EngagedVelocity,
            EngagedPoison:   key.EngagedPoison,
            DisengagedEarly: key.DisengagedEarly,
            HeldBand:        key.HeldBand,
            CadenceBand:     key.CadenceBand,
            PoisonClass:     key.PoisonClass,
            // Prevalence: bandOf(len(set)), // ONLY if D7a keeps a band; computed HERE,
            //                                  behind the boundary, from the raw count.
        })
    }
    return out
}
```

**Prevalence (only if D7a signs a band, not presence-only):** a closed `PrevalenceBand` enum, `String()`-ed
into the feed entry — never an int. The lowest emitted band is wide (e.g. `5-19`, `20+`), never `3-4`. The
enum value below `feedK` (`PrevalenceNone`) is **structurally never emitted** (a test asserts this), and a
test asserts no band has width below a minimum. Because the band is the ONE new derived scalar that did NOT
transit `clearFields`, its safety rests on (i) computation inside package `network` behind the unexported
count, (ii) being a closed enum type (not an int), and (iii) the conservative width / or omission — which is
exactly why D7a is rule-9-critical, not cosmetic.

**Structural-guard test (mirror `TestCoarseKeyHasNoHashOrIdentity`):** assert `AggregatedPattern` has no
field whose lowercased name contains `hash/scope/flow/cookie/ip/identity/seq/order/digest/count/raw/n/cardinality`,
and no `float`/`slice`/`map`/`pointer` field — so an exact N can never structurally appear.

---

## 3. D7-2 — The read view (`internal/intelligence/feed/feed.go`)

A pure value projection — mirrors the dashboard's `views.Derive*` → `writeJSON` discipline (backend.go).
It performs **NO** egress (no `Clear`, no `Marshal`, no `*Cleared`), touches **NO** raw data, holds **NO**
`Ledger` reference, and imports `network` for exactly ONE value type plus ONE interface method.

```go
// internal/intelligence/feed/feed.go (NEW)
package feed

import (
    "time"
    "github.com/canarysting/canarysting/internal/intelligence/network"
)

// Source is the narrow read-only seam the feed consumes — satisfied by *network.Ledger.
// Declared as an interface so feed takes NO engine/scope/boltevents/baseline/profile dep
// (it CANNOT reach raw data even by mistake) and is trivially testable with a fake.
type Source interface {
    Aggregated(minScopes int) []network.AggregatedPattern
}

// FeedEntry is one row: a coarse adversary pattern (the 7 already-cleared fields). It is a
// pure value copy of a network.AggregatedPattern — the feed adds NO field the ledger did
// not already vet. NO raw count, scope id, scope bucket, hash, or timestamp-of-observation.
type FeedEntry struct {
    ReachedContain  bool   `json:"reachedContain"`
    EngagedVelocity bool   `json:"engagedVelocity"`
    EngagedPoison   bool   `json:"engagedPoison"`
    DisengagedEarly bool   `json:"disengagedEarly"`
    HeldBand        int    `json:"heldBand"`
    CadenceBand     int    `json:"cadenceBand"`
    PoisonClass     string `json:"poisonClass"`
    // Prevalence string `json:"prevalence,omitempty"` // band.String() ONLY if D7a keeps a band; never an int
}

// FeedView is the materialized read view: entries + a coarse build stamp + the advertised
// anonymity floor. Pure value; no Ledger reference, no events, no scope state.
type FeedView struct {
    Entries     []FeedEntry `json:"entries"`
    Count       int         `json:"count"`        // number of patterns (coarse, non-identifying)
    FeedK       int         `json:"feedK"`        // advertised anonymity floor (transparency/trust)
    GeneratedAt string      `json:"generatedAt"`  // RFC3339; quantized to the refresh window (D7h), NOT an observation time
}

// BuildFeed is the pure read-view builder (mirrors views.DeriveReconTimeline). It snapshots
// the aggregated cells at the floor and projects each to a FeedEntry. NO egress, NO raw data,
// the ONLY place feed reads the source. Deterministic given src + now.
func BuildFeed(src Source, now time.Time) FeedView
```

**Single-deployment reality = empty feed, and that is correct.** With one box every cell is k=1, so
`Aggregated(feedK)` returns `nil` and `BuildFeed` yields `FeedView{Entries: nil, Count: 0}`. Fail-closed and
honest; it populates live when ≥feedK distinct scopes corroborate a cell. Testable now via the
`ledger_test.go` `{a,b,c,...}` recipe (`RecordForm` the same export under distinct scope strings drives a cell
toward k≥feedK).

---

## 4. D7-3 — Access control + rate limiting (`internal/intelligence/feed/handler.go`)

The genuinely new attack surface — the FIRST attacker-reachable inbound code in the intelligence layer
(transport.go's comment assigns access-control + rate-limiting here). In-process `Handler() http.Handler`
mounted by the control-plane (D7c), reusing the dashboard's `writeJSON`/`writeErr` shape (backend.go:320–330).

**Pinned middleware order (D7f):**
1. **Cheap global/per-IP request ceiling** — sheds unauthenticated floods BEFORE the expensive constant-time auth or the per-consumer maps are reached.
2. **Constant-time auth (D7e)** — hash the presented bearer to a fixed 32-byte digest; `subtle.ConstantTimeCompare` against EACH stored digest with OR-accumulation (no early exit); resolve the matched `Consumer` by a constant-time scan, NEVER a `map[hash]Consumer` lookup. Missing/empty/unknown ⇒ 401, fail closed.
3. **Per-consumer rate bucket + monthly budget (D7f/D7g)** — per-consumer-locked state (a `sync.Map` of `*consumerLimiter`), so one consumer's flood cannot serialize another's; over-rate ⇒ 429 + `Retry-After`; over-budget ⇒ 429. Budget fails CLOSED on restart (D7g).

**TLS (D7d):** the handler refuses to serve unless behind TLS (startup precondition). No plaintext bearer.

**Routes:** `GET /feed/v1/patterns` ⇒ `writeJSON(BuildFeed(src, now))`; `GET /feed/v1/healthz`. Read-only;
no query/filter surface in MVP (a whole-set read, identical for every authorized consumer — a queryable feed
is deferred and needs its own DP review + per-query budget). The view is recomputed at most once per refresh
window so intra-window polls are byte-identical (D7h).

**Threat model (the new surface):**
- **Unauthenticated reader** ⇒ 401 default-deny; never serves a byte before auth passes.
- **Token enumeration via timing** ⇒ fixed-width digest + full-scan constant-time compare + no map-hit oracle (D7e). Test: auth latency independent of token validity, allowlist position, and token length.
- **Scrape-the-whole-set to defeat k-anonymity** ⇒ set is already k≥feedK + suppressed (+ banded/presence-only); per-consumer monthly budget bounds total disclosure; differential-membership bounded per D7h.
- **Cross-consumer DoS** ⇒ per-consumer-locked limiter state; pre-auth flood ceiling. Test: a flood on consumer A does not raise consumer B's p99; an unauthenticated flood is bounded before the auth compare.
- **Credential leakage** ⇒ TLS mandatory (D7d); config stores only token hashes; audit logs neither payload nor token (D7j); hot-reload revocation + expiry (D7i).

---

## 5. Rule-9 — "never a second egress" guarantees

The guarantee is delivered **by construction**, not by re-running `Clear`. Each fact is verifiable against the live code at HEAD:

1. **Every byte the feed serves already passed `clearFields`/aggregation.** The feed's sole input is `Ledger.Aggregated`. The ledger's `seen` map is populated ONLY by `RecordForm`, whose first action is `coarseKeyFromExport → clearFields` (ledger.go:88–108) — a cell exists ONLY if its coarse form already passed the same field-walk `Clear`/`ClearWithLedger` run (an unclearable export records nothing; `TestRecordFormRejectsUnclearable`). So the 7 coarse fields in an `AggregatedPattern` ARE, field-for-field, the already-cleared `SharedPattern` shape (shared.go:17–25). The feed re-derives nothing and coarsens nothing — it reads a value that was coarse before it entered the ledger.
2. **The feed adds exactly ONE new derived scalar, and it is k-anonymity-safe (and may be omitted).** The only thing beyond the cleared tuple is the prevalence band (D7a) — a bucketed coarsening of `len(set)`, computed INSIDE package `network` behind the unexported count. `distinctScopes` stays unexported; `scopeBucket`s (the HMAC scope identities) never leave the Ledger. **Honest statement:** rule 9 here is "everything passed Clear EXCEPT one new derived scalar whose safety rests on the band being conservative / omitted" — which is precisely why D7a (band width) is rule-9-critical. Presence-only (the recommendation) removes even this one scalar.
3. **The feed touches no raw events/profiles/baselines/scope-state — structurally.** `feed` imports `network` for one value type and consumes one interface method (`Source.Aggregated`). It does NOT import `boltevents`, `engine`, `baseline`, `profile`, `contract`, or `intelligence` (events). It has no `EventSource`, no `ScopeKey`, no `Ledger.seen` access. A `FeedEntry`'s fields are all coarse scalars. **An import-discipline test pins this** (assert `feed`'s import set excludes the raw-data packages) — the review confirmed the no-second-egress confinement is real IF this discipline is enforced by a test.
4. **The feed is not an egress constructor.** It never calls `Clear`/`ClearWithLedger` and never produces or `Marshal`s a `*network.Cleared`. `Cleared` has unexported fields and `Clear`/`ClearWithLedger` are its only constructors, and `Marshal` additionally requires `ledgerVerified=true` (filter.go:32–40, 250–252) — `feed` cannot even build one. Egress (the A→B crossing) already happened upstream at `ClearWithLedger → transport`; the ledger cell is downstream of that. The feed is a **consumer** surface over post-Clear data, never a parallel `Clear` path.

**The disclosure bound (why D7 is the safe cut line):** even a total auth bypass leaks only coarse, k≥feedK,
suppressed, banded-or-presence-only patterns — no customer traffic, baseline, scope identity, raw count, or
AX4/AX5 (structurally absent from the coarse tuple AND name-denylisted upstream). A bypass that yields a valid
*credential* (D7d/D7i) additionally hands over budget, but still not raw data.

---

## 6. Rule guarantees (the contract D7 must keep)

- **Rule 9:** delivered by §5 (1–4). The feed is a downstream consumer of already-`Clear()`-ed coarse cells, never a second egress chokepoint. The single new scalar is bucketed/omitted behind the package boundary; the single new surface is a READ endpoint over post-Clear data.
- **Rule 5:** the feed serves an aggregated COUNT-derived presence (or wide band), never scope state, never a scope identity (`scopeBucket`s never leave the ledger). It reads the protective cross-scope aggregate, never per-scope learned state.
- **Rule 8:** N/A by construction — the feed is outbound-read-only; it has no path to a verdict/tier/attrition/touch-count and cannot be an inbound trigger.
- **Rule 1:** the feed takes no dependency on `engine`/`baseline`/`profile`; it depends only on the `network` value type + the `Source` interface (import-discipline test).

---

## 7. Build sequence

Design → implement → adversarial review → PR; founder merges. "Needs 3rd box" = a LIVE-populated feed only;
all code + a seeded-ledger test are in-repo unit-testable now.

1. **D7-1 ledger read** `network/aggregate.go` (**in-repo now**): `feedK` const (≥`aggregationK`, floored), `AggregatedPattern` (7 coarse fields mirroring `SharedPattern`; band field ONLY if D7a keeps one), `Aggregated(minScopes)` with the floor + sparse-cell suppression + (optional) inside-package bucketing. Tests: seed to k≥feedK via the `{a,b,c,d,e}` `RecordForm` recipe → entry appears; k<feedK → empty (fail-closed); structural-guard reflect test (no count/hash/identity/float/slice/map/pointer field); if a band exists, assert min band width and that `PrevalenceNone` is never emitted.
2. **D7-2 read view** `feed/feed.go` (**in-repo now**): `Source` interface, `FeedEntry`, `FeedView`, pure `BuildFeed`. Tests: empty feed on a single-deployment ledger; populated feed on a k≥feedK-seeded fake `Source`; structural-guard test that `FeedEntry` holds only coarse scalars and no integer prevalence/count; import-discipline test (no `boltevents`/`engine`/`baseline`/`profile`/`contract`/`intelligence` import).
3. **D7-3 handler + access-control + rate-limit** `feed/handler.go` (**in-repo now**, httptest): pinned middleware order (pre-auth ceiling → constant-time auth → per-consumer bucket + budget); TLS startup precondition; hashed-allowlist auth with fixed-width-digest constant-time compare + no map oracle; per-consumer-locked limiter; fail-closed monthly budget; audit log; hot-reload revocation + optional expiry. Tests: missing/bad key ⇒ 401; rate exceeded ⇒ 429 + `Retry-After`; budget exhausted ⇒ 429; valid key ⇒ 200 + JSON `FeedView`; never serves a raw count; auth latency independent of validity/position/length; flood on A does not raise B's p99; unauthenticated flood bounded before auth; refuse-to-serve without TLS; budget fails closed across a simulated restart.
4. **Adversarial review pass** against this doc + the live code; re-run the rule-9 checklist (no raw count/hash/scope on the wire; import discipline holds; `feed` cannot construct a `*Cleared`; band width / presence-only matches the D7a signoff; budget fails closed; TLS enforced). Then PR.
5. **Live-populated feed on ≥feedK calibrated boxes** (**needs the 3rd box, with Daniel**): drive `RecordForm` from each of ≥feedK standing scopes' real confirmations; DEMO the feed serving the cross-confirmed cell to an authenticated consumer, and a sub-feedK pattern staying ABSENT. Do NOT lower `feedK`.

**Deferred (tracked, NOT in D7 MVP):** OAuth/OIDC + mTLS (the upgrade path; clean seam = `Authenticator`);
true l-diversity/t-closeness (assessed not-meaningful for this data shape, D7b — only relevant if a future
entry ever carried a sub-distribution, which the "no sub-distributions ever" invariant forbids); a
queryable/incremental feed (needs DP accounting + per-query budget); a central-aggregator topology (D7l);
bbolt budget persistence if MVP ships in-memory-fail-closed (D7g).

---

## 8. The demo framing (honest, not over-claimed)

D7 is the **safe cut line**: it adds no new moat DATA, only a consumer surface, so if D6 overruns D7 can be
cut entirely with zero loss to the moat. The honest demo beats:

1. **The product-line proof.** A SIEM/ISAC consumer authenticates (bearer over TLS) and `GET /feed/v1/patterns` returns the cross-confirmed coarse patterns — the SECOND product line, live.
2. **The privacy proof, shown literally.** `cat` a feed response on screen: only coarse bands/bools/one-enum (+ presence/wide-band), each corroborated by ≥feedK independent deployments. Point at what is ABSENT — no IP, hostname, decoy names, raw timing, hash, raw count, scope identity, exploit/exposure axes.
3. **The conservative-by-default beat.** On a 2–3-box network, `feedK=5` means the feed is **honestly empty** — "we only publish a pattern once ≥feedK customers independently corroborate it; until then we say nothing." A block-averse CISO trusts conservative-and-empty over a feed that leaks on the first sighting.
4. **The bounded-blast-radius beat.** Narrate the disclosure bound: even a total auth bypass exposes only coarse k≥feedK suppressed patterns — never a customer's traffic, baseline, or identity. That bound IS why D7 is the safe cut line.