# AX5 / F4 — Operational-Exposure Axis & the In-Perimeter Harmlessness Predicate

**Status:** ✅ FOUNDER-APPROVED 2026-06-11. §0 signed off: **AX5 ships PASSIVE-ONLY** (operational-
exposure fingerprint captured from the attacker's inbound request shape → `Outcome.ExposureSignals`,
reusing the AX4 digest path; **no live sink, no reach-back**). The **live in-perimeter sink** and the
**F4 `insink` predicate package** are **DEFERRED** behind a separate future review — the F4 predicate
SHAPE in §3 is approved now as that gate's design, not built yet. This document **is** the
register-**F4** (`docs/ATTRITION_FIVE_AXIS_DESIGN.md` §15) separately-reviewed in-perimeter
harmlessness predicate, satisfying the **"Founder review BEFORE any AX5 code"** gate. The
reach-back review verdict was no-hack-back SOUND / sink-safety SOUND / rule-9 CLEAN (minor only).

**Authoritative basis:** `docs/ATTRITION_FIVE_AXIS_DESIGN.md` §7 (Axis-5 CORE-RULE CORRECTION),
§14 (no-hack-back / rule-9, esp. §14.3 the four F4 conjuncts), §15 register F4/F2; `docs/STING.md`
(the no-hack-back hard line, line 177; "what the sting layer must never do"); `CLAUDE.md` rules
1 / 5 / 8 / 9 and the safety/posture rules.

**The hard line, restated up front (`docs/STING.md`):** *"Reach back into the attacker's own
systems. Attrition imposes cost on traffic inside your perimeter that is touching things it never
should — it is not outbound retaliation / hack-back."* AX5 is **PASSIVE intelligence capture
only**: the defender NEVER initiates an outbound connection toward attacker infrastructure, never
fires a probe/exploit back, never beacons, never dials a sink. AX5 only **OBSERVES** connections
the attacker's OWN tooling makes INTO assets already inside the defender's perimeter.

---

## 0. Decisions needing founder signoff

| # | Decision | Recommendation |
|---|----------|----------------|
| **D-AX5-1** | **Is the AX5 MVP passive-digest-only (no live sink)?** Operational exposure (tool/C2 fingerprint) captured from the SHAPE of the attacker's own inbound requests to our in-perimeter decoys, surfaced as `Outcome.ExposureSignals int64` — the exact `DriverObservation` digest path the AX0 spine reserved. | **YES. Ship passive-only.** It carries zero routable-sink hazard, needs no new harmlessness basis (its served bait stays RFC-reserved + `CrossScan`-clean like every other axis), and delivers the tool/C2 fingerprint from connections the attacker already makes. This is the maximally-conservative reading of the §7/§14 correction. |
| **D-AX5-2** | **Is the live in-perimeter capture SINK deferred (built later, if at all) behind F4?** | **YES. Defer indefinitely.** Design + land F4 now as a **dormant, disabled-by-default gate** (empty approved-sink set ⇒ live sink OFF). Do not schedule sink/listener infrastructure until a concrete intelligence gap passive cannot fill is shown AND a separate founder review of F4 + the sink design completes. Design §7 rates the live sink **XL / riskiest**. |
| **D-AX5-3** | **Is F4 a NEW predicate, distinct from `harmless.CrossScan`, that does NOT reuse the reserved-host rule?** | **YES.** A routable in-perimeter sink CANNOT pass `AllHostsReserved` by construction. F4 governs an orthogonal invariant (defender-owned-in-perimeter-not-attacker-reachable). Folding it into `CrossScan`/`AllHostsReserved` would **weaken the universal reserved-host invariant for the canary catalog and all five axes** — forbidden. F4 lives in a new stdlib-only sibling package; the other four axes keep `CrossScan` unchanged. |
| **D-AX5-4** | **Does landing F4 NOW (dormant, disabled) itself need founder signoff, or only the eventual live sink?** | **F4 needs founder signoff now** (register: "Founder review BEFORE any AX5 code"). Sign off the F4 **predicate shape** + the passive-MVP scope before any AX5 code. The eventual live-sink **implementation** gets its OWN second review (D-AX5-2). |
| **D-AX5-5** | **F4 predicate package location/name** — a new `internal/harmless/insink` sibling vs. a sub-API inside `internal/sting/attrition`. Must NOT be a `CrossScan` extension. | New stdlib-only sibling **`internal/harmless/insink`**, beside the single-source-of-truth safety package, reviewable as a discrete safety deliverable, keeping `attrition`'s import set clean. Confirm the exact name at review. |
| **D-AX5-6** | **How does the operator ATTEST defender-ownership + in-perimeter membership of a (deferred) live sink?** | Require BOTH a config allowlist of `host_or_cidr` + `owner_label` AND a structural non-public check (private / loopback / link-local / ULA, or operator-declared private CIDR), with hostname entries pinned at validate-time. Defer any stronger cryptographic attestation to the live-sink review; do not gold-plate before the sink is scheduled. |
| **D-AX5-7** | **Cross-boundary export of `ExposureSignals`?** | **Out of MVP scope.** `ExposureSignals` stays **deployment-local-only**. The built egress filter already hard-blocks it (see §6). Defer band/enum coarsening + k-anonymity to the egress-export work; the MVP adds only the §2.5 deployment-local-only guard test. |

---

## 1. Premise correction (load-bearing for whoever builds this)

> **UPDATE 2026-06-11 (post-design):** this section was written against `main` BEFORE AX4 merged.
> **AX4 has since shipped (PR #9, on `main`).** So the digest path DOES now exist: `Stream.Observe`
> accumulates `ExploitsObserved` from `DriverObservation.SuspectedExploit`, `digestObservation` is in
> `adapters/envoy/pump.go`, and `ExploitBaitService` / `MechExploitBait` exist. AX5-passive therefore
> **REUSES** the AX4 digest pattern (adding a `ToolingExposed` bool + an `op_exposure` generator +
> `MechOpExposure`/`AxisOpExposure` + `decoy.OpsSurface`), it does NOT establish it. The original
> "first consumer" framing below is retained for the historical record; read it as superseded.

**(Original, against pre-AX4 `main`:) AX4 has NOT shipped.** Do not assume an `ExploitsObserved` digest path exists to copy. Verified
against the code:

- `Stream.Observe` is a literal **no-op**: `func (s *stream) Observe(contract.DriverObservation) {}`
  (`internal/sting/attrition/attrition.go:346`; the interface method is at `attrition.go:63-66`).
  It is called **NOWHERE** in production (adapter/cmd grep empty).
- There is **no** `MechExploitBait` / `MechOpExposure`. `cost.go:42-46` defines only
  `MechNoOp / MechTarpit / MechFakeTree / MechTokenBait / MechPoison`.
- There is **no** exploit/op-exposure generator. `generators.go` has only `tarpit` (AX1 velocity,
  `minTier=TierContain`), `fakeMaze` (poison|oppcost), `poisonField` (AX2 poison, `MechPoison`),
  and `tokenBait` (oppcost, `minTier=TierJail`).
- There is **no** `ExploitBaitService` in `internal/harmless/decoy` — `decoy.go` is seed-driven
  body builders only (`ExampleAWSKeyID`, `ExampleAWSSecret`, `ReservedHost`).
- There is **no** `digestObservation` in the adapter. `adapters/envoy/pump.go` does only the
  disengage classification.

Shipped past the AX0 spine: **AX1** (`adaptiveDelay`/tarpit) and **AX2** (`poisonField`). The carrier
fields (`StingOutcome.ExploitsObserved`/`ExposureSignals` at `contract.go:180-181`; `Outcome.*` at
`cost.go:101-102`) exist **zero-valued**, and `DriverObservation` (`contract.go:193-197`) exists as a
defined-but-unused seam. **AX5-passive would be the FIRST real consumer of the `Observe` seam and
ESTABLISHES the digest pattern** that AX4 later reuses — it does not inherit it. An implementer who
assumes a shipped AX4 precedent will wire against non-existent code.

---

## 2. AX5 MVP scope — PASSIVE in-perimeter digest capture (no live sink)

### 2.1 What ships (MVP, lowest-risk, delivers the axis)

An op-exposure generator (`MechOpExposure`, `AxisOpExposure`) constructed **only at
`FloorAggressive`**. `contract.go:114-117` already maps `FloorAggressive ⇒ … | AxisOpExposure`, and
`attrition.New` (`attrition.go:142-152`) constructs only generators whose `axis()` overlaps
`Floor.Axes()`, so op-exposure can never be a silent default. Its `minTier()` **MUST be `TierJail`**
(copy `tokenBait` at `generators.go:296`, NOT `fakeMaze`'s `TierContain`) so `selectAxes`
(`attrition.go:235-243`) never admits it at Tier 2.

- **Served bait is `CrossScan`-clean.** The generator's emitted bytes embed only RFC-reserved,
  non-routable locators (built via `internal/harmless/decoy` `ReservedHost` / `ExampleAWSKeyID`,
  `decoy.go:62-74`) and pass `harmless.CrossScan` at construction via the existing `genSelfTest`
  discipline (`generators.go:455` calls `harmless.CrossScan(data)` on every sample). **Identical to
  every other axis. No F4 needed for the MVP bait.**
- **Operational exposure is captured PASSIVELY.** The Envoy adapter digests the SHAPE of the
  attacker's own inbound requests to our in-perimeter decoys into a `contract.DriverObservation`
  (counts/bools/enums only) and feeds it through the existing `Stream.Observe` seam
  (`attrition.go:66` interface, `:346` no-op body today). The stream folds the digest into
  `Outcome.ExposureSignals int64` (`cost.go:102`; mirrored on `contract.StingOutcome.ExposureSignals`,
  `contract.go:181`).
- **The defender NEVER originates a connection.** The only new data path is INBOUND.
- **Deployment-local-only.** `ExposureSignals` is persisted via `boltevents.AmendOutcome` (rule 5,
  scope-isolated) and is structurally blocked from crossing a boundary by the now-BUILT egress
  filter (see §6).

### 2.2 Why passive delivers the axis

The `docs/STING.md` Axis-5 spec is *force-infrastructure-to-reveal-itself / fingerprint-the-tooling /
capture-C2-patterns*. The attacker's tooling **already** connects into our in-perimeter decoys —
that connection is the canary touch that drove the flow to Tier-3 in the first place. From requests
the attacker already sends, the adapter derives the tool/C2 fingerprint as counts/bools/enums:

- **user-agent FAMILY** as a small closed enum (a known-tool-family bucket) — never the raw UA string;
- **header-set cardinality** (a count) and a **header-order / casing bucket** as a bounded enum/hash-
  bucket (order + casing fingerprint a client library) — never the raw header list;
- **method** as a closed enum;
- a **suspected-exploit** structural-marker bool (already on `DriverObservation`);
- **cadence** (inter-request timing) as a **coarse band** computed adapter-side across the flow —
  never a raw interval (and capped to the egress band span if it ever crosses; §6).

All derived scalars. **None** may be a raw header / UA / address / path (rule 9 + the
`DriverObservation` reflection guard). This is the tool/C2 fingerprint at **zero routable-sink
hazard**.

### 2.3 Why the live sink is deferred behind F4

A live capture sink must be **ROUTABLE** to receive the attacker tooling's inbound connection. That
**directly contradicts** `harmless.AllHostsReserved` (`harmless.go:220-231`, which rejects any
served-payload host that is not RFC-2606/5737/3849 reserved — verified: it iterates URLs and returns
`"payload references a routable host"` for any non-reserved host). So live-sink bait would **FAIL
`CrossScan` by construction**. The live sink is the only mechanism that needs a brand-new safety
basis (F4), new listener/sink infrastructure, a hardened inbound service (a DoS/abuse surface), and
the egress dependency — design §7 rates it XL/riskiest, and it is the only part that could be
*misread* as hack-back if mis-built. Its marginal value over passive: it only elicits a connection
from tooling that would not otherwise touch our decoys. **Verdict: ship passive now; build the live
sink later, if at all, ONLY after F4 founder review.**

### 2.4 Gating (inherited unchanged from the AX0 spine)

- `minTier=TierJail` + `FloorAggressive` only (op-exposure generator constructed only at the
  aggressive floor; FloorPassive is the zero value and unlocks `AxisVelocity` only —
  `attrition.go:142-152`, `contract.go:114-122`).
- Reached **only** via `attrition.Open`, which is a no-op below `TierContain` and on
  `SocketCookie == 0` (`attrition.go:181-187`) — i.e. off a canary-touch-derived verdict, NEVER off
  baseline deviation / novelty / recon (rule 8).
- Tier-3 stays **fail-closed**: an engine outage must not release a confirmed-malicious flow
  (`config: fail_closed.tier3: true`).
- Defender-cost bounded by the shared `Governor` + kill switch, O(1)/chunk — the path consumes only
  the digest, never buffers attacker traffic (design §14.6).

---

## 3. F4 — the in-perimeter harmlessness predicate (the gate the DEFERRED live sink must pass)

F4 is a **NEW, separately-founder-reviewed** predicate, **distinct from `harmless.CrossScan`**, that
the deferred live-sink mechanism must pass before any AX5 bait may embed a routable in-perimeter
sink locator. The other four axes keep using `CrossScan` unchanged; F4 is additive and
AX5-live-sink-specific. **F4 does not block the passive MVP** (passive bait stays `CrossScan`-clean).

### 3.1 Why `CrossScan` / `AllHostsReserved` CANNOT serve (confirmed in code)

`harmless.AllHostsReserved` (`harmless.go:220-231`) parses every URL in the **SERVED PAYLOAD** and
returns an `Error` unless `IsReservedHostOrIP()` (`harmless.go:138-143`) is true for each host
(RFC-2606 `.example`/`.invalid`/`.test`/`.localhost`, RFC-5737 TEST-NET, RFC-3849 `2001:db8::/32`).
`CrossScan` (`harmless.go:239-251`) ends by calling `AllHostsReserved`. It is purely a served-bytes
scan and governs **nothing outbound**. A live in-perimeter sink is by definition **routable**, so its
locator is NOT a reserved host and `AllHostsReserved` would **REJECT** the bait.

Two different predicates, two different invariants:
- **`CrossScan`:** *"the served payload points at no routable asset"* (universal, all five axes + the
  canary catalog depend on it).
- **F4:** *"the one embedded live-sink locator points at a defender-owned in-perimeter sink the
  attacker cannot reach back through"* (orthogonal, AX5-live-sink only).

F4 **cannot** be a tweak to `CrossScan`. Folding the routable-host admission into `AllHostsReserved`
would silently weaken the universal reserved-host invariant for every generator and the canary
catalog (see Risk R-3).

### 3.2 The F4 property — four conjuncts, ALL required, conservative / deny-by-default

A host `H` embedded in AX5 bait that points at a LIVE capture sink is admissible only if F4 proves
ALL of (design §14.3):

- **(a) IN-PERIMETER + structurally NON-PUBLIC.** `H` is a member of the operator-declared
  approved-sink set AND `net.ParseIP(H)` is a private / loopback / link-local / ULA address, or
  falls inside an operator-declared private CIDR. **Any global-unicast / publicly-routable address
  is REJECTED even if listed** (defense-in-depth against a misconfigured allowlist). Crucially, `H`
  is NOT reserved — it must be routable INSIDE the perimeter to receive the connection — which is
  exactly why `AllHostsReserved` cannot serve.
- **(b) DEFENDER-OWNED.** `H` is in the operator's EXPLICITLY-declared owned-sink set, never
  inferred, never derived from traffic.
- **(c) NOT-ATTACKER-REACHABLE / NOT-THE-ATTACKER'S-SYSTEM.** `H` is NEVER derived from the
  attacker's flow. F4 REFUSES any host that originated in an attacker-supplied Host / SNI / header /
  path — the smuggling vector that would turn a sink into an attacker-controlled relay (i.e. make us
  beacon to attacker infra by proxy). Only the static operator-declared set is admissible.
- **(d) NO THIRD-PARTY BEACON.** The sink only ever RECEIVES inbound; the defender never initiates
  outbound toward `H`. Enforced **structurally** by the import-graph guarantee (§5), not by the
  predicate alone.

**Hostname-rebind hardening (correction folded in).** `ApprovedInPerimeterSink` prefers IP literals.
A host that does NOT parse as an IP literal is admitted ONLY IF the operator-declared in-perimeter
hostname resolves **at validate-time** to a private / loopback / link-local / ULA / declared-CIDR
address AND that resolution is **pinned** (not re-resolved per bait), to close DNS-rebinding /
late-rebind of an allowlisted hostname to a public/attacker address. Any unresolvable or
publicly-resolving hostname is **DENY**. This makes (a)+(b) airtight against a hostname-allowlist
rebind.

Like `IsInertPrivateKey` / `IsExampleAWSKeyID`, F4 is **conservative**: anything it cannot
affirmatively prove approved + owned + in-perimeter + non-public it treats as **NOT approved (deny)**.
It returns a typed `*harmless.Error`-style reason.

### 3.3 Enforcement — construction-time, fail-closed, refuse-to-start

Mirroring the existing repo discipline (`attrition.New` proving generators harmless at construction;
`cmd/envoy-adapter/main.go:103-105` empty-`-scope` ⇒ `log.Fatal`; the bad-floor `log.Fatalf` at
`main.go:154-156`; `boot.go` refuse-to-start on schema mismatch):

1. **Construction-bound.** The approved-sink set is bound into the `Attritor` at construction (like
   `Floor`/`Budget` on `attrition.Config`, `attrition.go:88-106`) — NEVER passed per-call, so a live
   sink can never be a per-call surprise (matches the aggressive-is-never-a-silent-default structural
   guard).
2. **Empty ⇒ DISABLED.** An empty/missing approved-sink set ⇒ the live sink is **DISABLED** (AX5
   falls back to passive `ExposureSignals` capture, or no-op) — **NEVER an implicit any-host sink.**
   This mirrors `sting_floor` empty ⇒ passive (`config:22-26`) and the egress
   `ContributionContext` zero-value ⇒ deny.
3. **Validate at the composition root.** Before the `Attritor` serves any AX5 bait, EVERY declared
   sink must pass F4 (in-perimeter + defender-owned + parseable + non-public-unless-private-CIDR +
   pinned-resolution). ANY entry failing ⇒ **refuse to start** with a typed error naming the bad
   sink (mirror `main.go:154` `log.Fatalf` / `boot.go`).
4. **Post-`CrossScan` insertion.** The validated sink locator is inserted into bait **AFTER**
   `CrossScan` from the F4-approved set, so no generator can ever synthesize an arbitrary routable
   host; the bait still passes `CrossScan` for ALL its non-sink content. **`CrossScan` and F4 BOTH
   run** (F4 in addition to, never instead of, `CrossScan`).
5. **Deny-by-default.** Anything F4 cannot affirmatively prove ⇒ deny.

---

## 4. API surface

### 4.1 F4 predicate (NEW — for the DEFERRED live sink; do NOT extend `harmless.CrossScan`)

Lives in a new stdlib-only sibling so the routable-host admission can never leak into the universal
reserved-host gate: **`internal/harmless/insink`** (confirm name at review, D-AX5-5).

```go
// SinkPolicy is the operator-declared, construction-bound config. Zero value
// (no sinks) => live sink DISABLED.
type SinkPolicy struct {
    ApprovedSinks []ApprovedSink // explicit; never inferred
    PrivateCIDRs  []*net.IPNet   // operator-declared in-perimeter space; empty => RFC1918/loopback/link-local/ULA only
}

// ApprovedSink is one declared sink. Host is an IP literal (preferred) or an
// in-perimeter hostname pinned at validate-time; OwnerLabel is the operator's
// ownership attestation (audit + refuse-to-start error text). Never inferred.
type ApprovedSink struct {
    Host       string
    OwnerLabel string
}

// ApprovedInPerimeterSink is THE F4 PREDICATE. Returns nil only if host
// satisfies all four conjuncts: (a) in-perimeter + non-public, (b) defender-
// owned / in the approved set, (c) not attacker-derived, (d) inbound-only.
// Conservative deny-by-default; returns a *harmless.Error-style typed reason
// otherwise. DISTINCT from harmless.CrossScan.
func ApprovedInPerimeterSink(host string, p SinkPolicy) error

// Validate is the startup gate: runs ApprovedInPerimeterSink over EVERY declared
// sink, pinning hostname resolutions, returning a typed error naming the first
// bad entry. Called at the composition root BEFORE the Attritor serves AX5 bait
// (mirror main.go:154 log.Fatalf). Empty policy validates trivially (sink stays
// disabled).
func (p SinkPolicy) Validate() error

// Enabled is true only if len(ApprovedSinks) > 0; the op-exposure generator
// consults it to choose passive-only vs live-sink bait. Empty => false => passive.
func (p SinkPolicy) Enabled() bool
```

`attrition.Config` gains an `OpExposure insink.SinkPolicy` field (construction-bound, like
`Floor`/`Budget`). `attrition.New` validates it via `p.Validate()` alongside the existing
per-generator `selfTest` (`attrition.go:154-158`) and **refuses to start** on any failure — it never
constructs a live-sink generator from an invalid/empty policy.

### 4.2 Passive MVP (ships now — NO F4 needed)

- Wire the existing `Stream.Observe` seam (`attrition.go:66`/`:346`): replace the no-op body to fold a
  `contract.DriverObservation` digest into `s.out.ExposureSignals` (and analogously `ExploitsObserved`
  for the later AX4). O(1)/chunk; never buffers.
- Adapter side: a `digestObservation(reqShape) contract.DriverObservation` helper in `adapters/envoy`
  (alongside `pump.go`'s `classifyDisengage`), reducing `observationFromHeaders()` output
  (`identity.go`) to counts/bools/closed-enums; called per request on the flow, then `s.Observe(obs)`.
- **No contract change** — `DriverObservation` + `ExposureSignals` already exist. The carrier is
  already threaded composition-root → durable store (`cost.go:102` →
  `cmd/envoy-adapter/main.go` `OnOutcome` copy → `contract.go:181` → `intelligence/event.go` →
  `boltevents.AmendOutcome`); the MVP only POPULATES `ExposureSignals` and adds the deployment-local
  guard test.

### 4.3 Config (NEW optional block — disabled by default)

```yaml
# Operational exposure (AX5). OPTIONAL. Default disabled + empty => passive-only.
# An unrecognized/empty value => disabled (fail-safe), NEVER an any-host sink
# (mirrors sting_floor's empty => passive).
sting_op_exposure:
  enable: false
  approved_sinks: []   # [{host_or_cidr, owner_label}] — each must pass F4 at startup or the adapter refuses to start
```

Parsed into `attrition.Config.OpExposure`. Empty/missing ⇒ live sink disabled ⇒ passive fallback.

---

## 5. No-hack-back structural guarantees

The strongest guarantee is structural, not a comment. The reach-back review found that the existing
import test is **not** sufficient as written — folded in below as **G1**.

- **G1 — POSITIVE import allowlist (CORRECTION, MUST land before any AX5 code).**
  `TestAttritionImportsOnlyContractAndHarmless` (`attrition_test.go:869-901`) is a **DENYLIST**: it
  forbids only `canarysting/internal/{engine,canary,intelligence}` and `canarysting/adapters`. It
  does **NOT** forbid stdlib `net`, `net/http`, `os/exec`, or any dialer. A future engineer could add
  `import "net"` + `net.Dial(approvedSink)` to the op-exposure generator and **the test stays
  green** — so it is **NOT** proof the layer cannot dial out. **FIX:** add a POSITIVE allowlist guard
  asserting `attrition` + `insink` production code import ONLY
  `{internal/contract, internal/harmless, internal/harmless/decoy, internal/harmless/insink, stdlib
  minus dialers}`, plus a dedicated test that asserts NO import of `net` (dialer surface), `net/http`,
  `os/exec`, or any transport package in those packages. The structural no-dial guarantee must be the
  **test**, not a comment. A layer that physically cannot dial out cannot hack-back. (Confirmed today:
  `grep` for `net.Dial`/`http.Client`/`http.Get`/`http.Post`/`DialContext`/`RoundTrip`/`exec.Command`/
  `.Do(` across `internal/sting/attrition` + `internal/harmless` returns **empty** — G1 locks that in
  permanently.)
- **G2 — OBSERVATION ONLY.** The only new data path is the inbound `Stream.Observe(DriverObservation)`
  seam — a digest of requests the attacker ALREADY sent INTO our in-perimeter decoys. The defender
  originates zero traffic. This is the only compliant reading of "callbacks to controlled endpoints"
  (design §14.2): the attacker's OWN tooling connects in; the defender owns + observes the sink and
  NEVER dials out.
- **G3 — third-party beacon impossible.** F4 conjunct (d) + G1's import-graph mean no code path takes
  an embedded host and connects to it. Even the deferred live sink is a **LISTENER** the attacker
  connects into, never a client the defender drives.
- **G4 — relay/smuggle vector closed.** F4 conjunct (c): the sink locator is NEVER derived from
  attacker-supplied Host / SNI / header / path — only from the static operator-declared set, inserted
  post-`CrossScan`. An attacker cannot steer our bait to embed a locator pointing at attacker infra or
  a third party.
- **G5 — no raw attacker bytes retained.** `DriverObservation` carries counts/bools/enums ONLY;
  `TestDriverObservationCarriesNoRawData` (`contract_test.go`) reflects over it and rejects any
  byte-slice / address-shaped field. There is nothing to accidentally replay back at the attacker.
  **(CORRECTION folded in)** the **reduction step** `digestObservation(RequestObservation) →
  DriverObservation` is itself a new raw-data surface: `RequestObservation` holds raw
  `Headers map[string]string`, raw `Path`, raw `Method` (`adapters/envoy/identity.go`). FIX: (i) keep
  `DriverObservation` strictly counts/bools/closed-enums — never add a free string field; any
  UA/header-order signal is a bounded enum/band computed in the adapter, never the raw value; (ii) add
  a guard test that, for adversarial raw inputs (UA strings, long paths, header floods), the digest
  output contains **none** of the input substrings; (iii) `digestObservation` lives adapter-side as a
  transport-fact reduction (rule 1) with a fixed small enum codomain.
- **G6 — defender-cost bound.** The capture path consumes only the digest under the shared `Governor`
  + kill switch, O(1)/chunk — it never buffers attacker traffic, so observation cannot be turned into
  defender-side amplification (design §14.6).

The passive MVP satisfies the no-hack-back hard line **trivially** (zero new outbound surface). The
deferred live sink satisfies it because it is a **listener gated by F4 + G1**, never a dialer.

---

## 6. Rule 8 / 9 / 1 / 5 + fail-closed-T3 interactions

- **Rule 8 — the canary touch is the only trigger.** AX5 is reached ONLY via `attrition.Open`, a
  no-op below `TierContain` and on `SocketCookie == 0` (`attrition.go:181-187`), off a Tier-3
  (`TierJail`) canary-touch-derived verdict — NEVER baseline deviation / novelty / recon. The
  in-perimeter sink/decoy is **PLACED** in negative space (seeder `OriginNegativeSpace`; the planner
  is unreachable from the signal-emission path); the attacker CONNECTING INTO it is itself the
  canary-style touch — that touch is the trigger AND the captured signal. **No new non-canary trigger
  path** is introduced. Baseline only informs PLACEMENT, never a sting.
- **Rule 9 — egress / anonymized-only crossing.** `ExposureSignals` is captured RAW only LOCALLY
  (rule 5, scope-isolated), surfaces as an int64 COUNT scalar (no raw bytes/addresses/headers/decoy
  contents), and is **DEPLOYMENT-LOCAL-ONLY**. The now-BUILT default-deny egress filter
  (`internal/intelligence/network`) structurally blocks it: `block.go` **type-denylists**
  `contract.StingOutcome` by package-path + name (verified `block.go` `denylistedTypeName` matches
  `internal/contract` `StingOutcome` precisely because it carries the AX4/AX5 fields), and the
  denylist **recurses embedded fields** so wrapping it cannot launder it; the zero-value
  `ContributionContext` denies; and even a hand-tagged int64 count is denied unless it declares a
  coarse band ≤ `maxBandSpan` with the opt-in + k-anonymity gates. A cross-boundary AX5 path is
  **BLOCKED** until a field is explicitly egress-tagged, coarsened to a band/enum, and re-justified.
  **F4 governs the SINK; the egress filter governs the SIGNAL crossing — both apply, and the stricter
  wins.** The MVP adds the §2.5 deployment-local-only guard test and keeps `ExposureSignals` an int64
  COUNT (never a richer fingerprint struct) until the egress-export work bands it.
- **Rule 1 — proxies stay thin.** `digestObservation` is a transport-fact reduction (request shape →
  counts/bools/enums), NOT detection/decision logic. No scoring/tiering moves into the adapter. The
  op-exposure decision (which axes, which bait) stays in `attrition`, bound at the composition root.
- **Rule 5 — scope isolation.** `ExposureSignals` and the `DriverObservation` digest are per-scope
  local state, persisted via `boltevents.AmendOutcome`, never aggregated across scopes. The egress
  denylist of the carrier types enforces this at the boundary.
- **Fail-closed T3.** Tier 3 stays fail-closed (`config: fail_closed.tier3: true`); an engine outage
  must NOT release a confirmed-malicious flow. AX5 inherits this unchanged; the live-sink/F4 machinery
  never relaxes it.
- **Aggressive-is-never-a-silent-default (stacked fail-safes).** The op-exposure generator is
  constructed ONLY at `FloorAggressive` (`contract.go:114-117`); `FloorPassive` (the zero value)
  unlocks `AxisVelocity` only, so an unset floor can never reach AX5. The F4 `SinkPolicy` is likewise
  empty-by-default ⇒ live sink disabled. **Two independent fail-safe defaults stack.**

---

## 7. Sequenced build plan

**Gate 0 (this doc).** Founder signoff on §0 (the F4 predicate shape + passive-MVP scope). **No AX5
code lands before this.**

**Phase 1 — passive MVP (ships the axis; no sink, no F4 dependency).**
1. **G1 first:** convert `TestAttritionImportsOnlyContractAndHarmless` to a positive allowlist + add
   the no-dialer test (`net`/`net/http`/`os/exec`/transport forbidden in `attrition` + `insink`). Land
   this BEFORE any generator that could be tempted to dial.
2. Add `MechOpExposure` (`cost.go`) + `AxesForMechanism` mapping; add the `opExposure` generator
   (`axis()=AxisOpExposure`, `minTier()=TierJail`, `CrossScan`-clean bait via `decoy`); it passes
   `genSelfTest`.
3. Populate the `Stream.Observe` body to fold a `DriverObservation` into `s.out.ExposureSignals`
   (O(1)/chunk).
4. Adapter: add `digestObservation` (counts/bools/closed-enums; UA family enum, header-set count,
   header-order/casing bucket, method enum, suspected-exploit bool, coarse cadence band) and call
   `s.Observe(...)` per request alongside the pump.
5. Tests: the §2.5 deployment-local-only guard for `ExposureSignals`; the G5 digest-no-raw-substring
   guard; gating test (op-exposure only at `FloorAggressive` + `TierJail`); G1 import tests.

**Phase 2 — F4 dormant gate (lands now, disabled; SIGNED OFF but inert).**
6. New `internal/harmless/insink` package: `SinkPolicy`, `ApprovedSink`, `ApprovedInPerimeterSink`,
   `Validate`, `Enabled` (deny-by-default, the four conjuncts + hostname-pinning).
7. `attrition.Config.OpExposure insink.SinkPolicy`; `attrition.New` calls `p.Validate()` and refuses
   to start on failure; empty ⇒ disabled.
8. Config: `sting_op_exposure { enable: false, approved_sinks: [] }`; parse + fail-closed wiring.
9. Tests: F4 predicate unit tests (public IP rejected even if listed; attacker-derived host rejected;
   empty ⇒ disabled; rebind/unresolvable hostname rejected); refuse-to-start on a bad sink; a guard
   test that `AllHostsReserved` STILL rejects every non-reserved host and no generator's bait embeds a
   routable host outside the post-`CrossScan` F4 insertion path (Risk R-3 guard).

**Phase 3 — live sink (DEFERRED, separate founder review; build later if at all).**
10. Only after a concrete intelligence gap passive cannot fill is shown AND a second founder review of
    F4 + the sink/listener design completes: build the in-perimeter listener lifecycle, harden it
    against inbound DoS/abuse, and have the op-exposure generator embed an F4-approved locator
    post-`CrossScan` when `SinkPolicy.Enabled()`.

---

## 8. Test plan

| Test | Asserts |
|------|---------|
| `TestAttritionImportsAllowlist` (G1, **load-bearing**) | `attrition` + `insink` production code import ONLY the allowlisted set; NO `net`/`net/http`/`os/exec`/transport package. The machine-checkable no-dial proof. |
| `TestOpExposureGatedToJailAggressive` | op-exposure generator constructed only at `FloorAggressive`; its `minTier()==TierJail`; `selectAxes` never returns it at Tier 2; `FloorPassive`/`FloorModerate` never construct it. |
| `TestOpExposureBaitCrossScanClean` | the passive generator's emitted bytes pass `harmless.CrossScan` over `genSelfTest` samples (embeds only reserved hosts). |
| `TestObservePopulatesExposureSignals` | `Stream.Observe(DriverObservation)` folds into `Outcome.ExposureSignals`; O(1)/chunk; no buffering. |
| `TestDigestObservationNoRawData` (G5) | for adversarial raw UA / long path / header flood inputs, `digestObservation` output (a `DriverObservation`) contains none of the input substrings; only counts/bools/closed-enums. |
| `TestExposureSignalsDeploymentLocalOnly` (§2.5) | `contract.StingOutcome` (carrying `ExposureSignals`) is denied by `network.Clear` three ways (type denylist / opt-in zero-value / band requirement); reuse/extend `TestAX4AX5NeverCross`. |
| `TestF4RejectsPublicSink` | `ApprovedInPerimeterSink` denies a global-unicast host even if allowlisted. |
| `TestF4RejectsAttackerDerivedHost` | F4 conjunct (c): a host not in the static operator set is denied; no attacker-supplied value admitted. |
| `TestF4EmptyPolicyDisabled` | empty `SinkPolicy` ⇒ `Enabled()==false`, `Validate()==nil`, live sink off (passive fallback). |
| `TestF4RebindHostnameDenied` | unresolvable or publicly-resolving hostname denied; only pinned private/loopback/link-local/ULA/declared-CIDR admitted. |
| `TestAttritorRefusesToStartOnBadSink` | `attrition.New` returns a typed error naming the bad sink; the adapter `log.Fatalf`s (mirror `main.go:154`). |
| `TestCrossScanInvariantPreserved` (R-3 guard) | `AllHostsReserved` still rejects every non-reserved host; no generator's bait embeds a routable host outside the F4 post-`CrossScan` insertion path. |

---

## 9. Risks

- **R-1 — LIVE-SINK = HACK-BACK CONFUSION (highest).** A routable defender-owned listener the
  attacker connects into could be MISREAD (auditor) or mis-built (later engineer) as outbound
  retaliation. **Mitigation:** keep it deferred + disabled-by-default; G1's positive import allowlist
  is the structural proof it cannot dial out; F4 conjunct (c) blocks attacker-derived locators.
- **R-2 — ALLOWLIST MISCONFIG.** An operator could list a publicly-routable host, turning bait into a
  beacon to a public address. **Mitigation:** F4's non-public structural check REJECTS any
  global-unicast address even if listed; refuse-to-start at `New()` naming the bad entry; hostname
  resolutions pinned at validate-time (anti-rebind).
- **R-3 — `CrossScan` EROSION.** A future engineer might fold the routable-sink admission into
  `harmless.AllHostsReserved` to avoid a second predicate, silently weakening the universal
  reserved-host invariant for the canary catalog and all five axes. **Mitigation:** F4 MUST be a
  separate sibling package; `TestCrossScanInvariantPreserved` asserts `AllHostsReserved` still rejects
  every non-reserved host and no bait embeds a routable host outside the post-`CrossScan` F4 path.
- **R-4 — EGRESS LEAK of fingerprint.** `ExposureSignals` (or a richer fingerprint) exported before
  coarsening / k-anonymity. **Mitigation:** the built egress filter type-denylists the carriers
  (`block.go`); the §2.5 deployment-local-only guard test; nothing crosses until explicitly banded +
  justified through `Clear`.
- **R-5 — SMUGGLING via attacker-controlled bait input.** If the bait locator were ever derived from
  attacker-supplied Host/SNI/headers, the attacker could steer our sink into a relay. **Mitigation:**
  F4 conjunct (c) admits ONLY the static operator-declared set; the sink locator is inserted
  post-`CrossScan` from that validated set, never from the flow.
- **R-6 — ADAPTER DIGEST LEAKING RAW DATA.** The passive digest must reduce UA/headers/path to
  counts/bools/enums only; a careless digest could carry a raw UA/path. **Mitigation:** keep
  `DriverObservation` scalar-only (the reflection guard) and add the G5 no-raw-substring test; extend
  only with enums/bands, never raw strings.
- **R-7 — PREMISE DRIFT.** Implementers may assume AX4's `Observe`→digest path already exists to copy.
  It does NOT (`attrition.go:346` is a no-op; no exploit/op-exposure generator; no `ExploitBaitService`;
  no `digestObservation`). AX5-passive is the FIRST consumer of the seam and establishes the pattern.
  **Mitigation:** §1 is load-bearing; do not wire against non-existent code.
- **R-8 — DEFENDER-COST under high-rate inbound.** A confirmed-hostile flow could send many requests;
  digesting each must stay O(1)/chunk and never buffer. **Mitigation:** shared `Governor` + kill switch
  + per-flow `Budget`; the digest is incremental counts, never accumulated raw traffic (design §14.6).
