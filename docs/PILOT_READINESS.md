# Pilot Readiness — what a CISO panel needs before they engage

Status: strategy (2026-06-15). Distills a four-persona CISO panel's findings on
"what would you need to engage in a pilot" into a prioritized roadmap. Read
alongside `docs/ROADMAP.md` (the build plan this reorders) and `docs/INTELLIGENCE.md`
(the egress filter / cross-customer rules). The panel personas: skeptical-enterprise,
SOC/threat-hunting, cloud-native/platform, regulated/compliance.

This is a positioning-and-sequencing document, not an architecture spec. Where it
names a file or a status it is grounded in the code as of this date; where it
recommends, it says so plainly.

## The verdict

All four personas converged on the **same** answer, independently:

- **Conditional YES** to a tightly-scoped, **NON-PRODUCTION**, **observe-only /
  auto-response-OFF** pilot in **one blast-radius-limited segment** (a single
  cluster or app segment, not a fleet).
- **Hard NO** to production **auto-jail** until a specific bar is cleared.

The bar, stated plainly — production auto-response stays off until **all** of:

1. At least one **one-way SIEM/SOAR egress path** carries every canary touch and
   every kernel-jail action into the customer's own console as a correlatable,
   enriched event (with ATT&CK technique tags).
2. A **tamper-evident, per-action audit record** + a **verifiable, timed,
   RBAC-gated kill-switch** exist as controls the customer can independently
   evidence and operate — decoupled from the (self-described immature) control
   plane.
3. A published **safety evidence package** (measured inline latency/CPU under
   load, kernel/distro support matrix, documented per-tier fail-open/fail-closed
   incl. in-flight-flow semantics) plus a real **multi-node + CNI-coexistence**
   proof on a real cluster.
4. The **deviants hunting page is real and demonstrable** — the on-screen answer
   to "a skilled attacker who avoids the canaries gets a free pass."

The **zero-false-positive-by-construction wedge** — a canary touch is the *only*
thing that arms a response; the eBPF baseline is scoring context, never a trigger
(CLAUDE.md rule 8) — is the **sole reason all four spend pilot time at all**. It is
the only credible basis any of them has seen for *safely* auto-responding on
east-west traffic, where every FP-noisy IDS forces a human in the loop. Flow-precise
socket-cookie containment (jail the flow, not the host; bystander keeps serving) and
"zero real data reached" are the proof points that make that wedge land. Everything
below is the bar to flip auto-response on later — not a reason to widen the wedge.

## Pilot must-haves

The synth's `pilot_must_haves`, each mapped to **exists / planned / NEW-gap** with
the recommendation. "Planned" means it is in `docs/ROADMAP.md` but not yet in hand;
"NEW-gap" means it is not in the current plan at all.

| # | Must-have | Status | Recommendation |
|---|---|---|---|
| 1 | **One-way SIEM event egress** on every canary touch + jail (JSON over CEF/syslog/OCSF or webhook/HEC), stable schema | **NEW-gap** | **BUILD FIRST.** Absent from the roadmap entirely; named by all 4 as the literal gate to *start*. Small relative to the control plane. Emit the record the engine already carries by socket cookie — do not invent fields it doesn't have (see §SIEM). |
| 2 | **Tamper-evident per-action audit record** (hash-chained/WORM, exportable; "bytes of real data crossed = 0" as a provable field) | **planned** | **PROMOTE out of the immature M8/M10 control plane** and ship standalone. Wrap the existing `EventStore` arc (`internal/intelligence/event.go`). The regulated CISO's GC vetoes auto-mode without it. |
| 3 | **Verifiable global + per-scope kill-switch** + RBAC/SSO + audited command palette | **planned (partial)** | Concept exists — `Governor.Kill()`/`Revive()` in `internal/sting/attrition/governor.go` — but with **zero external callers**, no timing proof, no RBAC, no audit. `cmd/canaryctl` is an 8-line stub. Ship a demonstrable **timed** kill-switch + a basic **audited** palette for pilot; SSO is a fast-follow. |
| 4 | **Top non-tripwire deviants page** as a real investigation surface (pivot/group/filter/export) + a canary-avoiding flow in the demo | **planned (gating)** | **BUILD.** Page does not exist *and* the current simdriver has no canary-avoiding flow, so the #1 dismissal has zero on-screen answer today. Detection-eng calls a sortable table with no pivot/export "worse than nothing." See §Roadmap item 2. |
| 5 | **Volume/fidelity controls on the deviants stream** (events/day estimate, tunable threshold, ack/suppress known-good) | **NEW-gap** | **BUILD alongside the page.** The trigger is zero-FP; the deviants stream is an anomaly feed and is **not** — without volume prediction + suppression it becomes the alert-fatigue swamp the SOC already fights. |
| 6 | **Documented safety / blast-radius package** (per-tier fail behavior, crash semantics, kernel/distro matrix, measured p50/p99/p99.9 latency + CPU/node, in-flight-flow-on-jail behavior) | **planned (evidence missing)** | The fail-open-by-construction datapath and per-tier posture **exist and are tested** (ROADMAP M1/M5). What is missing is the *published evidence*: measured numbers, the matrix, the in-flight doc, and a first-class async-only mode. **Produce it.** |
| 7 | **MITRE ATT&CK technique mapping** on touch + deviant events | **NEW-gap** | **BUILD — small, high-leverage.** The catalog already knows `CanaryType`; map each type to technique IDs and attach to the emitted event. Pairs naturally with the SIEM schema (§SIEM). |
| 8 | **IR case package per jail event** (what touched, zero-data proof, flow timeline, identity, attrition actions; exportable) | **planned** | **BUILD a report view** over the existing `EventStore` arc. Overlaps the audit-record work — package the same data as an IR-handoff artifact. |
| 9 | **Coverage statement + reproducible "zero-FP" test harness** enumerating benign-touch failure modes (misplaced decoy, range/vuln scanners, service discovery, health-checkers, backup/DR, NAT/cookie reuse) | **planned** | Harmlessness + scope tests exist; the *benign-touches-a-canary* boundary is not enumerated as a control narrative. **Write it.** State plainly that a misplaced decoy a legit service reaches **is** a real FP path. The regulated CISO will run the harness independently. |
| 10 | **Egress-filter data contract** for the cross-customer network (field-level schema, server-side k>=3, proven irreversibility, auditable "shares nothing" OFF mode) | **planned (D6 stub)** | `internal/intelligence/network/` is a `doc.go` stub; peers are simulated. **For the pilot: do NOT sell the moat.** Ship and demonstrate "shares nothing / fully isolated" as the *default*; build the filter as its own independently-reviewable milestone before any byte crosses. See §Roadmap item 9 and §Honesty. |

## The biggest NEW gaps

These are the things **not in the current plan** that block or tip a pilot. They are
the highest-value deltas because the panel treats them as table stakes while the
roadmap is busy deepening detection and the moat.

1. **No SIEM/SOAR/EDR integration anywhere in the roadmap.** Confirmed against
   `docs/ROADMAP.md` — there is no SIEM/SOAR/EDR milestone, near-term or otherwise.
   Yet all four personas name a one-way event push as the literal precondition to
   pilot: "no egress = invisible = not a detection source I can own." This is the
   single biggest blind spot. The founder is building deeper detection and response
   while the panel will not even *watch the output* unless it lands in their console.
   A small one-way push must be elevated to pilot-gating, ahead of most of the
   current plan. **Lead with this gap.** (Full treatment in §SIEM.)

2. **The deviants page has no demo flow that exercises it.** The demo-data design
   itself names this: the current simdriver's malicious archetypes **all touch
   canaries immediately**, so every adversary flow arms a response and there is
   literally no canary-avoiding deviant on screen. The marquee answer to the #1 CISO
   dismissal has zero on-screen evidence today. The `careful-mover` worker — a fresh
   identity walking a novel east-west path of *normal* (non-canary) paths at a slow
   cadence, with its path set asserted disjoint from `canaryPaths` (rule 8) — is the
   single most important addition.

3. **Audit + kill-switch + RBAC are trapped inside the immature control plane
   (M8/M10).** The regulated and platform CISOs cannot authorize any production
   auto-jail without a tamper-evident per-action audit record and a verifiable,
   RBAC-gated, timed kill-switch. Bundling these behind a control plane the founder
   himself calls immature means the production gate slips indefinitely. **Decouple
   them and ship early** — the `EventStore` already holds the underlying events, and
   `Governor.Kill/Revive` already exists (it just has no caller, no timing proof, no
   audit).

4. **The deviants stream is an anomaly feed with no volume/suppression story** — it
   can re-introduce the exact false-positive alert-fatigue the whole product is
   positioned *against*. The plan treats deviants as a pure win; the SOC persona is
   explicit that without an events/day estimate, a tunable threshold, and ack/suppress
   of known-good, analysts abandon the page in a week. The zero-FP claim is about the
   **trigger** only; the human-hunting surface needs its own fidelity controls.

5. **No published latency/overhead numbers or kernel-support matrix for the
   inline/eBPF path.** Platform and regulated are blocked on exactly the "engine-down
   → fail-closed → 403s on legit east-west traffic" case and the "privileged BPF
   DaemonSet fights the CNI for the TC hooks → node-down" case. The §7 TCX/CNI/ambient
   coexistence is asserted from research precedent (eunomia/Cilium/Tetragon), **not
   demonstrated on a real multi-node cluster with the customer's CNI**. A measured
   async-only (engine-off-the-hot-path) mode must be a first-class supported posture.

6. **The "staged demo vs production behavior" separation is itself a gate the panel
   will actively test.** Every persona has read the project's own `DEMO_DATA_FLOOR` /
   simulated-peers notes and will separate "works" from "looks like it works in a
   rigged demo." The on-screen honesty fences (staged-names caption, simulated-flow-
   but-real-detection, window-observed recurrence) are therefore trust-*preserving*
   controls, not decoration. The corresponding new gap: there is no on-box,
   customer-runnable way to reproduce the detection on the customer's *own* traffic
   during the pilot — a "replay/sandbox over the last N days of captured baseline"
   mode should be elevated, because it is how a CISO converts a staged demo into
   evidence on their data.

7. **Vendor-maturity / supply-chain gap.** For a tool this deep in the kernel and
   traffic path, the skeptic and regulated personas require **signed agent releases**
   and a **third-party security review of the eBPF programs** before prod — plus an
   answer to "does this founder-led, single-box company survive the pilot and support
   me." Not a feature, but a real pilot-to-production gate the plan does not address.
   At minimum, signed releases + a stated path to external eBPF review belong on the
   roadmap.

## SIEM/SOAR egress — the #1 pilot gate — with the two-egress clarification

This is the gate every persona names first. It is also the section most likely to be
built wrong, because CanarySting already has an egress concept (the cross-customer
network) and it is easy to conflate the two. **They are distinct paths with opposite
data postures.**

### Two egress paths, opposite postures

| | (a) Cross-customer moat | (b) SIEM/SOAR |
|---|---|---|
| Package | `internal/intelligence/network/` (the egress filter) | NEW — a local SIEM emitter |
| Destination | Another customer's deployment / the intelligence network — **crosses a customer boundary** | The customer's **own** SIEM/SOAR — **local, stays in their boundary** |
| Data posture | Coarse, hashed, k>=3 anonymized, default-deny per-field (rule 9) | The **rich** event, **NOT anonymized** |
| Governing rule | Rule 9 (only anonymized patterns cross a boundary) | Rule 5 (scope isolation) — local retention is sanctioned (`INTELLIGENCE.md` §3.3) |

The key insight the panel relies on: **the SIEM data is valuable precisely because it
does NOT go through the cross-customer filter.** The moat filter exists to strip
everything identifying because the data is leaving the customer. The SIEM path is the
opposite — it carries the full src/dst identity, the L7 path, the fingerprint, the
verdict, *because it stays inside the customer's own boundary and is exactly the
correlatable, enriched event the SOC needs.* Routing the SIEM event through the
cross-customer anonymizer would defeat its entire purpose.

### Proposed SIEM event schema

One record per canary-touch and per kernel-jail action. Field, source, and
today-vs-needs-capture status:

| Field | Source | Exists today? |
|---|---|---|
| event id | generated | yes (trivial) |
| scope | `AdversaryInteractionEvent.ScopeKey` | **yes** |
| event-type (`canary-touch` \| `kernel-jail` \| `deviant-surfaced`) | engine tier/verdict + sting action; deviant from the observe surface | partial — touch/jail derivable; `deviant-surfaced` needs the deviants page |
| src/dst service identity + resolved name | eBPF observer sees src/dst; Envoy adapter sees the source addr/SPIFFE — **threaded nowhere durable** | **needs capture** (see below) |
| socket cookie | `AdversaryInteractionEvent.FlowID` | **yes** |
| canary type touched | `AdversaryInteractionEvent.CanaryType` | **yes** |
| fused L7 + east-west fingerprint | L7 path/method (adapter) + 4 novelty dims (`Features`) | partial — `Features` exist; L7 half **needs capture** |
| east-west path | the multi-hop pivot the flow walked | **needs capture** (today only hashed adjacency exists) |
| verdict / tier / action | `AdversaryInteractionEvent.Verdict/Tier` + `Sting.Mechanism` | **yes** |
| attrition axes | `Sting.Axes` (Track E AX0) | yes (once AX0 lands) |
| ATT&CK technique id | mapped from `CanaryType` | **needs the small mapping addition** |
| posture-at-the-time | engine posture/floor config at decision time | partial — known to the engine, not stamped on the event |
| "bytes of real data crossed = 0" | structural (the response intercepts before any real resource) | **yes, provable by construction** |
| timestamp | `AdversaryInteractionEvent.Timestamp` | **yes** |

Transports: **CEF/syslog + OCSF + webhook/Splunk HEC.** **One-way push first**
(every persona gates on this); bidirectional (accept context back, SOAR-driven
release) is a later fast-follow.

### Critical dependency and sequencing — read before building

**The rich SIEM event cannot be built on today's engine event.** The durable engine
record, `intelligence.AdversaryInteractionEvent` (`internal/intelligence/event.go`),
is **structurally addressless**: it carries `ScopeKey`, `FlowID` (socket cookie),
`CanaryType`, `Features` (the 4 novelty dims), `Tier`/`Verdict`/`Score`, and `Sting`
— and that is all. It has **no L7Attributes field, no path, no method, no resolved
identity.** By design (rule 9, deployment-local hygiene) it records "structured
features and identifiers internal to the deployment," not raw identity.

The rich data **is observed** — it is simply discarded rather than threaded:

- the **eBPF observer** sees src/dst (`bpf/observe`), but consumes the addresses only
  to compute FNV hashes and never persists them raw (rule 9);
- the **Envoy adapter** sees the SPIFFE id and the full L7 — `observationFromHeaders`
  in `adapters/envoy/identity.go` extracts `:method` and `:path`, and
  `adapter.go:onRequestHeaders` even stamps the source address into
  `flow.L7Attributes` — but `AdversaryInteractionEvent` has no field to carry any of
  it, so it stops at the adapter.

**Therefore the rich SIEM event DEPENDS ON the local-rich capture** (see
`docs/TOPOLOGY_AND_DEVIANTS.md`) plus **threading the adapter's `L7Attributes` (and
the observer's resolved src/dst) into a local enriched record.** SIEM egress is built
**on top of** that local-rich capture — **not** on today's addressless event. If you
emit the addressless event to a SIEM, you ship an identity-poor signal (cookie +
novelty floats + canary type, no who/what/where), which is *making things worse*: a
SOC cannot correlate it, which is the exact failure the integration is meant to
solve. Get the capture right first; the SIEM emitter is then a thin serializer over
the enriched record.

The **ATT&CK technique mapping** (from `CanaryType`) is a small, high-leverage
addition that pairs directly with this schema — it is a static map, not new
plumbing, and it is what lets the SOC slot the signal into coverage matrices.

## Decoupled trust controls (ship early, ahead of the full control plane)

The regulated CISO's GC vetoes any production auto-jail without these. They do **not**
require the full multi-node control plane and must be **decoupled** from it (gap #3).

- **Tamper-evident per-action audit record + IR case package.** Wrap the existing
  `EventStore` arc (`internal/intelligence/event.go`) in an **append-only,
  hash-chained, exportable** log: one immutable, timestamped record per automated
  action capturing the canary touched, socket cookie, src/dst identity, L7 context,
  verdict/tier, operator posture at the time, and **"bytes of real data crossed = 0"**
  as a provable field — built to survive an examiner asking "prove *this* containment
  was justified." Package the same data as an IR-handoff case report (overlaps
  must-have #8). The underlying events already exist; only the chaining, export, and
  report view are new. Note that this inherits the SIEM section's capture dependency
  for the *identity/L7* fields — the audit record is only as defensible as the
  enriched record under it.

  > **Shipped (slice A + external-witness anchor):** the per-action chain is a
  > **per-scope, hash-chained, append-only** log (`internal/intelligence/audit`), keyed
  > with HMAC-SHA256 when `-audit-hmac-key` is set (tamper-EVIDENT against a file-only
  > attacker lacking the key), exportable as an IR-handoff case report (`Export`) with a
  > recomputed `Verify` verdict, carrying **"bytes of real data crossed = 0"** as a
  > provable field. Two residuals are **in-band undetectable** even keyed — (a)
  > truncate-to-a-valid-prefix + head-rewrite and (b) whole-scope erasure — because a
  > fresh store sees a consistent-but-incomplete state with nothing left to recompute
  > against. These are now closed **at the SOC, not in-engine**: the engine PUBLISHES a
  > per-scope **external-witness anchor** (the audit chain's high-water-mark — head hash,
  > record count, latest seq, algo/keyed markers) to the operator's OWN SIEM on a coarse
  > cadence, as an add-only `audit-anchor` SIEM event (schema v2; the new fields are
  > omitempty so a v1 touch event is byte-identical except `schema_version`). The SOC
  > holds the last-seen anchor and **compares** it against the live chain (`Verify` /
  > `Export` / the next anchor): a scope that is now empty, shorter (latest-seq
  > regressed), or different-headed than the witness it last saw is a **provable**
  > deletion/truncation. This is **publish-then-detect-AT-the-SOC, NOT in-engine
  > auto-detection** — the SIEM path is one-way (the engine never reads it back, never
  > alarms on its own), and it is **not** proof against an attacker who *also* controls
  > the operator's SIEM endpoint and can forge/suppress anchors or rewrite the SOC's
  > stored anchor history (same-box-plus-SIEM-control is out of scope). The anchor is
  > **LOCAL operator metadata** on the operator's own SIEM path (rule 9) — chain
  > metadata about their own deployment, never the cross-customer feed. Coarse cadence
  > means anything appended after the last anchor and then erased is below the witness's
  > resolution (the SOC detects relative to the last-seen high-water-mark, not the
  > instantaneous tip).

- **Verifiable, timed, RBAC-gated kill-switch + basic audited command palette.** The
  primitive exists — `Governor.Kill()` / `Governor.Revive()` in
  `internal/sting/attrition/governor.go` — but it has **zero external callers**, no
  timing proof, no RBAC, and no audit; `cmd/canaryctl` is an 8-line stub. For pilot:
  wire a kill-switch that **demonstrably halts all enforcement within seconds**
  (timed, shown on screen), behind RBAC, with every operator action written to the
  audit log above. SSO/SAML can fast-follow; the **audit log on operator actions** and
  the **timed-kill proof** are the pilot-gating parts for the platform and regulated
  personas.

  > **Shipped (slices B1 + B2):** a deployment-wide, **timed, auto-expiring** enforcement
  > kill-switch (`internal/sting/killswitch`) is wired at the engine emit-seam — when
  > engaged it floors every emitted verdict's tier to observe, which provably halts BOTH
  > the inline attrition pump AND the async kernel jail downstream (enforcement is strictly
  > downstream of the emitted tier), evaluated against the engine's own trusted clock.
  > Every engage/revive is appended to the tamper-evident audit chain. A loopback-only,
  > fail-closed admin endpoint (`-killswitch-admin-addr`) operates it, with `canaryctl
  > killswitch engage|revive|status` (+ `-json`) as the operator/agent surface.
  > **B2 per-identity RBAC SHIPPED:** `-killswitch-principals-file` carries a JSON
  > directory of named operators, each with their own bearer token (stored as a
  > `token_sha256`; the raw token is issued out of band) and a role (`viewer` = status
  > only; `operator` = engage/revive/status). The admin resolves a **VERIFIED** identity
  > from the presented token (constant-time hashed lookup) and records it in the audit —
  > a caller **cannot** falsify the operator via a header. The legacy single
  > `-killswitch-token-file` (advisory operator) still works (back-compat). **Remaining
  > gap → further B2:** mTLS/SSO client identity (this is still a bearer-token secret, not
  > a cert/federated identity) and a kernel-map flush for already-jailed *silent* cookies
  > (a flow that re-touches a canary IS de-escalated). So "RBAC-gated" is now SHIPPED as
  > per-identity **token** RBAC; mTLS/SSO remains the target.

## Safety evidence package + posture controls

The skeptic and platform personas block on the *evidence*, not the design — the safe
defaults already exist (fail-open-by-construction kernel datapath, per-tier fail
posture, three structural guards on aggressiveness). What is missing is published,
measured proof and two explicit posture modes.

- **Published latency/overhead numbers:** measured **p50/p99/p99.9 inline latency**
  per request at Tier 2/3, and **CPU/node** for the DaemonSet, **under load**.
- **Kernel/distro support matrix:** CO-RE coverage + the **BTFHub fallback**, with the
  per-build BTF-breakage caveat (ROADMAP §7) stated, so a kernel/AMI bump on one node
  group does not silently drop enforcement fleet-wide.
- **Documented per-tier fail-open/fail-closed behavior**, including **in-flight-flow
  semantics on jail** (what happens to a legitimate flow already in flight when a
  sibling flow is jailed) — the case platform and regulated will be grilled on
  internally is precisely "engine hiccups → fail-closed Tier-3 403s on legit traffic."
- **A first-class ASYNC-ONLY mode** (engine off the hot path) as an explicit,
  supported posture — so a customer can adopt detection without ever putting the
  engine on the service-to-service call path.
- **A SHADOW / DRY-RUN mode** (score + would-jail, log-only, per scope) showing what
  *would* have been jailed over 30/60/90 days with full justification.
- **An auto-response CONFIDENCE LADDER** the operator controls: **observe → tag →
  contain on a named set**, each tier scoped by **namespace / label / SPIFFE**, with a
  full per-verdict audit trail. Every persona wants to earn trust gradually, not flip
  a kernel-jail switch on day one.

## The prioritized roadmap

The synth's `roadmap_additions`, ordered by **pilot-leverage**. The build-queue front
(items 1–4) is what flips a pilot from "interesting demo" to "engaged"; items 5–10 are
the bar to flip auto-response on in production later.

1. **One-way SIEM egress** (syslog/CEF/OCSF + webhook + Splunk HEC) on canary-touch +
   jail, stable documented schema, ATT&CK technique tags. **Highest leverage** — named
   by all 4 as the gate to start, small relative to the control plane, currently absent
   from the roadmap. *Sequencing: built on top of the local-rich capture (§SIEM), not
   today's addressless event.*

2. **The deviants hunting page made real:** view-builder + pivot/group/filter/export
   (CSV/JSON/STIX) **and** the simdriver `careful-mover` canary-avoiding flow (path-set
   asserted disjoint from `canaryPaths`) + per-identity recurrence rollup + ack/suppress
   + an events/day fidelity readout. The demo centerpiece and the on-screen answer to
   the #1 dismissal; doubles as the hunt-feed-won't-become-a-swamp control.

3. **The learned topology view** (`nodes[] + edges[]` with class tags + `staged_labels`
   flag + the live source→decoy touch edge) plus the **expanded mesh (~14 nodes)** and
   expanded benign identities. Turns the "lab toy" graph into a fabric, makes the
   zero-FP trigger a *visible physical event*, and delivers standalone segmentation-audit
   value as an exportable adjacency graph.

4. **Decoupled trust controls, shipped early** (ahead of the full M8/M10 control plane):
   the tamper-evident hash-chained per-action **audit record + IR case package**, and a
   verifiable, **timed, RBAC-gated kill-switch** with a basic audited command palette.
   The production-auto-jail gates for the regulated + platform personas.

5. **Published safety evidence package:** measured p50/p99/p99.9 inline latency + CPU/node
   under load, kernel/distro support matrix (CO-RE + BTFHub), documented per-tier
   fail-open/fail-closed incl. in-flight-flow-on-jail semantics, and a first-class
   supported **async-only** mode.

6. **Shadow/dry-run mode + auto-response confidence ladder** (observe → tag →
   contain-on-named-set, scoped by namespace/label/SPIFFE) — how every persona earns
   trust before arming.

7. **Real multi-node K8s DaemonSet + CNI-coexistence proof** on a real cluster (AWS VPC
   CNI *and* Cilium present; program-ordering + CNI-upgrade survival test) + end-to-end
   **SPIFFE-identity model** (SVID → Envoy/waypoint → kernel verdict). The gate to
   extrapolate fidelity/burden to a fleet; larger effort, sequence after the pilot-start
   items.

8. **Bidirectional SOAR/EDR/identity correlation** (push socket cookie/SPIFFE to EDR/IdP),
   examiner/board-ready **compliance report** (PCI/HIPAA/SOC2/NIST 800-53 AC/AU/SI
   mappings), and an **ambient-mesh (ztunnel/waypoint) coverage answer**. Fast-follows
   that move a pilot toward production adoption.

9. **The cross-customer egress filter (D6)** as its own independently-reviewable
   milestone — server-side k>=3 + proven irreversibility + an auditable,
   contractually-guaranteed "shares nothing" OFF mode — **before any real cross-customer
   crossing.** Until then, sell the isolated mode as default and the network as future
   upside, not pilot value.

10. **Supply-chain hardening:** signed agent releases + a stated path to a third-party
    eBPF security review. A real pilot-to-production gate for the skeptic and regulated
    personas the plan does not currently address.

## Honesty + positioning guidance (the meta-point every persona raised)

Every persona named the same thing as the founder's biggest asset: **intellectual
honesty about the gaps.** A founder who names their own weaknesses (single-node, no
integrations, simulated peers, east-west-only, the canary-avoider problem) earns more
trust than one who hides them — and it is what tells the panel the planned deviants
page is a real answer, not a dodge. Protect this asset; do not spend it.

**Pre-empt the framing trap.** "Zero false positives by construction" is true about the
**trigger** — only a canary touch arms a response (rule 8). It is **not** a claim of
zero **operational** risk. Agent bugs, perf regressions, a misplaced decoy a legit
service reaches, and false **negatives** (the quiet canary-avoider) are all real. The
panel will push hard on this rhetorical slide; get ahead of it by stating plainly that
a misplaced decoy *is* a real FP path and showing the placement/verification methodology
that prevents it (must-have #9).

**Position and price as a tripwire layer, not a platform.** CanarySting is an
**east-west-with-canaries tripwire layer** — defense-in-depth — explicitly **NOT a
detection platform**. No north-south, no endpoint. Sell it as the feature in their
stack that lets them safely auto-respond on east-west, not as a replacement for NDR or
EDR. Over-claiming coverage is the fastest way to lose this panel.

**Do not sell the simulated cross-customer moat as pilot value.** It is a `doc.go` stub
with simulated peers; the SOC persona assigns it **zero** pilot value and the regulated
CISO will "assume the worst and keep egress fully off." Ship **"shares nothing / fully
isolated"** as the *default* and contractual baseline; present the network as future
upside. The on-screen honesty fences in the demo (staged-names caption, "simulated flow
but real detection," window-observed recurrence) are **trust controls the panel will
test** — never present hashed adjacency as if the engine knows service names, never imply
the deviants page auto-*catches* the careful attacker (it surfaces for a human; claiming
otherwise re-introduces the very anomaly-detection FP behavior rule 8 exists to prevent).

**Strong-wants worth building toward** (these convert, in priority order):

- The **live red-team / purple beat**: an operator deliberately traverses *without*
  tripping a wire → it surfaces #1 on the deviants page (and as a faint anomalous
  east-west edge on the topology map that never reaches the decoy ring). The skeptic
  says this single demo converts them more than any architecture slide — and the staged
  `careful-mover` is exactly what enables it.
- **Board-ready attacker-cost / dwell metrics:** "contained the flow in X ms, attacker
  burned Y on tarpit/poison, zero real data egressed" — measured, framed as
  defender-cost-flat vs attacker-cost-climbing.
- **Detection-efficacy side-by-side vs existing NDR:** canary touches CanarySting caught
  vs what the customer's existing east-west detections caught over the same window —
  quantify the *marginal* coverage to justify spend.
- **Sized operational cost:** FTE-hours/week to run, who triages the hunting page, decoy
  lifecycle/refresh effort, agent upgrade cadence. If it needs a dedicated analyst the
  customer doesn't have, the deal dies on headcount regardless of detection quality.

## Open questions for the founder

The synth's `open_questions_for_founder`, verbatim in intent:

1. SIEM egress is not on the roadmap and all 4 CISOs gate the pilot on it — can a
   minimal one-way push (CEF/syslog + webhook, stable schema, ATT&CK tags) be pulled
   **forward** ahead of the control plane and the moat work? What is the realistic
   effort, given the engine already carries the event by socket cookie (but **not** the
   rich identity/L7 — see §SIEM capture dependency)?

2. The current simdriver has no canary-avoiding flow, so the deviants page has no hero
   row today. Will you commit the `careful-mover` worker (path-set asserted disjoint from
   `canaryPaths`) as part of the deviants build, since the pilot's marquee answer depends
   on it being demonstrable, not planned?

3. Can the tamper-evident audit record + verifiable timed kill-switch + RBAC/audited
   command palette be **decoupled** from the immature M8/M10 control plane and shipped as
   standalone controls? The regulated CISO's GC vetoes auto-mode without the per-event
   evidence record + dry-run history.

4. What is the explicit, **dated** timeline to multi-node + a real control plane +
   CNI-coexistence proof on a real cluster? Every persona will pilot single-node but none
   will sign a production commitment off single-node results — and they want the timeline
   stated up front.

5. Do you have (or can you run in-pilot) a red-team/purple-team result where an operator
   deliberately traverses without tripping a canary *and* it surfaces on the deviants
   page? Is the staged `careful-mover` enough, or do you need a live operator beat?

6. Can you publish measured inline latency (p50/p99/p99.9) + CPU/node overhead and a
   kernel/distro support matrix, and is an **async-only** "engine-off-the-hot-path"
   detection mode a supported posture? Platform and regulated are blocked on the
   engine-down → fail-closed-403-on-legit-traffic case.

7. For the pilot, will you position and price as an east-west-with-canaries **tripwire
   layer** (defense-in-depth), explicitly **not** a detection platform, and explicitly
   **not** sell the simulated cross-customer moat as pilot value? Over-claiming on coverage
   or the moat is the fastest way to lose this panel's trust.

8. What is your near-term answer on **supply-chain integrity** — signed agent releases and
   a path to a third-party review of the eBPF programs — given that running a kernel-jailing
   agent is itself a new attack surface and a kernel panic is a reportable incident in
   regulated environments?

9. **Operational cost:** can you size the FTE-hours/week to run this and triage the hunting
   page, plus decoy lifecycle/refresh effort and agent upgrade cadence? If it needs a
   dedicated analyst the customer doesn't have, the deal dies on headcount.

10. **Decoy placement:** what is the methodology to verify decoys are reachable and
    believable in the *customer's* real environment (not pre-seeded demo data), and how do
    you prevent a misplaced decoy that a legitimate service reaches — the one real
    false-positive path that undercuts "zero-FP by construction"?
