# CanarySting — GAP_REPORT Verification (Milestone 0, code-grounded)

**Status of this document:** verification + planning only. No feature code was written. No
existing file was modified. This is the code-grounded delta the GAP_REPORT itself asked for
("the agent that can see the code should still run a quick verification pass").

**What was verified against:** the actual source tree at HEAD (branch `main`), the three pivot
docs (`docs/ARCHITECTURE_SPEC_K8S.md`, `docs/BUILD_TASK_PLAN.md`, `docs/GAP_REPORT.md` — renamed
from their original `CanarySting_*.md` filenames, see §0), CLAUDE.md core rules 1–11, and the
per-layer docs each area references.

**Method:** an 18-agent verification fan-out — one assessor per package area (implemented vs
stub, with file:line evidence and doc cross-check); an assess→adversarially-refute pipeline over
the four load-bearing invariants (the two non-negotiable ones got a dedicated skeptic trying to
find a counterexample in code); and a collision check of the five proposed net-new package names.
Findings were then cross-checked by hand against the contract source and a local toolchain run.

**Independent confirmation (run by hand, not just agent-reported):**
- `go build ./...` → clean (exit 0).
- `go test` on the load-bearing correctness packages → all `ok`: `internal/contract`,
  `internal/engine/{scope,scoring,baseline,calibration,tiers,observebaseline}`,
  `internal/intelligence/network`, `internal/sting/{attrition,containment,killswitch,killswitch/principals}`,
  `adapters/envoy{,/identity}`.

---

## 0. Process divergence (resolved / pending)

1. **Doc filenames — RESOLVED.** CLAUDE.md's K8s-native section referenced
   `docs/ARCHITECTURE_SPEC_K8S.md`, `docs/BUILD_TASK_PLAN.md`, `docs/GAP_REPORT.md`, but the files on
   disk were `docs/CanarySting_*.md`. The three files have now been renamed to the CLAUDE.md names
   (zero references to the old names existed anywhere, so the rename is non-breaking and makes the
   CLAUDE.md references resolve). Decided + done.
2. **CLAUDE.md "Status" + pivot integration — RESOLVED.** CLAUDE.md has been updated: the pending
   "INSERT / SMALL EDIT" meta-blocks were woven into the body (the K8s-native section, core rules 10–11,
   and the observe-before-enforce / mesh-identity safety rules are now canonical), the `## Status` text
   was corrected from "early scaffold" to the verified mid-flight reality, stale details were refreshed
   (bpf `observe`/`sockops`/`enforce`; engine `baseline`/`observebaseline`/`persist`), and this review's
   decisions (identity consolidation, M1 watch-items) are reflected. Done.

---

## 1. Headline delta against GAP_REPORT.md

**`GAP_REPORT.md`'s central premise is wrong, and it told us it might be.** It was written from the
README + CLAUDE.md only, both of which self-describe the repo as "early scaffold… most files are
placeholders with signatures and TODOs." **That is false.** The repo is substantially, and in most
layers fully, implemented production-grade Go with comprehensive passing tests. There were **zero**
`panic("not implemented")`/empty-body stubs found in any assessed area except the nginx adapter.

### What the GAP_REPORT got RIGHT (its structural conclusions hold)
- **"The pivot extends the repo, it does not fight it."** Correct. Every load-bearing decision in
  the Architecture Spec maps onto code that already exists and already honors it.
- **The nine core rules are upheld in code** (verified per-rule below). The pivot is almost entirely
  additive.
- **The genuine gaps it named are real:** no Kubernetes deployment model (no DaemonSet, no operator,
  no CRDs); no operator/CRD layer; no mesh identity integration; no blast-radius *graph* in the
  PERMITTED/ADVERSARIAL sense; no K8s API ingestion; scope key not yet mapped to K8s
  namespaces/clusters. All confirmed absent.
- **Conflicts are scope-narrowing, not contradictions** (generic-east-west → K8s-only; nginx
  deprioritized; engine-service → DaemonSet+operator is additive). Confirmed.

### What the GAP_REPORT got WRONG
- **Gap item 6 — "eBPF baseline likely stub-level."** Wrong. `bpf/observe`, `bpf/sockops`, and
  `bpf/enforce` are real, committed-`.o`, root-gated-integration-tested eBPF datapaths (details §2).
- **The blanket "early scaffold / placeholders + TODOs" framing.** Wrong for engine, canary, sting,
  contract, intelligence, the Envoy adapter, and bpf. These are the most-built parts of the system.
- **"`deploy/` is a stub."** Wrong — `deploy/` holds a large, real demo harness (`m7-window/` with a
  mesh sim, prober, SIEM sink, spend ledger, load profiles, red-team harness). Not K8s manifests, but
  not a stub.

### What SURPRISED me (net-new facts the GAP_REPORT could not have known)
- **The blast-radius "narrow case" substrate already exists.** `internal/engine/observebaseline/topology.go`
  is a fully-implemented OBSERVED node/edge store (directed `src→(dst,port)` edges with
  counts/bytes/first-seen/last-seen, role classification, cap+TTL eviction, gob persistence,
  `TopologySnapshot`). This is exactly the OBSERVED-edge ground truth the proposed `internal/graph`
  must reuse under **rule 10**. The graph work is "add PERMITTED + ADVERSARIAL edges + dark-reachability
  + transitive closure on top of the existing observed store," not "build a graph from scratch."
- **Two packages are already named `identity`** — `internal/topology/identity` (SPIFFE/IP workload-name
  resolver) and `adapters/envoy/identity` (the socket-cookie L7↔kernel join). This directly affects the
  proposed `internal/identity` (see §5).
- **Sting is ahead of its own docs.** All five attrition axes have working generators, including AX4
  (exploit-burn) and AX5 (operational-exposure) which `docs/ATTRITION_FIVE_AXIS_DESIGN.md` still marks
  as deferred.
- **The Envoy adapter runs the live M6 attrition pump**, which `docs/ADAPTERS.md` still describes as a
  future seam.
- **The intelligence egress filter exceeds its design doc** (D6/D7 ledger, aggregation, transport are
  built though `docs/EGRESS_FILTER_DESIGN.md` §7.2 lists them deferred).
- **A milestone vocabulary is already pervasive** (M1–M7, AX0–AX5, D2/D5/D6/D7, B1) — this is a
  mid-flight, milestone-tracked codebase, not a fresh scaffold.

---

## 2. Stub-vs-implemented status by package

Legend: ✅ implemented (real logic + passing tests) · 🟡 partial/seam · ⛔ stub.

| Area | Status | Evidence (representative) | Matches docs? |
|---|---|---|---|
| `internal/contract` (+ `api/proto`, `api/gen`, `api/convert`, `api/enginegrpc`) | ✅ | Full type set: `SignalEvent`→`Engine.Submit`→`Verdict`; imports only stdlib `time` (rule 3 clean). gRPC transport with compile-time `contract.Engine` assertions. | partial — see drift in §4 |
| `internal/engine` core (`engine.go`, `scoring`, `tiers`, `calibration`, `feedback`, `scope`, `persist`) | ✅ | `Score = Base×M` (scoring.go:213–231); tier discipline enforced *and* config-validated (tiers.go:92–116); rule-7 triad (calibration.go); fail-closed scope (scope.go:81–103); bbolt scope-partitioned persist incl. hash-chained audit log. | yes |
| `internal/engine/baseline` + `observebaseline` | ✅ | Multiplier math matches `BASELINE_MULTIPLIER.md` exactly (bounded/floored-at-one/multiplicative, 5 invariants unit-tested); `observebaseline/topology.go` = OBSERVED graph substrate; deviants are Score=0, display-only. | partial — D5 term, see §3 watch-item |
| `internal/canary` (`catalog`, `seeder`, `signal`) | ✅ | Seed weights 1.8/1.5/1.2/1.1/1.0 match `CANARY.md`/`DECOY_WEIGHTS.md`; 3-layer harmlessness; scope-partitioned registry; touch→`SignalEvent` only via real placement. | yes |
| `internal/sting` (`attrition`, `containment`, `killswitch`, `killswitch/principals`) | ✅ | All 5 attrition axes have real generators; per-flow budget + host governor + kill switch; containment refuses cookie 0; bearer-token RBAC admin (loopback, 401/403, audited). | yes (code ahead of docs) |
| `internal/intelligence` (15 subpkgs; focus `network/`) | ✅ | Single default-deny egress chokepoint, type-enforced, ledger-verified-only egress, AX4/AX5 triple-blocked, structural `go list -deps` import guards. ~11k LOC, all green. | yes (code ahead of docs) |
| `bpf/observe`, `bpf/sockops`, `bpf/enforce` | ✅ | Real cgroup/sockops C programs all keyed on `bpf_get_socket_cookie`; committed `.o`; root-gated precision/oracle integration tests. | partial — kernel-pin gap, §3 |
| `bpf/loader` | ✅ | Interface/contract pkg; non-linux `NoopLoader` fails loud (no silent no-op enforcement). | yes |
| `adapters/envoy` (+ `identity`) | ✅ | Full ext_proc server; thin (machine-enforced by `guard_test.go`); live M6 attrition pump; socket-cookie resolver + staleguard. | partial — doc stale |
| `adapters/nginx` | ⛔ | 15 lines: struct + TODO, no `Process`, no tests. The one genuine stub. | matches "thinner, later" framing |
| `cmd/operator`, `internal/operator`, `internal/graph`, `internal/k8s`, `internal/identity` | ⛔ (absent) | Net-new for the pivot; none exist yet. | n/a |

Also present and real (beyond the GAP_REPORT's map): `internal/dashboard` (backend + tap + topology/deviant/journey/fingerprint views), `internal/topology/identity`, `internal/harmless`, `internal/llm` (Anthropic client + scripted attacker for red-team sim), `internal/boot` (composition root), `internal/transport/grpccreds`, and the `deploy/m7-window` demo harness.

---

## 3. Load-bearing invariant verdicts

All four hold in code. Both **non-negotiable** invariants survived a dedicated adversarial
refutation pass (a skeptic agent that tried to find a counterexample and failed).

| Invariant (rule) | Verdict | Decisive evidence | Test |
|---|---|---|---|
| **Socket-cookie is the sole L7↔kernel join (rule 4)** | ✅ holds · refutation failed | Every datapath (`sockops`/`observe`/`enforce`) and `containment`/`scoring` keys on the cookie; SPIFFE & PID/Cgroup explicitly "context, never the join key" (contract.go:26–32). | sockops cookie-oracle + layout-parity tests |
| **Scope isolation fails closed (rule 5)** ⚠ non-negotiable | ✅ holds · refutation failed | Resolver never returns `("",nil)`; `engine.New`/`boot.Build` refuse to start on unresolved scope; wire scope is re-resolved, never trusted; per-scope bbolt sub-buckets via a single `scopeSub` chokepoint. | `TestSubmit_ForgedScopeCannotDriveCrossScopeState`, cross-scope no-bleed tests across 5 pkgs |
| **Canary-touch-only trigger (rule 8)** ⚠ non-negotiable | ✅ holds · refutation failed | `Score = base×M`, `base` accrues only from `ev.Canary` touches, `M∈[1,M_max]` → base 0 ⇒ Score 0 "guardrail in arithmetic"; deviants/topology/novelty are Score=0, display-only; `sting`/`tiers`/`scoring` do **not** import `observebaseline`. | `TestScore_ZeroBaseStaysZeroUnderAnyMultiplier`; deviant armed/non-armed/normal tests |
| **Thin adapter / proxy-agnostic engine (rules 1,2)** | ✅ holds · refutation failed | `go list -deps ./internal/engine/...` → zero adapters, zero proxy SDK; adapter closure forbids engine/ebpf/intelligence/containment via `guard_test.go`. | `TestAdapterImportsAreThin` (executable import guard) |

No CLAUDE.md core rule (1–11) is violated anywhere in the assessed code.

### Watch-items (not violations — defense-in-depth / hygiene, worth a decision)
1. **eBPF kernel-version pin is missing (spec asks for it).** The Architecture Spec says "Pin a
   minimum kernel version that provides a system-global socket cookie." No `features.Have*` /
   version gate exists in any Go loader; the only mention is a CI provisioning note ("kernel ≥ 5.10")
   in `TECHNICAL_ARCHITECTURE.md` §12.4, not a runtime assertion. Containment precision depends on the
   never-reused-cookie property, which is currently *assumed* at runtime, not *verified*. → Add a
   startup kernel-capability assertion. Good first-class task for Milestone 1.
2. **`ReportOutcome` trusts the wire scope.** `capturingEngine.ReportOutcome` (boot.go:964–986) does
   not re-resolve `rec.Scope` the way `Submit` does. The adversarial pass confirmed it is *mitigated*
   (per-scope event-store isolation + `AmendOutcome` empty-scope refusal prevent cross-scope
   aggregation), so it is **not** a current violation — but re-resolving scope on this path too would
   make the rule-5 defense uniform.
3. **No engine-side import-guard test.** The thin-adapter seam is machine-enforced on the *adapter*
   side only. A symmetric `go list -deps` test asserting `internal/engine` never imports an adapter or
   proxy SDK would close the loop (the property holds today; nothing enforces it against regression).
4. **`FeedbackLabel`/`FeedbackSink` are absent from the proto boundary.** Rule 7's single calibration
   signal exists in the Go contract but has no proto message/RPC, so feedback cannot cross the gRPC
   boundary. Fine if feedback is intended to stay engine-process-local; a real gap if not. Decide
   intent and either document it or mirror it.
5. **Doc/code drift to reconcile (honesty discipline, spec §10):** the D5 baseline-sharpening term
   (`α·FingerprintMatch`, off-by-default, bounded, governed by `D2_D5_DESIGN.md`) lives inside the
   multiplier but is not in `BASELINE_MULTIPLIER.md` — reconcile so the multiplier has one source of
   truth. `STING.md`/`ATTRITION_FIVE_AXIS_DESIGN.md` (AX4/AX5 "deferred"), `ADAPTERS.md` (attrition
   "seam"), and `EGRESS_FILTER_DESIGN.md` §1.1/§7.2 all describe as future things that are now built.
   Minor cosmetic: `internal/canary/catalog/generators.go:53` comment says `CSTING-CANARY-<token>` but
   the marker is `x-ref-`.

---

## 4. Contract / proto drift (rule 3 is clean; mirror is incomplete)

The contract itself is exemplary: `internal/contract` imports only `time`; dependencies point inward.
The proto **mirror** is the source of truth only for the core request/verdict/outcome boundary
(`SignalEvent`/`Verdict`/`StingOutcome`/`OutcomeRecord` + `Engine` service), with enum-value-alignment
and round-trip tests. Go-contract types **not** mirrored in proto: `FeedbackLabel`/`FeedbackSink`
(watch-item §3.4), `StingFloor`, `DriverObservation`, and a dedicated `AttritionAxis` message (the
bitset rides as `uint32`). `StingFloor`/`DriverObservation` omissions are defensible by design (bound
at the composition root / in-process seam). Treat the proto as mirroring the *engine RPC* boundary,
not the entire Go contract — and say so in the proto header.

---

## 5. Proposed final package layout (collision check on the five net-new names)

| Proposed | Collision? | Verdict |
|---|---|---|
| `cmd/operator` | none | **use as-is.** No operator binary in `cmd/`. `canaryctl` stays as the human CLI alongside it. |
| `internal/operator` | none | **use as-is.** No controller-runtime/CRD code exists. |
| `internal/k8s` | none | **use as-is** (read-only client-go ingestion → PERMITTED edges, rule 11). `internal/permitted` is the only acceptable alt. |
| `internal/graph` | name clean; **functional overlap** | **use as-is, with a rule-10 constraint.** Heavy overlap with the already-built OBSERVED store in `internal/engine/observebaseline/topology.go` (+ dashboard topology views). `graph` must *consume* `observebaseline.TopologySnapshot` for OBSERVED edges and add only the net-new parts (PERMITTED + ADVERSARIAL edges, dark-reachability, transitive reachable-set, ranking). It must **not** fork the observed data path. The name `graph` is correct precisely because `topology` is already taken by the observed-map feature. |
| `internal/identity` | name clash → **consolidate (DECIDED)** | Two packages are already named `identity`: `internal/topology/identity` (SPIFFE/IP workload-name resolver, importguard-locked to stdlib/config so it stays production-importable) and `adapters/envoy/identity` (the socket-cookie join). **Decision: do the larger consolidation** — give workload identity a single home under `internal/identity/` rather than a third scattered package. See the chosen layout below. |

### Chosen identity layout — consolidation (DECIDED)

The operator chose the larger, long-term-stable consolidation over the lighter sub-package split.
Rationale: workload identity is "the spine" in the spec, so it should have one conceptual home; and
the move is far cheaper to do **now**, before any `mesh`/`labels` code is built on top of a scattered
layout, than later.

**Scope of the consolidation — two homes by *concern*, not three packages named `identity`:**
- **Move** `internal/topology/identity` → `internal/identity/naming` and **retire** the now-empty
  `internal/topology/` container. The moved package **keeps its stdlib/config-only import guard** (it
  stays production-importable for operator node-naming).
- **Leave `adapters/envoy/identity` where it is.** It is *not* workload-identity-the-spine — it is
  adapter-local socket-cookie-join plumbing, import-guarded thin (rule 1). Pulling it into
  `internal/identity` would risk that guard and conflate two different concerns. After consolidation,
  the two surviving homes are cleanly separated: `internal/identity/*` = workload identity;
  `adapters/envoy/identity` = the cookie join.
- **Add** the net-new mesh work as separate leaves so they can pull `client-go`/SPIRE **without**
  polluting `naming`'s guarded closure:
  - `internal/identity/mesh` — mesh/SPIFFE/SPIRE resolution, **primary, high-confidence**.
  - `internal/identity/labels` — label-derived fallback, **explicitly lower-confidence**.
  - `internal/identity/workload` (optional facade) — mesh → labels; feeds attribution and `internal/graph`.

**Consolidation blast radius (bounded, ~10 files, mostly import-path strings):** importers of
`internal/topology/identity` are `cmd/staged-range/main.go`, `internal/dashboard/tap/{tap.go,
topology.go, deviants.go}` (+ `tap/topology_test.go`), and the package's own
`importguard_test.go` / `democonfig_test.go`. A rename refactor with existing test coverage to catch
breakage. Schedule as the **first step of Milestone 1**, before adding `mesh`/`labels`.

### Target package set for the pivot
```
cmd/operator/              # NEW: controller-runtime operator binary
internal/operator/         # NEW: reconcile loop + CRD types (DeceptionPolicy, scope/graph config)
internal/k8s/              # NEW: read-only client-go ingestion → PERMITTED edges (rule 11)
internal/graph/            # NEW: blast-radius — OBSERVED(reuse observebaseline) + PERMITTED + ADVERSARIAL,
                           #      dark-reachability, transitive closure, ranking (rule 10)
internal/identity/
  naming/                  # MOVED from internal/topology/identity (keeps stdlib/config-only guard)
  mesh/                    # NEW: mesh/SPIFFE/SPIRE primary identity (may import client-go/SPIRE)
  labels/                  # NEW: label-derived fallback (explicitly lower confidence)
  workload/                # NEW (optional): facade preferring mesh → labels
# internal/topology/       # RETIRED (empty container after the move)
# adapters/envoy/identity/ # UNCHANGED: socket-cookie join stays adapter-local (rule 1)
```

---

## 6. Bottom line for the plan

- The substrate Milestone 1 targets (eBPF-observed, identity-attributed, socket-cookie-joined,
  per-scope-isolated flow observation) **largely already exists and is tested.** Milestone 1 is mostly
  *wrapping it in a DaemonSet + operator and adding mesh identity*, plus the kernel-version pin
  (watch-item §3.1) and the K8s scope mapping — not building the datapath.
- Milestone 4 (narrow blast radius) has its OBSERVED substrate already (`observebaseline/topology.go`);
  the graph layer is additive.
- The biggest genuinely-greenfield work is exactly what the GAP_REPORT named: the **operator/CRD layer**,
  **K8s API ingestion** (medium case), and **mesh identity** — none of which collide with existing code
  except the `internal/identity` naming, resolved above.

**Decisions log (review outcome):**
- (a) Doc filenames — **DECIDED + DONE.** Renamed to the CLAUDE.md names (§0.1). CLAUDE.md "Status"
  text update still pending (§0.2).
- (b) Identity layout — **DECIDED: larger consolidation** (§5). `internal/topology/identity` →
  `internal/identity/naming` + retire `internal/topology/`; `adapters/envoy/identity` stays put; new
  `mesh`/`labels`/`workload` leaves added. To be executed as Milestone 1's first step.
- (c) Watch-items for Milestone 1 — **DECIDED.** §3.1 (kernel-version pin), §3.2 (uniform scope
  re-resolution on `ReportOutcome`), and §3.3 (engine-side import-guard test) are all folded into
  Milestone 1. §3.4 (feedback proto mirror) and §3.5 (doc/code drift) are deferred to the milestone
  that touches them.

**STOP — still awaiting your go-ahead before Milestone 1 implementation work begins.**

### Milestone 1 opening sequence
1. **Identity consolidation** (decision b) — ✅ **DONE** (branch `feat/m1-identity-consolidation`).
   `internal/topology/identity` → `internal/identity/naming` (package `identity` → `naming`, error
   prefixes aligned to `naming:`); `internal/topology/` retired; `adapters/envoy/identity` left in place;
   the 5 importers (`cmd/staged-range/main.go`, `internal/dashboard/tap/{tap,topology,deviants,topology_test}.go`)
   updated; the production-importable import guard kept (passes on the new path). `go build ./...`,
   `go vet ./...`, and `go test ./...` all green; git records the moves as renames.
2. **Watch-items §3.1 + §3.3 + §3.2** — NEXT: startup kernel-version assertion for the system-global
   socket cookie; an engine-side `go list -deps` import-guard test; re-resolve scope on the `ReportOutcome` path.
3. **Substrate proper** (per `BUILD_TASK_PLAN.md` M1): DaemonSet + operator skeleton, mesh identity
   (`internal/identity/mesh`) primary with label fallback (`internal/identity/labels`), scope keyed to
   namespace/cluster, and the cross-scope-isolation test as an explicit gate.
