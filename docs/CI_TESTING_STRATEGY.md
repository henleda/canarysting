# CanaryPlatform risk-tiered CI strategy

This document defines the validation policy for pull requests, integration batches, and releases. It changes orchestration and frequency, not test meaning: no test is removed, no required assertion becomes a warning, and uncertain impact expands coverage.

## Validation levels

| Level | Command / trigger | Required content | Budget |
|---|---|---|---|
| 0 — edit loop | `make check-fast` | Changed-package compile/tests, inexpensive reverse dependents, changed static/generated/frontend/eBPF checks, gate self-tests, and applicable fast invariants. | 3 minutes |
| 1 — local PR precheck | `make check-pr-local` | Full formatting/static/build/non-race Go suite; affected race/integration/frontend/eBPF checks; deterministic affected adversarial replay; schema and drift checks. | 10 minutes |
| 2 — authoritative PR | CI calls `make check-pr` | Level 1 definitions plus automatic risk selection, required invariants, affected replay, and any selected privileged/DGX smoke. | LOW/STANDARD 15 minutes; HIGH/CRITICAL 30 minutes |
| 3 — integration qualification | `make check-integration-full`; main/integration batch, nightly, release candidate, or on demand | Complete local race/integration/replay/frontend/eBPF/harness graph plus the complete implemented DGX kernel matrix. | Measured and scheduled |
| 4 — soak/campaign | `make check-campaign`; weekly, major release, attacker/response change | Level 3 prerequisites plus repeated seeds, concurrency/resource/cleanup stress, resilience, performance, and bounded live Ollama/Qwen campaigns. | Measured and scheduled |

Level 0 and targeted replay are repair evidence, not merge evidence. Level 1 is recommended before push and does not replace CI. Level 2 is the PR authority. Level 3 is deliberately not required after every repair or before every push.

The repository does not yet contain the bounded Ollama/Qwen runtime or its approved tool catalog. The scheduled Level 4 workflow therefore fails closed at that exact boundary rather than pretending deterministic legacy fixtures are a live campaign. Re-baselined M2D, decomposed by the preserved detailed M2C/M2D rows in `docs/DEVELOPMENT_PLAN.md`, is the unblock path.

## Automatic risk classification

`make check-risk` writes `.test-artifacts/gates/risk.json` and prints the automatic risk, effective risk, reasons, selected check IDs, remote profiles, and executable/frontend/eBPF/gate flags. It uses the local merge base when available and never fetches. A `risk:standard`, `risk:high`, or `risk:critical` PR label or `RISK=<level>` can increase coverage. A lower label is recorded and ignored.

| Risk | Representative paths | PR policy |
|---|---|---|
| LOW | Prose, docs, slides, comments/non-executable material | Level 1 plus Level 2 light profile; no DGX |
| STANDARD | Ordinary Go/UI code, isolated parsing/model work | Full Level 2; affected race/UI/replay as applicable |
| HIGH | Contracts, engine, identity, scope, scoring, adapters, operator/deploy/config, or gate orchestration | Broad Level 2 race/security/replay profile; selected remote smoke only when the path map requires it |
| CRITICAL | `bpf/`, containment, DGX execution/cleanup, attacker tool authority | Broad Level 2 plus relevant privileged or DGX qualification |

Multiple matches choose the highest. Unknown paths are HIGH. Manual CRITICAL with no mapped profile produces an unsatisfied remote profile and fails closed rather than guessing.

## Conservative path-to-gate map

| Change area | Level 0/1/2 selection | DGX selection |
|---|---|---|
| Docs/slides/prose | Structural/schema/config checks | None |
| Dashboard/operator UI | Lint/build and affected Go/UI checks | None unless deployment integration changes |
| CanaryView model/evidence/provenance/correlation | Relevant Go/replay/invariant checks; shared contracts expand | None unless runtime identity/reference environment changes |
| Connectors | Schema/parser/replay/capability fixtures; no vendor write | Only when part of the approved reference stack |
| Engine, Sting, contract, trigger, scope | Full fast invariants, broad Go/race checks, affected deterministic replay | Selected datapath smoke only when kernel behavior changes |
| `bpf/`, cgroup, kernel, cookiespike/enforcespike | All local eBPF compile/contract checks and privileged proof | `kernel-full` or enforcement profile with exact cleanup |
| Operator, Kubernetes identity/manifests/deploy | Unit/envtest when present, broad local security checks | Kubernetes smoke is selected but currently fails closed because that M2 profile is not implemented |
| CanaryAttacker scenario/runner/tool | Schema, bounded-policy tests, deterministic replay | Live smoke is selected for tool-authority changes; currently blocked on re-baselined M2D |
| Test-gate orchestration | Gate self-tests, synthetic collect-all, broad Level 2 local graph | Level 3 through main/nightly/integration; DGX harness changes also select the relevant DGX profile |

Go selection computes changed packages and repository reverse dependents from `go list -deps -test -json`. Module changes and unresolved package impact expand to `./...`. Scenario selection uses each manifest entry's `affected_paths`; unmapped security impact expands to the complete deterministic corpus.

## Fast deterministic security invariants

Every executable PR runs the `security-invariants` check. It requires named Go JSON `PASS` events for canary-touch-only triggering, zero baseline-only response, hard failure instead of global scope, forged-scope rejection, zero-cookie refusal, precise bystander-safe containment, unattributable observe-only behavior, bounded scenario commands, cleanup/safety-stop behavior, credential redaction beyond the retained-log limit, and external destination rejection before dial. Missing named events fail the gate even when `go test` exits zero.

The full suites retain redirect, integration, race, eBPF, and scenario variants. The fast list is a deterministic floor, not a replacement for affected/full tests.

## Adversarial placement

1. **Deterministic replay (Levels 1–3).** Versioned manifests record `AttackerIntent`, `AttackerAction`, deterministic seed, expected evidence/response, prohibited outcomes, exact required test passes, cleanup, ground truth, affected paths, and replay command. PRs select relevant entries; uncertain impact selects all.
2. **Targeted live smoke (Level 2 HIGH/CRITICAL only).** One or two fixed scenarios, approved DGX target, strict timeout, one workflow preflight/build/transfer, and exact cleanup. The current bounded kernel `cookie`, `enforcement`, and `kernel-full` profiles are implemented. Kubernetes and live-Qwen profiles refuse weaker substitution until their planned harnesses exist.
3. **Full live campaign (Level 4).** Weekly/on-demand only. The workflow is scheduled, but its Qwen step intentionally fails closed pending re-baselined M2D. It must eventually measure trace completeness, identity/correlation accuracy, evidence gaps, response precision, resource ceilings, cleanup, and repeatability without giving Qwen shell, SSH, Kubernetes, Docker, filesystem, or unrestricted network authority.

## DGX capacity and safety

PR concurrency is keyed by PR number with cancellation enabled, and checkout is pinned to the latest PR head SHA. Remote work depends on a green local Level 2 job. `scripts/dgx/pr.sh` accepts only fixed profiles and run IDs. A compatible workflow performs one `check.sh` preflight, one allowlisted ARM64 build, and one checksum-verified transfer. A short-lived run/revision/host-bound proof lets compatible leaf scenarios reuse that inspection; leaf stage verification, before/after assertions, platform health checks, safety stops, and cleanup remain mandatory.

Mutable state is isolated by run ID. Immutable artifacts may be reused only within that compatible workflow. The coordinator cleans exact scenario/stage state on every exit. Unsupported profiles fail closed. Developers must not run the same full DGX matrix manually and in CI for the same commit.

## CI topology and merge policy

Feature-branch pushes no longer start a second full workflow: PR events run Level 2, while pushes to `main`, nightly schedules, and integration dispatches run Level 3. A single Level 2 local job installs each affected toolchain/dependency once; privileged and DGX jobs start only after it passes. Gate logs are buffered by check ID and uploaded on failure; the small risk decision is always retained.

- LOW: Level 2 light profile.
- STANDARD: Level 2.
- HIGH: broad Level 2 and any selected smoke.
- CRITICAL: broad Level 2 plus mandatory relevant privileged/DGX evidence.
- Level 3: main/integration batch, nightly, on demand, and release promotion.
- Level 4: weekly/on demand and major release/attacker-response qualification.

Direct merges plus nightly qualification are faster but permit `main` to contain a defect until post-merge Level 3 completes. A merge train is slower to promote but batches approved PRs and proves the batch with Level 3 before it becomes qualified `main`. When fully qualified `main` is mandatory, use the merge train; GitHub plan limitations currently leave that operating control procedural.

## Timing and repair workflow

Each timed gate records its budget and `timing_budget_exceeded` in console/JSON without turning the first over-budget implementation into a false product failure. Over-budget checks create optimization work; they never justify removing coverage or weakening assertions.

```sh
# edit loop
make check-fast

# recommended before push
make check-pr-local

# repair a compatible failure ledger
make check-last-failed

# final local view of the risk-selected PR gate
make check-pr

# scheduled/integration proof, not an every-repair command
make check-integration-full
```

Baseline evidence on 2026-08-28: the old warm complete local gate took 68.65 seconds at `.test-artifacts/gates/20260828T180353.250803000Z`; the prior cold local measurement was 364.11 seconds, dominated by a 274.72-second race compile. A recent pre-refactor GitHub run's longest duplicated Go job took 12m35s, with both push and PR workflows running for the same change.

The first new `check-fast` completed its selected graph in 30.23 seconds while collecting two independent introduced test-gate failures; direct replays took 0.28s and 2.57s after the incompatible ledger correctly refused replay. The final exact-tree Level 0 graph passed in 22.62s at `.test-artifacts/gates/20260828T185941.425479000Z`. A pre-deduplication Level 1 run passed in 67.49s and showed the broad Go suite repeating manifest-owned adversarial tests. After those tests were made single-owner, the first changed-command Level 1 run passed in 325.40s: the non-scenario Go suite fell from 33.99s to 21.77s, but the changed race command incurred a 190.33s cold compile. The immediately compatible Level 3 run hit that cache (race 2.51s) and passed its complete 34-node local graph in 103.64s with two honest Darwin eBPF skips at `.test-artifacts/gates/20260828T185454.886105000Z`.

These measurements prove the intended reduction in repeated scenario work and repeated full-suite invocations. They do not yet prove a hosted-CI wall-clock improvement: the final authoritative PR workflow has not run because this task forbids committing/pushing, and cold Go race compilation remains the primary local bottleneck.
