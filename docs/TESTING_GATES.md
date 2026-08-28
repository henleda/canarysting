# CanaryPlatform testing gates

The repository uses one standard-library Go runner (`cmd/testgate`) and two versioned JSON manifests under `test/gates/`. Make and GitHub Actions call the same check IDs. The runner executes argument arrays directly; manifests do not expose shell evaluation, arbitrary host commands, model tools, cluster-admin, or arbitrary network targets.

## Preferred loop

First full diagnostic run:

```sh
make check-merge-local
```

Repair loop:

```sh
make check-last-failed
# or, when no failure ledger exists:
make check-fast
```

Final proof for this repository task's declared tier:

```sh
make check-merge VALIDATION_TIER=local
```

A targeted replay proves a repair. Only the final full gate proves merge readiness. `check-fast` and every `*-last-failed`, `*-one`, and `*-repeat` target are diagnostic tools, never merge qualification.

## Gate hierarchy

| Gate | Scope | Merge evidence |
|---|---|---|
| `make preflight` | Cheap toolchain, manifest, fixture/target/port, formatting, generation, package, frontend, and eBPF discovery checks. Independent failures collect. | No |
| `make check-fast` | Conservative checks affected by local changes; unknown impact expands to `check-local`. | No |
| `make check-local` / `make check` | Complete non-privileged local suite. `make check` is the compatibility alias. | No |
| `make check-adversarial` | Full bounded local adversarial scenario manifest. | No |
| `make check-last-failed` | Compatible failed/blocked IDs, prerequisites, and conservative affected expansion after working-tree changes. | No |
| `make check-merge-local` | Preflight, static, generated, unit/integration/race, frontend, local DGX-harness, locally supported eBPF build, self-check, and adversarial nodes. | Local tier only |
| `make check-dgx` | Explicit read-only DGX safety preflight. It does not pretend to execute a task-specific kernel/Kubernetes/attacker proof. | No |
| `make check-merge` | Runs the full local qualification. `VALIDATION_TIER=local` may pass; non-local tiers deliberately fail closed after DGX preflight until the task-specific approved qualification and artifact are represented. | Yes, for the declared tier only |

DGX integration, privileged eBPF, Kubernetes end-to-end, and attacker/correlation work still requires the exact plan task's repository-owned DGX procedure, before/after evidence, cleanup, and artifact. A generic read-only host check cannot satisfy that tier.

## Execution graph and semantics

`test/gates/checks.json` records, for every node: ID, label, direct command arguments, dependencies, gates, timeout, privilege, isolation key, concurrency group, default failure class, cleanup handler, supported platforms, and replay command. `test/gates/adversarial-scenarios.json` supplies scenario nodes. The runner validates unknown fields, duplicate IDs, dependencies, durations, failure classes, privilege declarations, local target allowlists, required ground truth, and cycles before executing a scenario.

Independent ready nodes run with bounded parallelism (`JOBS=<n>`, default half the logical CPUs capped at six). A concurrency group or isolation key runs once per scheduling wave. Output is buffered per node, capped at 4 MiB, and printed only as concise progress; detailed output goes to the node log. A dependency executes once even when several nodes require it, which is recorded as DAG reuse. Go's content-addressed build/test cache and the existing npm installation remain authoritative caches; mutable scenario state is never cached or shared.

Ordinary failure behavior:

- Record `FAIL`, preserve the log, continue unrelated checks.
- Mark only downstream nodes `BLOCKED`, naming each failed prerequisite.
- Treat any required failure or block as a nonzero gate.
- A platform-inapplicable optional compile node is `SKIPPED` with the supported-platform reason; it is not presented as executed coverage.

Safety behavior:

- A safety-critical check, credential-like log output, or safety-critical cleanup/after-state failure raises `SAFETY STOP`.
- The runner starts no further privileged or adversarial node, runs the current node's bounded cleanup, preserves redacted diagnostics, and exits nonzero.
- Scenario target validation permits only loopback in the local manifest. Qwen/Ollama is not invoked and receives no tool or shell authority.
- DGX and privileged checks remain explicit, serial, and outside ordinary local iteration.

The mandatory stop conditions for future privileged manifests are: target outside the approved lab allowlist; unexpected external destination; BPF/Kubernetes/process residue; connectivity degradation; namespace/cgroup/port/staging escape; credentials in logs; response-scope excess; unapproved write credential; missing before-state; unverifiable after-state; or failed emergency cleanup. Such nodes must provide an exact recovery handler and manual recovery text before they may enter a qualifying gate.

## Result model

Every run creates `.test-artifacts/gates/<run-id>/` containing:

- `summary.txt`, `summary.json`, and `junit.xml`
- `environment.json` and `dependency-graph.json`
- `failed-checks.json`, `blocked-checks.json`, and `skipped-checks.json`
- `timing.json`, `repro.sh`, and `logs/<check-id>.log`

The console and durable summaries show `PASS`, `FAIL`, `BLOCKED`, `SKIPPED`, or `SAFETY STOP`, duration, failure class, direct reproduction, and log path. Failure classes are product, test, build, environment, missing prerequisite, cleanup, nondeterministic/flaky, safety invariant, timeout, or unknown. `make check-report` reprints the latest summary.

Development-validation evidence is a local, synthetic operational data class. It may contain source/test diagnostics but must not contain credentials, customer traffic, canary values, or production payloads. Output is capped and credential-like material is replaced before writing. Artifacts reside only in the developer/CI workspace under its encryption boundary, are ignored by Git, are prohibited from model training/use, and derive from the recorded source/toolchain/manifest/environment fingerprints. Recommended local retention is 72 hours; deletion is exact run-directory removal by the developer or CI retention policy. There is no legal-hold feature; a required hold must be exported through an approved evidence process. Derived summaries are invalid when their run is deleted. Expected storage is a few MiB per run plus bounded logs (maximum 4 MiB per node).

## Replay and repeat

```sh
make check-last-failed
make check-adversarial-last-failed
make check-one CHECK=go-test-race
make adversarial-one SCENARIO=canary-touch-verdict
make check-repeat CHECK=go-test-race COUNT=10
make adversarial-repeat SCENARIO=bounded-attrition COUNT=10
```

`LAST_FAILED` points to the newest failing ledger. Replay requires the same source revision, toolchain, manifest versions/content, and environment. An exact working-tree match replays failed and blocked IDs plus prerequisite closure. If the working tree changed at the same revision, the runner records that fact and adds conservative affected checks. A revision, toolchain, manifest, or environment mismatch refuses replay and requires `check-fast` or a wider gate. The new run links to its parent ID.

A diagnostic retry may be requested directly with `testgate run --diagnostic-retry`. If the retry passes, the original check stays failed and is classified `nondeterministic or flaky behavior`; both logs, seed, and timing remain. There are no silent retries or quarantines.

## Affected selection

Selection uses the local working tree and never fetches. The current conservative map is:

| Change | Selected impact |
|---|---|
| Gate runner, manifests, Makefile, or workflow | Full local suite plus gate self-tests |
| Any Go/module change | Vet, build, full race suite; security-layer changes also select both self-checks and every adversarial scenario |
| `internal/contract`, engine, sting, adapters, identity, operator, deploy, attacker | Wide security/adversarial selection |
| `bpf/` | All local eBPF checks, Go race suite, adversarial scenarios |
| Dashboard | Frontend config, lint, and build |
| DGX scripts | Every local DGX harness contract check |
| Protobuf/operator-generation input | Applicable drift check and Go race suite |
| Documentation/skill/gitignore | Structural preflight |
| Unknown | Full local suite |

This mapping is a speed feature, not a coverage exemption. Shared-model and uncertain changes deliberately expand.

## Adversarial manifest

Each scenario declares its ID/version, title/objective, target scope, binaries/services/privilege, allowed hosts/ports, fixtures, deterministic seed, setup/actions, expected observations, expected CanaryView evidence, expected CanarySting behavior, prohibited outcomes, timeout, cleanup, after-state assertions, isolation key, replay, `AttackerIntent`, `AttackerAction`, and ground truth. Per-run JSON records expected/observed/missing evidence, incorrect joins, identity/correlation/response/cleanup result, seed, and scenario version.

The present local scenarios are deterministic legacy fixture proofs, not a claim that the roadmap CanaryAttacker/Qwen correlation laboratory exists. They use only Go test fixtures and loopback. The bounded Qwen tool policy, live CanaryView evidence correlation, and DGX scenarios remain M2C/M2D work and cannot be inferred from this gate.

## Previous gate inventory and baseline

Before this refactor, `make check` was the serial dependency line `generated-check frontend-check dgx-harness-check fmt-check vet build test selfcheck`. Every Make recipe and `set -e` script stopped at its first failure; a failure in any target prevented every later target. No target emitted a durable check ID, graph, log, JUnit, compatibility fingerprint, or reproduction ledger.

| Old command | Purpose / approximate warm duration | Dependencies / authority / network | Artifacts, cleanup, repetition, replay |
|---|---|---|---|
| `scripts/generated.sh check all` | Protobuf and operator/CRD drift; about 1s | Pinned Go/protoc tools; local, no network when installed | Temp dir removed; proto failure prevented operator check; component replay existed but was not printed |
| `make frontend-check` | npm presence, lint, Next build; about 8s | Existing `node_modules`; local, no install/network | `.next`; lint stopped build; no ledger/replay |
| `make dgx-harness-check` | shell syntax plus seven local harness contract suites; about 20s warm | Bash/Go/file tools; no DGX/network; temp fixtures | Each script cleans exact temp state, but target stopped at first script; build/copy suites rebuilt ARM64 fixtures repeatedly |
| `make fmt-check` | Go formatting; under 1s | gofmt; local | None; direct target replay only |
| `make vet` / `make build` | Static/compile checks; roughly 1–3s warm each | Go toolchain/cache; local | Repeated package loading/compilation; no ledger |
| `make test` | All Go tests with race; roughly 4s warm | Go toolchain/cache; root-gated eBPF cases skip off Linux/root | Go package output only; no durable logs/direct check ID |
| `make selfcheck` | Sting then Envoy executable self-checks; under 2s warm | Go build cache; local | First failure stopped second; no logs/replay |
| `make bpf` / `make test-ebpf` | Linux compile / privileged datapath | Linux clang+BTF / Linux root+cgroup-v2 | Not in old local gate; CI-only compile and mandatory no-skip kernel proof |
| `scripts/dgx/check.sh` and task profiles | Read-only host state / explicitly approved integration proofs | SSH to fixed `falcon1`; task-dependent privilege | Bounded task artifacts and exact cleanup; intentionally outside local iteration |

The clean-tree warm-cache baseline on 2026-08-27 passed in approximately 35.4 seconds. Because it passed, no first defect existed and every stage was reached; static inspection identified all serial fail-fast boundaries. Repeated Linux/ARM64 fixture builds and repeated Go package loading were visible. New timings are recorded per node and total in every `timing.json`. A reduction in repeated *full-suite invocations* is the primary improvement; raw wall-clock improvement is claimed only when comparable measurements support it.

The first complete new gate used an intentionally isolated cold Go cache and passed 33 nodes, with two explicit Darwin eBPF skips, in 364.11 seconds (`.test-artifacts/gates/20260828T010003.305040000Z`). The race suite accounted for 274.72 seconds. This is not comparable evidence of a raw speedup and is recorded as a remaining cold-cache bottleneck. The demonstrated workflow improvement is that the single scenario failure was replayed with prerequisites in 0.47 seconds instead of rerunning the entire suite; the final broad gate still executed all required local checks.

## GitHub Actions

Ordinary Go/harness, frontend, eBPF compile, and bounded adversarial jobs invoke the same manifest gates (`check-ci-*`) and upload `.test-artifacts/gates/` on success or failure. The privileged eBPF job retains its additional structured no-skip/PASS-floor assertion because folding that safety proof into an ordinary local runner would weaken its boundary. It uses the same `make test-ebpf` leaf and remains mandatory CI evidence.
