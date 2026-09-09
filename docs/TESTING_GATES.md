# CanaryPlatform testing gates

The repository uses one standard-library Go runner (`cmd/testgate`) and two versioned JSON manifests under `test/gates/`. Make and GitHub Actions call the same check IDs. The runner executes argument arrays directly. Adversarial definitions are narrower still: validation accepts only an exact, uncached, race-enabled `go test -json` command for a declared repository fixture package and an anchored list that exactly equals the required tests. The manifests do not expose shell evaluation, arbitrary host commands, model tools, or cluster-admin.

## Preferred loop

Edit loop:

```sh
make check-fast
```

Recommended local pre-push check:

```sh
make check-pr-local
```

Repair a compatible failure ledger:

```sh
make check-last-failed
# or, when no failure ledger exists:
make check-fast
```

Authoritative PR proof:

```sh
# CI invokes this with the automatic/effective risk classification.
make check-pr
```

A targeted replay proves a repair. Only the final risk-appropriate Level 2 gate proves PR readiness. Level 3 (`make check-integration-full`) qualifies an integration batch, nightly build, or release; it is not required after each repair or before each push. See `docs/CI_TESTING_STRATEGY.md` for the policy and tradeoffs.

## Gate hierarchy

| Gate | Scope | Merge evidence |
|---|---|---|
| `make preflight` | Cheap toolchain, manifest, fixture/target/port, formatting, generation, package, frontend, and eBPF discovery checks. Independent failures collect. | No |
| `make check-fast` | Level 0 changed-package/reverse-dependent/static/invariant selection; unknown impact expands. | No |
| `make check-pr-local` / `make check` | Level 1 full static/build/non-race suite plus affected race/integration/replay/frontend/eBPF checks. | Recommended before push; not CI evidence |
| `make check-pr` | Level 2 risk-selected local graph. CI adds applicable privileged/DGX jobs. | Yes, with every risk-selected CI job |
| `make check-local` | Legacy complete non-privileged local suite. | No |
| `make check-adversarial` | Full bounded local adversarial scenario manifest. | No |
| `make check-last-failed` | Compatible failed/blocked IDs, prerequisites, and conservative affected expansion after working-tree changes. | No |
| `make check-integration-full` / `make check-merge-local` | Level 3 complete local race/integration/replay/frontend/eBPF/harness graph. | Integration/nightly/release evidence |
| `make check-campaign` | Level 4 deterministic prerequisites. Scheduled CI additionally requires the bounded live campaign, which currently fails closed pending the re-baselined M2D laboratory. | Campaign evidence only when all live jobs pass |
| `make check-dgx` | Explicit read-only DGX safety preflight. It does not pretend to execute a task-specific kernel/Kubernetes/attacker proof. | No |
| `make check-merge` | Compatibility interface for explicit full tier qualification; not the ordinary PR command. | Integration/release evidence for the declared tier only |

DGX integration, privileged eBPF, Kubernetes end-to-end, and attacker/correlation work still requires the exact plan task's repository-owned DGX procedure, before/after evidence, cleanup, and artifact. A generic read-only host check cannot satisfy that tier.

## Execution graph and semantics

`test/gates/checks.json` records, for every node: ID, label, direct command arguments, dependencies, gates, timeout, privilege, isolation key, concurrency group, default failure class, cleanup handler, supported platforms, and replay command. `test/gates/adversarial-scenarios.json` supplies scenario nodes. The runner validates unknown fields, duplicate IDs, dependencies, durations, failure classes, privilege declarations, local target allowlists, required ground truth, and cycles before executing a scenario.

Independent ready nodes run with bounded parallelism (`JOBS=<n>`, default half the logical CPUs capped at six). A concurrency group or isolation key runs once per scheduling wave. Checks that fingerprint the checkout share `workspace-build` isolation with eBPF compilation and object assertion, preventing transient compiler output from changing deterministic source manifests. Output is buffered per node, capped at 4 MiB, and printed only as concise progress; detailed output goes to the node log. Credential detection scans the complete stream, including bytes beyond the retained-log cap and matches split across writes. A dependency executes once even when several nodes require it, which is recorded as DAG reuse. Go's content-addressed build/test cache and the existing npm installation remain authoritative caches; mutable scenario state is never cached or shared.

Ordinary failure behavior:

- Record `FAIL`, preserve the log, continue unrelated checks.
- Mark only downstream nodes `BLOCKED`, naming each failed prerequisite.
- Treat any required failure or block as a nonzero gate.
- A platform-inapplicable optional compile node is `SKIPPED` with the supported-platform reason; it is not presented as executed coverage.

Safety behavior:

- A safety-critical check, credential-like log output, or safety-critical cleanup/after-state failure raises `SAFETY STOP`.
- The runner starts no further privileged or adversarial node, runs the current node's bounded cleanup, preserves redacted diagnostics, and exits nonzero. A safety stop is never diagnostically retried.
- `SIGINT`/`SIGTERM` terminates the active process group, runs cleanup with its own bounded non-cancelled context, blocks work not yet started, and writes the interrupted run's artifacts.
- Scenario target validation permits only loopback in the local manifest, arbitrary scenario commands are rejected, the HTTP attacker fixture independently rejects non-loopback target URLs, and process-group absence is checked after every scenario command. Qwen/Ollama is not invoked and receives no tool or shell authority. This local boundary does not claim to be an OS network sandbox for future fixture code; any new network-capable fixture requires an explicit test-only allowlist seam or a privileged/DGX isolation gate before admission.
- DGX and privileged checks remain explicit, serial, and outside ordinary local iteration.

The mandatory stop conditions for future privileged manifests are: target outside the approved lab allowlist; unexpected external destination; BPF/Kubernetes/process residue; connectivity degradation; namespace/cgroup/port/staging escape; credentials in logs; response-scope excess; unapproved write credential; missing before-state; unverifiable after-state; or failed emergency cleanup. Such nodes must provide an exact recovery handler and manual recovery text before they may enter a qualifying gate.

## Result model

Every run creates `.test-artifacts/gates/<run-id>/` containing:

- `summary.txt`, `summary.json`, and `junit.xml`
- `risk.json` with automatic/effective classification, reasons, and remote profiles
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

`LAST_FAILED` points to the newest failing ledger. Replay requires the same source revision, toolchain, manifest versions/content, and environment. An exact working-tree match replays failed and blocked IDs plus prerequisite closure. If the working tree changed at the same revision, the runner records that fact and adds conservative affected checks. A revision, toolchain, manifest, or environment mismatch refuses replay and requires `check-fast` or a wider gate. The new run links to its parent ID. An adversarial-only subset replay never replaces or clears a parent ledger containing unresolved non-adversarial checks; only a complete successful failure replay may clear it.

A diagnostic retry may be requested directly with `testgate run --diagnostic-retry`. If the retry passes, the original check stays failed and is classified `nondeterministic or flaky behavior`; both logs, seed, and timing remain. There are no silent retries or quarantines.

## Affected selection

Selection uses the union of the local working tree and committed branch changes since the locally available `origin/main` merge base (falling back to local `main`, then `HEAD`) and never fetches. The current conservative map is:

| Change | Selected impact |
|---|---|
| Gate runner, manifests, Makefile, or workflow | Gate self-tests plus broad Level 2; Level 3 runs through main/nightly/integration |
| Any Go/module change | Affected compile/tests and reverse dependents in Level 0; full build/non-race in Level 1/2; affected race unless HIGH/CRITICAL expands to full race |
| `internal/contract`, engine, sting, adapters, identity, operator, deploy, attacker | Wide security selection and path-matched deterministic replay; unknown security impact selects the full replay corpus |
| `bpf/` | All local eBPF checks, Go race suite, adversarial scenarios |
| Dashboard plus the Go-backed trace fixture/projection/handler | Frontend config, lint, build, and zero-retry Playwright against the canonical Go projection when selected; fixture-only or projection-only changes cannot bypass the browser gate |
| DGX scripts | Relevant local DGX harness contracts plus CRITICAL remote profile selection; trace proof paths select `dgx-trace`, while `attackercheck` paths select the inspection-only `dgx-attacker-check` |
| Protobuf/operator-generation input | Applicable drift check and Go race suite |
| Documentation/skill/gitignore | Structural preflight |
| Unknown | HIGH broad Level 2 selection |

This mapping is a speed feature, not a coverage exemption. Shared-model and uncertain changes deliberately expand.

## Adversarial manifest

Each scenario declares its ID/version, title/objective, target scope, binaries/services/privilege, allowed hosts/ports, fixtures, deterministic seed, setup/actions, expected observations, expected CanaryView evidence, expected CanarySting behavior, prohibited outcomes, timeout, cleanup, after-state assertions, isolation key, replay, `AttackerIntent`, `AttackerAction`, ground truth, validation forms, affected paths, live-smoke profile, and exact test names that must report `PASS` in the Go JSON event stream. Port `0` means an OS-assigned ephemeral port and is valid only with a loopback host declaration. Per-run JSON records declarations separately from parsed observed/missing test evidence; it does not manufacture identity, correlation, or CanaryView evidence from a zero exit code. Cleanup status and process-group after-state are recorded independently.

The local scenarios are deterministic fixture proofs, not a claim that the complete CanaryAttacker/Qwen correlation laboratory exists. The M2C.3 closed executor and M2C.4 bounded planner add exact loopback DGX smokes; they do not supply real Kubernetes targets or live CanaryView evidence correlation. Those capabilities remain M2C.5/M2D work and cannot be inferred from this gate.

## Previous gate inventory and baseline

Before this refactor, `make check` was the serial dependency line `generated-check frontend-check dgx-harness-check fmt-check vet build test selfcheck`. Every Make recipe and `set -e` script stopped at its first failure; a failure in any target prevented every later target. No target emitted a durable check ID, graph, log, JUnit, compatibility fingerprint, or reproduction ledger.

| Old command | Purpose / approximate warm duration | Dependencies / authority / network | Artifacts, cleanup, repetition, replay |
|---|---|---|---|
| `scripts/generated.sh check all` | Protobuf and operator/CRD drift; about 1s | Pinned Go/protoc tools; local, no network when installed | Temp dir removed; proto failure prevented operator check; component replay existed but was not printed |
| `make frontend-check` | npm presence, lint, Next build; about 8s | Existing `node_modules`; local, no install/network | `.next`; lint stopped build; no ledger/replay |
| `make dgx-harness-check` | shell syntax plus twelve local harness contract suites (including the M2B.2 read-only DGX-stack, M2B.3 unprivileged correlation, M2B.4 unprivileged trace-construction, and M2C.1 passive attacker-readiness proofs); duration depends on the additional deterministic ARM64 proof builds | Bash/Go/file tools; no DGX/network; temp fixtures | Each script cleans exact temp state, but target stops at the first script; build/copy suites rebuild ARM64 fixtures repeatedly |
| `make fmt-check` | Go formatting; under 1s | gofmt; local | None; direct target replay only |
| `make vet` / `make build` | Static/compile checks; roughly 1–3s warm each | Go toolchain/cache; local | Repeated package loading/compilation; no ledger |
| `make test` | All Go tests with race; roughly 4s warm | Go toolchain/cache; root-gated eBPF cases skip off Linux/root | Go package output only; no durable logs/direct check ID |
| `make selfcheck` | Sting then Envoy executable self-checks; under 2s warm | Go build cache; local | First failure stopped second; no logs/replay |
| `make bpf` / `make test-ebpf` | Linux compile / privileged datapath | Linux clang+BTF / Linux root+cgroup-v2 | Not in old local gate; CI-only compile and mandatory no-skip kernel proof |
| `scripts/dgx/check.sh` and task profiles | Read-only host state / explicitly approved integration proofs | SSH to fixed `falcon1`; task-dependent privilege | Bounded task artifacts and exact cleanup; intentionally outside local iteration |

The clean-tree warm-cache baseline on 2026-08-27 passed in approximately 35.4 seconds. Because it passed, no first defect existed and every stage was reached; static inspection identified all serial fail-fast boundaries. Repeated Linux/ARM64 fixture builds and repeated Go package loading were visible. New timings are recorded per node and total in every `timing.json`. A reduction in repeated *full-suite invocations* is the primary improvement; raw wall-clock improvement is claimed only when comparable measurements support it.

The first complete new gate used an intentionally isolated cold Go cache and passed 33 nodes, with two explicit Darwin eBPF skips, in 364.11 seconds (`.test-artifacts/gates/20260828T010003.305040000Z`). The race suite accounted for 274.72 seconds. This is not comparable evidence of a raw speedup and is recorded as a remaining cold-cache bottleneck. The demonstrated workflow improvement is that the single scenario failure was replayed with prerequisites in 0.47 seconds instead of rerunning the entire suite; the final broad gate still executed all required local checks.

## GitHub Actions

PR CI first records explainable LOW/STANDARD/HIGH/CRITICAL risk, then runs one shared Level 2 local graph. Frontend and eBPF prerequisites are installed only when selected. Privileged and DGX jobs wait for that graph and run only when required; every selected implemented DGX profile runs with its own exact-cleanup run ID derived from the checked-out head, and any unsupported profile fails the job closed. `scripts/dgx/pr-batch.sh` preserves that per-profile remote isolation while sharing one private, alias-resolved SSH control connection across all selected coordinators; the batch owns only that local connection, and each ordinary coordinator still owns its exact remote cleanup. Bootstrap allows three 20-second connection attempts only before any profile begins; once the master is verified, child clients cannot open a fallback transport if it is lost. Because changes to shared cleanup, coordination, or transport can affect both kernel proofs and live-model recovery, `scripts/dgx/cleanup.sh`, `scripts/dgx/pr.sh`, `scripts/dgx/pr-batch.sh`, and `scripts/dgx/ssh-control.sh` each select both `dgx-kernel` and `dgx-attacker-loop` and require live-Qwen authorization. The `dgx-attacker-check` mapping runs only the exact passive M2C.1 inventory, bypasses the general BPF-capability preflight, emits a minimized non-secret summary, and keeps live-Qwen authorization false. `dgx-attacker-executor` runs the M2C.3 closed loopback executor, while `dgx-attacker-loop` runs the M2C.4 one-proposal fixed-Qwen proof, requires synchronized time, at least one GPU, and at least 40 GiB available memory, and verifies prompt-free exact-model unload before deleting its stage. Its read-only preflight precedes lock-file creation. One remote supervisor owns the exclusive shared-model lock and the reviewed proof process group; it waits for proof-group termination and then retains the lock through the independent unload postcheck and recovery-marker retirement. HUP/INT/TERM terminates and waits for the complete group before lock release. Every nested GNU `timeout` uses foreground mode, keeping the bounded artifact and cleanup invocations in that supervised group. A remote supervisor that survives local SSH-client loss continues holding the lock until the bounded proof exits. A strict run-owned marker created immediately before possible model load is the only authority to unload Qwen; an absent marker forbids cleanup from unloading a model owned by another process. Ollama's unload acknowledgement does not retire that authority: the marker remains until the independent inspector proves zero loaded models while the same exclusive lock is held. If that scenario-specific unload or zero-loaded postcheck fails, the coordinator preserves the marker, verified stage, and trusted unload artifact; generic cleanup must not delete the recovery path. PR concurrency cancels superseded commits; the DGX job has its own per-PR cancellation group and 20-minute overall timeout. Feature pushes do not duplicate the PR workflow. Failed jobs upload `.test-artifacts/gates/`; the compact risk decision is always retained. DGX jobs require the repository-level `canarysting-dgx-controller` self-hosted Mac runner documented in `docs/DEVELOPMENT_ENVIRONMENT.md`; an unavailable runner leaves the job queued and never permits a weaker substitute. Its persistent local Go cache is reused directly rather than uploaded through `actions/setup-go`.

For M2C.4, “independent” means independent of the model-unload acknowledgement, not a second remote session. The same flock-owning SSH supervisor accepts the proof and then one fixed finalization program. That program rechecks stable Ollama identity, loopback-only owned listeners, the pinned model ID, and zero loaded models before marker retirement. Linux regressions cover client EOF during both supervised phases and supervisor signals during finalization; the lock cannot become available until the active process group has terminated.

Pushes to `main`, nightly schedules, and integration dispatches run Level 3 once. Weekly and campaign dispatches proceed to Level 4 only after Level 3 succeeds. The live campaign step is scheduled but deliberately fails closed until M2C.5 supplies real Kubernetes fixtures and the remaining M2D campaign contract exists; the bounded M2C.4 loopback smoke is not substituted. The privileged `ebpf-privileged` check retains its structured zero-skip PASS floor when selected.
