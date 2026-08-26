# CanarySting Development Environment

This document defines the supported development split between the Mac workstation and the DGX Spark integration node. It records capabilities and risks, never credentials. `AGENTS.md` remains authoritative for architecture and safety; `docs/DEVELOPMENT_PLAN.md` controls task order and completion.

## Environment model

The Mac is the canonical source and build environment. Source editing, Go development, unit tests, static analysis, generated-code checks, cross-compilation, CI-equivalent checks, and Git operations happen here. Do not make the DGX the canonical checkout and do not edit source on it unless the user explicitly requests that exception.

The DGX Spark is the canonical Linux ARM64 integration environment. It is used for K3s, Cilium coexistence, Envoy integration, eBPF load/attach, socket-cookie and cgroup behavior, kernel enforcement, workload identity, NetworkPolicy, operator/DaemonSet deployment, and end-to-end validation. It is also CanaryPlatform's initial correlation laboratory: CanaryView will compare observations from the local Kubernetes/Cilium/Hubble/Envoy/kernel/CanarySting stack against controlled CanaryAttacker ground truth there. Synthetic lab evidence remains execution output governed by `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`; it is not canonical source and must remain isolated from production baselines and customer models.

The build/execution boundary is deliberate. The Mac owns source, builds, tests, manifests, and Git history. The DGX executes checksum-identified ARM64 artifacts and declarative lab fixtures from repository scripts. Do not create a canonical source checkout or edit source directly on the DGX; a remote staging directory is an execution input, not a development workspace.

Preferred flow:

1. Select one task and validation tier from `docs/DEVELOPMENT_PLAN.md`.
2. Edit and complete Tier A validation on the Mac.
3. Cross-build only named Linux/ARM64 artifacts on the Mac with `scripts/dgx/build.sh`.
4. Run `scripts/dgx/check.sh` before any remote mutation.
5. Transfer only named artifacts to a run-specific directory beneath `/var/tmp/canarysting/`.
6. Execute a repository script; collect logs and before/after state.
7. Remove only resources bearing the run identifier, then verify K3s/Cilium/connectivity and BPF state.
8. Record evidence in `docs/DEVELOPMENT_PLAN.md`.

## Mac workstation

Verified 2026-08-24:

- macOS 26.6 on ARM64.
- Go 1.25.3 (`go.mod` remains the version authority for builds).
- Git, Make, Apple Clang, `protoc`, Docker, Node, and npm are present.
- This repository is the canonical checkout.

Mac builds must not silently depend on DGX state. eBPF C compilation and privileged runtime checks are Linux validations even when Go userspace cross-compiles successfully on macOS.

## DGX Spark

Connection uses the existing SSH alias `falcon1`; scripts must not embed an address, password, key, token, or kubeconfig. Expected hostname is `spark-5343`. A hostname or architecture mismatch is a hard stop.

Read-only verification on 2026-08-24 found:

- Ubuntu 24.04.4 LTS, ARM64, NVIDIA kernel `6.17.0-1031-nvidia`.
- 20 CPU cores, about 121 GiB memory, and a 3.7 TB root NVMe volume.
- K3s `v1.36.3+k3s1` active; the single node was Ready; K3s uses containerd.
- Cilium CLI `v0.19.7`; Cilium/operator `1.19.5` and Cilium Envoy were healthy (1/1 each). Hubble Relay and ClusterMesh were disabled.
- cgroup v2, bpffs, readable kernel BTF, and BPF JIT enabled.
- kernel support for `sock_ops` and `cgroup_skb`.
- root cgroup attachments were Cilium-owned multi-attach programs; no CanarySting attachment was observed.
- Docker, `bpftool`, K3s, kubectl, Cilium CLI, and Ollama were present. Go and Clang were absent.
- The local Ollama model `qwen3-coder:30b-a3b-q8_0` was observed in an earlier environment review. Its current presence, version, loopback binding, and readiness were not re-verified by this architecture bootstrap and must be checked read-only before a future CanaryAttacker task depends on it.
- no CanarySting Kubernetes resources, matching test pods, NetworkPolicies, CiliumNetworkPolicies, process, or named BPF program/map was found.
- an earlier interrupted validation left `/tmp/canarysting-m15.Nq0THn` and the Docker image `ubuntu:24.04`. These are historical test artifacts, not a source checkout or product deployment; remove them only through an explicitly authorized cleanup task.

Facts above are observations, not permanent assumptions. Re-run `scripts/dgx/check.sh` before depending on them. The first Cilium CLI call must set `KUBECONFIG=/etc/rancher/k3s/k3s.yaml`; without it, the CLI falls back to an unusable localhost configuration.

## DGX harness contract

The repository-owned entry points are:

- `check.sh` — read-only host, cluster, Cilium, BPF, policy, and CanarySting inventory.
- `build.sh` — deterministic, offline Mac Linux/ARM64 builds from an allowlisted target catalog. It requires an explicit destination outside the repository whose parent already exists, refuses to overwrite it, separates `product/` from `test/`, and writes `manifest.tsv` plus `SHA256SUMS` with source-state evidence. Here `product/` means a deployable-component artifact rather than a test diagnostic; it does not assert production maturity. Use `--list` to inspect the catalog; for example: `scripts/dgx/build.sh --output-dir /tmp/canarysting-build-m1b2 --target cookiespike`. The local Go toolchain and module cache must already satisfy the build; the script never downloads or installs them.
- `build_test.sh` — focused local regression proof for the build harness. It verifies input refusals, product/test separation, ARM64 ELF output, manifest checksums, overwrite protection, and byte-identical repeated builds.
- `copy.sh` — checksum-verified transfer of a `build.sh` output directory to the fixed `falcon1` alias. It requires a strict run ID, validates the exact local manifest/allowlist/filesystem inventory, verifies `spark-5343` and ARM64 before mutation, uploads to `/var/tmp/canarysting/.incoming-<run-id>`, repeats the validation remotely, and atomically publishes `/var/tmp/canarysting/<run-id>`. Existing stages are never overwritten, pre-finalization failures remove only their exact incoming directory, `--dry-run` performs no SSH access, and `--verify-only` rechecks a published stage read-only. Successful stages are retained explicitly for the named downstream run until the cleanup workflow removes them.
- `copy_test.sh` — focused local negative coverage for transfer inputs, including corrupt or missing artifacts, unexpected files, symlinks, unsafe manifest paths, malformed inventories, and invalid run IDs.
- `run.sh` — deterministic execution of one fixed profile from a verified immutable artifact stage. It accepts no arbitrary command, argument, timeout, path, or privilege. The initial `engine-selfcheck` and `engine-timeout-probe` profiles are unprivileged, in-memory, listener-free, database-free, and BPF-free. Each profile has a hardcoded timeout and expected outcome. Bounded logs plus an atomic `result.tsv` are written to the explicit sibling `/var/tmp/canarysting/execution-<run-id>` directory; an existing evidence directory is never overwritten, and the script verifies no artifact process remains.
- `run_test.sh` — focused local coverage for the execution profile catalog, dry-run contract, input validation, and arbitrary-command/argument/privilege refusals.
- `collect.sh` — fixed-schema collection of one verified M1B run. It accepts only a strict run ID and a new absolute output directory outside the repository; verifies the remote artifact stage and execution evidence; bounds all files; refuses credential-like material before transfer; rechecks transfer digests; runs the read-only DGX state checker; removes ANSI presentation codes; and atomically publishes mode-0600 files beneath a mode-0700 directory with a manifest and SHA-256 inventory. It never accepts an arbitrary remote path and never reads kubeconfig or Kubernetes Secret contents. `--dry-run` is local-only; `--fixture-dir` exercises the same local schema/sensitivity checks without SSH.
- `collect_test.sh` — focused collection coverage for schema/checksum linkage, exact inventory, output modes, retention/model-use metadata, overwrite and arbitrary-path refusal, wrong run identity, manifest drift, symlinks, and negative bearer/kubeconfig-secret fixtures.
- `cleanup.sh` — exact-run, idempotent cleanup for the generic M1B harness. A required strict run ID resolves only `/var/tmp/canarysting/.incoming-<run-id>`, `/var/tmp/canarysting/<run-id>`, and `/var/tmp/canarysting/execution-<run-id>`. Before removing any candidate, the remote half verifies the expected host/architecture, root and entry ownership, non-symlink types, fixed artifact/evidence schemas, published-stage checksums, evidence run identity, and absence of a process executing from the stage. `--inspect` validates remotely without mutation; `--dry-run` does not access the DGX. A normal cleanup proves each exact path absent and runs the full read-only DGX checker afterward. Repeating it against absent state is a successful no-op.
- `cleanup_test.sh` — focused local coverage for exact path derivation, excluded state, strict run IDs, mutually exclusive modes, and refusal of arbitrary paths, broad cleanup, historical cleanup, or privilege escalation.
- `cookiespike.sh` — the M1C observe-only socket-cookie proof. It accepts only a strict run ID and fixed run/inspect/cleanup modes, verifies the immutable `test/cookiespike` stage, and runs the artifact as root under a 15-second timeout in `/sys/fs/cgroup/canarysting-dgx/<run-id>`. The binary creates one loopback connection, rebuilds the Envoy remote-to-local tuple, resolves it through the production staleness guard, compares the nonzero result with `SO_COOKIE`, proves an absent tuple remains unattributable, and proves close-delete with an error-preserving map lookup. The harness observes `canary_sockops` live on the exact child and absent from its parent/root, compares complete program/map/link ID inventories and root cgroup attachments before/after, fails closed when any BPF inventory cannot be read, refuses pre-existing named CanarySting BPF/process state, and never loads enforcement. Stdout and stderr are each capped while being drained; discarded output makes the run fail without allowing either file to exceed 1 MiB. The fixed three-file evidence directory is bound to the verified artifact checksum and validated for exact modes, byte counts, checksums, and required result fields before read-only inspection. Cleanup removes only the run's empty child cgroup, M1C evidence, and verified artifact stage, and is idempotent.
- `enforcespike.sh` — future precise containment/Cilium coexistence proof.
- `deploy.sh` — future declarative product deployment, distinct from test fixtures.

`enforcespike.sh` and `deploy.sh` remain bootstrap scaffolds and currently fail closed. The generic cleanup intentionally excludes Kubernetes resources, BPF objects and attachments, containers and images, system configuration, product deployments, and historical artifacts. `cookiespike.sh` owns only its exact temporary child cgroup and evidence directory; M1D, deployment, and explicitly authorized maintenance workflows must define their own similarly narrow ownership and cleanup.

M1C proof evidence is `development-validation-evidence` with `internal-operational` sensitivity. It contains only the run ID, artifact checksum, loopback tuple/cookie proof markers, bounded stdout/stderr, timestamps, fixed safety results, and hashes of the root attachment inventory; it contains no customer traffic, credential, request body, canary value, kubeconfig, or Secret data. Each file is capped at 1 MiB and the only intended retention is the short run→inspect→record→cleanup interval on the DGX. Legal hold is unsupported, deletion is the exact idempotent `--cleanup` path, residency is the DGX filesystem, encryption inherits the operator-managed host boundary, model use is prohibited, lineage is the source-tree/artifact checksum plus run ID, and expected storage is well below 3 MiB per run. Durable non-secret conclusions belong in `docs/DEVELOPMENT_PLAN.md`, not in retained raw proof files.

Collected M1B bundles are `development-validation-evidence` with `internal-operational` sensitivity. They use an explicit 72-hour ephemeral retention profile and carry collection/expiration timestamps, payload size, source mode, checksum lineage, residency, encryption-boundary, and model-use metadata. The collector does not schedule hidden deletion: the operator removes the exact local output directory at or before expiration after durable non-secret conclusions have been recorded in the development plan. Legal hold is intentionally unsupported for this temporary bundle; evidence needing a hold must be exported through a future governed case store. Local filesystem encryption and residency are operator-managed, model use is prohibited, and the bundle must never feed production baselines or customer models. Refusal—not partial masking—is the boundary for credentials, canary secret values, authorization headers, kubeconfig key/certificate data, request bodies, and other prohibited payloads.

## Validation tiers

### Tier A: local

Use for documentation, pure Go logic, serialization, generated code, static analysis, and non-kernel refactors. Typical gates are formatting, vet, focused and race tests, build, generated drift checks, and frontend lint/build when relevant.

### Tier B: local plus DGX integration

Required for `bpf/`, socket cookies, cgroups, kernel enforcement, Cilium interaction, ARM64 behavior, Envoy-to-kernel attribution, DGX scripts, and low-level networking. Tier A must pass, followed by the relevant deterministic DGX proof and cleanup verification.

### Tier C: local plus DGX Kubernetes end-to-end

Required for identity, Kubernetes ingestion, the operator, CRDs/manifests, DeceptionPolicy reconciliation, workload scope mapping, policy ingestion, Kubernetes-derived graphs, complete request-to-verdict behavior, and Kubernetes enforcement. Tier A and relevant Tier B primitives must pass before the DGX K3s end-to-end test.

### Tier D: DGX attacker/correlation

Required for CanaryAttacker scenarios, Ollama/Qwen execution, ground-truth emission, and correlation-quality claims. Tier A and any relevant Tier B/C primitives must pass first. A Tier D run gathers before-state, emits intent, executes only bounded allowlisted tools, gathers independent observations, correlates them against ground truth, calculates declared metrics, cleans run-owned state, and gathers after-state.

## CanaryAttacker safety boundary

The DGX model may plan only through a reviewed structured tool catalog such as bounded HTTP requests, DNS lookups, TCP connects, endpoint enumeration, same-target link following, explicit lab-fixture credential attempts, and response inspection. The model does not receive arbitrary shell, SSH, Kubernetes, Docker, filesystem, or unrestricted network access. The executor—not the model—enforces target allowlists, method/payload rules, redirects, timeouts, concurrency, request/body/token budgets, credential references, and cancellation.

Every scenario is confined to a dedicated CanarySting lab fixture and emits `AttackerIntent` before an action and `AttackerAction` after it. These records are declared harness ground truth, never trusted network telemetry. Independent Cilium/Hubble, Envoy, kernel, Kubernetes, and CanarySting observations determine correlation quality. Versioned synthetic ground truth may be retained indefinitely as a development-lab evaluation corpus, but it must be marked synthetic and remain outside production baselines, customer behavior models, and production incident statistics. Scenarios must stop processes, remove only run-labeled execution state, verify connectivity/Cilium/BPF after cleanup, and never retain secret values in evidence. See `docs/CANARYATTACKER_ARCHITECTURE.md` and `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`.

## Operating and cleanup rules

Before any DGX mutation, run `scripts/dgx/check.sh`, inspect local Git status, state the exact remote changes and cleanup, and verify that they belong to the selected task. Do not install host packages or alter K3s, Cilium, firewall, SSH, kernel configuration, or system services implicitly.

For eBPF tests, inventory attachments first, use the smallest cgroup/hook scope and a multi-attach-safe mechanism where supported, never replace Cilium programs, collect before/after state, detach CanarySting-owned programs, delete only CanarySting-owned maps/links, and verify unrelated connectivity after cleanup.

For Kubernetes tests, prefer a dedicated namespace, apply declarative manifests, label every resource with the project and unique run identifier, never read or print Secret data, and remove only those labeled resources. Cleanup must be idempotent and must prove the cluster, Cilium, connectivity, BPF attachments, processes, and staging state returned to the recorded baseline.

## Security baseline and hardening backlog

The following lab risks were observed previously and remain backlog items unless a later read-only check proves otherwise:

1. **Highest priority: `/etc/rancher/k3s/k3s.yaml` is mode `0644` and contains cluster-admin credentials.** Correcting its permissions requires explicit approval and post-change K3s/Cilium validation.
2. The current user has passwordless sudo and cluster-admin access; reduce routine workflows to a least-privilege ServiceAccount and narrowly scoped sudo/capabilities.
3. UFW is inactive.
4. SSH listens beyond loopback.
5. The Kubernetes API listens beyond loopback.
6. Cilium health/metrics endpoints, including observed ports 4240 and 9964, listen beyond loopback.
7. Cilium host firewall was previously observed disabled or not configured.
8. Cilium network encryption was previously observed disabled or not configured.
9. No workload NetworkPolicies or CiliumNetworkPolicies existed at the 2026-08-24 inspection.

Do not batch-fix these during ordinary development. Each correction needs an explicit task, approval, rollback, and before/after health evidence. Never commit kubeconfig contents, private keys, bearer tokens, Secret values, or copied credentials.
