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
- `cleanup.sh` — exact-run, idempotent cleanup for the generic M1B harness. A required strict run ID resolves only `/var/tmp/canarysting/.incoming-<run-id>`, `/var/tmp/canarysting/<run-id>`, and `/var/tmp/canarysting/execution-<run-id>`. Before removing any candidate, the remote half verifies the expected host/architecture, root and entry ownership, non-symlink types, fixed artifact/evidence schemas, published-stage checksums, evidence run identity, and absence of a process executing from the stage. `--inspect` validates remotely without mutation; `--dry-run` does not access the DGX. A normal cleanup proves each exact path absent and runs the full read-only DGX checker afterward. Repeating it against absent state is a successful no-op.
- `cleanup_test.sh` — focused local coverage for exact path derivation, excluded state, strict run IDs, mutually exclusive modes, and refusal of arbitrary paths, broad cleanup, historical cleanup, or privilege escalation.
- `cookiespike.sh` — future observe-only socket-cookie correlation proof.
- `enforcespike.sh` — future precise containment/Cilium coexistence proof.
- `deploy.sh` — future declarative product deployment, distinct from test fixtures.
- `collect.sh` — future redacted log and before/after evidence collection.

`cookiespike.sh`, `enforcespike.sh`, and `deploy.sh` remain bootstrap scaffolds and currently fail closed. The user-provided project baseline records M1B.5 collection as completed, but this checkout still contains the fail-closed `collect.sh` scaffold and lacks its detailed implementation evidence. This architecture task did not replay or alter that work; reconcile the authoritative implementation/history before a future collection-dependent run. The generic cleanup intentionally excludes Kubernetes resources, BPF objects and attachments, containers and images, system configuration, product deployments, and historical artifacts. Those require separate ownership labels/manifests and narrowly scoped cleanup in their responsible M1C, M1D, deployment, or explicitly authorized maintenance workflow.

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
