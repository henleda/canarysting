---
name: canarysting-dev
description: Execute one plan-driven CanaryPlatform task across CanaryView, CanarySting, CanaryAttacker, shared platform, or development infrastructure for requests to continue, resume, take the next task, or work on Kubernetes/DGX integration.
---

# CanaryPlatform Development

Use `docs/DEVELOPMENT_PLAN.md` to select, execute, validate, and record exactly one coherent task. `AGENTS.md` remains authoritative for coding, architecture, and safety invariants.

## Orient and select

1. Read `AGENTS.md` and `docs/DEVELOPMENT_PLAN.md` fully.
2. Read `docs/DEVELOPMENT_ENVIRONMENT.md` for environment, Kubernetes, Cilium, kernel, eBPF, deployment, identity, DGX, attacker, or correlation work.
3. Read the applicable product architecture:
   - CanaryPlatform/CanaryView/shared model: `docs/CANARY_PLATFORM_ARCHITECTURE.md` and `docs/CANARYVIEW_DATA_MODEL.md`.
   - CanaryView connector or cross-vendor action work: `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`.
   - Persistence, evidence lifecycle, graph history, cases, retention, or model work: `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`.
   - CanarySting: `docs/ARCHITECTURE.md` plus the layer guidance required by `AGENTS.md`.
   - CanaryAttacker: `docs/CANARYATTACKER_ARCHITECTURE.md`.
   - Any operator-facing task: `docs/CANARYPLATFORM_OPERATOR_EXPERIENCE.md`.
4. Inspect `git status` and relevant diffs. Treat all uncommitted and untracked work as user-owned; never overwrite, discard, reset, clean, stash, or silently reformat it.
5. If one task is `IN_PROGRESS`, resume it. Otherwise select the first `TODO` task in document order whose dependencies are all `DONE`. Do not start a second task while another is `IN_PROGRESS`.
6. Classify and record the selected task before editing:
   - **PRODUCT AREA:** `CanaryView`, `CanarySting`, `CanaryAttacker`, `Shared platform`, or `Development infrastructure`.
   - **VALIDATION TIER:** `local`, `DGX integration`, `DGX Kubernetes end-to-end`, or `DGX attacker/correlation`.
   - **PR RISK:** `LOW`, `STANDARD`, `HIGH`, or `CRITICAL`, with changed-path reasons and any required remote profile. Unknown impact is `HIGH`; manual direction may only increase coverage.
7. Inspect the relevant architecture, implementation, tests, and `internal/contract/` when cross-layer behavior is involved.
8. Before editing, state the objective, acceptance criteria, expected files, product area, validation tier, DGX requirement, safety considerations, and—when operator-facing—the operator job, interaction path, and expected click count. Then mark only that task `IN_PROGRESS`.

## Product-area rules

### CanaryView

- Preserve scope isolation, provenance, explicit confidence, and immutable source observations.
- Keep vendor-specific details as evidence without making them canonical requirements.
- Retain raw-event references; distinguish source observation, correlation, inference, model interpretation, recommendation, and action.
- Reuse the existing observation path and models where appropriate; do not create a parallel source of truth.
- Keep recommendations advisory and never auto-enforce them.

### Connector work

- Read `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`, identify the connector category, and inspect the versioned `ConnectorCapabilityManifest` before designing or changing a connector.
- Start read-only and request the smallest required permission set. Never add write credentials during a collector-only task; read and write authority remain separate.
- Preserve raw evidence references and hashes when available, source and collector-observed timestamps, provenance, assertion mode, and evidence/normalization confidence.
- Keep vendor-specific fields in the bounded extension/evidence envelope. Never add a vendor-specific field to the canonical model without architecture review.
- Add category-contract schema fixtures plus checkpoint, replay, pagination/backfill, duplicate, out-of-order, delayed, partial-event, clock-skew, permission-denial, rate-limit, reconnect, raw-reference, schema-drift, upgrade, isolation, minimization, and read-only tests as applicable.
- Add operator-visible health, lag, last event, field/coverage gaps, schema warnings, permissions, authority, and capability state; expose the same manifest to the agent interface.
- Never mark a connector supported because authentication succeeded. Its wave exit criteria, capability verification against current official documentation and a licensed environment, and applicable certification suite must pass.

### Action-adapter work

- Require an M7-scoped task and a manifest-declared action capability. Collector completion alone never authorizes an Action Adapter.
- Require separate write authority, least-privilege permissions, and the normal operator approval workflow; passive onboarding must remain read-only.
- Design plan/preview, scope and expected impact, validation, expiration, verification, and rollback before apply; define multi-adapter conflict and rollback ordering when applicable.
- Preserve action provenance, immutable approved plan version, native control plane, vendor change identifier, before/after evidence, partial-failure state, verified removal, and rollback audit.

### Persistent data

- Before creating or changing persistent data, identify its data class, sensitivity, retention profile, `expires_at` behavior, legal-hold behavior, deletion propagation or derived-data invalidation, residency, encryption/key boundary, model-use permission, derivation lineage, and estimated storage impact.
- Preserve source and collector-observed timestamps. Keep raw-event references and integrity hashes when available; do not copy full vendor payloads by default.
- Do not retain secrets, actual canary secret values, request bodies, or sensitive payloads by default. Diagnostic retention must be redacted, bounded, authorized, and visibly expiring.
- Keep operational retention permission separate from model-use authorization. Do not enable cross-tenant learning without explicit opt-in, de-identification, cohort, regional, provenance, purpose, and deletion controls.
- Keep synthetic attacker evidence isolated from production baselines and customer models.
- Do not mark a persistence task `DONE` until lifecycle and deletion behavior are documented and deterministically tested.

### CanarySting

- Preserve canary-touch-only punitive triggering, engine-side scope authority, bounded response, and precise socket-cookie containment.
- Consume CanaryView opportunities conservatively and only through reviewed contracts and approval.
- Publish placement, touch, verdict, response, containment, and outcome back to CanaryView as provenance-bearing evidence.

### CanaryAttacker

- Constrain execution to designated lab targets and reviewed bounded tools. Never expose arbitrary host shell or unrestricted network/control-plane access to the model.
- Emit `AttackerIntent` before and `AttackerAction` after execution; attacker/model output is ground truth about the harness, not trusted telemetry.
- Enforce budgets outside the model, clean run-owned state, and preserve reproducible scenario IDs/evidence.

### Operator-facing work

- Identify the operator job and keep explanation beside evidence, recommendation beside explanation, and preview/rollback visible.
- Lead with application, identity, flow, risk, and action; expose raw implementation identifiers only through progressive disclosure.
- Core paths require no query, YAML, JSON, CLI, or prompt.
- Add frontend validation appropriate to the workflow and fixture-driven Playwright tests for critical paths.
- Do not mark the task `DONE` until its operator workflow and interaction budget pass.

## Implement and validate

- Make the smallest coherent change that satisfies the task. Add or update deterministic tests and choose the minimum valid gate for the task's current risk and affected paths.
- Run focused tests first, then `make check-fast` during edits. With no compatible failure ledger, `check-fast` is the default narrow loop. After a selected gate fails, use `make check-last-failed` (or the adversarial-specific replay) until every recorded failure and block is resolved; incompatible state must expand or refuse safely.
- Run `make check-pr-local` before presenting completion. This is the Level 1 local precheck, not authoritative merge evidence.
- A targeted replay proves only the repair. Rely on authoritative CI `make check-pr` plus every automatically selected privileged/DGX job for the final risk-appropriate PR gate. Never treat `check-fast`, `check-pr-local`, `check-one`, or last-failed replay as merge evidence.
- Use deterministic adversarial replay by default. Invoke live Qwen only through a targeted HIGH/CRITICAL smoke or scheduled Level 4 campaign with its approved bounded tool catalog; never improvise model authority.
- Do not require or rerun Level 3 after every repair. Record which merge-train, main/integration, nightly, on-demand, or release Level 3 path will provide the complete matrix. Record the Level 4 schedule when attacker/response work requires broader soak/campaign evidence.
- Invoke DGX qualification only when the risk classifier, changed paths, dependencies, and validation tier require it. LOW/STANDARD work does not consume DGX by default. CRITICAL work is never complete without the relevant implemented remote qualification; an unavailable remote profile is a blocker, not permission to substitute weaker coverage.
- Preserve the `.test-artifacts/gates/<run-id>/` paths used as completion evidence. Report every failure, blocked check, skip, and safety stop; never bypass a gate, hide a result, or convert a required failure to a warning.
- Never bypass, skip, or weaken a failing gate or security invariant to satisfy a timing budget. Do not install dependencies without approval. Do not commit or push unless explicitly requested.
- For selected DGX work, complete the local risk gate first. Before mutation run the workflow preflight, inspect local status, state exact remote changes and cleanup, and confirm scope. Reuse repository profiles instead of ad hoc SSH once a deterministic path exists; a compatible workflow should preflight/build/copy once while preserving per-scenario mutable isolation and cleanup.
- Treat unexpected Kubernetes, Cilium, BPF, or host state as a reason to inspect and report, not repair unrelated infrastructure. Never replace Cilium attachments or implicitly alter K3s, Cilium, firewall, SSH, kernel, or host packages.
- For DGX correlation: gather before-state; execute the scenario; gather independent observations; correlate; compare with ground truth; clean up; gather after-state; report trace completeness, join/identity accuracy, missing/conflicting evidence, time alignment, and cleanup.
- Preserve full cleanup evidence for privileged tests. Never mark kernel/Kubernetes/Cilium/identity/attacker-correlation work complete from local evidence alone.

## Record the outcome

- Update `docs/DEVELOPMENT_PLAN.md` with status, product area, validation results, implementation summary, completion evidence, and discovered follow-up work. Update architecture docs only when architecture or intended behavior changes.
- Mark `DONE` only when every acceptance criterion, required validation tier, cleanup proof, and applicable operator interaction budget passes—not merely because code was written.
- Mark `BLOCKED` only when completion depends on something unavailable; record the exact blocker, safe checks attempted, and unblock condition. Otherwise keep incomplete work `IN_PROGRESS` with remaining work and latest results.
- Stop after completing one coherent task unless the user explicitly instructs you to continue.
