---
name: canarysting-dev
description: Execute one plan-driven CanarySting task for requests to continue, keep developing, resume, work on the next task, Kubernetes milestone, DGX integration, or current CanarySting task.
---

# CanarySting Development

Use `docs/DEVELOPMENT_PLAN.md` to select, execute, validate, and record exactly one coherent CanarySting development task. `AGENTS.md` remains authoritative for architecture and safety.

## Orient and select

1. Read the repository `AGENTS.md` fully.
2. Read `docs/DEVELOPMENT_PLAN.md` fully.
3. Read `docs/DEVELOPMENT_ENVIRONMENT.md` when work involves environment, Kubernetes, Cilium, kernel, eBPF, deployment, identity, or the DGX.
4. Inspect `git status` and relevant diffs. Treat all uncommitted and untracked work as user-owned; never overwrite, discard, reset, clean, stash, or silently reformat it.
5. If one task is `IN_PROGRESS`, resume it. Otherwise select the first `TODO` task in document order whose dependencies are all `DONE`. Do not start a second task while another is `IN_PROGRESS`.
6. Determine the task's validation tier before editing and record the selected task and tier in the plan.
7. Inspect the relevant architecture, implementation, tests, and `internal/contract/` when cross-layer behavior is involved.
8. Before editing, state the objective, acceptance criteria, expected files, validation tier, whether DGX participation is required, and safety considerations. Then mark only that task `IN_PROGRESS`.

## Implement and validate

- Make the smallest implementation that satisfies the selected task. Preserve every architectural and security invariant in `AGENTS.md`.
- Add or update deterministic tests for changed behavior. Run focused validation first, then the broader gates appropriate to the task.
- Never bypass, skip, or weaken a failing gate. Never weaken security behavior to make a test pass.
- Do not install dependencies without approval. Do not commit or push unless explicitly requested.
- For Tier B or C, complete Tier A first and then run the required DGX validation. Never mark kernel/Kubernetes/Cilium/identity work done from local evidence alone.
- Do not access or modify the DGX unless the selected task requires it. Before remote mutation run `scripts/dgx/check.sh`, inspect local status, state the exact change and cleanup, and confirm it fits the task.
- Reuse repository DGX scripts once a deterministic path exists. Treat unexpected Kubernetes, Cilium, BPF, or host state as a reason to inspect and report, not to repair unrelated infrastructure.
- Preserve full cleanup evidence for privileged tests. Never replace Cilium attachments or silently alter K3s, Cilium, firewall, SSH, kernel, or host packages.

## Record the outcome

- At completion, update `docs/DEVELOPMENT_PLAN.md` with status, validation results, completion evidence, and newly identified follow-up work.
- Record the implementation summary as well as the exact validation results; update architecture documentation only when architecture or intended behavior changes.
- Mark the task `DONE` only when every acceptance criterion is satisfied and every required validation gate passes.
- Never mark a task `DONE` merely because its code was written.
- Mark the task `BLOCKED` when completion depends on something unavailable; record the exact blocker, attempted safe checks, and what would unblock it.
- If work remains locally incomplete but is not externally blocked, leave the task `IN_PROGRESS` and record the remaining work and latest validation results.
- Stop after completing one coherent task unless the user explicitly instructs you to continue.
