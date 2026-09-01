# CanaryPlatform Deployment Profiles

Status: product and architecture baseline. Profiles are progressive adoption choices, not implementation-completeness claims.

## Profile 1: CanaryView SaaS

**Components:** CanaryView Core; direct vendor APIs; event streams; log/SIEM/telemetry integrations; customer-owned telemetry stores.

**Customer-side footprint:** no new CanaryPlatform data-plane software. Existing vendor integration configuration and scoped credentials remain customer-managed.

**Permissions:** read-only collector authority by default. No action credential is requested during passive onboarding.

**Data movement:** normalized evidence, source references, and policy-permitted minimum snapshots move to the configured CanaryView residency boundary. Raw telemetry remains source-owned where practical. Retention and model use are separately authorized.

**Resilience:** source systems retain their native records; collector health, lag, replay limits, and gaps are visible. A SaaS interruption delays correlation but does not alter customer traffic or native controls.

**Use cases:** cross-tool traces, workload/API intelligence, identity mapping, policy interpretation, graph analysis, telemetry-gap detection, impact assessment, evidence-grounded explanation, and recommendations.

**Buyer concerns:** SaaS trust, data residency, connector permissions, source coverage, retention, and proof that CanaryView is more than another SIEM.

**Upgrade owner:** CanaryPlatform upgrades Core; the customer approves connector/version and permission changes.

**Rollback/removal:** revoke connector credentials and disconnect collection; preserve or delete retained evidence according to lifecycle policy. No customer data-plane binary is removed.

**Packaging questions:** connector count/volume, retained evidence, graph/case features, agentic-operation usage, support tier, region, and SIEM integration.

This is the default commercial entry point.

## Profile 2: CanaryView Private Access

**Components:** Profile 1 plus one optional Canary Site Gateway per site, cluster, cloud account, private network, or trust zone where required.

**Customer-side footprint:** a bounded gateway, not a per-host or per-workload agent.

**Permissions:** outbound connectivity, read access to approved private sources, bounded spool/storage access, and only explicitly configured controlled-delivery authority. Read and write principals remain separate.

**Data movement:** the gateway may preprocess, minimize, buffer, and enforce residency policy before outbound delivery. It never creates an undeclared raw-data egress path.

**Resilience:** quota-bounded encrypted buffering and visible replay/loss behavior during SaaS or network interruption. Native controls continue operating. Local action delivery, if enabled later, uses cached approved policy and explicit expiry.

**Use cases:** private API access, local buffering, preprocessing, customer-managed egress, residency enforcement, disconnected-window tolerance, and controlled action delivery.

**Buyer concerns:** gateway privileges, outbound destinations, patching, availability, local storage, support ownership, compromise impact, and removal.

**Upgrade owner:** defined during architecture review—customer-operated, CanaryPlatform-managed, or shared—with signed artifacts, compatibility policy, and rollback.

**Rollback/removal:** stop outbound delivery, revoke credentials, export or expire buffered state, remove the single deployment unit, and verify that native systems continue unchanged.

**Packaging questions:** gateway count, managed-versus-customer operations, buffering capacity, private-source count, residency region, high availability, and controlled-delivery support.

Use Profile 2 only when Profile 1 cannot satisfy private access, buffering, residency, or delivery requirements.

## Profile 3: CanaryView plus CanarySting Managed Assets

**Components:** Profile 1 or 2 plus selected managed canary assets.

**Customer-side footprint:** asset-dependent. Prefer honeytokens, inert credentials, routes, API endpoints, data objects, synthetic identities, and external decoy services before broad local runtimes. Kubernetes Services/Deployments, proxy routes, workload-local files/configuration, database records, and object-store artifacts remain optional forms.

**Permissions:** least-privilege placement and lifecycle authority for the selected asset form. Placement authority is separate from punitive response authority.

**Data movement:** placement metadata, safe fingerprints, touch evidence, lifecycle, and outcomes enter CanaryView. Actual canary secret values and prohibited payloads are not retained.

**Resilience:** assets have explicit ownership, expiry, validation, cleanup, and stale-placement detection. A CanaryView interruption does not silently broaden their scope or authorize response.

**Use cases:** active ground truth, high-confidence interactions, adversarial graph updates, placement intelligence, telemetry validation, and canary lifecycle management.

**Buyer concerns:** accidental legitimate access, asset discoverability, credential governance, ownership, cleanup, change control, runtime footprint, and alert/response behavior.

**Upgrade owner:** depends on asset form; CanaryPlatform manages definitions and lifecycle contracts while the customer approves placement and local integration changes.

**Rollback/removal:** expire and remove each owned asset, revoke inert credentials where applicable, verify absence, and update CanaryView evidence. Removal does not erase historical authorized touch evidence.

**Packaging questions:** managed asset count/type, placement recommendations, lifecycle automation, external services, private placement, and included touch/correlation volume.

## Profile 4: CanaryView plus CanarySting Local Response

**Components:** Profile 3 plus selected local response runtime or vendor-native Action Adapters. Kubernetes operator/DaemonSet and eBPF are important implementations for relevant estates, not universal requirements.

**Customer-side footprint:** the smallest response unit needed for the approved action: proxy integration, Cilium/native policy adapter, eBPF node runtime, rate limiter, connection jail, cgroup/workload containment, or another manifest-declared adapter.

**Permissions:** separately authorized write-capable credentials or local privileges. Exact preview, human approval, immutable plan, scope, verification, expiry, rollback, and audit are mandatory.

**Data movement:** approved plans and controlled-delivery messages flow to the executing control plane; before/after evidence, native change identifiers, validation, expiry, removal, and rollback return to CanaryView.

**Resilience:** local response may continue only within explicit cached scope and expiry during SaaS interruption. Loss of evidence, identity, before-state, or after-state fails safe. Emergency cleanup and kill-switch behavior remain available.

**Use cases:** precise containment, local response during SaaS interruption, verified vendor-native actions, rollback, and bounded attrition where approved.

**Buyer concerns:** privilege, blast radius, availability impact, false attribution, vendor/control-plane conflict, upgrade/rollback, emergency recovery, and support burden.

**Upgrade owner:** explicitly assigned for every runtime/adapter; compatibility and rollback are validated in its reference environment. Kubernetes/eBPF changes require their established DGX validation tiers.

**Rollback/removal:** release containment, verify native action removal, detach only CanarySting-owned state, preserve unrelated Cilium/kernel/control-plane state, revoke write authority, and remove the optional runtime.

**Packaging questions:** response runtime/adapter type, protected estates, action volume, approval model, offline resilience, verification/rollback service, and premium support.

## Terminology boundaries

| Term | Meaning |
|---|---|
| Managed canary asset | A harmless deception object or service managed through CanarySting lifecycle and evidence contracts. It is not an agent. |
| Canary Site Gateway | One optional local connectivity, buffering, preprocessing, residency, and controlled-delivery component per approved boundary. It is not per-workload software. |
| Endpoint agent | A third-party or future host-installed endpoint component. CanaryPlatform does not require one for Profile 1. |
| AI agent | A model-driven/non-human actor using structured operations and the same evidence/authorization contracts as a person. |
| Local response runtime | Optional software or native adapter that executes separately authorized precise response near the workload/control plane. |

## Progressive-footprint rule

Choose the lowest numbered profile that delivers the required value. A higher profile must justify why SaaS and existing vendor integration are insufficient, every new privilege, the deployment unit, upgrade owner, failure mode, removal path, support burden, and whether the component remains optional.
