# CanaryView Connector Architecture

Status: conceptual architecture and M6/M7 sequencing contract. This document does not claim that any listed enterprise connector or action adapter is implemented or supported.

## Purpose and product promise

CanaryView is the vendor-neutral security intelligence plane above the security and infrastructure control planes a customer already chose.

> Keep the security tools that fit the business. CanaryView connects their evidence into one security story and one operator workflow.

Each vendor retains its native control plane and configuration source of truth. CanaryView:

- collects evidence;
- preserves vendor-specific context;
- normalizes only the fields required for cross-tool intelligence;
- correlates observations into traces and graph relationships;
- explains why a conclusion exists;
- identifies telemetry gaps;
- recommends operator actions; and
- may later delegate approved, narrow actions back to native control planes.

CanaryView is not an F5, Cilium, firewall, endpoint, identity, cloud, or Kubernetes management layer. It is not a replacement SIEM and is not a lowest-common-denominator policy engine.

## Scope and existing seams

This architecture extends existing CanaryPlatform contracts rather than creating parallel ones:

- `docs/CANARYVIEW_DATA_MODEL.md` owns the vendor-neutral `Observation`, `Evidence`, provenance, confidence, correlation, trace, recommendation, and action concepts.
- M2B.1 in `docs/DEVELOPMENT_PLAN.md` owns the first minimal read-only collector interface, checkpoint/replay semantics, health seam, and normalized-observation output. M6A productizes and extends that seam; it must not create a second collector interface.
- M2B.2 adapts the existing CanarySting, kernel/eBPF, Envoy, Kubernetes, Cilium, and Hubble lab sources. M6A promotes those adapters into reference, supportable connector contracts after the earlier work is complete; it does not reset or replay M2B.
- `internal/engine/observebaseline` remains the authoritative existing source for attributed `OBSERVED` topology. A connector or graph adapter must not duplicate its attribution path.
- `internal/contract` remains CanarySting's narrow flow/signal/verdict contract. The broader CanaryView observation model does not widen that hot-path contract incidentally.
- `internal/intelligence/transport` is a prototype file transport for anonymized cross-deployment patterns, not a general connector SDK or event bus.
- `internal/intelligence/siem` is an existing deployment-local one-way CanarySting emitter. Future SIEM connectors may reuse lessons from it, but must not mistake its source-specific event shape for the CanaryView canonical model.
- `adapters/envoy` and `adapters/nginx` are thin CanarySting proxy adapters. An Evidence Collector or Action Adapter is a different product seam and must not acquire proxy-side detection or tiering logic.
- The existing `Recommendation`, `ActionPlan`, and `ActionExecution` concepts remain. M7 adds a vendor-neutral `SecurityIntent` above one or more vendor-native `ActionPlan` objects rather than introducing a generic cross-vendor policy.

## Architectural principles

1. **Category contracts precede vendor implementations.** A category defines the minimum useful cross-tool fields, evidence semantics, correlation keys, and health expectations. A vendor connector implements that contract and retains richer native context in evidence.
2. **Evidence precedes action.** Every connector begins read-only. Action authority is a separate M7 concern after evidence collection, correlation, explanation, onboarding, and health are proven.
3. **Collection, capability, and action are separate concerns.** Evidence Collector, Connector Capability Manifest, and Action Adapter are independent contracts with independent lifecycle and authorization.
4. **Read and write credentials stay separate.** Passive CanaryView must work without policy-change authority. Collector-only onboarding never requests write credentials.
5. **Native control planes remain authoritative.** CanaryView records evidence and action provenance; it does not claim ownership of vendor configuration.
6. **The canonical model remains vendor-neutral.** Vendor-native fields, enums, rule bodies, product features, and opaque IDs stay in the extension/evidence envelope unless architecture review establishes a genuinely cross-category canonical concept.
7. **Health and coverage are product data.** Connector state, freshness, lag, loss, schema drift, permissions, rate limits, backfill, field coverage, and capabilities are queryable by both operators and agents.
8. **Traditional click-ops is a first-class path.** An operator can onboard, inspect, test, rotate, and disconnect a connector without CLI, YAML, raw JSON, or vendor API expertise.
9. **Capabilities are verified at implementation time.** Roadmap examples are candidates, not promises. Before a connector or action adapter is implemented, current behavior must be verified against official vendor documentation and a licensed test or design-partner environment. The published manifest records versions, editions, regions, licensing assumptions, and a sanitized non-identifying validation attestation; detailed environment evidence remains protected and deployment scoped.

This program does not broaden CanarySting rule 9 or create a second egress path. Under the current architecture, customer-rich observations, source records, identities, and configuration evidence stay inside their deployment boundary. Only already-approved anonymized patterns may cross it through `internal/intelligence/network`. Any future hosted or hybrid execution model that would move customer-rich evidence across that boundary requires explicit architecture and privacy review; a connector implementation may not assume that authority.

## Three separate contracts

```text
vendor source
    |
    | read credentials only
    v
Evidence Collector --> canonical Observation + Evidence reference
    |                         |
    +--> health/coverage -----+--> correlation --> trace/graph/case/explanation

ConnectorCapabilityManifest --> console + agent interface + planner

proposed SecurityIntent
    |
    v
capability check --> vendor-native ActionPlans --> exact preview + human approval
                                                        |
                                                        | separate write authority, M7 only
                                                        v
                                                  Action Adapters --> native control planes
                                                        |
                                                        +--> verify / expire / rollback / audit evidence
```

### Evidence Collector

An Evidence Collector streams, polls, receives webhooks, reads files, or backfills vendor observations. It:

- uses read-only credentials and the smallest required permission set;
- preserves source event time and collector observation time;
- records source system, source instance, collector version, and schema version;
- emits compact vendor-neutral observations;
- retains vendor fields in a bounded extension/evidence envelope;
- retains raw evidence references and content hashes when available;
- checkpoints and replays idempotently;
- reports health, coverage, loss, drift, and permission state; and
- never writes vendor policy, configuration, identity, tags, or containment state.

The collector contract must accommodate stream, poll, webhook, file, backfill, and customer-owned-bus acquisition without making any one transport canonical.

### ConnectorCapabilityManifest

The capability manifest is versioned product data available to the operator interface and agent interface. It is the only safe basis for advertising visibility or planning an action. Conceptual fields include:

- identity: `connector_id`, `vendor`, `product`, `product_version_range`, `connector_version`, `category`, `maturity_status`;
- acquisition: `evidence_modes` (`stream`, `poll`, `webhook`, `file`, `backfill`), `expected_latency`, `historical_backfill`, `raw_event_reference_support`;
- evidence: `supported_data_classes`, `supported_correlation_keys`, `schema_version`;
- visibility: `policy_visibility`, `configuration_visibility`, `identity_visibility`, `translation_nat_visibility`;
- authority: `read_permissions`, `write_permissions`;
- actions: `action_plan_support`, `action_preview_support`, `action_apply_support`, `action_verify_support`, `action_expiration_support`, `action_rollback_support`; and
- constraints: `rate_limits`, `regional_constraints`, `licensing_constraints`.

Runtime health is not a manifest field. The separate health model references the active manifest version and determines which declared capabilities are currently usable without mutating capability history.

The manifest also records the official documentation version/date and a sanitized validation attestation for each claimed capability. A published attestation may name only non-identifying product version, edition, region class, test class, and validation date. Licensed/design-partner environment identifiers, account or tenant IDs, source data, artifact locations, and detailed validation evidence remain tenant/deployment scoped and are linked only through protected local evidence references. Unknown, unavailable, unlicensed, and unverified are explicit states; absence is never inferred to mean support.

### Connector health and telemetry coverage

The health model records at least:

- overall state and reason;
- last successful connection and last successful event;
- source-to-collector and collector-to-CanaryView delay;
- accepted, duplicate, dropped, rejected, and quarantined record counts;
- reconnect, checkpoint, replay, and backfill state;
- schema version and drift warnings;
- authentication and permission failures without exposing secrets;
- rate-limit state and next eligible retry;
- historical backfill range and gaps;
- expected and missing fields or correlation keys;
- source clock skew and confidence impact;
- supported and currently usable capabilities; and
- data-volume and retention-impact estimates.

Coverage is not a binary connected/disconnected flag. It describes which expected sources, data classes, fields, identities, translations, time windows, and scopes are present, delayed, missing, or conflicting.

### Lifecycle for connector product data

These conceptual persistent types follow the common lifecycle envelope and do not contain credential values:

| Type | Data class and retention | Hold/deletion and derived effect | Boundary, model use, lineage, and storage impact |
|---|---|---|---|
| Connector capability manifest/version history | `CONNECTOR_CONFIGURATION`; active version plus superseded history for 1 year (Lean), 3 years (Standard), or 7 years (Regulated). | May be held only when it supports a case/action audit. Tenant-instance copies delete with the connector/tenant after the profile window; a capability removal invalidates affected unapproved plans and marks historical plans with the manifest version they used. | Tenant instance metadata and licensed/design-partner validation artifacts stay in the tenant/deployment region and encryption boundary. Only generic connector metadata plus a sanitized, non-identifying product/version/edition/region/test-class/date attestation may be global; environment identifiers, source data, account/tenant IDs, artifact locations, and detailed evidence never publish with it. No model use. Lineage includes connector build, schema, official-document review, non-identifying license/edition/region assumptions, sanitized attestation, and protected local evidence references. Low storage impact. |
| Connector health, coverage, checkpoint, and schema-drift history | `CONNECTOR_HEALTH`; 30 days (Lean), 90 days (Standard), or 13 months (Regulated), with bounded coarser summaries allowed under the selected profile. | Held only when required to explain evidence loss or an action/case. Connector deletion removes credentials/checkpoints immediately and expires health history by policy; traces/cases retain a scoped availability tombstone and update confidence rather than fabricating coverage. | Tenant/scope isolated, tenant-region resident, tenant-key encrypted. No model use by default. Lineage identifies connector/manifest/schema/checkpoint versions. Low-to-moderate impact determined by sampling cadence, scope count, and field-coverage cardinality. |
| Vendor extension/evidence envelope | Existing normalized observation/evidence data classes and profile periods in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. | Hold, deletion, raw-reference expiry, and derived invalidation follow the parent evidence. | Same tenant/residency/key/model-use boundary and lineage as the parent observation. Variable impact; bounded fields and payload minimization are required. |
| SecurityIntent and coordinated plan state | Existing `ACTION_AUDIT` periods: 1 year (Lean), 3 years (Standard), or 7 years (Regulated). | Hold/release follows case/action governance. Deletion or expiry preserves only policy-permitted audit/tombstone data; affected executions remain honest about missing evidence. | Tenant/scope isolated, tenant-region resident, tenant-key encrypted; no model use unless separately authorized for an approved purpose. Lineage links recommendation, evidence, manifests, native plans, approvals, executions, vendor change IDs, verification, expiration, and rollback. Low storage impact. |

### Action Adapter

An Action Adapter plans and later performs a narrow vendor-native action. It belongs primarily to M7, not the first M6 collector implementation. It:

- uses separate write credentials and authorization;
- accepts an approved, immutable vendor-native `ActionPlan`, not a generic policy document;
- calculates scope and expected impact;
- previews exact changes and required permissions;
- applies only the approved plan through the native control plane;
- records the vendor change identifier and before/after state;
- verifies the intended result;
- expires or rolls back the action and verifies removal; and
- emits audit evidence, including partial failure.

## Observation and evidence rules

Every collector must:

- preserve tenant, deployment, and scope isolation and fail closed on unresolved boundaries;
- preserve source event time, collector observation time, and ingest time;
- record source system/instance, collector version, and schema version;
- retain a raw-event reference and content hash when the source supports them;
- generate a stable, idempotent event identity from source identity and immutable event attributes;
- detect and safely handle duplicates;
- tolerate out-of-order and delayed arrival without rewriting the original observation;
- expose source clock skew and its effect on correlation confidence;
- accept useful partial records while naming missing expected fields;
- preserve vendor decisions and native rule/policy references;
- preserve pre- and post-translation addresses, ports, and proxy hops when present;
- preserve evidence and normalization confidence separately from later correlation confidence;
- distinguish `OBSERVED`, `DECLARED`, `INFERRED`, and `VERIFIED` assertions;
- keep vendor-specific fields in a bounded, versioned extension/evidence envelope;
- avoid sensitive payload, request/response body, secret, token, credential, or unrestricted label retention by default; and
- follow the data-class, retention, legal-hold, deletion/invalidation, residency, encryption, model-use, lineage, and storage-impact rules in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`.

If a raw source record expires, the canonical observation retains only the policy-permitted hash, source-native identity, safe summary, availability state, and provenance tombstone. CanaryView must not imply that expired evidence remains inspectable.

## Category-level contracts

The fields below are useful evidence candidates, not promises that every connector supplies every field. Each manifest states actual coverage and missing fields.

### 1. Edge, CDN, WAAP, and API security

Example sources: F5 Distributed Cloud, Cloudflare, Akamai, and Imperva.

Category evidence includes edge request identity; client and origin addresses; host, method, path, and status; WAF decision; bot and reputation signals; API-security findings; rate-limit decisions; DNS and origin-routing context; and vendor rule/policy IDs.

### 2. Network firewall, segmentation, and SASE

Example sources: Palo Alto Networks PAN-OS, Panorama, Prisma Access, and Strata Logging Service; Fortinet FortiGate, FortiAnalyzer, and FortiManager; Zscaler; and Check Point.

Category evidence includes session start/end; source and destination zones; application identification; user identity; pre- and post-NAT translation; allow/deny decision; security rule; threat and URL verdicts; and branch, remote-user, and private-application context.

### 3. Kubernetes, service networking, runtime, and workload security

Example sources: Kubernetes, Cilium, Hubble, Envoy, NGINX, kernel/eBPF, Sysdig, Prisma Cloud, and Wiz.

Category evidence includes workload identity; namespace and service account; pod UID; service and endpoint; process/socket identity; network policy; observed flow; runtime finding; socket cookie; and container/image context. CanarySting's cross-L7/kernel attribution continues to use only the socket cookie.

### 4. Endpoint, XDR, and EDR

Example sources: Microsoft Defender XDR and Defender for Endpoint, CrowdStrike Falcon, and later SentinelOne.

Category evidence includes device identity; process and network activity; detections and incidents; containment state; managed/unmanaged state; and host risk/policy context.

### 5. Identity and privileged access

Example sources: Microsoft Entra ID, Okta, CyberArk, and Ping Identity.

Category evidence includes human and application identity; sign-in event; token/session context without retaining token secrets; MFA result; device/application association; identity risk; and privileged-session context.

### 6. Cloud infrastructure and cloud-native security

Example sources: AWS, Microsoft Azure, and Google Cloud.

Category evidence includes account/subscription/project; VPC/VNet and subnet; load balancer; security group/cloud firewall; cloud identity; managed Kubernetes; flow logs; audit events; threat findings; and resource sensitivity.

### 7. Data security

Example sources: Imperva database/data-security products, cloud database audit sources, and future database activity-monitoring products.

Category evidence includes data asset; database identity; query/operation type; sensitive-data classification; access policy; and data-security verdict. Query text and returned data are sensitive payloads and are not retained by default.

### 8. SIEM, SOAR, observability, and ITSM

Example sources and destinations: Splunk, Elastic, Microsoft Sentinel, Google Security Operations, Datadog, Grafana, and ServiceNow.

These systems may be an evidence source, a destination for CanaryView `SecurityCase` and trace projections, a workflow/ticket orchestration system, or the owner of historical raw-event references. They do not define the CanaryView canonical model.

## Prioritization and architecture gates

Connector order is ranked using explicit evidence:

- cross-trace coverage gained;
- strength of correlation identifiers;
- NAT or translation context added;
- identity context added;
- operator/customer prevalence and design-partner demand;
- evidence API or stream accessibility;
- future action potential and ability to verify/roll back actions;
- licensing, tenant, region, and test-environment availability;
- implementation complexity and schema stability;
- data volume, retention impact, and cost; and
- value to stand-alone CanaryView adoption.

Design-partner pull may reorder vendors within a wave. It may not bypass these gates:

1. the canonical model exists;
2. provenance and confidence exist;
3. tenant/scope isolation exists;
4. the connector capability manifest exists;
5. the read-only collector passes validation; and
6. operator onboarding, health, authority, and capability visibility exist.

## M6 sequencing

### M6A / Wave 0: Connector framework and first certified lab sources

Goal: establish the reference connector architecture and promote only individually certified local/DGX sources without replaying completed work.

Candidate reference sources are CanarySting, kernel/eBPF, Kubernetes, Cilium, Hubble, Envoy, NGINX, and OpenTelemetry when present. Listing a candidate does not claim implementation or support. In particular, the current NGINX CanarySting proxy adapter remains a stub, and no NGINX Evidence Collector is implied.

M6A extends the M2B collector seam with a capability manifest, vendor extension/evidence envelope, product health model, schema drift, replay/backfill rules, fixture certification, permission review, and bindings into the generic M4.6 Integrations workflow. Exit requires at least one streaming source and one polling/backfill source to pass the applicable certification independently; each promoted source has its own current manifest, console-visible health, preserved provenance/confidence, duplicate/reordered/delayed/partial-event evidence, and read-only proof. Every other candidate remains explicitly unsupported or unimplemented. Completing the wave never promotes the candidate set as a whole.

### M6B / Wave 1: Cross-vendor proof

Goal: prove CanaryView across competing control planes and fill the largest gaps in an end-to-end security trace.

1. **Palo Alto Networks.** Candidate initial products are PAN-OS, Panorama, Prisma Access where design-partner access exists, and Strata Logging Service. Read-only scope covers traffic, threat, URL, identity, and policy evidence, especially session/rule, App-ID/User-ID, zone, NAT, and allow/deny context. It leads because it adds strong firewall translation/identity context, broad enterprise relevance, and a useful future native-action surface. Candidate M7 actions include a temporary security rule or address/tag update with scope, expiration, verification, and rollback.
2. **Cloudflare.** Candidate initial capabilities are Logpush datasets; HTTP request/firewall, bot, and rate-limit evidence; and licensed DNS/origin context. Read-only collection proves a competing edge/WAAP source, supplies clear north-south request context, and has strong stand-alone CanaryView value. Candidate M7 actions include a temporary scoped WAF, challenge/block, rate-limit, or list update with expiration, verification, and rollback.
3. **Endpoint and identity proof.** Select from either Microsoft Defender XDR/Defender for Endpoint plus Microsoft Entra ID, or CrowdStrike Falcon plus the identity provider available in the partner environment. Read-only scope covers event, incident, endpoint, process, and identity evidence, closing the gap between network evidence and the responsible actor/device/workload. Candidate M7 actions include endpoint containment/release, supported session revocation, or policy-group/tag actions with verification and rollback.
4. **AWS.** Candidate initial sources are VPC Flow Logs, CloudTrail, EKS audit logs, GuardDuty findings, and practical load-balancer/resource identity. Read-only collection fills the cloud path between edge and Kubernetes and fits the existing development/design-partner environments. Any M7 action remains narrow, approved, cloud-native, and deferred until the action architecture is proven.

Wave 1 exits only when one mixed-vendor trace joins edge, firewall/translation, workload/runtime, endpoint/identity, and CanarySting evidence from at least three independent vendor families; every join is explainable; missing/conflicting evidence and connector health/latency remain visible; and no vendor-specific canonical assumption was added.

### M6C / Wave 2: Enterprise breadth

Goal: broaden edge, data-security, endpoint, firewall/SASE, and identity coverage.

Priority order, subject to design-partner access within the wave:

1. Akamai DataStream/SIEM security events and WAF, bot, account-protection, edge/origin evidence.
2. Imperva database activity and sensitive-data context first, then API Security, Cloud WAF, bot, and account-takeover evidence using licensed documentation and a test/design-partner tenant.
3. The endpoint/XDR platform not selected in Wave 1: Microsoft Defender or CrowdStrike.
4. Fortinet FortiAnalyzer/FortiGate evidence, with FortiManager policy visibility later.
5. Zscaler Internet, private-application, SASE, and user-path evidence.
6. Okta sign-in, application, session, and identity-risk context.

Exit requires category contracts to support multiple vendors without one-off canonical fields; at least two edge/WAAP vendors; at least two firewall/SASE vendors; at least two endpoint/identity combinations; and a trace reaching a sensitive data asset or database-security observation.

### M6D / Wave 3: Cloud, posture, operations, and ecosystem expansion

Priorities are Microsoft Azure, Google Cloud, Check Point, Prisma Cloud, Wiz, Sysdig, CyberArk, Splunk, Elastic, Microsoft Sentinel, Google Security Operations, ServiceNow, and Datadog/Grafana where they contain useful evidence.

Goals are to expand cloud/workload context; add privileged-access and posture context; publish CanaryView `SecurityCase`, trace, explanation, and recommendation projections into existing SOC workflows; and support historical evidence references without copying all raw data into CanaryView.

### M6E: Connector operations and marketplace readiness

Productize guided click-ops onboarding, permission review, capability display, connection tests, health/lag monitoring, schema-drift alerts, connector versioning, upgrade compatibility, replay/backfill controls, data-volume and retention estimates, regional/licensing constraints, a fixture/certification kit, and honest support-status labels.

## M7 cross-vendor action architecture

CanaryView expresses a vendor-neutral `SecurityIntent` and delegates execution through one or more vendor-native `ActionPlan` objects. It does not push one generic policy everywhere.

Example intent:

> Prevent `checkout-api` from reaching `vault-proxy` for 30 minutes while preserving customer-facing traffic.

Depending on manifests and approved authority, separate plans might target a temporary Cilium `NetworkPolicy`, a Palo Alto Networks security-policy rule or object/tag update, a scoped Cloudflare WAF/rate-limit rule, Microsoft Defender or CrowdStrike endpoint containment, or a precise CanarySting flow jail. The operator sees one coordinated plan while every adapter retains its native target, semantics, permissions, validation, and rollback.

```text
Recommendation
    -> SecurityIntent (outcome, scope, constraints, duration, preserved traffic)
    -> capability check against current manifests
    -> one or more vendor-native ActionPlans
    -> preview + scope + expected impact + permissions + validation/rollback plan
    -> human approval of exact immutable plan versions
    -> revalidate source state and authority
    -> apply through each native control plane
    -> record vendor change IDs and partial outcomes
    -> verify intended effect
    -> expire or roll back in a defined order
    -> verify removal/restoration
    -> retain audit and evidence provenance
```

Every action adapter supports the applicable subset of plan, preview, scope calculation, expected impact, required permissions, human approval, apply, vendor change identifier, verify, expiration, rollback, and audit evidence. The capability manifest states which subset is actually available.

Action rules:

- human approval is required first;
- passive onboarding does not request write credentials;
- read and write credentials, principals, and authorization are separate;
- CanaryView never claims or plans a capability absent from the active manifest;
- every action uses the native control plane and retains provenance;
- every plan includes validation and explicit success/failure conditions;
- reversible, narrow, expiring actions are preferred;
- expiry is not assumed successful until removal is verified;
- partial apply, verification, expiration, and rollback failures remain visible; and
- one operator plan may coordinate several adapters without hiding their separate native effects.

## Operator onboarding and operations

The primary path is `Integrations -> category -> vendor/product -> capability and permission review -> connection setup -> test -> activate read-only`.

Before credentials are entered, the operator sees supported data classes, correlation keys, expected latency, backfill, raw-reference behavior, required read permissions, unavailable fields, licensing/region constraints, and separately labeled future action capabilities. Write authority is an explicit later transition, never a passive-onboarding step.

The integration overview answers on one screen:

- What does this connector see?
- What does it not see?
- How current is it?
- What permissions does it have?
- What actions could it eventually perform?
- Is CanaryView using read-only or write authority?

The same workspace provides test connection, health/lag/last-event details, schema and coverage warnings, volume/retention impact, credential rotation, backfill/replay controls, and disconnect. Secret values are never displayed.

## Testing, certification, and support

Every collector certification suite covers:

- schema fixtures and category-contract compliance;
- duplicate, out-of-order, delayed, clock-skewed, and partial events;
- pagination and historical backfill;
- rate limiting, reconnect, checkpoint, and replay;
- authentication and permission denial;
- tenant/deployment/scope isolation and no-bleed behavior;
- sensitive-field minimization and redaction;
- raw-reference and content-hash integrity;
- schema drift and unknown vendor fields;
- connector upgrade compatibility;
- health, lag, field-coverage, and loss reporting; and
- a structural and behavioral read-only guarantee.

Later M7 action-adapter certification adds preview accuracy, plan/version mismatch rejection, authorization denial, stale-state handling, apply idempotency, vendor change-ID capture, verification, expiration, rollback, rollback ordering, audit integrity, and partial-failure recovery.

Successful authentication proves only that credentials work. It does not establish field coverage, correctness, isolation, reliability, read-only behavior, correlation quality, or supported status. Support labels require the declared wave exit criteria, applicable certification suite, current manifest, official documentation review, protected licensed-environment evidence, and the matching sanitized manifest attestation.

## Unresolved architecture questions

These questions do not block the M6 plan update. They must be resolved by the task that makes the affected capability executable:

1. How is the connector SDK packaged and versioned?
2. Which pull, push, webhook, stream, file, and customer-owned-bus deployment patterns are supported by category?
3. Does each connector execute in the customer environment, CanaryPlatform service, or a hybrid of the two?
4. How are secrets stored, scoped, rotated, revoked, and audited without exposing their values?
5. What is the per-vendor schema-evolution and compatibility strategy?
6. What remains of a raw-event reference when source retention expires?
7. What certification, maturity, and support tiers are public, and what evidence does each require?
8. How are vendor edition, licensing, API plan, tenant, and rate-limit dependencies represented?
9. Which regional, residency, sovereign, and disconnected deployment patterns are required?
10. How are conflicting actions across several authoritative control planes detected and resolved?
11. What is the safe rollback order when several adapters partially apply or fail?
12. How is telemetry coverage calculated and displayed without implying false completeness?
13. How may design-partner access change vendor order without weakening architecture gates?
