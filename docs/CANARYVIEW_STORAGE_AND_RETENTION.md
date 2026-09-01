# CanaryView Storage and Retention Architecture

Status: architecture baseline for review and the M2A.0 gate. This document defines lifecycle principles and logical storage requirements. It does not select or implement a production database, change current CanarySting runtime behavior, or authorize collection of additional data.

## Guiding principle

**Retain intelligence longer than telemetry.** Raw telemetry has the highest volume, cost, and privacy exposure. Normalized evidence, correlated traces, relationship history, security cases, operator decisions, action outcomes, and learned features preserve more meaning in less data.

This lifecycle applies across CanaryView SaaS, optional Site Gateway, managed assets, and local response profiles. Profile 1 does not require a local spool; the edge spool exists only when an approved gateway or local connector needs buffering. Deployment profile never changes the common envelope, evidence distinctions, deletion lineage, or separation of retention from model use.

```text
raw telemetry
  -> normalized observations
  -> correlated traces
  -> security cases
  -> relationship history and graph summaries
  -> historical features
  -> placement and response models

volume and sensitivity generally decrease ->
durable explanatory and product value generally increase ->
```

Retention is not model influence. Older retained evidence should receive less weight in current behavioral models where appropriate, and permission to retain data operationally does not grant permission to use it for model building.

## Current repository persistence and lifecycle inventory

The present code is a CanarySting implementation, not a production CanaryView store. Its useful mechanisms should be reused deliberately, while its lifecycle gaps must not be hidden by new product names.

| Current mechanism | Current behavior | CanaryView relevance and gap |
|---|---|---|
| `internal/engine/persist` | The only bbolt database substrate. Files are created mode `0600`, schema-versioned, transactionally written, scope-partitioned, and fail on an incompatible schema unless an explicit reset is requested. Buckets hold baseline aggregates, malicious identities, append-only event blobs, topology, deviants, L7 touches, audit chains, triage overlays, and lifecycle metadata. | Reusable durability, isolation, schema, and integrity patterns; not a general normalized-observation, case, graph-history, or feature registry. Read-only open also contends with the live bbolt writer lock. |
| Baseline aggregates and malicious set | Baseline buckets are finite by time-bucket cardinality and per-bucket caps, but retained counters have no explicit tenant retention profile. The hashed malicious set has no TTL/deletion workflow. | Feature-state inputs need explicit training windows, expiry, deletion effects, and model-use permission. |
| `internal/intelligence/boltevents` | Scope-isolated, append-only, derived/addressless canary interaction and outcome blobs. Queries scan at most the newest 4,096 records, but the durable log has no TTL, compaction, or deletion policy. | Useful CanarySting evidence producer; it is touch-dependent and not the passive canonical observation store. |
| `internal/engine/observebaseline` topology | Local-rich OBSERVED nodes/edges, capped at 4,096 per scope and reaped after 30 days by `LastSeen`; removals are persisted. Current state is reconstructable only to the extent retained records remain. | The existing OBSERVED source required by rule 10. It lacks append-only relationship history, historical summaries, legal hold, and historical reconstruction semantics. |
| Deviant flow history and triage | Deviants are capped at 4,096 per scope with a 30-day TTL. ACK/suppress overlays deliberately outlive deviant reap/eviction and are deleted only by an explicit operator operation. | Shows why lifecycle must define behavior for a derived record after its source expires. Overlay rows currently have no general garbage-collection or retention profile. |
| `internal/intelligence/l7events` | Local-rich canary-touch records include source address, method, path including query, and SPIFFE ID; cap 4,096 and nominal 30-day TTL. A cap is active, but the documented periodic production TTL caller is not yet wired, so below-cap stale data may remain until rehydration or explicit reap. No request body is stored. | Sensitive local evidence that needs redaction, legal-hold, snapshot, and expiry controls before broader use. |
| `internal/intelligence/audit` | Per-scope append-only hash chain in bbolt. It can use an external HMAC key and publishes high-water anchors to an operator SIEM; unkeyed mode has a weaker threat model. It has no TTL or legal-hold workflow. | Valuable integrity/audit mechanism. Retention, external witness, deletion exceptions, and tenant key boundaries remain production decisions. |
| Intelligence file spools | `transport.Spools` and `ConfirmSpool` append mode-`0600` NDJSON and validate bounded input on read. They have no acknowledgement, truncation, rotation, expiry, quota, encryption-at-rest layer, or automatic cleanup. Demo runbooks clean/truncate manually. | Prototype transfer seams, not an edge replay service. M2A.0 must define delivery acknowledgement, replay windows, encryption, and deletion. |
| SIEM outputs and demo sink | Production emitters are one-way stdout/CEF/webhook projections. A demo receiver appends mode-`0644` NDJSON without rotation; retention belongs to the external SIEM or demo cleanup. | Source-system references and external witnesses are useful, but CanaryView must not claim control of external retention it cannot verify. |
| Dashboard/tap state | Read models primarily project bbolt/in-memory sources. The attacker-cost ledger is latest-value, in-memory, and considered stale after 30 seconds. | Useful view projections, not durable cases or trace storage. |
| Confirmed-profile and cross-scope ledgers | `internal/intelligence/sharpen` and the privacy-cleared contribution ledger are in memory. Restart loses them and safely lowers confidence. No feature/model registry exists. | Useful behavioral logic and privacy boundary; persistence, lineage, authorization, and retirement are unimplemented. |
| eBPF maps | Bounded runtime/kernel state with socket-release and loader cleanup behavior; it is execution state, not retained evidence. | CanaryView records references/outcomes rather than treating live BPF state as historical storage. |
| Canonical observations, cases, relationship history, models | No general normalized-observation store, `SecurityCase` store, append-only graph relationship journal, legal-hold service, model-use policy registry, or production graph backend exists. | These are planned architecture, not current capabilities. |

## Data classes and lifecycle envelope

Every planned persistent object must declare a data class and sensitivity before implementation. Initial classes are:

- `EDGE_REPLAY_SPOOL` — encrypted delivery/replay buffer.
- `RAW_TELEMETRY_REFERENCE` — pointer, checksum, and metadata for a source-owned event.
- `RAW_EVIDENCE_SNAPSHOT` — minimum bounded evidence copied for a case or audit.
- `SENSITIVE_PAYLOAD` — request body, credential-like field, token, or comparable content; disabled by default.
- `NORMALIZED_OBSERVATION` — compact vendor-neutral source report.
- `CORRELATED_TRACE` — versioned joins and journey state.
- `RELATIONSHIP_EVENT` — append-only graph relationship assertion or retraction.
- `GRAPH_CURRENT_STATE` and `GRAPH_SUMMARY` — rebuildable current view and historical aggregates.
- `SECURITY_CASE` and `CANARY_EVIDENCE` — operator-facing conclusions and confirmed deception evidence.
- `ACTION_AUDIT` — recommendation, approval, execution, validation, rollback, and audit.
- `CONNECTOR_CONFIGURATION` and `CONNECTOR_HEALTH` — versioned connector capability/configuration metadata plus bounded health, coverage, checkpoint, and schema-drift history; never credential values.
- `FEATURE_BASELINE` and `MODEL_ARTIFACT` — learned state, evaluation, and registry metadata.
- `SYNTHETIC_GROUND_TRUTH` — CanaryAttacker scenarios, intent, action, and evaluation evidence.

Every persisted observation, relationship, trace, case, recommendation, action, feature, or model artifact supports these fields where applicable:

- `tenant_id`, `scope_id`, `data_class`, `sensitivity`;
- `retention_profile`, `expires_at`, `legal_hold`;
- `residency`, `encryption_key_ref`;
- `source_system`, `source_timestamp`, `observed_timestamp`;
- `schema_version`, `collector_version`;
- `raw_event_ref`, `raw_event_hash`;
- `derivation_lineage`, `confidence`;
- `model_use_policy`;
- `synthetic`, `scenario_id`.

Ingest time and validity interval should also be present when they differ from the two required timestamps. `expires_at` is an enforceable lifecycle field, not a display hint. A legal hold suspends expiration but never silently changes `model_use_policy`.

## Federated evidence model

Raw telemetry remains in the originating system or a customer-owned archive where practical: Hubble/Cilium, Envoy/NGINX/F5, SIEM, OpenTelemetry backends, object storage, and customer log platforms remain their own records of authority.

CanaryView Core may receive customer-authorized, minimized evidence through direct vendor integrations in Profile 1 or through a Site Gateway in Profile 2. That transfer requires an explicit tenant, scope, residency, retention, and encryption boundary. It does not reuse or weaken CanarySting's default-deny cross-deployment intelligence egress: raw CanarySting traffic, baselines, scope state, decoy contents, and environment-identifying details remain governed by rule 9, while separately authorized CanaryView connector evidence follows this lifecycle architecture.

CanaryView normally retains:

- source-system and source-instance identifiers;
- raw-event reference and cryptographic checksum;
- schema and collector version;
- source and observed timestamps;
- a selected, redacted evidence excerpt when necessary;
- derivation lineage and the conclusions it supports or contradicts.

A reference must expose availability state: available, expired, deleted, access denied, moved, or integrity mismatch. A broken reference remains visible and lowers confidence where appropriate; CanaryView must not silently pretend the source is still retrievable.

Before likely source expiry, CanaryView may snapshot the minimum evidence required when an open security case, confirmed canary touch, completed/contested action, audit requirement, explicit legal hold, or reproducibility requirement would otherwise lose its supporting facts. Exact trigger and minimum-evidence rules remain an architecture question. Full vendor payloads are not copied by default.

Actual canary secret values are never retained. Store only a canary identifier, safe fingerprint, placement metadata, touch evidence, and provenance. Request bodies and sensitive payloads are not retained by default. Explicit diagnostic mode requires field-level redaction before persistence, a visible expiry, access audit, and the hard ceiling in the selected profile.

## Retention profiles

Profiles are defaults subject to customer policy, regulation, source capabilities, and validated cost. **Standard is the recommended default.** Advanced overrides are explicit, versioned, and audited.

| Data class | Lean | Standard (recommended) | Regulated |
|---|---:|---:|---:|
| Live correlation buffer | 6 hours | 24 hours | 24–72 hours by policy |
| Collector/edge replay spool | 24 hours | 24–72 hours | 72 hours unless policy requires less |
| Raw vendor telemetry in CanaryView archive | Source-owned by default; up to 7 days when explicitly archived | Source-owned by default; 7 days hot, 30-day normal maximum; override up to 90 days | Source-owned where possible; customer-approved 30–90 days |
| Request bodies/sensitive payloads | Not retained | Not retained; 24-hour diagnostic mode, 7-day hard default ceiling | Not retained unless explicitly required; redacted and access-audited, with the same 7-day hard default ceiling unless a separately reviewed legal/regulatory override applies |
| Normalized observations/evidence envelopes | 30 days hot; 6 months historical | 90 days hot; 13 months historical | 13 months hot; policy-defined historical period |
| Correlated security traces | 90 days | 13 months | 3 years or required policy |
| Security cases, confirmed canary touches, verdict evidence | 1 year | 3 years | 7 years; until release under legal hold |
| Detailed graph-edge history | 90 days | 13 months | 3 years or required policy |
| Daily/weekly graph summaries | 13 months | 36 months | 7 years or required policy |
| Current graph state | While tenant is active | While tenant is active | While tenant is active plus approved export/closure window |
| Recommendations, approvals, actions, validation, rollback, audit | 1 year | 3 years | 7 years |
| Connector capability/configuration history | Active version plus 1 year | Active version plus 3 years | Active version plus 7 years |
| Connector health, coverage, checkpoint, and schema-drift history | 30 days | 90 days | 13 months; coarser summaries may be retained by policy |
| Learned feature history and behavioral baselines | 12 months | 24 months | 36 months, subject to model-use policy |
| Model versions and evaluation results | Model life plus 12 months | Model life plus 24 months; retired artifacts 24 months | Model life plus 7 years when required for regulated decisions |
| CanaryAttacker/Qwen synthetic ground truth | Indefinite, versioned development-lab corpus | Indefinite, versioned development-lab corpus | Indefinite, versioned development-lab corpus |

Legal hold overrides expiry for held objects until authorized release. It does not automatically preserve unrelated raw payloads, grant broader access, change residency, or permit model use.

## Logical storage architecture

The logical layers are contracts, not database selections:

1. **Optional Site Gateway/edge spool** — short, encrypted, quota-bounded local delivery buffer with acknowledgement, replay, deduplication, 24–72-hour expiry, and observable loss/failure. It is absent in the SaaS-only profile unless a source-owned integration supplies its own buffer.
2. **Raw evidence layer** — federated source references plus minimum redacted incident snapshots. It does not duplicate full vendor streams by default.
3. **Normalized observation store** — tenant-isolated, compact, time-queryable, immutable/versioned observations and evidence envelopes.
4. **Append-only relationship history** — relationship assertions, retractions, provenance, and validity intervals from which current and historical graph views can be rebuilt.
5. **Security-case and audit store** — durable `SecurityCase`, `Explanation`, `ImpactAssessment`, `Recommendation`, `SecurityIntent`, `ActionPlan`, `ActionExecution`, `CanaryOpportunity`, approvals, holds, and audit records.
6. **Connector operations store** — tenant-isolated capability-manifest versions and bounded health, coverage, checkpoint, replay/backfill, permission, rate-limit, and schema-drift history. It stores references to credentials, never credential values.
7. **Feature and model registry** — feature definitions, training windows, input classes, model versions, evaluation results, deployment/retirement dates, lineage, and model-use authorization.

```text
collectors -> encrypted edge spool -> normalized observations
       \             |                       |
        \-> federated raw refs/snapshots     +-> relationship history -> graph views/summaries
                                              +-> traces -> cases/actions/audit
                                              +-> authorized features -> model registry
```

A graph database or materialized graph view must never be the only source of truth. Relationship history plus provenance must support reconstruction, correction, expiry, and historical queries. No production engine is selected by this bootstrap.

## Deletion, expiration, and derived-data behavior

Every persistent class defines its classification, sensitivity, profile, expiration behavior, hold behavior, deletion path, derived-data effect, residency, encryption boundary, model-use permission, lineage, and estimated storage impact.

The initial lifecycle rules are:

1. Expiry and customer deletion produce a scoped, audited lifecycle event.
2. Raw bytes are removed when required; a minimal non-sensitive tombstone may retain record ID, hash, source, time, deletion reason, and affected lineage when legally permitted.
3. Derived traces, edges, cases, recommendations, and features are found through `derivation_lineage`.
4. Rebuildable views are rebuilt or invalidated. Non-rebuildable conclusions are marked evidence-unavailable and confidence is recalculated rather than silently preserved.
5. A security case or audit record may retain the minimum independently authorized facts required by its own class, but must not use “derived” as a reason to retain deleted source payloads.
6. Feature sets and model artifacts record affected input windows. Deletion either retrains/rebuilds, excludes the subject on future evaluation, or marks the artifact constrained, according to a documented policy. The exact thresholds remain unresolved.
7. Legal hold suspends expiry for the held lineage and records who, why, when, scope, review date, and release. Roles and release policy require review.
8. Expiration never implies consent withdrawal from a source system, and a source-system deletion never goes unreported merely because CanaryView cannot enforce it remotely.

## Residency, encryption, and access boundaries

- Tenant and scope isolation applies in storage, indexing, caches, backups, exports, feature computation, and deletion jobs.
- Every durable object records its residency and logical key reference; keys and secret values are not embedded in evidence.
- Edge spools and snapshots require encryption at rest. Service-to-service transfer requires authenticated encryption.
- Tenant or region key boundaries, backup residency, key rotation, and customer-managed-key support remain architecture decisions.
- Sensitive evidence uses least-privilege access and access audit. Raw-evidence access is narrower than normalized-case access.
- A legal hold cannot silently move data to another region or key boundary.

## Model building and long-term value

Historical intelligence initially supports graph queries, rolling statistics, frequency distributions, seasonal baselines, deterministic rules, retrieval from prior cases, calibrated correlation scores, placement ranking, and action-outcome scoring. The project must not begin by training a custom language model on customer telemetry.

Per-tenant learning comes first. Each feature/model artifact records feature definition, time window, contributing data classes, source lineage, tenant/scope, evaluation, deployment/retirement dates, and model-use authorization. Historical evidence weighting is explicit and tested; retention does not make old evidence equally influential forever.

Cross-tenant learning requires separate explicit opt-in, de-identification, minimum cohort thresholds, provenance, regional controls, deletion support, a documented training purpose, and a dedicated model-use authorization. Operational retention permission is neither consent nor authorization for global model training.

Synthetic CanaryAttacker intent/action evidence is marked `synthetic=true`, carries a scenario ID/version, and is retained as a versioned development-lab corpus. It is isolated from production baselines, customer behavior models, and production incident statistics. Attacker output is never trusted telemetry.

## Storage volume and cost controls

Before activating a profile or override, CanaryPlatform estimates by class:

```text
daily retained bytes = events per day * average persisted bytes per event
retained footprint = daily retained bytes * retention days * replication/index/backup factor
```

The console shows measured or explicitly estimated event rate, average record size, retained volume, storage region/tier, sensitive fields, expiry, holds, and expected cost. Estimates distinguish source-owned raw telemetry from CanaryView-retained data. Quotas, sampling, aggregation, compaction, cold-tier transitions, and overload behavior are visible and fail without silently dropping high-value evidence. Cost pressure must not quietly widen privacy or shorten held/audit evidence.

## Operator workflow requirements

The graphical workflow presents Lean, Standard, and Regulated profiles with Standard recommended. Before approval it shows included classes, duration per class, estimated daily and retained volume, sensitive fields, earliest/latest expiry, legal holds, model-use status, region, and cost. It requires no YAML, query language, raw policy code, or CLI. Advanced overrides live one disclosure level deeper and show the same consequences.

Operators can inspect an object's data class, expiry, hold, raw-reference availability, lineage, and model-use status from the claim it supports. Authorized hold creation/release and model-use changes are separate, auditable workflows. These requirements are expanded in `docs/CANARYPLATFORM_OPERATOR_EXPERIENCE.md`.

## Open architecture questions

The unresolved storage questions are part of the full list in `docs/CANARY_PLATFORM_ARCHITECTURE.md`. In particular, architecture review must decide production storage engines, per-class volume/latency/cost targets, supported overrides, snapshot triggers, deletion propagation thresholds, residency/key boundaries, legal-hold roles, graph reconstruction/compaction, operational-retention versus model-use enforcement, historical weighting, and broken-reference behavior.

M2A.0 records and reviews these decisions before M2A canonical-model implementation. The gate may approve logical contracts while leaving vendor selection to a later explicitly approved task; it must not smuggle a production backend implementation into architecture work.
