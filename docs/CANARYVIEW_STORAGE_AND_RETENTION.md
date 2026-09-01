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

This inventory was code-grounded on 2026-08-31. “Owner” below means the current package or future product subsystem responsible for lifecycle behavior, not a staffing assignment. Current sensitivity uses four review labels:

- **Internal** — repository, synthetic-lab, or non-tenant operational metadata;
- **Confidential** — tenant or deployment metadata whose disclosure could reveal architecture, identity, or behavior;
- **Restricted** — raw/local-rich security evidence, cases, actions, credentials, or comparable high-impact data;
- **Not durable** — runtime state that must not be represented as retained evidence without a separate evidence record.

| Current mechanism and owner | Persisted content and sensitivity | Bounds, expiry, and cleanup | Code evidence | CanaryView relevance and gap |
|---|---|---|---|---|
| Shared bbolt substrate — `internal/engine/persist` | Schema v1 buckets for baseline aggregates, malicious hashes, event blobs, local-rich topology/deviants/L7 touches, audit chains, deviant-triage overlays, and global schema/heartbeat metadata. Content ranges from Confidential to Restricted by bucket. | Database mode `0600`; per-scope nested buckets; five-second open timeout; transactional writes. Boot refuses incompatible schema unless the operator explicitly requests reset. There is no database-wide tenant deletion, compaction, backup, legal-hold, or class-retention service. A read-only opener still competes for bbolt's file lock. | `persist.Open`, `persist.OpenReadOnly`, `persist.scopeSub`, `persist.PutBucketsAndHeartbeat`; `persist.TestScopeIsolation`, `persist.TestReadOnlyRefusesWrites`. | Reusable durability, scope-layout, schema, and atomic-write patterns; not a general observation, case, relationship-history, or feature/model registry. |
| Baseline aggregates — `internal/engine/observebaseline` | Per-scope/time-bucket hashed adjacency, identity, and port counts plus bounded quantile summaries and day/flow counts; Confidential derived feature state, with no raw flow or raw address in the aggregate. | Each of the three frequency maps is capped at 4,096 entries per bucket. Runtime selects the 168-bucket default or optional eight-bucket coarse window. Counters persist indefinitely; there is no TTL, old-bucket deletion, tenant retention profile, or model-use marker. | `aggregate.freqCapDefault`, `baseline.DefaultBucketer`, `baseline.WindowBucketer`, `baseline.TestBucketerCardinality`, `Aggregator.encodeDirty`. | Useful bounded feature input. M2A.0 must define training windows, expiration/deletion effects, and model-use authority independently of operational retention. |
| Malicious exclusion set — `internal/engine/observebaseline` over `persist.bktMalicious` | Per-scope hashed source identities confirmed malicious; Confidential derived security state. The hash is not a deletion or consent mechanism. | Durable and scope-isolated, but has no cardinality cap, TTL, removal API, tenant deletion workflow, or lineage/model-use metadata. | `persist.MarkMalicious`, `persist.RangeMalicious`; `persist.TestMaliciousSet`; aggregator rehydration in `observebaseline.Aggregator.rehydrate`. | Current baseline-of-normal exclusion input, not a canonical finding or model registry. Its unbounded lifetime is a lifecycle decision still to make. |
| Canary interaction log — `internal/intelligence/boltevents` over `persist.bktEvents` | Tier ≥ Tag, scope-isolated, append-only derived/addressless interaction events and outcome amendments; Confidential. The event shape structurally excludes raw address, payload, and decoy content. | Durable log has no cap, TTL, compaction, or deletion API. A query examines at most the newest 4,096 blobs and uses a one-hour consumer lookback; that scan cap does not bound on-disk growth and can under-sample an extreme burst without manufacturing a trigger. | `boltevents.recentScanCap`, `Store.Append`, `Store.AmendOutcome`, `Store.Query`; `TestQueryNeverCrossesScope`, `TestEventsSurviveReopen`. | Useful touch-dependent CanarySting evidence producer, not the passive canonical observation store. |
| OBSERVED topology — `internal/engine/observebaseline` over `persist.bktTopology` | Local-rich raw-address node and directed edge current state; Restricted. | Per scope: 4,096 edges and 4,096 nodes. Lowest-frequency/oldest records are evicted at cap; `LastSeen` TTL is 30 days. The fold tick reaps and transactionally persists deletions while incrementing an observable eviction count. No legal hold or historical edge journal exists. | `topoEdgeCapDefault`, `topoNodeCapDefault`, `topoTTLDefault`, `topology.reap`, `Aggregator.encodeDirty`; `TestTopologyCapEvictsLowest`, `TestTopologyReaperTTLAndLostCount`, `TestTopologyScopeIsolation`. | The rule-10 OBSERVED source. It is a bounded current-state projection, not append-only relationship truth or historical reconstruction. |
| Deviant flow history — `internal/engine/observebaseline` over `persist.bktDeviants` | Local-rich non-canary anomalous flow identity and novelty dimensions; Restricted. It is display/forensic context and never a punitive trigger. | 4,096 records per scope; lowest-hit/oldest eviction; 30-day `LastSeen` TTL; fold-tick reap persists deletes and increments an observable loss count. No hold or derived-deletion policy exists. | `deviantCapDefault`, `deviantTTLDefault`, `deviants.reap`; `TestDeviantCapEvictsLowest`, `TestDeviantReaperTTLAndLostCount`, `TestDeviantScopeIsolation`. | A useful local hunting source whose raw identity requires stricter access than normalized evidence. |
| Deviant triage overlay — `internal/engine/persist` | Per-scope ACK/suppress state, operator identity/reason/time, and attributed source address; Restricted operator decision data. | Deliberately outlives deviant cap/TTL churn and is removed only by explicit `DeleteDeviantTriage`. It has no cap, TTL, general garbage collection, or hold semantics. | `persist.bktDeviantTriage`, `PutDeviantTriage`, `DeleteDeviantTriage`; `TestDeviantTriageSurvivesRecordChurn`, `TestVerdictPathDoesNotReferenceTriageOverlay`. | Proves that source expiry and derived/operator-decision expiry cannot be assumed to match. |
| Enriched L7 touches — `internal/intelligence/l7events` over `persist.bktL7Touches` | Tier ≥ Tag local-rich source address, HTTP method/path including query, SPIFFE ID, decision facts, and bounded features; Restricted. No request body is stored. | 4,096 recurrence records per scope with oldest-`LastSeen` eviction and a 30-day TTL. When the SIEM path is enabled, `boot.Build` sets `ReapEnabled` and the drainer runs the reaper hourly; when SIEM is disabled, the cap remains active but periodic TTL reap is not started. Rehydrate does not itself age records. | `touchCapDefault`, `touchTTLDefault`, `Store.Reap`; `siem.reapInterval`, `siem.Drainer.drainOnce`, `boot.Build`; `TestCapEvictsOldest`, `TestTTLReaper`. | Sensitive local evidence. Broader use needs redaction, hold/snapshot rules, and a lifecycle owner that does not depend on optional SIEM configuration. |
| Tamper-evident audit chain — `internal/intelligence/audit` over `persist.bktAuditChain` | Per-scope Tier ≥ Tag decisions and operator actions with local-rich L7/identity/action facts; Restricted. | Append-only, no cap/TTL/delete/legal-hold workflow. Record and head advance atomically. Optional external HMAC key strengthens file-only tamper resistance; unkeyed re-forge and whole-scope erasure are documented limits. Hourly SIEM high-water anchors exist only when the optional SIEM drainer is enabled. | `audit.Store.append`, `audit.HighWaterMark`, `persist.AppendAuditAndHead`; `TestChainValidatesEndToEnd`, `TestDurableWholeScopeErasureNotDetectedDocumentedLimit`, SIEM anchor tests. | Valuable integrity pattern. Retention exceptions, witness durability, tenant key boundaries, and deletion policy require explicit review. |
| Intelligence file spools — `internal/intelligence/transport` | Cleared coarse patterns or opaque enrolled tokens plus cleared patterns; Confidential prototype transfer data, never raw customer telemetry. | Append-only mode-`0600` NDJSON. Readers cap a line at 1 MiB and fail closed on an overlong frame. There is no acknowledgement, truncation, rotation, expiry, quota, encryption-at-rest layer, or automatic cleanup; runbooks manage files manually. | `transport.Spool.Send/Receive`, `ConfirmSpool.SendConfirmation/ReceiveConfirmations`; round-trip, malformed-line, missing-file, and overlong-line tests. | Prototype transport seams, not the `EDGE_REPLAY_SPOOL` service. Delivery state, replay windows, encryption, and observable loss remain planned. |
| SIEM projections and demo receiver — `internal/intelligence/siem` / `deploy/m7-window/siem-sink` | One-way local-rich JSON/CEF/webhook events and audit anchors; Restricted when emitted. The demo sink keeps the latest 25 in memory and appends all received bodies to disk. | Product emitter retries twice, then logs and drops so it cannot block verdicts. External retention belongs to the operator's SIEM. The demo receiver accepts at most 1 MiB per event and appends mode-`0644` NDJSON without rotation/TTL; demo cleanup owns it. | `siem.maxRetries`, `Drainer.emit`; `siem-sink.keepLast`, `sink.handlePost`, `os.OpenFile(..., 0644)`; SIEM non-blocking/import-guard tests. | External references/witnesses are useful, but CanaryView must not claim control of external retention or treat the demo sink as production storage. |
| Dashboard/tap state — `internal/dashboard/tap` | Read projections over bbolt and in-memory sources; the latest attacker-cost value is deployment metadata, generally Confidential. | Non-authoritative in-memory views disappear on restart. The latest cost ledger becomes stale after 30 seconds; no durable case/trace history is created. | Tap snapshot/projector code and its stale-cost tests. | Useful UI projection behavior, not lifecycle-bearing storage. |
| Confirmed profiles and privacy contribution ledger — `internal/intelligence/sharpen` / `internal/intelligence/network` | Per-scope confirmed-malicious behavioral profiles and coarse-pattern-to-opaque-scope-bucket counts; Confidential derived state. | Both are in memory. Sharpening uses a 30-day freshness gate and one-hour event lookback but does not delete entries; restart loses state and lowers confidence. The privacy ledger uses a process-local random salt and loses all counts on restart, failing closed. Neither has a durable feature/model registry, lineage, deletion, or model-use policy. | `sharpen.FreshnessWindow`, `lookbackWindow`, `Store.Match`; `network.Ledger`, `NewLedger`; scope/freshness/k-gate tests. | Useful logic and privacy boundary; durable ownership, authorization, evaluation, and retirement are unimplemented. |
| eBPF maps — `bpf/observe`, `bpf/sockops`, `bpf/enforce` | Kernel execution state keyed by socket cookie; Not durable. | Each current LRU hash map is capped at 65,536 entries and lasts only for its attachment/process/kernel lifecycle. Sockops and enforcement entries delete on socket close; loaders close/detach during cleanup. This state has no retention or legal-hold semantics. | `observe.bpf.c`, `sockops.bpf.c`, and `enforce.bpf.c` map definitions; sock-release delete programs; `TestCloseDeleteRemovesEntry`, sockops delete-on-close tests. | CanaryView should retain evidence references and verified outcomes, never reinterpret live map contents as historical storage. |
| Canonical CanaryView stores — future CanaryView Core / Shared platform | No general normalized-observation store, raw-reference registry, `SecurityCase` store, append-only relationship journal, legal-hold service, model-use registry, feature/model registry, or production graph backend exists. | No current lifecycle implementation exists to inventory. | Repository search finds no Go/protobuf persistence definitions for `raw_event_ref`, `SecurityCase`, or `RelationshipEvent`; architecture documents describe them as planned. | These remain planned capabilities. This inventory does not choose a backend or imply implementation maturity. |

## Data classes and lifecycle envelope

Every planned persistent object must declare a data class, lifecycle owner, and default sensitivity before implementation. Owners below are architectural defaults for review; M2A.0.2 and M2A.0.3 must define enforceable policy and storage boundaries.

| Planned data class | Lifecycle owner | Default sensitivity | Intended content and guardrail |
|---|---|---|---|
| `EDGE_REPLAY_SPOOL` | Optional Site Gateway or source-connector runtime | Confidential | Encrypted, quota-bounded delivery/replay buffer. Absent from Profile 1 unless the existing source integration owns buffering. |
| `RAW_TELEMETRY_REFERENCE` | CanaryView Core evidence service | Confidential | Pointer, checksum, source/version, time, and availability state for a source-owned event; no credential value. |
| `RAW_EVIDENCE_SNAPSHOT` | CanaryView Core evidence service | Restricted | Minimum redacted evidence copied only for an approved case, audit, hold, or reproducibility trigger. |
| `SENSITIVE_PAYLOAD` | Source system by default; explicitly authorized CanaryView diagnostic custodian only when approved | Restricted | Request body, credential-like field, token, or comparable content. Persistence is disabled by default, bounded, redacted, access-audited, and short-lived when exceptionally enabled. Actual secrets remain prohibited. |
| `NORMALIZED_OBSERVATION` | CanaryView Core observation service | Confidential | Compact vendor-neutral source report with provenance and lifecycle envelope; vendor payload remains referenced rather than copied by default. |
| `CORRELATED_TRACE` | CanaryView Core correlation service | Confidential | Versioned joins, conflicts, missing evidence, confidence, and workload-security journey state. |
| `RELATIONSHIP_EVENT` | CanaryView Core graph/evidence service | Confidential | Append-only relationship assertion, correction, or retraction with validity interval and provenance. |
| `GRAPH_CURRENT_STATE` | CanaryView Core graph service | Confidential | Rebuildable present view; never the only source of relationship truth. |
| `GRAPH_SUMMARY` | CanaryView Core graph service | Confidential | Historical aggregates that remain linked to source relationship windows and deletion lineage. |
| `SECURITY_CASE` | CanaryView Core case service | Restricted | Operator-facing evidence, explanations, impact, decisions, and case history. |
| `CANARY_EVIDENCE` | CanaryView Core lifecycle owner; CanarySting evidence producer | Restricted | Confirmed managed-asset placement/touch/result evidence and safe fingerprints; never the canary secret value. |
| `ACTION_AUDIT` | Shared-platform action/audit service | Restricted | Recommendation, preview, approval, execution, validation, rollback, and verified outcome. Read and write authority remain separate. |
| `CONNECTOR_CONFIGURATION` | CanaryView connector operations | Confidential | Versioned capability/configuration metadata and credential references, never credential values. |
| `CONNECTOR_HEALTH` | CanaryView connector operations | Confidential | Bounded health, coverage, checkpoint, lag, permission, rate-limit, and schema-drift history. |
| `FEATURE_BASELINE` | CanaryView feature registry; CanarySting remains owner of its current local baseline | Restricted | Per-tenant learned state, contributing window/classes, evaluation, lineage, deletion impact, and model-use authority. |
| `MODEL_ARTIFACT` | CanaryView model registry | Restricted | Model/version/evaluation/deployment metadata and authorized artifact reference; no implicit customer-telemetry training permission. |
| `SYNTHETIC_GROUND_TRUTH` | CanaryAttacker development laboratory | Internal | Versioned synthetic scenario, intent, action, seed, and evaluation evidence, isolated from production baselines and customer statistics. |

### Inventory completeness checklist

- [x] Enumerated the complete bbolt schema, file mode, schema gate, scope layout, lock behavior, and reset boundary.
- [x] Classified baseline aggregates, malicious exclusions, canary interaction/outcome events, topology, deviants, L7 touches, triage, and audit data.
- [x] Recorded every implemented cap, query bound, TTL, periodic reaper owner, explicit delete path, and known unbounded durable collection.
- [x] Distinguished current-state projections from append-only history and runtime eBPF state from retained evidence.
- [x] Reviewed cleared-pattern and confirmation NDJSON spools, SIEM projections, the demo sink, dashboard/tap state, confirmed profiles, and the cross-scope privacy ledger.
- [x] Verified that canonical raw-reference, normalized-observation, case, relationship-history, legal-hold, feature/model-registry, and production graph stores are absent rather than relabeling current CanarySting stores.
- [x] Assigned every planned persistent class an architectural lifecycle owner and default sensitivity for the next policy review.
- [x] Copied no database record, raw customer evidence, canary value, request body, credential, token, HMAC key, or model artifact into this inventory.
- [x] Selected no production backend and changed no runtime, collection, retention, credential, or model-use behavior.

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
