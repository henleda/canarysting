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

Before likely source expiry, CanaryView may snapshot only the minimum evidence required by the approved trigger matrix below. Full vendor payloads are not copied by default. A source reference, retention profile, or legal hold alone does not grant permission to copy protected content.

Actual canary secret values are never retained. Store only a canary identifier, safe fingerprint, placement metadata, touch evidence, and provenance. Request bodies and sensitive payloads are not retained by default. Explicit diagnostic mode requires field-level redaction before persistence, a visible expiry, access audit, and the hard ceiling in the selected profile.

## Retention profiles

Profiles are defaults subject to customer policy, regulation, source capabilities, and validated cost. **Standard is the recommended default.** Advanced overrides are explicit, versioned, and audited.

| Data class | Lean | Standard (recommended) | Regulated |
|---|---:|---:|---:|
| Live correlation buffer | 6 hours | 24 hours | 24–72 hours by policy |
| Collector/edge replay spool | 24 hours | 72 hours | 72 hours unless policy requires less |
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

### M2A.0.2 profile decision

The Lean, Standard, and Regulated defaults above are accepted as the architecture baseline with three clarifications:

1. Standard replay is 72 hours, not an implementation-selected range. A connector may use less only when its approved capability/volume policy says so and the resulting replay-loss risk is visible.
2. Standard raw snapshots are exceptional, redacted, seven days hot and no more than 30 days normally. The 90-day value is an explicit reviewed override, never the default.
3. Standard diagnostic sensitive-payload capture remains off. When separately authorized, its default is 24 hours and its hard default ceiling is seven days. No profile enables it implicitly.

Regulated values described as “policy-defined” must be made concrete at tenant activation; an unset value blocks persistence for that class rather than becoming indefinite retention. Advanced overrides are versioned policy decisions. They may shorten a period after a deletion-impact preview or extend it after privacy/cost review, but may not disable scope isolation, sensitivity, lineage, residency, encryption, audit, or deletion behavior. Changing a profile never changes model-use authorization.

### Per-class lifecycle policy

`retention start` is a trusted lifecycle clock, separate from the source's event time. For collected records it is the collector-observed time after clock validation, falling back to CanaryView ingest time with the fallback recorded. For derived or workflow records it is the named close, finalization, supersession, or retirement time below. Last access never refreshes retention. All times are UTC and both source and collector-observed timestamps remain immutable.

| Data class | Profile retention (Lean / Standard / Regulated) | `expires_at` start and hold behavior | Deletion path and derived-data effect | Time semantics and minimum snapshot behavior |
|---|---|---|---|---|
| `EDGE_REPLAY_SPOOL` | 24h / 72h / 72h unless approved shorter | From enqueue; acknowledged entries may be removed earlier after durable acceptance. Not holdable because it is delivery state, not evidence of record. | Expiry/ack removes payload and dedupe state; an unacknowledged expiry emits observable replay-loss evidence. Accepted observations are unaffected. | Carries source and collector-observed time without rewriting either. Never creates a snapshot. |
| `RAW_TELEMETRY_REFERENCE` | At least as long as the longest linked observation, case, action, or held lineage | From last linked object's lifecycle end; a hold preserves reference metadata but cannot hold source-owned bytes. | Remove access locator/authorization material; retain only a policy-permitted tombstone and availability state. Dependents remain but recalculate evidence availability/confidence. | Preserves source time and collector-observed time. Snapshot only through an approved trigger, never because a reference exists. |
| `RAW_EVIDENCE_SNAPSHOT` | Up to 7d / 30d normal maximum / required concrete 30–90d policy | From snapshot acquisition. Holdable only when the hold names the evidence/lineage and snapshot trigger; hold does not widen content. | Cryptographically erase/delete protected bytes and indexes; retain a minimal tombstone if permitted. Dependents become evidence-unavailable or are recomputed. | Records source time, collector-observed time, acquisition time, trigger, authorizer, redaction, and hash. Contains only the minimum fields in the snapshot matrix. |
| `SENSITIVE_PAYLOAD` | Not retained / off; authorized 24h default, 7d ceiling / off unless separately required, same ceiling absent reviewed legal exception | From diagnostic capture. Ordinary hold cannot extend the ceiling; a separate documented legal/regulatory exception and access boundary are required. | Cryptographic erasure plus access-audit lifecycle event; derivatives must not contain recoverable payload. | Preserves event/observed time and diagnostic capture time. No snapshot-of-snapshot. Credentials, authorization headers, tokens, actual canary values, and unredacted request bodies remain prohibited. |
| `NORMALIZED_OBSERVATION` | 30d hot + 6mo historical / 90d hot + 13mo historical / 13mo hot + required historical policy | From trusted collector-observed time or recorded ingest fallback. Holdable by exact observation/lineage. | Delete normalized attributes and indexes; leave permitted tombstone. Rebuild/invalidate traces, relationships, cases, recommendations, features, and model lineage. | Source time remains the vendor event time; observed time is collector acquisition. Snapshot source evidence only when a matrix trigger applies. |
| `CORRELATED_TRACE` | 90d / 13mo / 3y or required policy | From trace close or supersession; open traces use a bounded active-window policy. Holdable by trace/case lineage. | Delete or supersede the trace projection; retain source observations only under their own policy. Dependent cases/explanations are recomputed or marked incomplete. | Carries min/max source and observed windows plus derivation time. Minimum snapshot is inherited from cited evidence triggers, not the trace as a whole. |
| `RELATIONSHIP_EVENT` | 90d / 13mo / 3y or required policy | From `valid_to`, or trusted observed time when immediately closed; open assertions must be periodically renewed. Holdable by exact edge lineage. | Append a retraction/tombstone, remove expired protected attributes, and rebuild current/historical graph views. | Carries source validity, observed time, and derivation time. No raw snapshot unless the supporting evidence independently qualifies. |
| `GRAPH_CURRENT_STATE` | Tenant active / tenant active / tenant active plus approved export/closure window | Rebuildable view has no independent hold; lifecycle follows relationship events and tenant closure. | Drop/rebuild affected materializations and caches. It never preserves expired source truth. | Shows source/observed coverage windows. Never snapshots evidence. |
| `GRAPH_SUMMARY` | 13mo / 36mo / 7y or required policy | From summary period end. Holdable only through named supporting lineage. | Delete/recompute affected aggregate cells; mark historical gaps when exact reconstruction is no longer authorized. | Records input source/observed window and summary creation time. Never embeds raw evidence. |
| `SECURITY_CASE` | 1y / 3y / 7y | From case closure; active cases require periodic review rather than an artificial far-future expiry. Holdable with reason, review date, scope, release authority, and audit. | Delete case-private content at expiry; retain only independently authorized audit/tombstone facts. Explanations/impact/recommendations are deleted or marked evidence-unavailable with the case. | Carries incident source/observed window and case create/update/close times. May trigger minimum snapshots only for evidence necessary to preserve a material claim. |
| `CANARY_EVIDENCE` | 1y / 3y / 7y | From placement cleanup or touch/verdict case closure, whichever is later. Holdable by placement/touch/case lineage. | Delete local-rich touch/placement detail and rebuild dependent trace/case state; safe fingerprint/tombstone may remain if independently authorized. | Records placement/touch source and observed times. Snapshot may retain bounded touch facts, never the actual canary secret or decoy content. |
| `ACTION_AUDIT` | 1y / 3y / 7y | From final verified removal/rollback or plan closure. Holdable with separation of hold and action authority. | Preserve only the minimum independently authorized audit facts; delete expired before/after payloads and invalidate dependent explanations as needed. | Records recommendation, approval, execution, validation, expiry/removal, and rollback times. Snapshot may retain exact plan/version, native change ID, bounded before/after facts, and validation evidence—never credentials. |
| `CONNECTOR_CONFIGURATION` | Active + 1y / active + 3y / active + 7y | From supersession or disconnect. Holdable only when configuration version is material to a held case/action. | Delete configuration values and credential references after revocation; retain permitted manifest/version/audit tombstone. Observations remain under their own policy. | Source time is vendor/config effective time; observed time is CanaryView verification time. Never snapshots credential material. |
| `CONNECTOR_HEALTH` | 30d / 90d / 13mo | From health sample/checkpoint time. Not held by default; a bounded case snapshot may preserve material outage/coverage evidence. | Delete detailed samples and recompute bounded summaries; cases retain only independently authorized facts. | Source clock/sequence and collector-observed time are both kept. Snapshot only the minimum gap/failure facts needed by a case. |
| `FEATURE_BASELINE` | 12mo / 24mo / 36mo | From feature window close or baseline retirement. Hold does not grant model use; holdable only when needed to reproduce a held decision. | Delete feature values and indexes; exclude lineage from future evaluation; retrain/rebuild or mark dependent artifacts constrained. | Records contributing source/observed windows and feature computation time. Never snapshots raw inputs merely to preserve a feature. |
| `MODEL_ARTIFACT` | Model life + 12mo / model life + 24mo / model life + 7y when required | From retirement. Holdable only for a named regulated/contested decision; model-use withdrawal is separate and can stop use before expiry. | Delete artifact/reference when due; retain permitted registry/evaluation tombstone. Retrain, withdraw, or mark constrained when input deletion invalidates it. | Records training/evaluation input windows and artifact create/deploy/retire times. Does not snapshot raw training evidence. |
| `SYNTHETIC_GROUND_TRUTH` | Indefinite versioned lab corpus / same / same | `expires_at=null` is allowed only with explicit Internal/synthetic classification, repository/lab ownership, and periodic corpus review. Legal hold is not required. | Explicit corpus/version deletion removes it without changing production baselines; any discovered production dependency is an isolation defect. | Records scenario source time, executor-observed time, seed, and version. Fixtures are already the durable source; no additional snapshot. |

### Minimum-evidence snapshot decision matrix

Snapshotting is a narrow preservation action, not a fallback archive. The decision is evaluated per evidence item before likely source expiry and is audited.

| Trigger | Snapshot decision | Minimum permitted content | Prohibited content and failure behavior |
|---|---|---|---|
| No open case, touch, action, audit, hold, or reproducibility need | Do not snapshot. Keep the reference and availability state only. | None. | No payload copy “just in case.” |
| Open case with a material claim that would otherwise lose its sole support | Snapshot the smallest redacted excerpt that proves or contradicts the named claim. | Source/record ID, source and observed time, schema/version, integrity hash, selected fields, safe summary, claim link, trigger/authorizer, expiry, and lineage. | Full vendor event, unrelated fields, secrets, bodies, tokens, and credentials. If minimization cannot be proven, do not snapshot and mark future availability risk. |
| Confirmed canary touch | Snapshot bounded touch/placement/verdict facts needed for the case or audit. | Safe canary fingerprint/ID, target/scope, touch time, evidence hash, decision/verdict reference, and zero-real-data assertion where proven. | Actual canary secret/value, decoy content, unrelated traffic, or raw body. |
| Completed, failed, contested, expiring, or rolled-back action | Snapshot the approved plan/version and bounded before/after/validation facts necessary to prove outcome and recovery. | Native change ID, approved scope, authorization, timestamps, result, verification, removal/rollback evidence, and hashes/references. | Write credentials, bearer tokens, full configuration exports, or unrelated vendor state. |
| Explicit legal hold or audit requirement | Snapshot only named evidence that is both necessary and authorized; a hold on a case does not copy every linked source event. | Same minimum claim/action fields plus hold ID, scope, reason, review date, and authorization reference. | Any content outside the hold scope or residency/key boundary. Failure to preserve is surfaced; scope is never silently widened. |
| Reproducibility dispute or integrity mismatch | Snapshot the minimum versioned parser/correlation input needed to reproduce the disputed result when authorized. | Schema/collector/model version, normalized input fields, hashes, timing/uncertainty, and transformation lineage. | Unbounded logs or payloads. If protected fields are indispensable and not authorized, record non-reproducibility explicitly. |
| Diagnostic sensitive-payload request | Use the separate diagnostic workflow, not ordinary snapshotting. | Pre-approved redacted fields, purpose, accessor set, 24h default expiry, and access audit. | Actual credentials/canary values and any unbounded or silently extended capture. |

### Expiration and hold execution semantics

- A versioned policy computes `retention_start` and `expires_at` when a record is accepted or finalized. Policy changes append a new lifecycle decision; they do not rewrite source/observed times.
- Expiry moves an object through `ACTIVE -> EXPIRY_DUE -> DELETION_PENDING -> DELETED` or `INVALIDATED`. A hold produces `HELD` and records the suspended original expiry. Errors produce `DELETION_FAILED` with retry/alert evidence; “expired” is never displayed as “deleted.”
- Legal holds are exact-scope and exact-lineage by default. A hold request requires a reason, owner, review date, residency/key-boundary check, and an authorized creator. Release requires separate release permission; Regulated policy may require separation of duties. The concrete RBAC mapping and review cadence remain an M2A.0.3 governance decision.
- Releasing a hold restores the original lifecycle decision. If its expiry already passed, the operator sees a deletion preview and a bounded policy-defined grace period before deletion; release never creates indefinite retention.
- Source-system expiry/deletion changes reference availability but cannot be treated as proof that CanaryView deleted its authorized copies. Conversely, CanaryView deletion cannot claim to delete source-owned data.
- Backup/index/cache deletion must follow the same tenant, residency, key, and lineage scope. Concrete backup purge objectives belong to M2A.0.3 and the later backend selection.

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
7. Legal hold suspends expiry for the held lineage and records who, why, when, scope, review date, and release. Creation and release are separate permissions; concrete RBAC roles and review cadence are assigned in M2A.0.3 governance review.
8. Expiration never implies consent withdrawal from a source system, and a source-system deletion never goes unreported merely because CanaryView cannot enforce it remotely.

### Lifecycle and deletion scenarios

| Scenario | Required lifecycle result | Derived and operator-visible result |
|---|---|---|
| Source event expires while its CanaryView reference remains | Change reference availability to `expired`; do not claim source deletion or fabricate a snapshot. | Recalculate evidence availability/confidence; keep the reference/tombstone while an authorized dependent remains and explain the gap. |
| Source reports deletion, access denial, movement, or integrity mismatch | Record the exact availability state and observation time; stop retrieval attempts that are no longer authorized. | Recompute affected claims where possible; otherwise mark them evidence-unavailable or conflicted without rewriting the original source report. |
| Raw snapshot or normalized observation reaches expiry | Delete protected bytes, indexes, caches, and authorized replicas; emit an audited lifecycle event and permitted tombstone. | Traverse lineage; rebuild traces/relationships/summaries, invalidate recommendations/features, constrain affected models, and update cases/confidence. |
| Customer requests scoped deletion | Resolve exact tenant/scope/subject/lineage; preview held and independently retained records; delete everything authorized by the request. | Report completed, held, failed, and externally source-owned items separately. Never silently broaden to another scope or claim external deletion. |
| Case/evidence is under legal hold when expiry arrives | Enter `HELD`, preserve the original expiry, and retain only the held data/lineage in its existing residency/key/access boundary. | Show hold reason/owner/review/release authority; unrelated evidence continues normal expiry and model use remains unchanged. |
| Legal hold is released after original expiry | Produce a deletion preview and bounded policy-defined grace period, then resume deletion. | Display `DELETION_PENDING`; require separate release permission and retain release audit. Do not reset retention from the release date. |
| Retention profile is shortened | Version the policy and preview volume, cases, holds, broken references, features/models, and deletion schedule before confirmation. | Newly due records enter the normal deletion workflow; held records stay held. The change does not revoke source consent or model-use permission. |
| Retention profile is extended | Version and audit the override after privacy/cost review; apply only to still-authorized, not-yet-deleted data. | Never recover deleted data, widen a snapshot, enable payload capture, or extend model use implicitly. |
| Per-tenant model use is withdrawn | Preserve operational data only until its independent retention expiry; stop new feature/training use immediately. | Remove/exclude affected inputs from future evaluation and retrain, withdraw, or mark existing artifacts constrained according to the model registry policy. |
| Cross-tenant model use is withdrawn | Stop new cross-tenant contribution and resolve affected opt-in lineage under the dedicated deletion policy. | Preserve no raw tenant identity in cohort artifacts; retrain/withdraw/constrain as required and report completion without changing per-tenant operational retention. |
| Connector is disconnected | Revoke connector authority and credential references; expire replay/checkpoint state under its class policy. | Source-owned data is untouched; already retained observations/references follow their existing profile and show stale/disconnected provenance. |
| Tenant closes or is deleted | Delete tenant-scoped current state, observations, relationships, cases, actions, features, indexes, caches, and keys under the reviewed closure policy; isolate any legally held partition. | Report source-owned data separately, complete backup/key destruction under backend objectives, and leave only legally permitted closure/audit tombstones. |
| Synthetic ground truth is deleted or misrouted | Delete the named synthetic corpus/version. If it entered production baseline/model/case statistics, treat that as an isolation defect. | Invalidate contaminated derivatives, rebuild from production-authorized inputs, and preserve the incident/audit—not the synthetic customer association. |

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

M2A.0.2 resolves the profile defaults, per-class expiry/hold/deletion behavior, minimum-snapshot triggers, broken-reference states, and lifecycle scenario outcomes above. The remaining storage questions are part of the full list in `docs/CANARY_PLATFORM_ARCHITECTURE.md`: production engines, measured per-class volume/latency/cost targets, the concrete supported override catalog, tenant/region/key and backup boundaries, legal-hold RBAC/review cadence, graph reconstruction/compaction, model-use enforcement mechanisms, historical weighting, and backend deletion/retry objectives. M2A.0.3 owns those governance/logical-storage decisions; M2A.0.4 records the architecture review outcome.

M2A.0 records and reviews these decisions before M2A canonical-model implementation. The gate may approve logical contracts while leaving vendor selection to a later explicitly approved task; it must not smuggle a production backend implementation into architecture work.
