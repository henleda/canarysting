# CanaryView Canonical Data Model

Status: approved conceptual specification (M2A.0.4, 2026-09-01) with the M2A.1 package/reuse boundary recorded. This document still defers persistence technology and runtime implementation.

## Purpose

The CanaryView model gives human and non-human consumers one vendor-neutral language for security activity without throwing away source-specific evidence. It must support passive intelligence before CanarySting is enabled and preserve the existing CanarySting `OBSERVED`, `PERMITTED`, and `ADVERSARIAL` graph semantics.

Connector category contracts, capability manifests, health, and the collector/action boundary are specified in `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`. They consume this model; they do not redefine it per vendor.

The model is optimized for explainability:

- immutable source observations are retained as facts about what a source reported;
- correlation records explain every join;
- inference is labeled rather than presented as observation;
- confidence, missing evidence, and conflicting evidence are explicit;
- recommendations are separate from actions;
- actions require authorization and retain execution and rollback evidence;
- every record is scope-isolated and bounded by retention/resource policy.

The model is authoritative across all four deployment profiles. Connector execution location, Site Gateway presence, managed-asset form, Kubernetes runtime, or response mechanism must not change the meaning of canonical evidence. Every vendor contributes an evidence fragment, never universal truth.

## Knowledge-state distinctions

These states must never collapse into a single “event” or “truth” flag:

| State | Meaning | Example |
|---|---|---|
| Source-of-truth observation | Immutable record of what a named source observed, declared, or decided. It is authoritative only about the source report. | Hubble reported flow X allowed by policy Y at time T. |
| Correlated observation | One or more source observations joined by a recorded method and confidence. | Envoy request R and Hubble flow F likely describe the same journey. |
| Inference | A conclusion derived from observations/correlations under stated logic or a model. | The request likely crossed a trust boundary. |
| Recommendation | Proposed operator outcome with evidence, risk, approval, and rollback expectations. | Place a harmless credential canary on a dark path. |
| Action | Approved or executed mutation by a named control plane. | CanarySting placed canary C after operator approval. |

The lifecycle vocabulary also keeps `observed`, `declared`, `correlated`, `inferred`, `model-generated`, `recommended`, `approved`, `executed`, and `verified` distinct. Model-generated language may summarize or interpret evidence; it cannot promote an inference to observation, a recommendation to approval, or a requested action to a verified outcome.

Every assertion also carries an assertion mode:

- `OBSERVED`: directly measured by a source.
- `DECLARED`: supplied by configuration, policy, CMDB, scenario, or operator.
- `VERIFIED`: supported by a defined verification procedure, such as authenticated mesh identity with trust-chain evidence.
- `INFERRED`: derived from other evidence.

A syntactically valid SPIFFE URI is not, by itself, `VERIFIED`. “Deterministic” describes how a conclusion was produced, not whether its premise was directly observed.

## Common envelope

Every durable canonical record should carry a common envelope, even if a connector retains a richer vendor payload elsewhere. Fields are required where applicable rather than populated with misleading empty values:

- stable record identifier, `schema_version`, and validity/version state;
- `tenant_id`, `scope_id`, deployment boundary, and `residency_cell_id`;
- `data_class`, `sensitivity`, `retention_profile`, policy/override version, `retention_start`, `expires_at`, lifecycle state, and legal-hold references;
- residency policy and purpose-scoped `encryption_key_ref` (a reference, never key material);
- `source_system`, source instance, `source_timestamp`, `observed_timestamp`, and ingest time;
- collector identity and `collector_version`;
- assertion mode and producer type (deterministic, correlation, inference, model-generated, operator);
- explicit `confidence` and confidence method;
- evidence references;
- `raw_event_ref` and `raw_event_hash`, not necessarily embedded raw content;
- `derivation_lineage` to parent observations/correlations;
- separate operational-processing, per-tenant model-use, and cross-tenant model-use policy references;
- `synthetic` and `scenario_id` for generated lab evidence;
- integrity/audit metadata;
- labels limited to approved, non-sensitive canonical attributes;
- conflict and missing-evidence references.

Canonical records should be append-only or versioned. Corrections supersede earlier interpretations without rewriting what a source originally reported.

The envelope and its lifecycle value types belong to the future standard-library-only `internal/canaryview/model` package and are composed into every durable canonical record. The model expresses the decision; it does not perform authorization, persistence, expiry, deletion, rebuild, or backend work. Those operations belong to later application and repository services. Source-specific TTLs or retention settings do not satisfy this contract by themselves, and a normalized record cannot persist until its reviewed envelope is complete.

The Go model is the semantic source of truth. A future external transport uses the separate `api/proto/canaryview/v1` path and `canaryview.v1` protobuf namespace, with explicit converters and round-trip/drift tests. The existing CanarySting `canarysting.v1` contract remains unchanged. Compatible additions may extend v1; breaking meaning or knowledge-state changes require v2 and explicit translators. Each durable record's `schema_version` identifies its record schema independently of the transport package version.

### Lifecycle policy contract

The M2A.0.2 lifecycle baseline makes retention executable data rather than prose attached later:

- `retention_start` uses a trusted collector-observed/ingest clock for collected records and the reviewed close, finalization, supersession, or retirement event for derived/workflow records. It never uses last access and never rewrites `source_timestamp` or `observed_timestamp`.
- `expires_at` is computed by a versioned `DataLifecyclePolicy` from data class, profile, and an approved override. A Regulated policy-defined period must be concrete before the record can persist.
- lifecycle state distinguishes `ACTIVE`, `EXPIRY_DUE`, `HELD`, `DELETION_PENDING`, `DELETED`, `INVALIDATED`, and `DELETION_FAILED`. Expired, deleted, held, and invalidated are not synonyms.
- a legal hold names exact records/lineage, reason, owner, review date, authorization, release authority, original expiry, residency, and key boundary. It suspends expiration only; it does not widen access, snapshot content, or model use.
- a lifecycle decision/event records policy version, trigger, actor/automation, affected lineage, before/after state, result, retries, and permitted tombstone. Profile changes append decisions rather than mutating history.
- raw references expose `available`, `expired`, `deleted`, `access_denied`, `moved`, or `integrity_mismatch`. Availability changes may lower confidence but never erase provenance.
- a raw snapshot records its approved trigger, minimum field set, redaction, authorizer, acquisition time, integrity hash, expiry, and lineage. Ordinary snapshots cannot contain secrets, credentials, actual canary values, authorization headers, or unredacted request bodies.

The class-by-class clocks, profile durations, hold eligibility, deletion effects, and snapshot triggers are authoritative in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. Persistence implementations must deterministically test those decisions; a backend default cannot replace them.

### Logical persistence and reconstruction contract

M2A.0.3 assigns each durable canonical record to one tenant and approved residency cell and gives it a purpose-scoped logical key reference. Operational retention/processing and the two model-use grants are independent: retention cannot enable training, per-tenant authorization cannot enable cross-tenant use, and a legal hold cannot change either. Both model-use grants default off.

Normalized observations and append-only relationship assertions/retractions are the durable inputs for graph reconstruction. A graph, trace/search index, summary, feature cache, or other projection records its tenant, residency cell, schema/policy versions, input high-water mark, build time, and integrity digest. Such a projection is not evidence by itself and cannot become the only representation of provenance, lifecycle, or historical state.

Relationship events preserve assertion ID, typed endpoints, validity/observation intervals, assertion mode, confidence, source and derivation lineage, and supersession/retraction/lifecycle state. Compaction must be semantically lossless across those fields. Deletion or expiry removes protected content, appends the lifecycle/retraction decision, and causes affected projections to rebuild or become explicitly invalidated.

Model artifacts use the registry as the authority for purpose, input windows/lineage, grants, evaluation bounds, constraint, deployment, and retirement. Affected input deletion or authorization withdrawal invokes a zero-tolerance default: an artifact without a pre-approved and tested nonzero removal rule is constrained and withdrawn, not silently reused. Synthetic records are rejected by production feature/model paths and live in a separate internal domain and registry namespace.

The authoritative layer matrix, reconstruction tests, tenant/residency/key and backup boundaries, hold roles/cadence, deletion objectives, model gate, and estimation contract are in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. Production storage engines and physical regional/key products remain unselected.

## Entity model

Every entity has a stable canonical ID, an operator-facing display name when known, a scope, a type, aliases, provenance, validity interval, and identity confidence. Technical IDs remain available but do not become primary display names.

### Actors and identities

- **Identity** — a resolved principal with one or more identifiers and confidence-bearing proofs.
- **Human** — a person acting through a system or credential.
- **AI agent** — a model-driven or automated non-human principal; it has no implicit authority. The term does not describe a managed canary asset, Site Gateway, endpoint collector, or local response runtime.
- **Workload** — a deployable/runtime workload identity.
- **Process** — a host process with executable/runtime evidence.

### Infrastructure and application

- **Host** and **Node** — physical/virtual host and orchestrator node.
- **Cluster** — an orchestration/security boundary.
- **Pod** — a Kubernetes pod instance, distinct from its workload owner.
- **Application** — operator/business-level application grouping.
- **Service** — network-addressable logical service.
- **Endpoint** — concrete addressable destination.
- **API** — semantic interface or operation exposed by a service.
- **Asset** — resource whose sensitivity or business value may affect impact.
- **Scope** — deployment, environment, tenant, cluster, namespace, or other enforced isolation boundary.

### Activity

- **Connection** — transport connection over time.
- **Flow** — directional or bidirectional network activity represented at a source-defined layer.
- **Request** — application-layer operation, possibly one of many on a connection.
- **Trace** — correlated security journey containing ordered observations and joins.
- **Observation** — immutable normalized claim made by one source.
- **Evidence** — material supporting or contradicting a claim.
- **Correlation** — explicit relationship joining records/entities.

### Security controls and outcomes

- **SecurityControl** — Cilium, Envoy, CanarySting, BIG-IP, NGINX, Kubernetes, or another observing/deciding/executing control.
- **Policy** — source policy with native reference and normalized intent where supported.
- **PolicyDecision** — a control's allow, deny, route, authenticate, authorize, inspect, or other decision.
- **Verdict** — CanarySting or another engine's assessed outcome, preserving producer semantics.
- **ActionRecommendation** — evidence-backed proposal; a specialization of `Recommendation`.
- **SecurityIntent** — vendor-neutral desired security outcome, scope, duration, and preservation constraints; it coordinates rather than replaces vendor-native policy.
- **Action** — intended mutation type independent of its plan/execution state.

### Deception and adversarial concepts

- **Canary** — harmless deception object definition/instance.
- **CanaryPlacement** — materialized CanarySting placement with ownership, scope, validity, and cleanup data.
- **CanaryTouch** — observed interaction with a canary; for CanarySting this remains the only punitive trigger.
- **AttackerIntent** — declared pre-action ground truth from a bounded scenario.
- **AttackerAction** — post-action execution ground truth and outcome.

### Operator and governance concepts

- **SecurityCase** — durable investigation root joining explanation, impact, evidence, recommendations, and actions.
- **Explanation** — evidence-backed answer to why CanaryPlatform believes a claim.
- **ImpactAssessment** — observed effect and potential blast radius, with uncertainty.
- **Recommendation** — advisory next step, distinct from authority or execution.
- **ConnectorCapabilityManifest** — versioned declaration of what a connector can observe or an adapter can plan, preview, apply, verify, expire, and roll back; available to operators and agents.
- **ActionPlan** — immutable, previewed vendor-native mutation proposal with validation and rollback, optionally derived from a `SecurityIntent`.
- **ActionExecution** — approved execution, result, validation, and rollback history.
- **CanaryOpportunity** — evidence-backed candidate for human-approved CanarySting placement.
- **CanaryPlacementRecommendation** — operator-facing `Recommendation` projection that references an immutable, versioned `CanaryOpportunity`; it is not a second canonical placement or wire object.
- **DataClass** — classification that binds sensitivity and lifecycle requirements to an object.
- **RetentionProfile** — named Lean, Standard, Regulated, or approved override policy for expiration by class.
- **DataLifecyclePolicy** — expiration, deletion, invalidation, hold, residency, encryption, and storage-impact behavior.
- **LegalHold** — separately authorized suspension of expiration for named data/lineage; it does not grant model use.
- **ModelUsePolicy** — permission and purpose boundary for feature/model use, independent of operational retention.
- **DerivationLineage** — versioned acyclic links from a derived object to its inputs and transformations.

## Observation and evidence

### Observation

An `Observation` minimally contains:

- observation ID, type, scope, and times;
- source and collector;
- subject and object entity references where applicable;
- network/application attributes that were actually present;
- source-native decision and policy reference;
- source-native IDs (transaction, proxy connection, signal, trace/span, canary, scenario);
- assertion mode;
- raw evidence reference;
- canonical attributes produced by normalization;
- a bounded, versioned extension/evidence envelope for vendor-specific fields;
- confidence in the normalization, distinct from confidence in later correlation;
- missing expected fields and parser warnings.

An observation records what a source said even if another source disagrees. Vendor payloads stay behind evidence references and source-specific extensions rather than polluting the canonical required schema.

### Evidence

`Evidence` contains:

- evidence ID and scope;
- source system, source instance, collector, and acquisition time;
- content type and a safe summary;
- immutable raw-event reference or bounded embedded value;
- integrity/checksum metadata;
- sensitivity, access control, retention, and redaction state;
- identifiers extracted from the evidence;
- claims it supports or contradicts;
- availability status when raw data has expired or is inaccessible;
- when embedded as a minimum snapshot, the approved trigger, authorizer, selected/redacted field manifest, acquisition time, expiry, and lifecycle decision reference.

Raw evidence is one click from the claim it supports, subject to authorization. Missing raw material must be represented as unavailable—not silently removed from provenance.

### Provenance

Every derived object retains an acyclic lineage to input observations/evidence and the exact transformation, rule, query, or model version. Provenance must answer:

- which source systems contributed;
- which evidence supports or conflicts with the claim;
- how the records were joined;
- which identity resolution was used;
- what was missing;
- what deterministic or model logic ran;
- who or what approved any action.

## Confidence model

Confidence is explicit, contextual, and auditable. A future implementation may choose numeric bands, but it must retain these components:

- confidence level or bounded score;
- method (exact ID, verified identity, tuple/time window, probabilistic inference, declared mapping, model interpretation);
- source quality and identity assurance;
- evidence completeness;
- ambiguity/candidate count;
- conflicts;
- time-window uncertainty;
- algorithm/model version and calibration state;
- human confirmation or rejection, when present.

Confidence in identity, correlation, explanation, impact, and recommendation are separate dimensions. Aggregation must not convert several weak observations into “verified” without a defined verification rule. Label-derived identity remains explicitly lower confidence than authenticated mesh identity.

## Identity model

An `Identity` may retain Kubernetes namespace, service account, pod UID, owner/workload, selected labels, Cilium identity, SPIFFE ID, process/host identity, human identity, and vendor principal IDs. Each identifier has:

- issuer/source;
- assertion mode;
- validity interval;
- verification evidence;
- aliases and mappings;
- confidence;
- scope.

Resolution prefers validated mesh/SPIFFE identity, then lower-confidence declared/label-derived workload identity. Conflicting identities are retained as alternatives. Ambiguity must not fall back to a global scope or enable precise enforcement.

## Correlation and security traces

### Correlation identifiers

Correlation may use any subset of:

- event and ingest timestamps with uncertainty;
- source/destination IP and port, protocol, and five tuple;
- pre- and post-NAT tuples;
- proxy downstream/upstream connection IDs and translations;
- Kubernetes namespace, service account, pod UID, workload, node, and Cilium identity;
- SPIFFE identity and its verification evidence;
- process/cgroup/socket context and socket cookie;
- HTTP method, host, path template, and bounded safe request metadata;
- request IDs and vendor transaction IDs;
- OpenTelemetry trace/span IDs;
- CanarySting flow, signal, policy-decision, verdict, and canary IDs;
- attacker, scenario, intent, and scenario-step IDs.

No identifier is universally required. The socket cookie remains the sole CanarySting L7/kernel join; it is not assumed to exist in other vendor observations.

### Correlation

A `Correlation` contains the candidate records, chosen relationship, join method, join keys, time window, confidence, rejected candidates, missing fields, conflicts, and algorithm/operator provenance. It never overwrites source records.

NAT and proxy translation must preserve both sides of a translation and the translating control. An eventual representation must support chained translations without pretending the original and translated tuple are identical.

### Trace

A `Trace` contains:

- trace ID, scope, validity window, and status (partial, complete under declared coverage, conflicted);
- ordered observations and policy decisions;
- correlations between hops;
- participating identities, applications, services, endpoints, processes, and controls;
- explanation and evidence links;
- missing expected controls/telemetry;
- conflicts and alternate paths;
- canary touches, verdicts, recommendations, actions, and containment state;
- aggregate completeness/confidence with its method.

OpenTelemetry IDs are strong correlation evidence when present but do not define the CanaryView trace boundary by themselves.

## Policy decisions

A `PolicyDecision` records the deciding control, native policy/rule reference and version, subject/object, action, direction, observed result, reason, source semantics, time, and evidence. “Allowed,” “routed,” “authenticated,” and “authorized” are distinct relationships and must not be conflated.

Read-only policy ingestion may produce declared `PERMITTED` relationships. An observed vendor decision may support `PERMITTED`, `DENIED`, `ROUTED`, `AUTHENTICATED`, or `AUTHORIZED` edges while retaining the native decision. Policy interpretation uncertainty is explicit, and policy recommendations remain advisory until approved.

## Graph model

Canonical relationships include:

- `OBSERVED`
- `PERMITTED`
- `DENIED`
- `ROUTED`
- `TRANSLATED`
- `AUTHENTICATED`
- `AUTHORIZED`
- `CONNECTED`
- `CALLED`
- `SPAWNED`
- `TOUCHED`
- `CANARY_TOUCHED`
- `ADVERSARIAL`
- `ENFORCED`
- `CONTAINED`

Every edge contains source/destination entities, direction, scope, validity interval, provenance, confidence, assertion mode, evidence, source controls, and protocol/port/API constraints where relevant.

Existing CanarySting semantics are preserved:

```text
DARK REACHABILITY = PERMITTED - OBSERVED
```

The subtraction is scope-, identity-, direction-, protocol-, port-, API-, and time-aware. Unknown or incomparable constraints remain uncertain; they are not silently treated as dark. `ADVERSARIAL` edges require confirmed canary-derived malicious activity under CanarySting rule 8, not baseline novelty alone. Graph output is advisory until a separately approved action is executed.

## Operator decision contracts

These contracts are durable backend concepts, not text the front end reverse-engineers from raw events.

### SecurityCase

A `SecurityCase` is the incident/finding workspace root:

- case ID, scope, state, severity, confidence, and times;
- plain-language title and summary;
- affected applications, identities, assets, and environments;
- contributing security controls;
- traces and correlated timeline;
- `Explanation`;
- `ImpactAssessment`;
- current `Recommendation` objects;
- current `SecurityIntent` objects;
- available `ActionPlan` objects;
- current containment and rollback state;
- owner, approvals, audit, and evidence access policy.

### Explanation

An `Explanation` contains:

- claim;
- plain-language explanation;
- supporting evidence;
- source systems;
- confidence;
- correlation method;
- missing evidence;
- conflicting evidence;
- producer type and deterministic/rule/model version;
- alternate explanations where material.

It must directly answer “Why do you believe this?” Model-generated language may summarize the explanation but may not replace its evidence or hide uncertainty.

### ImpactAssessment

An `ImpactAssessment` contains affected and potentially affected applications, identities, assets, and scopes; observed impact; estimated blast radius; attack/dark paths; sensitivity context; confidence; assumptions; missing/conflicting evidence; and time horizon. Observed impact and potential risk are visually and semantically distinct.

### Recommendation

A `Recommendation` contains:

- recommended action;
- reason and expected result;
- affected scope;
- risk and urgency;
- confidence;
- executing control plane;
- approval requirement and required authorization;
- reversibility and rollback plan;
- supporting evidence and explanation;
- constraints, expiry, and alternatives;
- state (proposed, previewed, approved, rejected, expired, superseded).

No recommendation ends with an unqualified “investigate elsewhere.” It provides evidence and a concrete next step, even when that next step is to acquire named missing evidence.

### SecurityIntent

A `SecurityIntent` expresses the operator outcome without pretending that several native control planes share one policy language. It contains:

- intended outcome and affected scope;
- protected traffic, identities, assets, or business functions that must remain available;
- duration/expiry and urgency;
- constraints, risk, and acceptable impact;
- supporting recommendation, explanation, and evidence;
- capability requirements and the manifest versions used during planning;
- one or more proposed vendor-native `ActionPlan` references;
- approval policy and plan coordination/rollback-order requirements; and
- state (proposed, planned, previewed, approved, executing, partially applied, verified, expired, rolled back, failed, or superseded).

An intent is advisory until the exact derived plans are previewed and approved. It never authorizes a capability absent from the active connector manifest.

### ActionPlan

An `ActionPlan`, shown before approval, contains:

- parent `SecurityIntent` where applicable, target, and executing native control plane;
- connector/action-adapter identity, capability-manifest version, and native action type;
- expected concrete changes;
- expected traffic effect;
- affected workloads/applications/identities;
- estimated blast radius and confidence;
- prerequisites and authorization;
- validation plan and success/failure conditions;
- rollback plan and rollback validation;
- supporting recommendation/evidence;
- expiry/idempotency and conflict checks.

### ActionExecution

An `ActionExecution` contains the immutable approved plan/version, approver and executing principal, authorization decision, start/end time, control-plane request/reference and vendor change identifier, before/after state, result, validation evidence, expiry/removal verification, audit provenance, errors, partial-failure state, current effect, and rollback availability/state. An agent uses this same contract and cannot bypass approval.

### CanaryOpportunity

`CanaryOpportunity` is the canonical basis for a CanarySting placement recommendation:

- target and scope;
- reason and risk;
- expected signal value;
- recommended canary type and placement location;
- supporting evidence and confidence;
- expiry and constraints;
- dark-reachability, fan-out, trust-boundary, asset-sensitivity, weak-visibility, and identity-confidence factors;
- proposed CanarySting executing control plane;
- approval, materialization, validation, and rollback expectations.

`CanaryOpportunity` is the canonical domain and wire name. A `CanaryPlacementRecommendation` is an operator-facing `Recommendation` projection that references the immutable opportunity. Neither is approval, placement, or action, and initial placement is never automatic.

## Canary and adversarial state

`CanaryPlacement` records the approved opportunity/plan, CanarySting materialization choice, owner/run ID, target/scope, lifecycle, harmlessness constraints, observability, cleanup, and resulting canary ID. `CanaryTouch` records cookie/flow/request/identity/canary linkage, touch evidence, confidence, and related verdict.

CanarySting activity—placement, observation, touch, verdict, response, containment, attrition outcome, and attacker behavior—returns to CanaryView as source observations with provenance. CanaryView does not rewrite the Sting verdict.

## Attacker ground truth

`AttackerIntent` is emitted before execution and includes attacker ID, model and version, scenario ID/version, objective, intended action/tool, target, scenario step, constraints, and timestamp.

`AttackerAction` is emitted after execution and includes the corresponding intent/scenario step, action/tool, target, start/end time, result, latency, bounded response metadata, error, and executor evidence.

These are declared lab ground truth about harness intent/execution—not trusted network telemetry. CanaryView compares them with independent Cilium/Hubble, Envoy, kernel, Kubernetes, and CanarySting observations to measure trace completeness, precision/recall, identity accuracy, false joins, missing observations, and time alignment.

## Human and agent interfaces

The same CanaryView application/query services and canonical objects drive the graphical console and structured machine access. Human projections emphasize application, service, identity, environment, asset, and business scope. Technical identifiers remain one disclosure level below. Agent and transport projections may reshape or omit fields for their consumers, but begin outside `internal/canaryview/model`; they cannot create a second interpretation, an unlogged raw path, or extra authority. Human and agent requests retain the same evidence IDs, confidence, authorization state, and audit identity.

Initial conceptual read operations are `query_graph`, `explain_path`, `get_trace`, `get_evidence`, `get_identity`, `get_policy_decisions`, `find_dark_reachability`, `find_attack_path`, `find_canary_opportunities`, and `recommend_canary_placement`. Action simulation and approved execution are later phases.

## Evidence-grounded agentic operations

Agentic operations consume normalized evidence, provenance, confidence, identity, traces, policy decisions, graph relationships, historical cases, and action outcomes. Initial read-only/recommendation operations are `explain_trace`, `explain_path`, `summarize_case`, `identify_missing_evidence`, `identify_conflicting_evidence`, `assess_impact`, `find_dark_reachability`, `find_canary_opportunities`, `recommend_next_step`, `generate_action_preview`, `explain_expected_impact`, and `explain_rollback`.

Every conclusion links to its evidence. Every recommendation includes reason, confidence, expected result, affected scope, executing control plane, approval requirement, validation plan, and rollback plan. The operation records deterministic facts, model-generated interpretation, operator decision point, execution authority, validation, and rollback separately. Core workflows work without prompts; natural language supplements the visual console. Later `simulate_action`, `request_approval`, `execute_approved_action`, `validate_action`, and `propose_rollback` operations may exist only through the same reviewed contracts and authority as human users.

## Persistence, retention, and privacy requirements

- Scope isolation applies to observations, correlations, graph state, learned parameters, evidence, and actions.
- Storage and queries are bounded; the data class, profile/policy version, retention start, expiry, lifecycle state, legal hold, residency, encryption boundary, model-use policy, lineage, and storage impact are explicit.
- Raw vendor events have separate sensitivity, access, and retention from normalized records and remain in their source systems by default.
- Customer raw traffic, baselines, scope state, and identifying detail do not cross deployment boundaries; CanarySting rule 9 remains the cross-deployment egress floor.
- Deletion/expiry of raw evidence removes protected content and leaves only a policy-permitted provenance tombstone; dependent traces, edges, cases, features, recommendations, and models are rebuilt, invalidated, constrained, or marked evidence-unavailable according to their own policy. Deletion failure is a visible retry/alert state, never success.
- Legal hold suspends expiration without widening access, residency, or model-use permission.
- Source-owned raw expiry/deletion and CanaryView deletion are reported separately; neither system claims deletion in the other.
- Minimum snapshots are created only for the approved open-case, canary-touch, action/audit, hold, or reproducibility triggers and contain only the authorized redacted fields needed for the named claim/outcome.
- The append-only relationship history—not a graph materialization alone—supports current-state reconstruction and historical summaries.
- Model prompts/outputs are evidence only when explicitly retained and authorized; they are never hidden decision state.
- Synthetic CanaryAttacker data is marked and isolated from production baselines and customer models.

The authoritative lifecycle defaults, current-store inventory, Lean/Standard/Regulated profiles, federated-evidence model, and logical storage layers are in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. M2A.0.4 approved those contracts; each M2A implementation task must still resolve its declared package, schema, lifecycle, and validation decisions without weakening them.

## Package and reuse boundary

The M2A.1 review selected `internal/canaryview/model` as the future canonical package. It is a standard-library-only leaf and cannot import CanarySting engine/contract/intelligence packages, adapters, dashboard code, vendor/Kubernetes SDKs, transport-generated code, or persistence implementations. Source-specific integration adapters map into it; CanaryView application, correlation, graph, case, and query services depend on it; human/API/agent projections depend on those services. The existing Sting runtime never imports CanaryView.

The code-grounded reuse boundary is:

- `internal/engine/observebaseline` remains the only local source of socket-cookie-attributed OBSERVED topology. A one-way adapter may normalize its current snapshots or future deltas, but its capped, expiring current-state store is not canonical relationship history or the CanaryView graph backend.
- `internal/identity` supplies mesh-first resolution and confidence/proof semantics through an adapter. Its Kubernetes-oriented `WorkloadID`, naming, and Sting scope mapping are not the cross-vendor entity model. Parsed SPIFFE syntax alone never produces a canonical `VERIFIED` assertion.
- `internal/intelligence` remains CanarySting-owned. Touch, L7, profile, cost, reconnaissance, audit, feed, and related outputs are source evidence; selected tamper-evidence and bounded-delivery patterns may be reused without adopting their schemas or stores as canonical.
- `internal/intelligence/network` remains the single default-deny boundary for Sting-derived cross-deployment patterns and is not a general connector transport.
- `internal/dashboard` and `dashboard/app` remain presentation projections and reusable console assets, not model ownership.
- `internal/contract`, `api/proto/contract.proto`, and `canarysting.v1` retain the narrow CanarySting flow/signal/verdict responsibility. CanaryView uses its separate model and versioned transport namespace.

Approved placement crosses the product boundary through an outer integration/composition adapter: it receives the exact immutable `CanaryOpportunity` and approved `ActionPlan` version, invokes the existing CanarySting control plane, and maps placement/outcome evidence back into CanaryView observations. Neither core package imports the other, and CanarySting retains materialization and safety authority.

Production storage engines, physical graph implementation, detailed correlation windows, calibrated identity confidence, translation/OpenTelemetry mapping, and vendor-action authorization remain separately reviewed implementation choices in `docs/CANARY_PLATFORM_ARCHITECTURE.md`.
