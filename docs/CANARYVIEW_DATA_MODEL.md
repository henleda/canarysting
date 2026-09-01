# CanaryView Canonical Data Model

Status: conceptual specification for architecture review. This document deliberately defers Go package placement, wire schemas, persistence technology, and runtime implementation.

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
- `tenant_id`, `scope_id`, and deployment boundary;
- `data_class`, `sensitivity`, `retention_profile`, `expires_at`, and `legal_hold`;
- `residency` and `encryption_key_ref` (a reference, never key material);
- `source_system`, source instance, `source_timestamp`, `observed_timestamp`, and ingest time;
- collector identity and `collector_version`;
- assertion mode and producer type (deterministic, correlation, inference, model-generated, operator);
- explicit `confidence` and confidence method;
- evidence references;
- `raw_event_ref` and `raw_event_hash`, not necessarily embedded raw content;
- `derivation_lineage` to parent observations/correlations;
- `model_use_policy`, separately authorized from retention;
- `synthetic` and `scenario_id` for generated lab evidence;
- integrity/audit metadata;
- labels limited to approved, non-sensitive canonical attributes;
- conflict and missing-evidence references.

Canonical records should be append-only or versioned. Corrections supersede earlier interpretations without rewriting what a source originally reported.

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
- **CanaryPlacementRecommendation** — operator-facing recommendation form derived from a `CanaryOpportunity`; naming may converge during wire-contract review, but neither form is a placement or action.
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
- availability status when raw data has expired or is inaccessible.

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

The final wire name (`CanaryOpportunity` versus `CanaryPlacementRecommendation`) is an open review question. Initial placement is never automatic.

## Canary and adversarial state

`CanaryPlacement` records the approved opportunity/plan, CanarySting materialization choice, owner/run ID, target/scope, lifecycle, harmlessness constraints, observability, cleanup, and resulting canary ID. `CanaryTouch` records cookie/flow/request/identity/canary linkage, touch evidence, confidence, and related verdict.

CanarySting activity—placement, observation, touch, verdict, response, containment, attrition outcome, and attacker behavior—returns to CanaryView as source observations with provenance. CanaryView does not rewrite the Sting verdict.

## Attacker ground truth

`AttackerIntent` is emitted before execution and includes attacker ID, model and version, scenario ID/version, objective, intended action/tool, target, scenario step, constraints, and timestamp.

`AttackerAction` is emitted after execution and includes the corresponding intent/scenario step, action/tool, target, start/end time, result, latency, bounded response metadata, error, and executor evidence.

These are declared lab ground truth about harness intent/execution—not trusted network telemetry. CanaryView compares them with independent Cilium/Hubble, Envoy, kernel, Kubernetes, and CanarySting observations to measure trace completeness, precision/recall, identity accuracy, false joins, missing observations, and time alignment.

## Human and agent interfaces

The same canonical objects drive the graphical console and structured machine access. Human projections emphasize application, service, identity, environment, asset, and business scope. Technical identifiers remain one disclosure level below. Agent APIs expose structured evidence and confidence, not an alternate unlogged raw path or extra authority.

Initial conceptual read operations are `query_graph`, `explain_path`, `get_trace`, `get_evidence`, `get_identity`, `get_policy_decisions`, `find_dark_reachability`, `find_attack_path`, `find_canary_opportunities`, and `recommend_canary_placement`. Action simulation and approved execution are later phases.

## Evidence-grounded agentic operations

Agentic operations consume normalized evidence, provenance, confidence, identity, traces, policy decisions, graph relationships, historical cases, and action outcomes. Initial read-only/recommendation operations are `explain_trace`, `explain_path`, `summarize_case`, `identify_missing_evidence`, `identify_conflicting_evidence`, `assess_impact`, `find_dark_reachability`, `find_canary_opportunities`, `recommend_next_step`, `generate_action_preview`, `explain_expected_impact`, and `explain_rollback`.

Every conclusion links to its evidence. Every recommendation includes reason, confidence, expected result, affected scope, executing control plane, approval requirement, validation plan, and rollback plan. The operation records deterministic facts, model-generated interpretation, operator decision point, execution authority, validation, and rollback separately. Core workflows work without prompts; natural language supplements the visual console. Later `simulate_action`, `request_approval`, `execute_approved_action`, `validate_action`, and `propose_rollback` operations may exist only through the same reviewed contracts and authority as human users.

## Persistence, retention, and privacy requirements

- Scope isolation applies to observations, correlations, graph state, learned parameters, evidence, and actions.
- Storage and queries are bounded; the data class, profile, expiry, legal hold, residency, encryption boundary, model-use policy, lineage, and storage impact are explicit.
- Raw vendor events have separate sensitivity, access, and retention from normalized records and remain in their source systems by default.
- Customer raw traffic, baselines, scope state, and identifying detail do not cross deployment boundaries; CanarySting rule 9 remains the cross-deployment egress floor.
- Deletion/expiry of raw evidence removes protected content and leaves only a policy-permitted provenance tombstone; dependent traces, edges, cases, features, recommendations, and models are rebuilt, invalidated, or marked evidence-unavailable according to their own policy.
- Legal hold suspends expiration without widening access, residency, or model-use permission.
- The append-only relationship history—not a graph materialization alone—supports current-state reconstruction and historical summaries.
- Model prompts/outputs are evidence only when explicitly retained and authorized; they are never hidden decision state.
- Synthetic CanaryAttacker data is marked and isolated from production baselines and customer models.

The authoritative lifecycle defaults, current-store inventory, Lean/Standard/Regulated profiles, federated-evidence model, and logical storage layers are in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. M2A implementation is gated on M2A.0 review of that document.

## Reuse and unresolved implementation choices

Likely reuse candidates are `internal/engine/observebaseline` for OBSERVED topology, `internal/identity` for workload identity/confidence, and selected `internal/intelligence` audit/evidence mechanisms. None is automatically the canonical model package. The open architecture questions in `docs/CANARY_PLATFORM_ARCHITECTURE.md` govern package placement, persistence, retention, lifecycle, correlation windows, identity confidence, translations, OpenTelemetry mapping, graph storage, APIs, placement communication, and action authorization.
