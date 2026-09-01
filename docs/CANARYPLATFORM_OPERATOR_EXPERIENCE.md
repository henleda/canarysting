# CanaryPlatform Operator Experience

Status: product-experience contract for architecture review. It defines workflows and validation requirements, not polished visual design.

## Experience promise

CanaryPlatform is architecturally modular and experientially unified. CanaryView and CanarySting appear as capabilities in one console, preserve investigation context, and use the same evidence, confidence, recommendation, approval, action, and rollback contracts.

CanaryView is the lead experience and begins with read-only value. An operator can connect existing security systems, inspect a cross-control trace, understand impact, and receive an evidence-grounded next step without deploying CanarySting or new per-workload software. The console progressively discloses whether a capability uses SaaS only, a Site Gateway, a managed canary asset, or a local response runtime.

Connector category, capability, health, and authority semantics come from `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`; the interface displays those contracts rather than inferring support from successful authentication.

The primary user is a traditional security or network operator. Core workflows assume no software-development, Kubernetes, eBPF, distributed-tracing, query-language, schema, or vendor-API expertise. The product speaks first in incidents, applications, identities, flows, risk, policies, canaries, recommendations, actions, approvals, and rollback.

Every significant finding answers, in one workspace:

1. What happened?
2. Why does CanaryPlatform believe it?
3. What is affected or at risk?
4. What does CanaryPlatform recommend?
5. What action is available?

## Primary personas

| Persona | Needs | Product obligation |
|---|---|---|
| Security operations analyst | Triage, explanation, evidence, related activity, escalation. | Plain-language incident summary with confidence and evidence one click away. |
| Network/security operator | Understand flows and policy decisions; preview and safely execute/rollback controls. | Cross-vendor trace, expected traffic effect, control-plane provenance, and validation plan. |
| Incident responder | Establish timeline, impact, containment, and handoff. | One correlated workspace with affected identities/assets, actions, and immutable audit. |
| Platform/Kubernetes owner | Validate workload identity, policy, and runtime effects without losing application context. | Progressive disclosure from application/workload to namespace, pod, Cilium, and kernel evidence. |
| Approver/change owner | Evaluate risk, blast radius, reversibility, and authorization. | Concise ActionPlan, one confirmation, current execution/rollback state. |
| Auditor/risk owner | Determine why a conclusion/action occurred and who approved it. | Durable provenance, confidence, approvals, execution evidence, and rollback history. |
| Data/privacy administrator | Set retention, residency, legal-hold, and model-use boundaries and understand cost. | Guided profiles, explicit consequences, separate permissions, audit, and lifecycle visibility without policy code. |

AI agents are non-human consumers, not a privileged persona. They use the same contracts and authorization gates. Managed canary assets, Site Gateways, endpoint products, and local response runtimes are not called agents.

## Operator jobs

- Monitor operational/security health and telemetry coverage.
- Triage a significant finding without assembling it from vendor portals.
- Follow a request or attacker journey across controls.
- Understand why a flow was allowed, denied, routed, or contained.
- See what an identity touched and what it could reach.
- Distinguish observed reachability from permitted-but-unused dark reachability.
- Evaluate a canary opportunity and approve safe CanarySting placement.
- Preview, approve, validate, and rollback a containment or policy action.
- Inspect raw evidence without losing case context.
- Onboard a connector and understand coverage, permissions, freshness, and gaps.
- Select a retention profile, inspect expiry/holds/residency/cost, and authorize model use separately from storage.
- Ask CanaryView to explain a trace or case, identify missing/conflicting evidence, assess impact, and recommend a next step without losing the visual workflow or evidence chain.

## Unified console information architecture

The top-level navigation is intentionally small:

1. **Operations** — system posture, active incidents, coverage/telemetry health, and actions needing attention.
2. **Incidents** — SecurityCase queue, triage, ownership, severity, confidence, and state.
3. **Flows** — security traces, topology paths, identity journeys, policy decisions, and raw evidence drilldown.
4. **Canaries** — opportunities, recommendations, placements, touches, lifecycle, and signal value.
5. **Actions** — previews, approvals, execution, validation, rollback, and audit.
6. **Integrations** — category/vendor browsing, collectors and native control planes, capability manifests, read/write authority, permissions, freshness, field coverage, health, errors, onboarding, replay, rotation, and disconnect.

Vendor names/logos communicate provenance within these views; they are not the navigation model. Context persists when moving from incident to flow, canary, action, or integration evidence and back.

The existing CanarySting console offers useful Operations, flow, topology, and evidence foundations. Its current Recon/Deviants/Attack Surface/Adversary Intel/Attacker Cost/Credibility navigation is not yet this platform information architecture and should be migrated incrementally when real CanaryView traces exist.

## Incident workspace

The initial view, in decision-path order, shows:

1. Plain-language title, summary, state, severity, confidence, and last update.
2. Affected applications, services, identities, assets, environments, and business scope.
3. Contributing security controls and current telemetry coverage.
4. Correlated timeline/trace with observed, correlated, inferred, recommended, approved, and completed states visibly distinguished.
5. Explanation: claim, plain-language reason, supporting/contradicting evidence, source systems, correlation method, confidence, and missing evidence.
6. Potential impact: observed effect versus estimated risk/blast radius.
7. Recommendation: action, reason, expected result, urgency, risk, confidence, executing control plane, approval, and reversibility.
8. Available action with preview; current containment, validation, and rollback state.

Explanation and recommendation are visible in the summary or one click away. The operator does not need to navigate to vendor pages to understand the incident. A vendor deep link may supplement the evidence.

## Flow and trace workspace

One workspace shows the complete correlated journey:

- application/identity-oriented source and destination names;
- ordered controls/hops and time;
- observed route, translations, authentication, authorization, policy decisions, canary touch, verdict, and response;
- join confidence and method between each hop;
- missing expected observations and conflicting observations;
- related incident, canary, and action state;
- an evidence drawer anchored to the selected claim/hop;
- technical identifiers on demand.

The operator can ask visually: why allowed, which controls observed it, what disagreed, what else this identity touched, what was permitted, and what containment is possible. Core paths do not require a query or prompt.

## Canary recommendation workflow

CanaryView creates a `CanaryOpportunity` from dark reachability, asset sensitivity, fan-out, trust-boundary crossing, unused permitted paths, visibility gaps, workload-identity confidence, and historical evidence. CanarySting remains responsible for safe materialization.

Interaction path (maximum two steps from recommendation to approved placement):

1. The recommendation card already shows target, reason, risk, expected signal value, confidence, canary type, evidence summary, constraints, expiry, and “CanarySting will execute.” Selecting **Preview placement** opens the ActionPlan in context. (One click.)
2. The preview shows concrete target/change, traffic effect, affected workloads, estimated blast radius, validation, expiration/cleanup, and rollback. Selecting **Approve placement** is the single confirmation. (Second click.)

The placement then appears with pending/executing/completed/failed state, evidence, validation, and rollback. No automatic placement is the initial default.

## Action approval workflow

Every recommendation is adjacent to its explanation and evidence. **Preview action** opens a `SecurityIntent` and its one or more vendor-native `ActionPlan` objects without mutation. The operator sees one coordinated plan while every native change remains separately identified. The preview names each executing control plane and shows:

- exact target and expected changes;
- expected traffic effect;
- affected workloads/applications/identities;
- estimated blast radius and uncertainty;
- required permissions, separate read/write authority, and authorization/approval;
- validation success/failure plan;
- expiration and removal-verification behavior;
- rollback plan, ordering, and trigger;
- evidence and recommendation provenance.

Approval is one confirmation step and produces immutable approved plan versions. Material changes or lost manifest capabilities invalidate the preview and require re-approval. Execution state and partial failure are explicit; “requested” is not displayed as “completed.” Vendor change identifiers remain visible. Failed validation or expiration offers rollback or a named safe next step, and an expired action is not shown removed until removal is verified.

## Rollback workflow

A completed reversible action exposes **Rollback** on its incident and Actions views. One click opens the rollback preview; one confirmation executes it (two clicks maximum). The preview shows what will be restored, expected traffic effect, validation, conflicts/drift, and any irreversibility. Emergency controls may have distinct authorization but no hidden agent-only path.

Rollback produces its own ActionExecution, before/after evidence, validation result, and audit link. If rollback is unavailable, the reason and alternative recovery procedure are visible before initial approval.

## Explanation contract

The backend supplies a durable `Explanation`; the front end must not infer conclusions from raw events. It includes:

- claim;
- plain-language explanation;
- supporting evidence;
- source systems;
- confidence;
- correlation method;
- missing evidence;
- conflicting evidence;
- deterministic/rule/model producer and version;
- alternate explanation when material.

The claim, explanation, confidence, and evidence summary remain adjacent. Selecting evidence opens the evidence drawer, not a disconnected workspace.

## Recommendation and action contracts

A `Recommendation` includes recommended action, reason, expected result, affected scope, risk, urgency, confidence, executing control plane, approval requirement, reversibility, rollback plan, constraints, and supporting evidence.

A `SecurityIntent` expresses the desired outcome, scope, duration, preservation constraints, and risk without pretending to be a generic vendor policy. Each vendor-native `ActionPlan` includes target, exact native change, expected traffic effect, affected workloads, estimated blast radius, required permissions, validation, expiration, and rollback. An `ActionExecution` records approval, authorization, executor, vendor change identifier, before/after state, result, validation, expiration/removal evidence, audit, partial failure, and rollback state.

The canonical definitions live in `docs/CANARYVIEW_DATA_MODEL.md`. Human and agent users consume those same concepts.

## Interaction budgets

| Journey | Budget |
|---|---|
| Incident summary to explanation | Zero or one click. |
| Incident summary to recommendation | Zero or one click. |
| Recommendation to action preview | One click. |
| Action preview to approval | One confirmation step. |
| Completed action to rollback | One or two clicks. |
| CanaryView recommendation to approved CanarySting placement | No more than two interaction steps. |
| Claim to raw evidence | One click. |
| Complete correlated trace | Available within the incident/flow workspace. |
| Integration capability/authority answers | Available together on the integration overview; no vendor/API navigation. |

Click counts start from the visible summary/recommendation and exclude authentication only when a still-valid authenticated session exists. Modal open/close gymnastics, vendor navigation, copying IDs, and query construction count as failures, not hidden steps.

Core workflows must not require writing queries, editing YAML, reading raw JSON, using a CLI, or entering a natural-language prompt.

## Progressive disclosure

Primary display names use application, service, identity, environment, asset, and business scope. Technical detail remains attached:

| Operator layer | Supporting technical layer |
|---|---|
| Application/service identity | Namespace, service account, workload owner, selected labels, pod UID. |
| Verified/lower-confidence identity | SPIFFE ID, Cilium identity, identity source and proof. |
| Security journey | Five tuple, translated tuples, proxy connection, request/vendor transaction IDs, trace/span IDs. |
| Kernel correlation | Cgroup, process, socket cookie, BPF program/map evidence. |
| Policy outcome | Native policy/rule UID/version and vendor decision payload reference. |

Simple must not mean incomplete. Expanding detail keeps the selected claim and recommendation visible so the operator never loses the decision path.

## Plain-language requirements

- Titles describe outcome and affected application, not an implementation signal.
- Summaries use active voice, concrete times/scopes, and distinguish observed effect from potential risk.
- Severity and confidence are separate and explained.
- “Allowed,” “authenticated,” “authorized,” “observed,” and “inferred” are not interchangeable.
- Acronyms and vendor terms receive an inline explanation on first use.
- Errors state what failed, impact on confidence, and the next step.
- No dead-end “investigate in vendor X” message; cite the specific evidence/gap and offer a deep link only as a supplement.
- Socket cookies, BPF maps, CRDs, raw pod IDs, schemas, and JSON never lead the primary experience.

## Evidence presentation

Evidence is attached to claims, trace hops, impact statements, recommendations, and actions. The evidence drawer shows a safe summary, source/collector, source and observed time, assertion mode, confidence, correlation method, integrity/retention status, expiry, legal-hold state, lineage, model-use state, and supported/contradicted claims. Authorized users can reveal bounded raw evidence or follow a native reference without leaving the case context.

Conflicts and missing evidence are first-class, not small-print warnings. Expired/unavailable raw evidence leaves its provenance and availability state visible.

## AI transparency and trust

The interface visibly distinguishes:

- deterministic observation;
- correlated conclusion;
- inference;
- model-generated interpretation;
- recommendation;
- approved action;
- completed action.

AI-generated text summarizes but never replaces the deterministic evidence, confidence, correlation method, or authorization record. Operators can use every core workflow without prompts or prompt engineering. Agent suggestions appear under the same recommendation contract and cannot execute through hidden authority.

The initial agentic-operation catalog is read-only and recommendation-oriented: explain trace/path, summarize case, identify missing/conflicting evidence, assess impact, find dark reachability/canary opportunities, recommend a next step, generate an action preview, and explain expected impact/rollback. Each result shows its evidence sources, provenance, confidence, deterministic facts, model interpretation, operator decision point, and execution authority. Write-capable operations follow only after preview, approval, validation, and rollback contracts are proven.

## Deployment profile and local-footprint experience

Integrations and setup present the four profiles defined in `docs/CANARYPLATFORM_DEPLOYMENT_PROFILES.md`. Profile 1 is the default. Before advancing to a higher profile, the console states why direct SaaS/existing integrations are insufficient, required privileges, deployment unit, upgrade owner, failure mode, removal path, support burden, and whether the component is optional.

Canary placement starts with low-footprint managed assets. The interface calls them honeytokens, credentials, routes, API endpoints, data objects, synthetic identities, external decoys, or Kubernetes/service assets as applicable—never agents. Kubernetes implementation details are shown only for a Kubernetes deployment profile.

## SIEM workflow

The SIEM remains the broad event, alert, hunting, compliance, and enterprise incident record. CanaryView consumes authorized SIEM evidence and historical search results, and publishes enriched cases, traces, evidence references, impact assessments, canary touches, recommendations, approved plans, execution, and rollback outcomes. Operators should recognize the SIEM handoff without being forced to leave CanaryView to understand the workload security journey.

## Connector onboarding and Integrations workspace

Integrations uses a guided click-ops workflow that requires no CLI, YAML, raw JSON, query language, or vendor API expertise:

1. **Browse.** Select a connector category, then vendor/product, deployment pattern, region, and scope. Unsupported, unlicensed, unverified, preview, and supported states are explicit.
2. **Understand capability.** Review supported data classes, correlation keys, policy/configuration/identity/NAT visibility, expected latency, raw-reference support, historical backfill, regional/licensing constraints, and future action capabilities from the versioned capability manifest.
3. **Review permission and impact.** See every requested read permission in plain language, the network path, estimated daily volume, retention/storage impact, and missing visibility. Passive onboarding is labeled **Read-only** and never asks for write credentials.
4. **Configure securely.** Configure a secret reference or approved credential flow without displaying secret values. Read and write credential slots are separate; the write slot remains absent during collector-only setup.
5. **Test connection.** Validate connectivity, authentication, permission coverage, source clock, latency, schema compatibility, and a safe sample. Successful authentication alone does not mark the connector healthy or supported.
6. **Activate observation.** Start the approved stream/poll/webhook/file/backfill mode and show checkpoint/backfill progress, field coverage, duplicates/rejections, freshness, lag, rate limits, schema warnings, and gaps.
7. **Operate.** Provide connection retest, replay/backfill controls, credential rotation, permission re-review, upgrade compatibility, and disconnect. Disconnect explains evidence-retention effects and removes authority without deleting source-owned data.

The integration overview answers together, without opening a vendor portal:

- What does this connector see?
- What does it not see?
- How current is it?
- What permissions does it have?
- What actions could it eventually perform?
- Is CanaryView using read-only or write authority?

The same screen shows category/vendor/product/version; maturity/support status; supported and currently usable capabilities; supported data classes and correlation keys; expected and measured latency; backfill availability/coverage; action plan/preview/apply/verify/expire/rollback capability; health and lag; last successful event; schema/version warnings; missing fields and coverage gaps; rate-limit/permission failures; and data-volume/retention impact.

Action enablement is a separate M7 workflow. It introduces a distinct write principal only after exact capability, required permissions, preview, approval, verification, expiration, rollback, and audit have been reviewed. Vendor-specific fields remain in evidence even when no canonical mapping exists.

## Retention-profile and data-lifecycle workflow

Retention is configured through graphical controls, not YAML, policy code, a query language, or a CLI. During onboarding—and later under **Integrations → Data & retention**—the operator sees three comparable profiles:

| Profile | Operator intent | Summary |
|---|---|---|
| Lean | Minimize local storage and privacy exposure. | Short correlation/history windows, source-owned raw telemetry, and reduced historical depth. |
| Standard | Recommended balance of investigation value, privacy, and cost. | 24-hour correlation; 24–72-hour replay; 90-day hot/13-month normalized evidence; 13-month traces; 3-year cases/actions; 24-month features. |
| Regulated | Preserve regulated case/action evidence under tighter governance. | Seven-year case/action defaults, policy-defined history, stronger hold/review visibility, and no automatic increase in sensitive payload capture. |

Each profile card shows included data classes, retention by class, measured or estimated daily volume, estimated retained volume, sensitive fields collected, earliest/latest expiry, legal holds, model-use status, storage region/tier, and expected cost. Standard is preselected as a recommendation, not silently activated. One additional **Advanced overrides** screen may change a class; it shows the delta in volume, cost, exposure, expiry, and downstream model availability before confirmation.

The approval summary separates four choices:

1. operational retention;
2. diagnostic sensitive-payload capture, off by default and visibly expiring;
3. per-tenant model use;
4. cross-tenant model use, off by default and requiring separate explicit opt-in.

Accepting operational retention never checks a model-use box. Legal hold suspends expiration but never changes either model-use permission. A hold badge appears on cases, evidence, actions, and affected lineage; authorized users can open it to see scope, reason, owner, creation/review date, release authority, and audit without exposing protected content.

Data-lifecycle transparency follows the object. From a claim or evidence item, one click shows data class, sensitivity, source ownership, raw-reference availability, snapshot/redaction status, expiry, legal hold, residency, encryption-key boundary identifier, lineage, model-use policy, and deletion/invalidation behavior. Broken source references are labeled expired, deleted, inaccessible, moved, or integrity-mismatched, and their effect on confidence is explained.

Storage estimates distinguish customer/source-owned bytes from CanaryView-retained bytes and label measured versus projected inputs. Cost surprises, quota pressure, replay loss, compaction, or cold-tier transitions appear in Operations and Integrations with a specific impact and next step.

## Accessibility

- Target WCAG 2.2 AA for core workflows.
- Full keyboard operation, visible focus, logical headings/landmarks, and no keyboard traps.
- Screen-reader names for severity, confidence, trace edges, graph alternatives, action state, and controls.
- Do not encode severity, confidence, source, or state by color alone.
- Sufficient contrast, scalable text, reduced-motion support, and alternatives to graph-only understanding.
- Timelines and graphs have equivalent ordered/table views.
- Plain-language labels and errors are tested with representative operators.
- Confirmation dialogs announce scope, effect, and rollback, and safely retain focus.

## Usability and workflow validation

Every operator-facing development task identifies the operator job, expected interaction path, expected click count, and fixture. Critical paths require fixture-driven Playwright coverage appropriate to the change:

- incident summary to explanation/evidence;
- incident recommendation to action preview/approval;
- completed action to rollback preview;
- canary opportunity to approved placement;
- security trace with partial/conflicting evidence;
- connector category/vendor browse, capability/authority review, read-only setup, connection test, first-event health, credential rotation, failure/recovery, and disconnect;
- duplicate/reordered/delayed/partial events, schema drift, rate limiting, backfill gaps, and permission-loss visibility;
- Standard profile selection, an advanced retention override, separate model-use authorization, expiry visibility, and legal-hold create/release permissions;
- keyboard and accessible-name checks.

Tests assert language/state correctness and interaction budget, not screenshots alone. Frontend lint/build remains the floor. DGX end-to-end validation uses real correlated traces once the task's validation tier requires it.

Interface work begins alongside M2B's first correlated trace: the initial vertical slice includes a fixture-backed trace projection, operator workspace, and Playwright path. M4 expands this into the full console; it is not the first time users see the data.

## Product-adoption and trust metrics

- time from incident open to explanation/evidence view;
- time from incident open to recommendation and action preview;
- interaction-budget success rate;
- percentage of cases resolved without vendor-portal navigation, CLI, query, or prompt;
- trace/evidence views opened from their supporting claims;
- recommendation acceptance, rejection, expiry, and override reason;
- CanaryOpportunity preview/approval rate and post-placement signal value;
- action validation success, rollback availability, rollback time, and failed-action recovery;
- confidence calibration and operator agreement by confidence band;
- cases with visible conflicting/missing evidence and whether operators understood the limitation;
- connector time-to-first-observation, source freshness, field coverage, and error recovery;
- Standard/Lean/Regulated selection, override rate/reason, estimate accuracy, expiry-job success, legal-hold review/release time, broken-reference rate, and lifecycle-deletion completion;
- percentage of tenants authorizing per-tenant versus cross-tenant model use, tracked without treating opt-in as an adoption success target;
- estimated versus actual storage volume and cost by data class, plus operator comprehension of the consequence preview;
- accessibility task completion and keyboard-only completion;
- weekly active operators and repeat investigation/response usage.

Metrics must not reward hiding evidence, inflating confidence/severity, or encouraging unsafe action. Operator trust, containment precision, and correct restraint are primary outcomes.
