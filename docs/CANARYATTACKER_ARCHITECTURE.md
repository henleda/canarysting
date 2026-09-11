# CanaryAttacker Architecture

Status: approved architecture with the M2C.1 passive DGX readiness inspector, M2C.2 scenario/ground-truth contract, M2C.3 closed bounded executor, M2C.4 fixed-loopback Ollama/Qwen planner, and M2C.5 reproducible Kubernetes fixture journey implemented. M2D.1's separate declared ground-truth ingestion/evaluation boundary is implemented; full independent multi-source observation correlation, correlation metrics, and live-campaign orchestration remain later M2D work. The executor adds narrowly reviewed private-laboratory network authority but no shell, filesystem, container, Kubernetes, or host-control authority; the model may select only opaque zero-argument handles whose complete actions remain outside the model boundary.

## Purpose

CanaryAttacker is CanaryPlatform's bounded synthetic adversary and correlation-validation harness. Its primary job is to generate reproducible, labeled ground truth: what an attacker intended, what tool action actually ran, and what the independent security stack observed.

It is an internal development and validation system, not the default customer-facing product, a managed canary asset, or a reason to deploy customer-side software. Deterministic ground-truth replay supports ordinary development; live Ollama/Qwen campaigns remain bounded laboratory work.

The initial execution environment is the DGX Spark CanaryPlatform correlation laboratory and Kubernetes reference environment. That laboratory choice does not make Kubernetes or local Qwen part of the CanaryView customer deployment boundary. Every live planner run re-verifies Ollama service reachability, the exact `qwen3-coder:30b-a3b-q8_0` inventory ID, loopback-only binding, synchronized system time, at least one available GPU, at least 40 GiB of available host memory, and zero preloaded models before use; historical observations are never treated as current authority.

CanaryAttacker is not a general penetration-testing agent and is not production telemetry. It targets only explicitly designated CanarySting lab fixtures.

## Existing code to reuse deliberately

The repository already contains `internal/llm/attacker`, `internal/llm/anthropic`, `cmd/llm-attacker`, and staged-range fixtures. They demonstrate useful safety patterns: a fixed target, one structured HTTP tool, bounded response reads, hard turn/token/dollar budgets, cancellation, scripted mode, deterministic cassette replay, and separation from engine/Sting imports.

That implementation is Anthropic/demo-specific, uses a narrow result ledger, and does not emit the proposed scenario-level `AttackerIntent` and `AttackerAction` records. The Qwen harness should reuse appropriate generic safety mechanisms rather than duplicate them, but it should not rename or redesign the working demo merely to fit the CanaryAttacker name.

`internal/canaryattacker/groundtruth` is the standard-library-only M2C.2 contract leaf. It defines schema-v1 scenarios, stable explicit scenario/step identifiers, canonical opaque target and fixture references, whole-millisecond hard budgets, pre-action intent, approved/denied policy decisions, post-action success/failure/denial truth, direct lineage, and deterministic strict JSON that rejects duplicate or unknown object fields. Scenario, intent, and action records serialize independently under their exact parent so an executor can durably record intent before attempting the action; the canonical fixed-seed corpus bundles the same records for replay. The package deliberately does not import or wrap the Anthropic demo runtime: it reuses its reviewed safety shape—external bounds, deterministic replay, cancellation-ready records, and separation from the decision engine—without coupling the new contract to a provider or executor.

`internal/canaryattacker/evaluation` is the M2D.1 outer laboratory boundary between that leaf and CanaryView traces. It ingests strict corpus bytes without projecting attacker records into CanaryView observations, correlation records, or hops. The immutable view preserves native declaration kind and lineage, exact scope/run/scenario identity, bounded time hints, all reviewed steps, corpus lifecycle and isolation metadata, and disabled model use. Evaluation requires an independently collected, provenance-only trace-hop marker that retains a domain-separated opaque evidence reference for the exact run ID, scenario ID, and scenario version plus a source-issued 256-bit nonce that is absent from the corpus; corpus-visible fields alone cannot derive that binding. It refuses production traces, a different run, scenario, version, or scope, a missing marker hop or missing exact marker evidence on that hop, any attempt to count the marker as action telemetry, any trace hop or lineage parent that reuses the corpus, scenario, intent, or action record ID, cross-step hints, and duplicate associations. Assisted associations cite an exact intent/action hint; unassisted associations carry none. Reports retain both the marker hop and opaque evidence reference as provenance, preserve unmatched steps, and count assisted and unassisted associations separately. The nonce is not retained in the binding or report. The boundary is in memory only and adds no network, model, execution, persistence, or customer-side authority.

`internal/canaryattacker/executor` is the provider-neutral M2C.3 execution boundary. An immutable policy registers exact target aliases/references/fixture identities, canonical scheme/host/port bindings, private or loopback address sets, opaque payload/credential fixtures, and concrete operations for exactly seven tools. A run accepts only a scenario whose target, operation, fixture, and budgets fit that policy. It commits a ground-truth intent before resolver or dialer access; ledger failure closes the run. Denials, failures, timeouts, and cancellations produce ground-truth actions without leaking raw targets, addresses, payloads, credentials, response bodies, or headers into the audit record. Response content remains bounded in run memory and is exposed only through the reviewed `inspect_response` result.

`internal/canaryattacker/planner` is the provider-neutral M2C.4 coordinator. It exposes stable handles from `action_001` through the ground-truth aggregate ceiling `action_1024`, but rejects any scenario whose active step would expose more than the transport's 256-tool ceiling; every handle has an empty-object schema. Exact `ActionSpec` values, targets, operations, fixtures, credentials, policy, and budgets remain in the coordinator/executor. Unknown handles and non-empty arguments become the same fixed non-executable `planner_rejected` proposal and are committed through the executor as denied intent/action truth without retaining attacker-controlled names or arguments. One accepted proposal is permitted per model response; additional well-formed calls within the remaining action-audit budget are committed as same-step denied proposals rather than executed or discarded. Steps advance deterministically, and externally enforced action, turn, duration, context, output-token, cumulative-token, proposal, observation, and response-size limits stop the loop. The loop retains at most 256 observations and never more than 64 KiB of serialized observation history: it truncates the final content prefix if necessary, audits the rest of that response, and stops with `observation_budget` before another model request. The maximum 256-tool envelope plus that complete history remains below the Ollama transport's 256 KiB request ceiling. Before each model call, the requested context-window and maximum-output allowances together fit inside the remaining cumulative token budget; reported prompt and output use must each fit its requested per-turn allowance, and their sum is checked against the remaining cumulative budget before any proposal executes. Cancellation reaches the model HTTP request and the executor; a proposal received before cancellation is still sent to the executor with the cancelled context so the attempt is audited. The fixed DGX scenario pins its v1 recorded-at and review-due dates so its review deadline cannot renew at runtime and its semantic identity stays stable; renewing review requires an explicit scenario-version change.

`internal/canaryattacker/ollama` implements the M2C.4 transport. It accepts only an explicit `http://127.0.0.1:<port>` origin, disables ambient proxies, pins every dial to the configured IPv4 loopback socket, forbids redirects, and uses only non-streaming `/api/chat` plus the prompt-free `/api/generate` unload operation. Redirects are returned without following them, and transport diagnostics are reduced to fixed operation/cancellation classes so a response-controlled location or protocol error cannot enter evidence. Requests set deterministic temperature/seed, bounded `num_ctx`/`num_predict`, `think=false`, and `keep_alive=0`. Response bytes, tool-call count/name/arguments, content, timestamps, completion marker, exact model name, and reported token usage are bounded and strictly decoded with duplicate, unknown, noncanonical, and case-aliased schema fields rejected before Go's case-insensitive struct matching. The argument object remains opaque so any nonempty content reaches the coordinator's fixed audited-rejection path. Raw model prose, call IDs, names, and arguments are never logged; the ground-truth intent carries only a SHA-256 reference to the complete bounded response.

## Components

```text
Scenario + approved lab target policy
                |
                v
        Scenario coordinator
          | emits intent
          v
     Ollama/Qwen planner  -- proposes --> bounded tool request
                                          |
                                  policy validation
                                          |
                                          v
                                  tool executor
                                          |
                                  emits action/result
                                          v
                               scenario evidence ledger
                                          |
                                          v
                                     CanaryView
                              correlation/evaluation only
```

- **Scenario registry** holds versioned, reviewable scenario definitions and fixture requirements.
- **Target policy** resolves scenario aliases to an allowlisted lab destination set; the model does not choose arbitrary hosts.
- **Planner** calls local Ollama/Qwen and may select only registered tools.
- **Tool policy** validates target, method, payload, credentials, budgets, and scenario state before execution.
- **Tool executor** performs the minimum network operation without exposing a shell.
- **Ground-truth ledger** writes immutable intent/action/result records with scenario IDs.
- **Collector coordinator** triggers before/after evidence collection through repository DGX scripts.
- **Evaluator** compares ground truth to independent CanaryView traces and metrics.

## Scenario model

A scenario should be declarative, versioned, deterministic where possible, and reviewable without reading a prompt. It includes:

- scenario ID, version, name, objective, and safety classification;
- required lab fixtures and target aliases;
- allowed tools and per-tool constraints;
- ordered or bounded-adaptive steps;
- harmless credentials/inputs referenced through approved fixtures;
- maximum actions, duration, concurrency, request/body bytes, and model tokens;
- expected intent/action sequence or allowed alternatives;
- expected independent telemetry sources;
- success, failure, abort, and cleanup conditions;
- owner/run ID labels and evidence-retention policy.

Initial scenarios are endpoint enumeration, HTTP probing, harmless credential testing against explicit fixtures, canary discovery, and canary touch. They do not include persistence, privilege escalation, malware, destructive payloads, uncontrolled credential reuse, or Internet-wide discovery.

`internal/canaryattacker/scenarios` implements the stable ordered M2C.5 journey. Its scenario/version, five step IDs, objectives, action specifications, fixed seed, and lifecycle dates do not depend on the run ID or dynamically allocated Service address. `cmd/attackerscenariospike` runs those exact actions through the M2C.3 executor and emits a content-bound schema-v1 corpus. Two executions must have an identical semantic digest over the reviewed steps, proposed actions, ordinals, attempted flags, and success statuses; their run-scoped intent, action, and corpus record IDs remain honestly distinct because those identities bind run IDs and timestamps.

## Bounded attacker tools

The initial reviewable tool interface may include:

- `http_request` — allowed methods, fixed scheme/host/port, bounded headers/body/response, redirects disabled or revalidated;
- `dns_lookup` — approved lab names and bounded query types only;
- `tcp_connect` — allowlisted lab addresses/ports with strict timeout and no arbitrary payload by default;
- `enumerate_endpoint` — bounded paths against the resolved scenario target;
- `follow_link` — only same-target links that pass target policy;
- `try_credential` — only named disposable fixture credentials against the matching fixture;
- `inspect_response` — bounded inspection of already-captured response metadata/content.

Additional tools require explicit architecture and safety review. The local model never receives arbitrary shell, SSH, Kubernetes API, Docker, filesystem, process-control, raw socket, package-manager, or unrestricted network tools merely because it is acting as an attacker.

Tool arguments are structured and schema-validated. The executor—not the model—owns target resolution, credentials, network restrictions, timeouts, budgets, and auditing.

The implemented executor disables ambient proxy selection, resolves each network action through an exact private-address binding, dials the pinned address rather than a model-provided locator, re-resolves after HTTP responses, and rejects any changed address set. Redirect responses are recorded as failures and never followed. `follow_link` accepts only a bounded link captured from a prior response and revalidates it to the identical scheme, canonical host, and explicit port before a request. HTTP is limited to reviewed GET/HEAD operations plus reviewed GET/POST fixture-credential operations; TCP sends no payload; DNS is limited to A/AAAA. Absolute compile-time ceilings cap actions, duration, action timeout, completion reserve, concurrency, request rate, request/response/stored bytes, response headers, resolved addresses, captured links, enumeration paths, targets, fixtures, and operations. Scenario and per-tool limits may only tighten those ceilings.

## Safety boundaries

Before any scenario:

1. Select the applicable M2D ground-truth-laboratory decomposition and DGX attacker/correlation validation tier.
2. Inspect local Git state and run `scripts/dgx/check.sh`.
3. Verify the exact K3s namespace, workload, service, endpoint, and run ID in scope.
4. State remote mutations, traffic effects, budgets, evidence collection, abort conditions, and cleanup.
5. Gather before-state for K3s, Cilium, BPF, connectivity, processes, and test resources.

During execution:

- use a dedicated labeled namespace/fixture where practical;
- deny destinations outside the scenario allowlist, including through redirects, DNS rebinding, NAT ambiguity, and proxy configuration;
- use disposable fixture credentials only;
- enforce action, time, token, byte, concurrency, and request-rate ceilings outside the model;
- keep Ollama on its approved local binding and do not expose it as a cluster/public service implicitly;
- capture every tool request/result, policy denial, model/version, and scenario step;
- make cancellation immediate and fail closed when target identity or policy is ambiguous;
- never modify K3s, Cilium, firewall, SSH, kernel configuration, or host packages implicitly.

After execution:

- stop the model loop and scenario processes;
- collect declared/redacted evidence;
- delete only run-owned fixtures and state through repository scripts;
- gather after-state and verify normal connectivity and unchanged Cilium/BPF baseline;
- record cleanup and correlation metrics;
- retain no credential or secret values in logs.

Unexpected state is inspected and reported, not repaired automatically.

## Ground-truth contracts

### AttackerIntent

Emitted and durably timestamped before the executor acts:

- intent ID;
- attacker ID;
- model/provider/version;
- scenario ID/version and step;
- objective;
- intended tool/action;
- canonical target alias and resolved target reference;
- timestamp and clock source;
- applicable constraints/budgets;
- planner output reference and policy decision;
- scope and run ID.

An intent rejected by policy remains valuable ground truth and links to a denied/no-action record.

### AttackerAction

Emitted after attempted execution:

- action ID and parent intent ID;
- attacker/scenario/step IDs;
- approved tool and normalized arguments;
- resolved target reference;
- start/end timestamps and latency;
- result/status/error;
- bounded response metadata (status, bytes, safe hashes/headers as approved);
- executor and tool-policy versions;
- network/request identifiers available to later correlation;
- scope, run ID, and evidence references.

Intent and action are separate: a model may intend something the policy denies, a tool may fail, or execution may differ from the proposed request after normalization.

The schema-v1 constructor enforces exactly one action record per intent, strict intent-before-action time, contiguous intent ordinals, ordered scenario steps where configured, aggregate scenario-definition limits, global action/duration/concurrency/request/response/model-token bounds, per-tool action/request/response ceilings, per-record evidence/reference limits, and exact run/scope/parent isolation. JSON input is capped at 32 MiB before decoding. Denied proposals remain non-attempted actions without executor, network, response, or fabricated timing facts. A separate semantic SHA-256 binds the content behind the stable human-facing scenario/version ID; canonical intent and action identifiers bind their complete semantics and exact reviewed scenario; the corpus identifier also binds the fixed seed and ordered records. The committed golden fixture covers successful, failed, and policy-denied outcomes without invoking a model or network target.

## Trust and evidence handling

Attacker records are **declared lab ground truth about the harness**, not proof of what the network or workload observed. CanaryView stores them in a distinct ground-truth source class and compares them with independent telemetry. The model's prose and interpretation are untrusted inputs. A scenario label never manufactures a Cilium, Envoy, kernel, or CanarySting observation.

The versioned `AttackerIntent`, `AttackerAction`, scenario, and expected-result corpus is marked synthetic and may be retained indefinitely in the development lab for reproducible evaluation. It is physically/logically isolated from production baselines, customer behavior models, production incident statistics, and cross-tenant training. Credentials, actual canary secret values, and unredacted sensitive payloads are never retained. Corpus retention does not retain run-owned Kubernetes, BPF, process, or staging state; that execution state is cleaned after every scenario. See `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`.

Clock synchronization and timestamp uncertainty are recorded so evaluation does not reward a false join. The M2C.4 live proof requires the readiness inspector to confirm NTP synchronization and records a conservative 30-second uncertainty consistent with the DGX preflight's workstation/DGX clock bound; it does not claim one-millisecond alignment. Scenario IDs may improve attribution in fixtures, but correlation quality must also be reported with those hints excluded or identified, so measurements remain honest.

## CanaryView consumption

For each action, CanaryView attempts to locate related observations from Cilium/Hubble, Envoy, eBPF/kernel, Kubernetes identity, and CanarySting. It constructs a trace with:

- matched and unmatched ground-truth steps;
- evidence and join method for each hop;
- alternate candidate joins and conflicts;
- expected-but-missing telemetry;
- time-alignment error;
- identity mapping and confidence;
- canary touch, verdict, response, and containment where applicable.

CanaryView may use a Qwen-generated narrative only as labeled model interpretation adjacent to the deterministic trace/evidence. It must not use the attacker's narrative as hidden evidence.

## Evaluation metrics

- **Trace completeness:** expected independent hops observed and correlated.
- **Correlation precision:** correlated hops that belong to the ground-truth action.
- **Correlation recall:** ground-truth actions with the expected correlated evidence.
- **Identity accuracy:** correct workload/application/principal mapping by confidence tier.
- **Incorrect joins:** false merges, wrong target/source, or cross-scenario contamination.
- **Missing observations:** expected control observations absent or inaccessible.
- **Time-alignment error:** observed timestamp delta and uncertainty per source.
- **Canary detection rate:** canary touches detected among ground-truth touches.
- **Containment precision:** intended target affected while controls/bystanders stay healthy.
- **Vendor telemetry gaps:** missing fields/hops that lower trace or explanation quality.
- **Policy-denial correctness:** out-of-scope tool requests prevented and recorded.
- **Cleanup completeness:** no scenario process, resource, attachment, map, or staging residue.

Metrics include denominator, scope, scenario/version, source coverage, confidence thresholds, and evidence links. A single successful demo is not a quality claim.

## Reproducibility and phased delivery

PR validation is split from live campaign generation:

- **Deterministic replay (Levels 1–3)** uses versioned scenario intent/action, fixed seeds, exact required assertions, affected paths, and declared ground truth. It invokes no model and is the default PR evidence.
- **Targeted live smoke (Level 2 HIGH/CRITICAL)** is limited to one or two fixed approved-lab scenarios when attacker tools, trigger behavior, deployment, or response behavior changes. It requires strict timeout, fixed tool policy, before/after evidence, and cleanup.
- **Full live campaign (Level 4)** is scheduled weekly/on demand and measures trace, identity, correlation, response, resource, cleanup, and repeatability. It is not an ordinary PR blocker.

The repository currently implements deterministic legacy replay, bounded cookie/enforcement DGX profiles, the passive M2C.1 readiness inspector, the schema-v1 M2C.2 ground-truth corpus contract, the M2C.3 bounded executor, the M2C.4 live Qwen planner, the M2C.5 real Kubernetes fixture journey, and M2D.1's separate declared ingestion/evaluation boundary. The Level 4 CI entry remains deliberately fail-closed until later M2D work supplies independent multi-source observation correlation, complete correlation assertions, metrics, and campaign orchestration; the targeted M2C.5 journey must not be described as complete campaign coverage.

The M2C.5 safety boundary uses the same validated DGX runtime identity and exact `/run/user/1000/canarysting-response-posture.lock` path as the enforcement proof. Its passive check fails closed if labeled CanarySting NetworkPolicy, CiliumNetworkPolicy, or CiliumClusterwideNetworkPolicy state cannot be inventoried or is present. An EndpointSlice is accepted only when both its owner UID and `kubernetes.io/service-name` label bind it to the run-owned Service. After the namespace has been deleted, a later posture, publication, lease-release, or evidence-validation failure preserves the partial or published evidence plus the artifact stage; the outer coordinator also preserves every failed attacker-scenario run until a separate explicit exact cleanup. A partial workspace itself guards pre-publication recovery, and an owned mode-0600 fixed marker moves with published evidence to guard post-publication recovery; generic mutating cleanup refuses either state. Only successful scenario-specific cleanup/finalization may retire the marker after proving namespace absence and validating the complete evidence. Scenario shell changes select both the scenario invariants and their shell harness in the authoritative PR gate.

Before namespace creation, the scenario stores a random 256-bit ownership token in its mode-0600 recovery workspace and places only its SHA-256 digest in the Namespace annotation. If creation succeeds but its response or immediate UID persistence is interrupted, later cleanup may reacquire the observed UID only when the private token digest, run/fixture labels, and complete safe namespace inventory all match; after those checks it may replace only an owned mode-0600 temporary UID value that is an exact prefix of the observed UID, then atomically persists the complete UID and still deletes with the UID precondition. Any other mismatch remains preserved for manual inspection. Kubernetes reads have an 8-second request/12-second wall bound and at most one same-session retry; the readiness wait has a 65-second request/70-second wall bound; create and delete are one-shot with 15-second request/20-second wall bounds. All API-call bounds are capped by a mode-specific internal deadline, and the entire remote run/inspect/cleanup invocation has a 720/180/360-second hard timeout plus a 5-second termination grace. A process records its deletion attempt before issuing it, so EXIT cleanup cannot repeat an ambiguous DELETE; only a later explicit cleanup process may revalidate state and make one new attempt. No Kubernetes mutation, SSH session, resolved address, or route is retried after an ambiguous failure.

M2D now consumes the completed bounded execution and initial DGX scenario foundation: it ingests the declared ground truth separately from observations, correlates independent telemetry, publishes evidence-backed metrics, and only then broadens into repeated-seed campaigns. The preserved detailed M2C/M2D rows in `docs/DEVELOPMENT_PLAN.md` decompose that work. Initial execution remains small and deterministic; model-adaptive variation is added only after the fixed scenarios and safety denials are reliable.

Open decisions include clock synchronization against independent telemetry and whether later multi-scenario work needs another provider behind the same coordinator seam. M2C.5 closes initial fixture ownership and process isolation: one unique run-labeled namespace contains one non-root hardened Pod and ClusterIP Service; the Pod executes the checksum-verified artifact from a read-only host mount on an already-present digest-pinned image, receives no service-account token, and is deleted before evidence publication. The Service address is resolved from that run's object and admitted only as executor policy; neither it nor a DGX address is persisted. CanarySting response components must be absent for this canary-touch proof. The scenario holds the DGX host-global response-posture lease from before its first absence check through namespace deletion and the final absence check; the precise-enforcement proof takes the same lease before it can attach. The fixed disposable credential is not a Kubernetes Secret and its value, authorization header, raw fixture log, and address are never evidence. The Namespace create response supplies the UID that the harness immediately attempts to persist; the private-token recovery path handles interruption in either operation without inventing identity. Cleanup revalidates UID and labels, inventories all listable namespaced kinds by metadata name without reading Secret values, and supplies the captured UID as the deletion precondition; an API error, replacement namespace, unrelated resource/Event, or failed deletion preserves recovery state. Direct leaf operation uses one bounded invocation-owned SSH control connection, while a coordinator child accepts only a validated profile-scoped connection; neither can reconnect or select a new route after mutation. The M2C.4 loopback transport and model cleanup boundary and the M2C.3 executor review boundary remain unchanged.
