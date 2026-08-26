# CanaryAttacker Architecture

Status: conceptual architecture for a future DGX lab harness. No attacker runtime is created or changed by this document.

## Purpose

CanaryAttacker is CanaryPlatform's bounded synthetic adversary and correlation-validation harness. Its primary job is to generate reproducible, labeled ground truth: what an attacker intended, what tool action actually ran, and what the independent security stack observed.

The initial execution environment is the DGX Spark CanaryPlatform correlation laboratory. Ollama and `qwen3-coder:30b-a3b-q8_0` were previously observed there. That is historical state, not a permanent assumption; the future M2C task must verify service reachability, model presence, version, resource availability, and loopback binding before use.

CanaryAttacker is not a general penetration-testing agent and is not production telemetry. It targets only explicitly designated CanarySting lab fixtures.

## Existing code to reuse deliberately

The repository already contains `internal/llm/attacker`, `internal/llm/anthropic`, `cmd/llm-attacker`, and staged-range fixtures. They demonstrate useful safety patterns: a fixed target, one structured HTTP tool, bounded response reads, hard turn/token/dollar budgets, cancellation, scripted mode, deterministic cassette replay, and separation from engine/Sting imports.

That implementation is Anthropic/demo-specific, uses a narrow result ledger, and does not emit the proposed scenario-level `AttackerIntent` and `AttackerAction` records. The Qwen harness should reuse appropriate generic safety mechanisms rather than duplicate them, but it should not rename or redesign the working demo merely to fit the CanaryAttacker name.

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

## Safety boundaries

Before any scenario:

1. Select the M2C/M2D plan task and DGX attacker/correlation validation tier.
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

## Trust and evidence handling

Attacker records are **declared lab ground truth about the harness**, not proof of what the network or workload observed. CanaryView stores them in a distinct ground-truth source class and compares them with independent telemetry. The model's prose and interpretation are untrusted inputs. A scenario label never manufactures a Cilium, Envoy, kernel, or CanarySting observation.

The versioned `AttackerIntent`, `AttackerAction`, scenario, and expected-result corpus is marked synthetic and may be retained indefinitely in the development lab for reproducible evaluation. It is physically/logically isolated from production baselines, customer behavior models, production incident statistics, and cross-tenant training. Credentials, actual canary secret values, and unredacted sensitive payloads are never retained. Corpus retention does not retain run-owned Kubernetes, BPF, process, or staging state; that execution state is cleaned after every scenario. See `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`.

Clock synchronization and timestamp uncertainty are recorded so evaluation does not reward a false join. Scenario IDs may improve attribution in fixtures, but correlation quality must also be reported with those hints excluded or identified, so measurements remain honest.

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

M2C first verifies Ollama/Qwen, defines scenarios/contracts/tools, implements bounded execution, and proves cleanup. M2D then runs scenarios against the DGX stack, correlates observations, and publishes evidence-backed metrics. Initial execution remains small and deterministic; model-adaptive variation is added only after the fixed scenarios and safety denials are reliable.

Open decisions include Ollama API/model version pinning, process/container isolation, outbound network enforcement, fixture credential delivery, scenario schema location, clock synchronization, evidence-retention limits, and how generic safety code is extracted from the existing attacker without disrupting its working behavior.
