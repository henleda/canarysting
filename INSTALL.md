# Installing and Running CanarySting

This guide covers installing and running the **current** CanarySting product on a
single Linux node. Everything here is grounded in the code and deploy assets in
this repository (`cmd/`, `internal/`, `bpf/`, `adapters/`, `config/`, `deploy/`).
Where a path is demo/staging-only or a stub on a load-bearing surface, it is
flagged explicitly.

> **Maturity, honestly.** `CLAUDE.md` still describes the repo as an "early
> scaffold," but that line is stale. The load-bearing pieces are built and have
> been **running on a live two-box AWS environment**: the decision engine
> (`internal/engine`), the OBSERVE-ONLY eBPF baseline path (`bpf/observe`), the
> Envoy `ext_proc` adapter with sockops cookie bridge and kernel enforce
> (`cmd/envoy-adapter`, `bpf/sockops`, `bpf/enforce`), the inline multi-axis
> attrition pump (`internal/sting/attrition`), the read-only dashboard
> (`cmd/dashboard-backend` + the Next.js app under `dashboard/app`), and the D6
> cross-customer aggregator (`cmd/aggregator`). Known **stubs / staging-only**
> surfaces are called out inline; the biggest are: **`cmd/canaryctl` is an empty
> stub** (the operator CLI is not implemented — configure via flags/env instead),
> there is **no production engine entrypoint that auto-calibrates** (the live
> window uses the staging-only `cmd/staged-range` with a self-incriminating flag),
> and the **YAML config in `config/` is largely not wired** (only a few fields are
> read today — see §5). The eBPF **enforce** and **sockops** programs are
> Linux-only and exercised on-box; on macOS they are no-ops/skip.

---

## 1. What CanarySting is, and the runtime topology

CanarySting is a proxy-attached deception and active-response platform. It seeds
harmless decoy resources ("canaries") within reach of east-west traffic, scores
how each flow interacts with them, and escalates an automated response from silent
observation (Tier 0) through tag-and-deceive (Tier 1), kernel containment + inline
attrition (Tier 2), to a kernel jail / full adversarial attrition (Tier 3). The
single trigger is a **canary touch** — a learned baseline of normal traffic only
sharpens the score, it never arms a response on its own (rule 8 in `CLAUDE.md`).
See `docs/ARCHITECTURE.md` for the full product definition.

**Runtime topology (single node, the current product):**

```
                         ┌────────────────────────── one Linux node ──────────────────────────┐
   client / east-west    │                                                                     │
   HTTP traffic ────────►│  Envoy :8080  ──ext_proc(gRPC)──►  envoy-adapter :50051             │
                         │   (route to app)                    │  (thin adapter, rule 1)        │
                         │                                     │   • seeds negative-space       │
                         │                                     │     canaries (catalog+seeder)  │
                         │                                     │   • sockops cookie bridge      │
                         │                                     │   • inline attrition pump      │
                         │                                     │   • kernel enforce (verdict_map)│
                         │                                     ▼                                │
                         │                          engine (gRPC) :50052                        │
                         │            internal/engine: scoring · tiers · calibration ·          │
                         │            scope-keyed isolated state · feedback                     │
                         │                     │                          ▲                     │
                         │   bpf/observe ──────►│ per-scope baseline       │ verdicts            │
                         │   (cgroup_skb on     │ (multiplier M, gated)    │                     │
                         │    /sys/fs/cgroup)   ▼                          │                     │
                         │            bbolt /var/lib/canarysting/baseline.db                     │
                         │                     │ read-only tap :8088 (/raw/state, /raw/events)   │
                         │                     ▼                                                 │
                         │  dashboard-backend :8089 ──►  Next.js console :3001 (/api proxy)      │
                         │  (optional) intelligence: cross-customer aggregator / shared spool    │
                         └─────────────────────────────────────────────────────────────────────┘
```

- **Envoy ⟷ adapter ⟷ eBPF.** Envoy is the dataplane. The adapter
  (`cmd/envoy-adapter`) is a thin `ext_proc` server: it recognizes a canary touch
  by path, calls the engine for a verdict, runs the inline attrition hold at
  Tier 2/3, and programs kernel containment via `bpf/enforce` (`verdict_map`).
  The L7↔kernel identity join is the **socket cookie**, observed by both the Envoy
  filter and the `bpf/sockops` program (rule 4, `docs/IDENTITY.md`).
- **Engine.** `cmd/engine` (production) / `cmd/staged-range` (staging) compose
  `internal/engine`. Proxy-agnostic; it only speaks the contract in
  `internal/contract` (mirrored over gRPC in `api/`).
- **Baseline.** `bpf/observe` (`cgroup_skb` ingress/egress + `sock_release`)
  feeds a per-scope baseline that becomes a bounded multiplier `M` on a touch.
- **Dashboard (optional but built).** `cmd/dashboard-backend` polls the engine's
  read-only tap and serves JSON/SSE to the Next.js app in `dashboard/app`.
- **Intelligence / crossing (optional).** `cmd/aggregator` clears anonymized
  cross-customer fingerprints; an engine can `-consume` a shared spool to sharpen
  `M`. Only anonymized derived patterns ever cross a deployment boundary (rule 9).

---

## 2. Prerequisites

### Go toolchain
- **Go 1.24+** — `go.mod` declares `go 1.24`. The live AWS box pins **1.25.3**
  (`deploy/dev-box/user_data.sh`); any 1.24+ toolchain builds the binaries.

### Linux kernel + cgroup v2 (for the eBPF observe/enforce paths)
- A modern Linux kernel with **cgroup v2** mounted (the units attach at
  `/sys/fs/cgroup`). The eBPF programs are `cgroup_skb` (observe + enforce),
  `cgroup/sock_release`, and `sockops` hooks.
- **BTF** (`/sys/kernel/btf/vmlinux`) present for CO-RE.
- The eBPF objects (`bpf/**/*_bpfel.o`) are committed, so you do **not** need
  clang to *run*. To recompile them you need **clang/llvm + libbpf headers**
  (`make bpf`, Linux-only).
- The BPF programs declare `Dual BSD/GPL` because `bpf_get_socket_cookie` is
  GPL-only.

### Capabilities
The engine and adapter that load/attach eBPF must run with kernel privileges.
The systemd units run them as **root**. The relevant capabilities are
**`CAP_BPF`**, **`CAP_NET_ADMIN`**, and **`CAP_PERFMON`** (load + attach
`cgroup_skb`/`sockops` programs and program the verdict map). Run as root or grant
those caps. The dashboard backend needs **no** privileges (it is read-only over
HTTP and runs `DynamicUser=yes`).

### Envoy
- **Envoy v1.34.1** is used in the staged mesh (`deploy/m7-window/server-compose.yml`).
  Any Envoy with the `ext_proc` HTTP filter works. The adapter speaks the
  go-control-plane `ext_proc/v3` API (`go.mod`: `go-control-plane/envoy v1.32.3`).
- A sample config is `deploy/m7-window/envoy.yaml` (see §4).

### Node.js (for the dashboard web console only)
- **Node 20.x** (the unit comment specifies nodesource 20.x; `dashboard/app`
  pins `@types/node 20.x`). The console is **Next.js 14.2.35 / React 18.3**.
- Skip Node entirely if you do not need the web UI — the engine, adapter, and the
  read-only JSON tap run without it.

### Optional: AWS / Terraform / Docker
- Only needed for the **demo harness** (§7): Terraform provisions the boxes
  (`deploy/m7-window/terraform`, `deploy/dev-box`, `deploy/k3-boxes`), and Docker
  runs the staged service mesh + Envoy (`server-compose.yml`). None of this is
  required to run CanarySting itself on a node you already have.

A one-shot install of the full toolchain (from `deploy/dev-box/user_data.sh`) on
Ubuntu:

```sh
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
  git make curl ca-certificates jq unzip
sudo apt-get install -y linux-tools-common linux-tools-generic || true   # bpftool
# Go (adjust arch: linux-amd64 / linux-arm64)
curl -fsSL https://go.dev/dl/go1.25.3.linux-amd64.tar.gz -o /tmp/go.tgz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
export PATH="$PATH:/usr/local/go/bin"
```

---

## 3. Build

The `Makefile` is the source of truth. Pure-Go targets work on macOS and Linux;
the eBPF object build is Linux-only.

```sh
make build      # compile-check all Go packages (go build ./...)
make bin        # build the binaries into ./bin (go build -o ./bin ./cmd/...)
make test       # full test suite with the race detector
make check      # the full local gate: fmt-check + vet + build + test + selfcheck
make bpf        # recompile the eBPF C with clang (Linux only; objects are committed)
```

`make bin` builds every `cmd/` binary. To build them individually (as the deploy
scripts do):

```sh
go build -o ./bin/engine            ./cmd/engine             # production engine
go build -o ./bin/staged-range      ./cmd/staged-range       # STAGING-ONLY engine (auto-labels)
go build -o ./bin/envoy-adapter     ./cmd/envoy-adapter      # Envoy ext_proc adapter + canary seeding
go build -o ./bin/dashboard-backend ./cmd/dashboard-backend  # read-only dashboard API
go build -o ./bin/aggregator        ./cmd/aggregator         # D6 cross-customer aggregator (optional)
# canaryctl builds but is an EMPTY STUB today (TODO subcommands); do not rely on it.
go build -o ./bin/canaryctl         ./cmd/canaryctl
```

Self-checks (no kernel, no proxy — usable as CI gates and smoke tests):

```sh
go run ./cmd/sting-selfcheck    # drives the attrition library; prints attacker-cost vs flat defender-cost
go run ./cmd/envoy-selfcheck    # drives the adapter end-to-end against an in-process engine + fake resolver
```

The Next.js console builds with npm:

```sh
cd dashboard/app && npm ci && npm run build
```

---

## 4. Single-node install + run

Below is the manual single-node sequence. (`deploy/m7-window/run-window.sh`
automates the same on the live box; see §7.) Start the engine first, then the
adapter, then Envoy, then optionally the dashboard.

### 4.1 Choose your engine: `cmd/engine` vs `cmd/staged-range`

- **`cmd/engine`** is the production engine. It scores, tiers, calibrates **from
  real feedback**, learns the per-scope baseline, and emits verdicts. It is
  proxy-agnostic and **cannot** construct the staged ground-truth labeler (an
  import guard enforces this). It has **no built-in feedback source**, so in a
  fresh deployment it stays in **uncalibrated mode** (documented static thresholds
  from `docs/ARCHITECTURE.md` §8) until an external feedback path supplies labels.
  > **Honesty flag:** the operator CLI that would submit feedback labels
  > (`canaryctl feedback`) is **not implemented** (`cmd/canaryctl` is a stub).
  > Today, real auto-calibration in this repo only happens via `staged-range`.

- **`cmd/staged-range`** is **STAGING-ONLY**. It is identical to `cmd/engine`
  except it wires a ground-truth labeler that auto-confirms canary touches from
  declared source IPs, so a scope reaches calibrated mode during a staged window
  without a human in the loop. It **refuses to start** unless you pass both
  `-i-am-running-a-staged-range` and `-ground-truth-registry <file>`. **Never run
  it in production.**

#### Run the production engine (no proxy, observe baseline on, durable DB)

```sh
sudo ./bin/engine \
  -scope-boundary my-deployment \         # REQUIRED on a standalone box; refuses to start if empty
  -grpc-addr 127.0.0.1:50052 \            # serve the contract over gRPC for the out-of-process adapter
  -observe-cgroup /sys/fs/cgroup \        # attach the OBSERVE-ONLY eBPF baseline (cgroup v2 root)
  -baseline-db /var/lib/canarysting/baseline.db \  # durable bbolt store (empty => in-memory, no durability)
  -window 5m                              # scoring correlation window (default scoring.DefaultWindow)
```

`sudo` because `-observe-cgroup` loads/attaches eBPF (CAP_BPF/CAP_NET_ADMIN/
CAP_PERFMON). Omit `-observe-cgroup` to run touch-only (no baseline; `M` forced to
1.0). Omit `-grpc-addr` and the engine just composes and idles (useful with
`-selfcheck`).

Quick verdict smoke (no proxy, no kernel):

```sh
./bin/engine -scope-boundary my-deployment -selfcheck
# prints: selfcheck verdict: scope="my-deployment" tier=… mode=… score=… calibrated=false
```

#### Run the staging engine (the live-window invocation)

```sh
sudo ./bin/staged-range \
  -scope-boundary m7-window \
  -grpc-addr 127.0.0.1:50052 \
  -observe-cgroup /sys/fs/cgroup \
  -baseline-db /var/lib/canarysting/baseline.db \
  -window-bucketer \                                  # coarse 8-bucket M7 bucketer (reachable in a 2-wk window)
  -contain-inline \                                   # Tier 2 runs inline attrition (real attacker-cost) not async
  -ground-truth-registry /etc/canarysting/ground-truth-registry.json \   # REQUIRED
  -dashboard-tap-addr 127.0.0.1:8088 \                # serve the read-only dashboard tap
  -i-am-running-a-staged-range                        # REQUIRED self-incriminating acknowledgement
```

A minimal ground-truth registry (`deploy/m7-window/ground-truth-registry.json`):

```json
{ "scopes": [ { "scope": "m7-window",
  "legit": ["10.20.1.101","10.20.1.102","10.20.1.103"],
  "attacker": ["10.20.1.111"] } ] }
```

### 4.2 The Envoy `ext_proc` adapter + canary seeding

The adapter dials the engine over gRPC, seeds the **negative-space canaries** into
its registry, serves the `ext_proc` service Envoy connects to, and (on Linux)
attaches the sockops cookie resolver + kernel enforcer.

```sh
sudo ./bin/envoy-adapter \
  -listen 127.0.0.1:50051 \      # ext_proc gRPC address Envoy connects to
  -engine 127.0.0.1:50052 \      # the engine's -grpc-addr
  -scope my-deployment \         # REQUIRED; never falls back to a global scope
  -inline \                      # hold canary touches for the verdict (inline enforcement)
  -sting-floor 1                 # 0=passive/tarpit, 1=moderate(+poison/fake_tree), 2=aggressive(+token/exploit/exposure)
```

The canaries are pinned to **negative-space HTTP paths** a legitimate flow never
requests (each maps to a distinct canary type so distinct touches escalate):

| Canary type        | Leaf path             | Directory canary (prefix match) |
|--------------------|-----------------------|----------------------------------|
| PlantedCredential  | `/.aws/credentials`   | `/secrets/`                      |
| FakeSecret         | `/.env`               | `/config/`                       |
| DecoyFile          | `/backup/db.sql`      | `/backup/`                       |
| FakeBucket         | `/internal/buckets`   | `/internal/`                     |
| FakeEndpoint       | `/admin/metrics`      | `/admin/`                        |

These are disjoint from the legit demo app paths (`/shop /search /products
/account /cart /checkout /orders`), so a touch is almost certainly hostile. The
seeding is in `cmd/envoy-adapter/main.go` (`demoCanaryPaths`).

> **Platform note.** The kernel cookie resolver and enforcer are build-tagged: real
> on Linux, no-op elsewhere. On non-Linux the adapter still serves `ext_proc` and
> produces verdicts (proven by `cmd/envoy-selfcheck`), but cannot program a kernel
> jail.

### 4.3 Envoy configuration

Use `deploy/m7-window/envoy.yaml` as the template. The load-bearing parts:

- An `ext_proc` HTTP filter pointing at the `canarysting_extproc` cluster
  (`127.0.0.1:50051`), HTTP/2, with `request_attributes: [source.address,
  destination.address]` so the adapter can rebuild the 4-tuple and the engine-side
  staged labeler can attribute a touch.
- `timeout: 10s` and `message_timeout: 10s` on the ext_proc service — these MUST
  exceed the adapter's inline attrition hold (`-attrition-max-hold`, default 8s) or
  Envoy will time the stream out and 5xx the attacker instead of serving the
  deception body. `failure_mode_allow: false`.
- Body/response/trailer modes are `NONE`/`SKIP` (M7 uses path canaries).

Run Envoy:

```sh
envoy -c deploy/m7-window/envoy.yaml --log-level info
# admin/ready endpoint: http://127.0.0.1:9901/ready
```

The staged mesh behind Envoy (frontend → api → auth/db/cache) is in
`deploy/m7-window/server-compose.yml` / `deploy/m7-window/mesh` and is part of the
demo, not a requirement — point Envoy's `frontend` cluster at whatever app you are
protecting.

### 4.4 systemd units

The unit files in `deploy/m7-window/systemd/` are the canonical service
definitions and read variables from `/etc/canarysting/m7.env`:

- `canarysting-staged-range.service` — the engine (root; observe eBPF; durable
  `StateDirectory=canarysting` → `/var/lib/canarysting`).
- `canarysting-adapter.service` — the Envoy adapter (root; sockops + enforce;
  `After=` the engine).
- `canarysting-dashboard-backend.service` — read-only API (`DynamicUser=yes`,
  loopback-only, `NoNewPrivileges`/`ProtectSystem=strict`).
- `canarysting-dashboard-web.service` — Next.js console (`next start` on
  `127.0.0.1:3001`, runs as `ubuntu`).

`/etc/canarysting/m7.env` is the variable model (written by `run-window.sh`):

```sh
SCOPE=m7-window
BASELINE_DB=/var/lib/canarysting/baseline.db
GROUND_TRUTH=/etc/canarysting/ground-truth-registry.json
DASHBOARD_TAP_ADDR=<private-ip>:8088     # bind the VPC IP, not loopback, for cross-host reach
STING_FLOOR=1                            # adapter -sting-floor (1=moderate window default)
# optional posture toggles, word-split into the engine cmdline when set (empty => no flag):
AGGRESSIVE_FLAG=                         # -aggressive (single-touch escalation; demo)
DEMO_ESCALATION_FLAG=                    # -demo-escalation (3–5-touch dwell band; demo)
DEMO_FLOOR_FLAG=                         # -demo-data-floor (relax calendar-day gates; demo)
CONSUME_FLAG= ; SHARED_SPOOL_FLAG=       # -consume / -shared-spool (cross-customer)
```

Install + start:

```sh
sudo install -m0644 deploy/m7-window/systemd/canarysting-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canarysting-staged-range.service
sudo systemctl enable --now canarysting-adapter.service
```

### 4.5 Dashboard (backend + web)

The backend is **read-only**: it polls the engine tap over HTTP and never writes
(the engine holds the bbolt write lock).

```sh
# backend: derive the Overview view tree from the tap, serve JSON + SSE
./bin/dashboard-backend \
  -tap-addr http://127.0.0.1:8088 \   # engine -dashboard-tap-addr
  -listen-addr 127.0.0.1:8089 \       # loopback-only (the API has NO auth)
  -env my-deployment

# web: Next.js console, proxies /api -> the backend
cd dashboard/app
npm ci && npm run build
DASHBOARD_BACKEND_URL=http://127.0.0.1:8089 \
  node node_modules/next/dist/bin/next start -H 127.0.0.1 -p 3001
```

View it over an SSH tunnel (never bind a public interface — the console renders
attacker intelligence and has no auth):

```sh
ssh -L 3001:127.0.0.1:3001 user@<node>   # then open http://localhost:3001
```

---

## 5. Configuration reference (load-bearing flags/env)

> **Wiring honesty.** `config/canarysting.example.yaml` documents the full
> operator model, but **most of it is not loaded yet** — the YAML loader lands with
> the operator control plane (ROADMAP M10). Today the binaries are configured by
> **flags/env**, and only a few config fields have a runtime path
> (`max_coverage_gap_seconds` via `-max-coverage-gap`; baseline floor defaults live
> in `internal/engine/observebaseline/floor.go`). Treat the table below — the real
> flags — as authoritative.

### Engine (`cmd/engine` / `cmd/staged-range`)

| Flag | What it does | Safe default |
|---|---|---|
| `-scope-boundary` | The operator scope key. **Required** on a standalone box with no derivable cluster identity; empty ⇒ **refuse to start** (never a global scope, rule 5 / `docs/SCOPE.md`). | (none — must set) |
| `-grpc-addr` | Serve the engine contract over gRPC for the out-of-process adapter. | `cmd/engine`: empty (no server). `staged-range`: `:50052` |
| `-observe-cgroup` | cgroup v2 path to attach the OBSERVE-ONLY baseline eBPF (e.g. `/sys/fs/cgroup`). Empty ⇒ observe disabled, baseline `M` forced to 1.0 (touch-only). | empty (off) |
| `-baseline-db` | bbolt path for the durable baseline + interaction event store. Empty ⇒ in-memory (no durability across restarts). | `/var/lib/canarysting/baseline.db` |
| `-window` | Scoring correlation window. Tight windows reduce false positives. | `scoring.DefaultWindow` |
| `-aggressive` | DEMO/eval: lowers per-tier confidence so a flow escalates to Jail on fewer distinct touches (uncalibrated cold-start). | off |
| `-window-bucketer` | Coarse 8-bucket M7 learning-window bucketer instead of the 168-bucket production default. | `engine`: off / `staged-range`: on |
| `-max-coverage-gap` | Downtime longer than this forces baseline re-accrual on boot (a hole is never treated as normal). | 0 (built-in default) |
| `-baseline-db-reset-on-schema-change` | Discard the persisted baseline (logged) on a schema mismatch instead of refusing to start. | off (refuse) |

**`staged-range`-only (STAGING):** `-ground-truth-registry <file>` (**required**),
`-i-am-running-a-staged-range` (**required** acknowledgement), `-dashboard-tap-addr`
(serve the read-only tap), `-contain-inline` / `-jail-inline` (run Tier 2 / Tier 3
inline so attacker-cost is measured + outcomes reported), `-demo-escalation`
(3–5-touch dwell band; mutually exclusive with `-aggressive`), `-demo-data-floor`
(relax only the **calendar-day-span** gates so `M` goes live before the 7-day floor
— volume/population gates unchanged), plus the D6 cross-customer toggles below.

### Cross-customer / intelligence (D6, opt-in, default off — `staged-range`)

| Flag | What it does |
|---|---|
| `-contribute` | Record each local Tier-3 jail's coarse pattern into the cross-scope ledger; with `-scope-token` + `-confirm-spool`, emit a confirmation to the central aggregator under the **opaque** token (never the raw scope key). Requires both or refuses to start. |
| `-scope-token` | This deployment's opaque aggregator-issued token (never the scope key). |
| `-confirm-spool` | NDJSON spool written on each local jail (this deployment → aggregator). |
| `-consume` | Load cleared cross-customer patterns from `-shared-spool` to sharpen `M` for matching local flows — **detection context only, never a trigger** (rule 8). Requires `-shared-spool` or refuses to start. |
| `-shared-spool` | NDJSON spool of cleared cross-customer patterns loaded at boot. |
| `-sim-peers-demo` | DEMO: mark consumed patterns as **simulated** so the dashboard discloses synthetic peers (auto-detected from a `<spool>.simulated` marker too). |

### Adapter (`cmd/envoy-adapter`)

| Flag | What it does | Safe default |
|---|---|---|
| `-listen` | ext_proc gRPC listen address (Envoy connects here). | `:50051` |
| `-engine` | Engine gRPC address (`-grpc-addr`). | `localhost:50052` |
| `-scope` | Resolved scope key. **Required** — never a global scope. | (none — must set) |
| `-inline` | Inline enforcement: hold canary touches for the verdict. | `true` |
| `-sting-floor` | Attrition floor for inline Tier 2/3: **0=passive** (tarpit/velocity only), **1=moderate** (+ poison_field / fake_tree), **2=aggressive** (+ token_bait / exploit / op-exposure — all five axes). Maps to `contract.StingFloor` (`FloorPassive`/`Moderate`/`Aggressive`). A bad floor refuses to start (the attritor proves every generator is bounded + harmless at construction). | `0` (most conservative) |
| `-attrition-body-cap` | Max deception-body bytes in the single ext_proc ImmediateResponse. | `64 KiB` |
| `-attrition-max-hold` | Max wall-time to hold ONE inline attrition flow before returning the body. **Must be < Envoy's ext_proc `message_timeout`** (10s in the sample) or the proxy 5xx's instead of serving the bait. | `8s` |

> **Default-conservative by design** (`CLAUDE.md` safety rules): the zero-value
> floor is passive (velocity only); aggressive is never a silent default. The live
> window default is `STING_FLOOR=1` (moderate); the demo posture flips it to 2.

### Dashboard backend (`cmd/dashboard-backend`)

| Flag | What it does | Default |
|---|---|---|
| `-tap-addr` | Engine tap base URL. | `http://127.0.0.1:8088` |
| `-listen-addr` | API listen address — **loopback only** (no auth; exposes attacker intel). | `127.0.0.1:8089` |
| `-poll-interval` | Tap poll cadence. | `5s` |
| `-events-window` | Events window requested from the tap. | `1h` |
| `-env` | Free-form environment label in the topbar. | empty |

---

## 6. Verification

### 6.1 Liveness + state (the tap)

The engine's read-only tap (`internal/dashboard/tap`, served when
`-dashboard-tap-addr` is set) exposes:

```sh
curl -s http://127.0.0.1:8088/healthz             # -> "ok"
curl -s http://127.0.0.1:8088/raw/state | jq .    # live scalar state
curl -s 'http://127.0.0.1:8088/raw/events?since_sec=600' | jq .   # recent interaction events
```

In `/raw/state`, confirm the two gates before claiming the baseline is sharpening:
`calibration.Calibrated: true`, `baseline.Live: true`, and **`baseline` bucket
sufficiency for the current time bucket** — only then does `M > 1.0`. The
`recon_live` array proves restraint (anomalous-but-untouched flows are surfaced,
never actioned). Envoy readiness is `curl http://127.0.0.1:9901/ready`.

### 6.2 Self-checks (no proxy, no kernel)

```sh
go run ./cmd/envoy-selfcheck   # canary touch -> real verdict w/ socket cookie; benign waved through; unattributable observed-not-enforced
go run ./cmd/sting-selfcheck   # attacker cost climbs while defender cost stays flat + bounded
```

Both exit non-zero on any invariant violation.

### 6.3 Smoke test: a canary touch escalates, a benign flow is untouched

With Envoy + adapter + engine up (use `-aggressive` on the engine for a fast
single-touch escalation in a smoke test):

```sh
# benign flow — a real app path — should pass straight through (no engine round-trip, ~50ms)
curl -s -o /dev/null -w "benign:   %{http_code} %{time_total}s\n" http://127.0.0.1:8080/products

# canary touch — negative-space path — arms a response (verdict + escalation)
curl -s -o /dev/null -w "canary:   %{http_code} %{time_total}s\n" http://127.0.0.1:8080/.aws/credentials
curl -s -o /dev/null -w "canary2:  %{http_code} %{time_total}s\n" http://127.0.0.1:8080/secrets/foo
curl -s -o /dev/null -w "canary3:  %{http_code} %{time_total}s\n" http://127.0.0.1:8080/config/x
```

Confirm escalation in the adapter log (or `journalctl -u canarysting-adapter`):

```
CANARY TOUCH scope=… canary=… cookie=0x… tier=… mode=… score=…
ATTRITION    scope=… cookie=0x… tier=… mech=… bytes=… held=…s tokens=… …    # inline Tier 2/3 hold
KERNEL CONTAINMENT applied action=… cookie=0x… tier=…                       # Linux + async Tier 2/3
```

The benign `/products` request returns fast with no `CANARY TOUCH` line; the
negative-space touches escalate and (at moderate/aggressive floor) incur a visible
held latency as the attrition pump drips. On the dashboard, the jailed socket
appears in KernelContainment while same-host workloads keep serving 200 in
BystanderHealth — the flow-precise containment proof.

### 6.4 Live-window health (systemd path)

```sh
deploy/m7-window/healthcheck.sh
# asserts: engine+adapter units active, Envoy ready, the bbolt DB is GROWING,
# and the prober's canary touches are seen by the adapter. Non-zero exit on a stall.
```

---

## 7. The demo harness (DEMO/STAGING — not production)

Everything under `deploy/m7-window/` and `deploy/k3-boxes/` is the **demo and
staging harness**. It uses the staging-only `cmd/staged-range` engine (auto-labels
from declared ground truth) and is explicitly **not a production deployment**.

- **`deploy/m7-window/README.md`** — the two-box live learning window (CLIENT box
  generates benign + attacker traffic; SERVER box runs Envoy + adapter + engine +
  observe baseline). `run-window.sh` builds, installs the units, writes
  `/etc/canarysting/m7.env`, brings up the Docker mesh, and starts accrual.
- **`deploy/m7-window/DEMO_SCRIPT_V2.md`** — the **current** CISO run-of-show
  (supersedes `DEMO_SCRIPT.md`): one box, one screen, observe ON + fast inline
  verdicts, driven by the traffic simulator.
- **`deploy/m7-window/sim-setup.sh`** — the one-box traffic simulator (`simdriver`
  + `llm-attacker`): benign east-west, a recon scanner (`.112`), and a malicious
  flow (`.111`), with a fail-closed `$20/day` cap on live-LLM spend (live Tier-C
  runs are **off** by default; require `SIM_LIVE_INTERVAL` + an
  `/etc/canarysting/anthropic.key`).
- **`deploy/m7-window/set-demo-posture.sh`** — flips the demo posture (`demo` =
  aggressive floor + 3–5-touch dwell; `default` = moderate window posture;
  `aggressive` = single-touch). **Always revert with `default` after a demo** so
  the live window is not left at FloorAggressive.
- **`deploy/m7-window/deploy-dashboard.sh`** — builds + (re)starts the dashboard
  backend + web units.
- **`deploy/k3-boxes/`** — the multi-node **cross-customer crossing**: three
  contributor boxes (`box-setup.sh`, cold-start, `-contribute` under opaque
  tokens) each jail a scripted attacker and emit a confirmation;
  `run-crossing.sh` relays the spools and runs `cmd/aggregator` to show **k=2
  rejects / k=3 crosses** one anonymized pattern. `run-sim-peers.sh` /
  `DASHBOARD_WIRING.md` wire simulated peers (disclosed as simulated) into the
  one-box dashboard.

> **Do not point the demo harness at production traffic.** `staged-range` refuses
> to start without the self-incriminating flag and a ground-truth registry
> precisely because it auto-labels; `cmd/engine` cannot even import the labeler.
