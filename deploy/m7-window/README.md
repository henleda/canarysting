# M7 — the persistent learning window (two-box staged environment)

This stands up the real, always-on environment whose **elapsed time** the M7
milestone depends on: a genuine east-west service mesh generating continuous,
time-structured traffic, observed by the eBPF baseline path, so a **real**
per-scope baseline and **real** calibration accrue over a ≥2-week window — no
placeholder data. By demo time the scope is genuinely calibrated and live, and
the credibility panels show real state.

## Topology

```
  CLIENT box (t4g.small)                         SERVER box (the dev box, m7g.large)
  ┌─────────────────────────┐                    ┌──────────────────────────────────────────┐
  │ client-generator         │  3 legit IPs       │ Envoy :8080 ──ext_proc──► adapter :50051   │
  │   .101 .102 .103 ────────┼───private VPC──────►│   │ (sockops cookie bridge + enforce)      │
  │ prober (attacker .111) ──┼───private VPC──────►│   ▼                                        │
  │                          │  canary touches    │ frontend ─► api ─► auth / db / cache (mesh) │
  └─────────────────────────┘                    │   ▲ east-west observed by bpf/observe        │
                                                  │ staged-range engine :50052                  │
                                                  │   observe baseline (cgroup_skb) + labeler   │
                                                  │   bbolt /var/lib/canarysting/baseline.db    │
                                                  └──────────────────────────────────────────┘
```

The client presents **three distinct legitimate source identities** (real
secondary private IPs) plus the **attacker** identity. The server's observe path
sees them as real kernel-observed sources: the baseline learns the legit
population and adjacencies as normal; the attacker's unfamiliar source identity
is what lights up `AdjacencyNovelty`/`IdentityNovelty` so `M` sharpens the
response to its canary touch. All client→server traffic is **private VPC only**
(Envoy is never publicly exposed).

## The two gates (why the window is honest)

`M` amplifies only when a scope is BOTH:
- **live + bucket-sufficient** — enough real observed traffic across enough
  buckets and days (the eBPF data floor). The 24/7 generator accrues this.
- **calibrated** — enough real analyst-equivalent feedback labels. The prober
  touches canaries from the *declared* attacker identity; `cmd/staged-range`'s
  ground-truth labeler confirms each touch malicious and feeds it through the
  SAME feedback seam an analyst uses. These are real confirmations of an
  environment we built — not fabricated data. (Production `cmd/engine` cannot
  even construct the labeler; an import guard enforces it.)

## Run it

Prereqs: the dev/server box is up (`deploy/dev-box`) with the repo rsynced and
the engine/adapter/observe path proven (`bpf/observe` oracle green).

1. **Provision the client box** (from your laptop):
   ```sh
   cd deploy/m7-window/terraform
   terraform init
   terraform apply -var allowed_ssh_cidr="$(curl -s ifconfig.me)/32"
   terraform output            # note client_public_ip, server_private_ip
   ```
2. **Rsync the repo to the client box** (same pattern as the server box):
   ```sh
   rsync -az -e "ssh -i ~/.ssh/canarysting-dev" --exclude=.git --exclude=bin/ \
     ./ ubuntu@<client_public_ip>:/home/ubuntu/canarysting/
   ```
3. **Start the window on the SERVER box**:
   ```sh
   ssh -i ~/.ssh/canarysting-dev ubuntu@<server_ip> \
     'cd canarysting && deploy/m7-window/run-window.sh'
   ```
4. **Start the client** (pass the server's private IP from the terraform output):
   ```sh
   ssh -i ~/.ssh/canarysting-dev ubuntu@<client_public_ip> \
     'cd canarysting && deploy/m7-window/client-setup.sh <server_private_ip>'
   ```
5. **Verify accrual** (server box): `deploy/m7-window/healthcheck.sh` — units
   active, Envoy ready, the bbolt DB growing, the prober's touches seen.

Everything is `Restart=always` / `restart: unless-stopped` with Docker enabled on
boot, so the window survives reboots on both boxes. The bbolt store is durable;
on restart the engine forces the baseline STALE and re-confirms it from fresh
folds (a downtime gap forces re-accrual — a hole is never treated as normal).

## Bucketer graduation (D6)

The window runs with the **coarse** bucketer (`-window-bucketer`: 8 buckets =
{weekday,weekend} × {night,morning,afternoon,evening}) so bucket-sufficiency is
reachable within ~2 weeks. The production default is the 168-bucket
`Weekday×Hour`; graduate to it (drop `-window-bucketer`) as more weeks of real
data accrue — expect a sufficiency dip at graduation as the finer buckets refill.

## M9 — the LLM / scripted attacker

Two adversaries drive the live window from the declared-attacker IP (`10.20.1.111`),
plus one-command orchestration. Both keep a **single keepalive TCP connection** =
one socket cookie = one flow that escalates T0→T3 (the always-on prober deliberately
uses distinct flows; the M9 attacker inverts that).

- **LLM attacker** (`cmd/llm-attacker`) — a Claude **Opus 4.8** agentic loop with one
  `http_request` tool. The deception bodies it pulls back (fake_tree maze, token_bait)
  accumulate in its context and burn **real tokens**, capped by a hard dollar ceiling
  (`-hard-cap-usd`, default $5; two-layer enforcement + SIGINT/SIGTERM kill switch).
- **Scripted attacker** (`--scripted`) — deterministic, **zero-API** ($0). Same keepalive
  transport, fixed canary-touch sequence + maze follow. CI / rehearsal / reference trace.

**Run it (on the client box):**
```
deploy/m7-window/run-attack.sh --scripted                 # zero-API reference trace ($0)
deploy/m7-window/run-attack.sh --budget 0.50 --max-turns 5  # smallest live smoke
deploy/m7-window/run-attack.sh                            # full live run ($5 cap)
```
`run-attack.sh` health-checks the server, stops the prober for a clean single-cookie
trace (D6a, restarts on exit), builds, resolves the key, runs, and prints the
real-vs-proxy cost ledger.

**API key (D4):** create `/etc/canarysting/anthropic.key` (mode 0600), either a bare
key or an `ANTHROPIC_API_KEY=sk-ant-...` line. Never a CLI arg, never committed.

**Both demo postures (D6):** the realistic 3–5-touch escalation is the engine default;
single-touch escalation is `cmd/staged-range -aggressive`. Toggle it **on the server**:
```
server$ sudo deploy/m7-window/set-demo-posture.sh aggressive   # single-touch (fast)
server$ sudo deploy/m7-window/set-demo-posture.sh default       # revert
```
`run-attack.sh --aggressive` flips it for you when `SERVER_SSH=user@server` is exported,
else it prints the command. The attacker binary is identical in both postures.

**Live cost meter (D5):** the attacker PUTs its running real-token ledger to the tap's
`/raw/attack-ledger`; the dashboard-backend polls it and the CISO screen's Attacker-cost
panel shows the real `$` burn climbing toward the cap, **beside** the defender-side proxy
estimate (the two numbers are never merged). The meter needs the engine tap reachable
from the client box (`-dashboard-tap-addr` on the private IP, SG-restricted); if it's
loopback-only the meter no-ops and the run-end `-cost-out` JSON is the source of truth.

**Optional continuous unit** (`canarysting-llm-attacker.service`) is installed but **not
enabled** by `client-setup.sh` — for accruing continuous real adversary history at a lower
per-run cap ($0.50). Enable by hand only after the key file exists.

## Cost / lifecycle

The client box is a `t4g.small` (~$12/mo); the server box runs 24/7 for the
window (already ~$60/mo). BOTH must stay up for the ≥2-week window. To pause:
`sudo systemctl stop canarysting-generator canarysting-prober` (client) and
`aws ec2 stop-instances` — but note any downtime is a coverage gap that forces
re-accrual, so prefer leaving it running. Tear down the client when done:
`cd deploy/m7-window/terraform && terraform destroy` (removes the client box and
the server SG rule; the server box is untouched).
