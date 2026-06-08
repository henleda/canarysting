# deploy/m4-demo — the M4 end-to-end demo (and exit-bar gate)

Proves the M4 exit bar on the Linux box: **a real HTTP attacker through real Envoy
produces a real engine verdict, with the kernel socket cookie carried end-to-end.**

## Topology (single host, host networking)

```
curl ─HTTP:8080─▶ Envoy ──ext_proc/gRPC:50051──▶ adapter ──gRPC:50052──▶ engine
                   │                                  ▲
                   └──route──▶ backend (whoami:8000)  └── sockops eBPF (cgroup) ── socket cookie
```

- **Envoy** + **backend** run in `docker compose` with `network_mode: host` — so the
  accepted downstream socket lives in the host netns the sockops program observes,
  and there is no docker-proxy NAT rewriting the source tuple.
- The **engine** (`cmd/engine -grpc-addr`) and the **adapter** (`cmd/envoy-adapter`)
  run as host processes. The adapter runs as **root** (CAP_BPF/CAP_NET_ADMIN) to
  load the sockops program and attach it at the cgroup-v2 root.
- Canaries are seeded by the M3 seeder at negative-space paths (`/.env`,
  `/.aws/credentials`, `/backup/db.sql`, `/internal/buckets`, `/admin/metrics`).

## Run it

```sh
deploy/m4-demo/run-demo.sh
```

The script builds the binaries, starts the engine + adapter, brings up Envoy +
backend, fires legit then canary requests, prints the adapter ledger, and asserts
the exit bar (every canary touch produced a verdict carrying a non-zero,
kernel-resolved socket cookie; legit traffic produced none). It exits non-zero on
any violation, so it doubles as the M4 gate. Cleans up on exit.

Expected tail:

```
=== adapter ledger (canary touches with end-to-end cookie) ===
CANARY TOUCH scope=demo-scope canary=fake_secret cookie=0x… tier=… mode=… score=…
…
m4-demo: OK — real attacker -> real Envoy -> real verdict, socket cookie carried end-to-end.
```

## Notes

- Each `curl` is a fresh connection (its own socket cookie), so each touch scores
  as one flow. Single-connection escalation up the tier ladder (T0→T3) is the M9
  scripted/LLM attacker's job against this same stack.
- This stack is intended to also become the **always-on M7 baseline substrate** —
  keep it running to accrue a real baseline and real adversary-interaction history.
- The socket cookie is host-local; capture and enforcement are node-local. The
  same shape ports to K8s (M11) as a privileged DaemonSet (ROADMAP §7).
