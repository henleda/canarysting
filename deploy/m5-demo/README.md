# deploy/m5-demo — the M5 end-to-end demo (the CISO precision proof)

Proves, on the Linux box, the moment that lands the CISO: **a real attacker
escalates on one connection to Tier 3 and is JAILED in the kernel by its socket
cookie, while a bystander on the same host keeps working.**

## Topology (extends the M4 stack)

```
attacker (one keepalive conn) ─HTTP:8080─▶ Envoy ─ext_proc─▶ adapter ─gRPC─▶ engine
bystander (separate conn)      ─HTTP:8080─▶            │  ▲                 (-aggressive)
                                                       │  └ sockops bridge ── cookie
                                                       └ enforce: cgroup_skb/egress jail (verdict_map[cookie])
```

The engine, the adapter (root: sockops cookie bridge **and** the enforce cgroup
programs), Envoy, and a whoami backend are the same host-networked stack as
`deploy/m4-demo`. The engine runs with **`-aggressive`** so a single flow reaches
Tier 3 on a handful of cold-start canary touches (Jail threshold drops ~5.10 → ~3.03;
not a production posture). On a Tier-3 async verdict the adapter's `OnVerdict` seam
programs `verdict_map[cookie] = Jail`, and `enforce_egress` drops that socket's
outbound bytes in-kernel — keyed by the **same** cookie the sockops bridge resolved.

## Run it

```sh
deploy/m5-demo/run-demo.sh
```

It builds the binaries, starts the engine + adapter, brings up Envoy + backend, then
runs the scripted attacker (`attacker/`) as the gate and prints the escalation
ledger. The attacker holds ONE keepalive connection (a raw socket = one cookie; a
pooled `http.Transport` would retry a jailed request on a fresh connection and mask
the jail), brushes the negative-space canaries to escalate, and proves it is jailed
(its next request hangs — Envoy's egress to it is dropped) while a separate bystander
connection keeps getting 200s. Exits non-zero on any violation, so it is the M5 gate.

Expected tail:

```
  attacker GET /backup/db.sql       -> 200
  attacker GET /internal/buckets    -> jailed (i/o timeout)
  bystander: 6/6 requests -> 200 (unaffected)
m5-demo: OK — real attacker jailed in-kernel by socket cookie; bystander untouched.
```

## Notes

- The rigorous proof is the root oracle `bpf/enforce/loader_linux_test.go`
  (`sudo go test` shape): jail precision, fail-open-on-miss, cookie-0-refused,
  delete-on-close, and rate-limit-throttles-not-jails — verified against the
  `getsockopt(SO_COOKIE)` ground truth. This demo is the e2e visual on top.
- Tier-2 throttle is active (token bucket) but not visually obvious on whoami's tiny
  responses; the oracle proves it. A larger backend payload would show the slowdown.
- The socket cookie is host-local; capture and enforcement are node-local. K8s (M11)
  ports this as a privileged DaemonSet (ROADMAP §7).
