# kina demo — setup + operate

## 1. What this is

A local [kina](https://github.com/vinnie357/kina) (Kubernetes on Apple Containers) demo of CanarySting's eBPF deception → kernel containment pipeline: a gateway seeds canary paths, an attacker's repeated touches climb the engine's response tiers, and the final tier is enforced in the kernel (a socket-cookie-attributed jail). This requires a BTF-enabled kernel — the CO-RE eBPF containment path won't load without it. Everything here is local and unpushed (see Caveats).

## 2. Prerequisites

- **kina 0.2.0 with the load fix.** The stock `kina load` imports images under the wrong containerd namespace for CRI; the fix lives on branch `feature/kina-load-ns-fix` in `~/github/kina`. Reinstall from that branch:
  ```
  cd ~/github/kina
  git checkout feature/kina-load-ns-fix
  cargo install --path kina-cli --force
  ```
- **Apple Container running:**
  ```
  container system start
  ```
- **kubectl** installed.
- **`eval "$(mise env)"`** before any `kina` / `kubectl` / `container` command in a new shell. A stale cargo-installed `kina` 0.1.0 can shadow `~/.cargo/bin/kina` on `PATH` if mise's shims aren't active — always re-check `kina --version` reports `0.2.0` after activating.
- **`kubectl config use-context cs`** before driving the cluster. This machine carries many other kubeconfig contexts (including `vinlab`, a different cluster) and `kubectl`'s current context can point elsewhere. `kina create cs` sets the context to `cs` at creation time, but if you've touched `kubectl config` since, or you're returning to an existing cluster, re-confirm with `kubectl config current-context`.
- **The BTF kernel artifact**, prebuilt at `/Users/vinnie/github/kina/.kernel-spike/cz/kernel-btf/vmlinux-btf`. Build recipe: kina `docs/development/custom-kernel.md` → "BTF-Enabled Variant" section (on branch `feature/btf-kernel`). The build takes several minutes (the final link step alone ran ~3 min on this machine, 8 vCPU / 16GB container — allow more on a cold cache).

## 3. First-time setup (from scratch)

### a. Create the cluster on the BTF kernel

```
kina create cs --cni cilium \
  --kernel-path /Users/vinnie/github/kina/.kernel-spike/cz/kernel-btf/vmlinux-btf \
  --wait 300
```

Verify:
```
container exec cs-control-plane ls /sys/kernel/btf/vmlinux
kina status cs
```
`kina status` should report `1/1 Ready` nodes, `10/10 Ready` core pods, and `1/1 Ready` Cilium.

### b. Build + load images

All three images (core, mesh, dashboard-web):
```
nu deploy/kina/load-images.nu --images [core, mesh, dashboard-web]
```
The load fix means no manual retag step is needed — `load-images.nu` handles the CRI namespace bridging internally per image.

### c. Apply manifests in order

```
kubectl apply -f deploy/kina/00-namespace.yaml
kubectl apply -f deploy/kina/30-envoy-configmap.yaml
kubectl apply -f deploy/kina/40-gateway.yaml
kubectl apply -f deploy/kina/60-mesh.yaml
kubectl apply -f deploy/kina/80-dashboard.yaml
kubectl apply -f deploy/kina/81-dashboard-nodeport.yaml
```
`50-jobs.yaml` and `70-containment-demo.yaml` are Jobs applied on demand (see §4), not part of standing setup.

### d. Wait for readiness

```
kubectl -n canarysting rollout status deploy/gateway
kubectl -n canarysting rollout status deploy/dashboard
kubectl -n canarysting rollout status deploy/frontend deploy/api deploy/auth deploy/db deploy/cache deploy/payments
kubectl -n canarysting get pods
```

## 4. Operating the demo (day-to-day)

### Drive detection → kernel jail

```
kubectl -n canarysting delete job containment-demo --ignore-not-found
kubectl apply -f deploy/kina/70-containment-demo.yaml
kubectl -n canarysting logs deploy/gateway -c adapter --tail=20 | grep -E 'CANARY TOUCH|KERNEL CONTAINMENT'
```
`70-containment-demo.yaml` curls 4 DISTINCT canary paths (`.aws/credentials`, `.env`, `backup/db.sql`, `internal/buckets`) over one keep-alive connection, so all four touches share the same flow identity. That repeated-touch, single-identity pattern is what drives the engine's tier climb (0 → 1 → 2 → 3) — the fourth touch is expected to get jailed (connection reset, non-zero curl exit) rather than fail the job.

### Benign vs canary by hand

```
kubectl -n canarysting port-forward svc/gateway 8080:8080
```
Then in another shell:
```
curl http://localhost:8080/          # benign — mesh 404s unknown paths, so use / for a clean benign hit
curl http://localhost:8080/.env      # canary path — triggers detection
```

### Dashboard

`http://dashboard.192.168.64.132.nip.io:30301/` — the IP is the current `cs-control-plane` node VM's address; re-derive it via `container inspect cs-control-plane` (look for `ipv4Address`) if the cluster is recreated. Port `30301` is pinned in `81-dashboard-nodeport.yaml`.

Port-forward alternative:
```
kubectl -n canarysting port-forward svc/dashboard 3001:3001
```

### Hubble east-west flows

```
kubectl -n kube-system exec ds/cilium -- hubble observe --namespace canarysting --last 100
```

## 5. Teardown / reset

```
kina delete cs
```
Destroys the cluster entirely — re-run §3 to rebuild. Images and manifests persist in the repo/registry cache; only cluster state is lost.

## 6. Layout

| File | What it is |
|---|---|
| `00-namespace.yaml` | `canarysting` namespace |
| `30-envoy-configmap.yaml` | Envoy proxy config for the gateway |
| `40-gateway.yaml` | Gateway Deployment (envoy + adapter + engine containers) + Service |
| `50-jobs.yaml` | On-demand Jobs: `benign-traffic` (5x clean requests) + `l7-gate` (5x same canary path, never escalates past the first tier) |
| `60-mesh.yaml` | 6-service east-west mesh (frontend, api, auth, db, cache, payments) |
| `70-containment-demo.yaml` | On-demand Job: 4-distinct-canary-path demo, drives tier escalation to kernel jail |
| `80-dashboard.yaml` | Dashboard backend (loopback-only, no auth) + frontend Deployment/Service |
| `81-dashboard-nodeport.yaml` | NodePort (30301) exposing the dashboard for the nip.io demo URL |
| `Dockerfile.core` | Builds `canarysting/core:latest` (engine, adapter, dashboard-backend) |
| `Dockerfile.dashboard-web` | Builds `canarysting/dashboard-web:latest` (Next.js frontend) |
| `load-images.nu` | Builds + loads all three images into the `cs` cluster with CRI retag/bridge |

## 7. Caveats

- **BTF kernel required.** CO-RE eBPF (the kernel containment path) will not load on the stock kina kernel — you must boot `cs` with `--kernel-path vmlinux-btf`.
- **No NetworkPolicy yet.** The tap and attack-ledger paths have no NetworkPolicy in front of them — don't repurpose this manifest set for anything beyond the demo without adding one.
- **Everything here is private and local** — nothing in this branch set (`canarysting:feature/kina-demo`, `kina:feature/kina-load-ns-fix`, `kina:feature/btf-kernel`) has been pushed.
