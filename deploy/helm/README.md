# CanarySting Helm chart

A reproducible, single-command Kubernetes install of CanarySting for a single-node
**k3s** cluster. This is the CNCF-reproducibility artifact for the KubeCon EU 2027
demo: `helm install` and the DeceptionPolicy CRD, the operator, and the per-node
datapath come up together.

Chart lives in [`canarysting/`](./canarysting). It installs three things:

| Object | Kind | Source binary | Role |
|--------|------|---------------|------|
| DeceptionPolicy CRD | `CustomResourceDefinition` | — (`config/crd`) | the declarative API |
| operator | `Deployment` (1 replica) | `cmd/operator` | watches DeceptionPolicy, validates, writes status |
| node agent | **privileged `DaemonSet`** | `cmd/engine` + `cmd/envoy-adapter` | the datapath: observe baseline + ext_proc adapter + eBPF enforce |

The datapath is **per-node, not a sidecar.** The socket-cookie join (CLAUDE.md
rule 4) is per-socket and host-local, so enforcement must run on the same node as
the flow. The engine and adapter share one pod (and its network namespace); the
adapter dials the engine over pod loopback `127.0.0.1:50052`.

---

## Prerequisites

### Cluster
- **k3s** (or any Kubernetes ≥ 1.24) — single node is fine and is the demo target.
- `helm` ≥ 3.8 and `kubectl` on your workstation.

### Node (per node that runs the agent)
The target demo node is **ARM64 (aarch64)**, kernel **6.17**, cgroup v2, BTF present.
The hard requirements the eBPF datapath asserts at startup:

- **Linux kernel ≥ 5.10.** This is the pinned floor for a *system-global,
  never-reused* socket cookie (`bpf/kernel/kernel.go`: `MinMajor=5, MinMinor=10`);
  the engine refuses to enforce below it. Kernel 6.17 satisfies it comfortably.
- **cgroup v2 unified hierarchy** mounted at `/sys/fs/cgroup`. The observe/sockops/
  enforce programs are `cgroup_skb` / `sockops` / `cgroup/sock_release` and attach
  at the cgroup-v2 root.
- **BTF** present at `/sys/kernel/btf/vmlinux` (for CO-RE). k3s on a modern distro
  has this by default.
- **Architecture** matches your images. The chart defaults the node selector to
  `kubernetes.io/arch: arm64`; override for amd64 (see below).

You do **not** need clang on the node — the eBPF objects (`bpf/**/*_bpfel.o`) are
committed and embedded in the binaries. clang is only needed to *recompile* them.

### Privilege
The agent loads/attaches eBPF and programs the kernel verdict map, so it needs
`CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` (INSTALL.md §Capabilities). The chart
requests exactly those by default (`nodeAgent.capabilities`) rather than full
`privileged: true`. On a cluster with Pod Security admission, the node agent
namespace must allow the **`privileged`** PSA level (a privileged DaemonSet with
host mounts and those caps cannot run under `baseline`/`restricted`).

---

## Quickstart

```sh
# from the repo root
helm install canarysting deploy/helm/canarysting \
  --namespace canarysting --create-namespace \
  --set scope.boundary=kubecon-demo
```

`scope.boundary` is **required** — CanarySting never falls back to a global scope
(the engine and adapter refuse to start without it), so the install fails fast with
a clear message if you omit it.

Verify:

```sh
kubectl get crd deceptionpolicies.deception.canarysting.io
kubectl -n canarysting rollout status deploy/canarysting-operator
kubectl -n canarysting get ds canarysting-node-agent      # DESIRED == READY
kubectl -n canarysting logs ds/canarysting-node-agent -c engine
kubectl -n canarysting logs ds/canarysting-node-agent -c adapter
```

Apply a policy (see `config/samples/deception_v1alpha1_deceptionpolicy.yaml`):

```sh
kubectl apply -f config/samples/deception_v1alpha1_deceptionpolicy.yaml
kubectl -n default get deceptionpolicies      # Accepted column -> True
```

> **Honesty flag:** the M1 operator **validates** DeceptionPolicy and reports
> status; it plants **no** decoys yet (`SeededCount` stays `0`). Seeding is wired
> in M2. The negative-space demo canaries are currently seeded by the adapter
> in-process (`cmd/envoy-adapter` `demoCanaryPaths`), not by the operator.

Uninstall:

```sh
helm uninstall canarysting -n canarysting
# CRDs installed from crds/ are NOT removed by helm uninstall (Helm behavior):
kubectl delete crd deceptionpolicies.deception.canarysting.io   # if you want it gone
```

---

## Common overrides

```sh
# amd64 node instead of arm64
--set nodeSelector."kubernetes\.io/arch"=amd64

# fall back to full privileged if the capability set is rejected by the runtime
--set nodeAgent.privileged=true

# aggressive attrition floor (operator-elective; default is conservative)
--set nodeAgent.adapter.stingFloor=2

# expose the adapter ext_proc port on the node for mesh sidecars
--set nodeAgent.adapter.hostPort=50051

# mesh identity mode (documentation annotation today; see the caveat below)
--set mesh.enabled=true

# ephemeral baseline (no hostPath; loses the learned baseline on restart)
--set nodeAgent.persistence.enabled=false

# expose operator metrics
--set operator.metricsBindAddress=":8080"
```

See [`canarysting/values.yaml`](./canarysting/values.yaml) for the full, commented
knob set (image registry/repo/tag per component, resources, TLS, tolerations, host
mounts).

---

## How this maps from the old systemd model

The live M7 window ran the same binaries as **systemd units** on one box
(`deploy/m7-window/systemd/`, variables from `/etc/canarysting/m7.env`). This chart
is the Kubernetes-native equivalent:

| systemd (m7-window) | Helm chart | Notes |
|---------------------|------------|-------|
| `canarysting-staged-range.service` (root; observe eBPF; `StateDirectory=canarysting`) | node agent DaemonSet, **`engine`** container | The chart runs the **production `cmd/engine`**, not `staged-range` — the staged engine is staging-only (auto-labels ground truth; refuses to start without `-i-am-running-a-staged-range`). |
| `canarysting-adapter.service` (root; sockops + enforce; `After=` engine) | node agent DaemonSet, **`adapter`** container | Same flags: `-listen`, `-engine`, `-scope`, `-inline`, `-sting-floor`. |
| `EnvironmentFile=/etc/canarysting/m7.env` (`SCOPE`, `STING_FLOOR`, …) | `values.yaml` (`scope.boundary`, `nodeAgent.adapter.stingFloor`, …) | |
| `-observe-cgroup /sys/fs/cgroup` | `hostPath` volume → `/sys/fs/cgroup` | cgroup-v2 root, mounted read-only. |
| `StateDirectory=canarysting` → `/var/lib/canarysting` | `hostPath` volume (`nodeAgent.persistence`) | durable baseline across pod restarts on the node. |
| root user | `runAsUser: 0` + `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON` (or `privileged: true`) | least-privilege by default. |
| engine gRPC `127.0.0.1:50052`, adapter `127.0.0.1:50051` | same, but **intra-pod loopback** | both containers share the pod netns. |
| `canarysting-dashboard-*` units | **not included** | the read-only dashboard is out of scope for this chart. |

The **staged mesh, Envoy dataplane, ground-truth labeler, SIEM sink, and demo
attacker** from `deploy/m7-window/` are demo scaffolding and are intentionally
**not** part of this install.

---

## Known gaps / what still needs proving

1. **Container images do not exist yet.** The chart references
   `ghcr.io/canarysting/{operator,engine,envoy-adapter}:latest` as placeholders
   (`values.yaml` `image.*`, marked TODO). Nothing has been built or pushed. Build
   for `linux/arm64` (`make bin`), containerize, push, and pin real tags before a
   live install — otherwise pods `ImagePullBackOff`.
2. **The socket-cookie join under a CNI is unproven.** These manifests attach the
   eBPF at the host cgroup-v2 root and assume the node's flows traverse it (they do
   for pods on that node). But wiring a **service mesh's Envoys** to the adapter's
   `ext_proc` endpoint — so an L7 canary touch actually reaches the adapter and can
   be joined to the kernel socket cookie under the cluster's CNI — is **not** done
   here and is exactly what the separate spike must prove. Until then the agent
   observes and attaches on the node, but no L7 touches flow through it. The
   `nodeAgent.adapter.hostPort` knob is the minimal hook (node-address reachability)
   for that future wiring; the mesh-side `EnvoyFilter`/ext_proc cluster config is
   out of scope.
3. **`mesh.enabled` is documentation-only today.** It sets a
   `canarysting.io/identity-mode` annotation; the M1/M2 binaries do not yet consume
   a mesh-vs-label identity selector (`internal/identity/` is roadmap).
4. **cgroup namespace.** The chart mounts the host `/sys/fs/cgroup` so the attach
   resolves to the true host root even under a private cgroup namespace (the
   standard pattern). On a runtime where that isolation still blocks the host-root
   attach, set `nodeAgent.hostPID=true` (or `nodeAgent.privileged=true`). k3s on the
   demo node does not need it.
