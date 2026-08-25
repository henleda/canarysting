#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="${CANARYSTING_DGX_HOST:-falcon1}"

command -v ssh >/dev/null 2>&1 || {
  echo "FAIL: ssh is required" >&2
  exit 1
}

echo "CanarySting DGX read-only check: ${dgx_host}"
ssh -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes "${dgx_host}" 'bash -s' <<'REMOTE'
set -euo pipefail

section() { printf '\n[%s]\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
kctl() { sudo -n k3s kubectl "$@"; }

section host
printf 'hostname=%s\n' "$(hostname)"
printf 'architecture=%s\n' "$(uname -m)"
printf 'kernel=%s\n' "$(uname -r)"
. /etc/os-release
printf 'os=%s %s\n' "$NAME" "$VERSION_ID"
printf 'cpus=%s\n' "$(nproc)"
awk '/MemTotal/ {printf "memory_kib=%s\n", $2}' /proc/meminfo
df -h / | awk 'NR==2 {printf "root_disk=%s size=%s used=%s available=%s\n", $1, $2, $3, $4}'

section prerequisites
for tool in k3s kubectl cilium bpftool docker go clang ollama; do
  if have "$tool"; then
    printf '%s=%s\n' "$tool" "$(command -v "$tool")"
  else
    printf '%s=missing\n' "$tool"
  fi
done

section kubernetes
printf 'k3s_service=%s\n' "$(systemctl is-active k3s 2>/dev/null || true)"
kctl get nodes -o custom-columns=NAME:.metadata.name,READY:.status.conditions[-1].status,ARCH:.status.nodeInfo.architecture,KUBELET:.status.nodeInfo.kubeletVersion,RUNTIME:.status.nodeInfo.containerRuntimeVersion

section cilium
KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E cilium status --wait=false
KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E cilium version

section kernel_bpf
printf 'cgroup_fs=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
printf 'bpffs=%s\n' "$(findmnt -n -o TARGET,FSTYPE /sys/fs/bpf 2>/dev/null || echo unavailable)"
test -r /sys/kernel/btf/vmlinux && echo 'kernel_btf=readable' || echo 'kernel_btf=unavailable'
printf 'bpf_jit=%s\n' "$(sysctl -n net.core.bpf_jit_enable 2>/dev/null || echo unknown)"
sudo -n bpftool feature probe kernel 2>/dev/null | grep -E 'program_type (sock_ops|cgroup_skb) is available' || true

section root_cgroup_attachments
sudo -n bpftool cgroup show /sys/fs/cgroup || true

section canarysting_host_state
found_process=0
for proc_dir in /proc/[0-9]*; do
  comm="$(cat "${proc_dir}/comm" 2>/dev/null || true)"
  case "${comm}" in
    *canarysting*|cookiespike|enforcespike)
      printf 'pid=%s command=%s\n' "${proc_dir##*/}" "${comm}"
      found_process=1
      ;;
  esac
done
test "${found_process}" -eq 1 || echo 'canarysting_processes=none'
sudo -n bpftool prog show 2>/dev/null | grep -i canary || echo 'canarysting_bpf_programs=none_named'
sudo -n bpftool map show 2>/dev/null | grep -i canary || echo 'canarysting_bpf_maps=none_named'

section canarysting_kubernetes_state
kctl get all,networkpolicy -A -l app.kubernetes.io/part-of=canarysting 2>/dev/null || true
kctl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase --no-headers 2>/dev/null | grep -Ei 'canary|test|curl|netshoot' || echo 'matching_test_pods=none'
kctl get networkpolicy -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name 2>/dev/null || true
kctl get cnp,ccnp -A -o custom-columns=KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name 2>/dev/null || true

section security_observations
sudo -n stat -c 'kubeconfig_mode=%a owner=%U:%G path=%n' /etc/rancher/k3s/k3s.yaml
sudo -n ufw status 2>/dev/null || true
sudo -n ss -H -lnt 2>/dev/null | awk '$4 ~ /:(22|6443|4240|9962|9964)$/ {print $4}' | sort -u

section historical_artifacts
find /tmp -maxdepth 1 -name 'canarysting-*' -printf '%f\n' 2>/dev/null || true
REMOTE
