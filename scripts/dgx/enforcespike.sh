#!/usr/bin/env bash
set -euo pipefail

readonly remote_alias='falcon1'
readonly remote_root='/var/tmp/canarysting'
readonly cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
readonly snapshot_root='/var/tmp/canarysting-privileged'
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly check_script="${script_dir}/check.sh"
readonly copy_script="${script_dir}/copy.sh"
readonly cleanup_script="${script_dir}/cleanup.sh"

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/enforcespike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run one fixed precise-enforcement proof from the checksum-verified
/var/tmp/canarysting/ID/test/enforcespike artifact. The proof attaches sockops,
cgroup_skb/egress, and sock_release only to the exact run-owned child cgroup,
observes target and control traffic before enforcement, programs only the target
socket cookie, proves control/map-miss fail-open behavior, releases the target,
and proves restored connectivity. It never changes Cilium or Kubernetes state.

--inspect validates fixed evidence and runtime absence without mutation.
--cleanup removes only exact run-owned evidence, cgroup/snapshot residue, and the
verified artifact stage; it is idempotent. --dry-run never accesses the DGX.

No arbitrary command, path, cgroup, timeout, target, attach scope, or privilege is
accepted.
USAGE
}

fail() {
  printf 'enforcespike: %s\n' "$*" >&2
  exit 1
}

run_id=''
mode='run'
while (($#)); do
  case "$1" in
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may appear only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='dry-run'
      shift
      ;;
    --inspect)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='inspect'
      shift
      ;;
    --cleanup)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='cleanup'
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'

readonly stage="${remote_root}/${run_id}"
readonly evidence="${remote_root}/enforcespike-${run_id}"
readonly cgroup="${cgroup_parent}/${run_id}"
readonly snapshot="${snapshot_root}/enforcespike-${run_id}"

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: precise-enforcement proof contract passed; DGX was not accessed\n'
  printf 'run_id=%s\nstage=%s\nevidence=%s\ncgroup=%s\nsnapshot=%s\n' \
    "${run_id}" "${stage}" "${evidence}" "${cgroup}" "${snapshot}"
  printf 'attach_scope=run-owned-child-cgroup\nmutation=cgroup-and-transient-bpf-only\ncleanup=exact-run-idempotent\n'
  exit 0
fi

command -v ssh >/dev/null 2>&1 || fail 'required command is missing: ssh'
for required in "${check_script}" "${copy_script}" "${cleanup_script}"; do
  [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
done

if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${check_script}"
  printf 'pre_mutation_check=PASS\n'
fi
if [[ "${mode}" == 'run' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${copy_script}" --verify-only --run-id "${run_id}"
fi

ssh -T "${remote_alias}" bash -s -- "${mode}" "${run_id}" <<'REMOTE'
set -euo pipefail

mode="$1"
run_id="$2"
root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/enforcespike-${run_id}"
evidence_quarantine="${root}/.cleanup-enforcespike-${run_id}"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot="${snapshot_root}/enforcespike-${run_id}"
artifact_relative='test/enforcespike'
artifact="${stage}/${artifact_relative}"
readonly mode run_id root stage evidence evidence_quarantine cgroup_parent cgroup snapshot_root snapshot artifact_relative artifact

fail() {
  printf 'enforcespike(remote): %s\n' "$*" >&2
  exit 1
}

[[ "$(hostname -s)" == 'spark-5343' ]] || fail 'unexpected remote host'
[[ "$(uname -m)" == 'aarch64' ]] || fail 'unexpected remote architecture'
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || fail 'cgroup v2 unified hierarchy is required'
sudo -n true >/dev/null || fail 'non-interactive sudo is required'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid mode'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'

named_bpf_state() {
  local programs maps links state
  programs="$(sudo -n bpftool prog show 2>/dev/null)" || return 1
  maps="$(sudo -n bpftool map show 2>/dev/null)" || return 1
  links="$(sudo -n bpftool link show 2>/dev/null)" || return 1
  state="$(printf '%s\n%s\n%s\n' "${programs}" "${maps}" "${links}" |
    grep -E 'canary_sockops|enforce_(egress|release)|flow_cookies|verdict_map' || true)"
  [[ -z "${state}" ]] && printf 'none' || printf 'present'
}

bpf_ids() {
  local kind inventory
  for kind in prog map link; do
    inventory="$(sudo -n bpftool "${kind}" show 2>/dev/null)" || return 1
    awk -v kind="${kind}" '/^[0-9]+:/ { id=$1; sub(/:$/, "", id); print kind ":" id }' <<<"${inventory}"
  done | LC_ALL=C sort
}

assert_platform_healthy() {
  local ready desired
  sudo -n systemctl is-active --quiet k3s || return 1
  [[ "$(sudo -n k3s kubectl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" == 'True' ]] || return 1
  read -r ready desired <<<"$(sudo -n k3s kubectl -n kube-system get daemonset cilium -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  read -r ready desired <<<"$(sudo -n k3s kubectl -n kube-system get daemonset cilium-envoy -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  read -r ready desired <<<"$(sudo -n k3s kubectl -n kube-system get deployment cilium-operator -o jsonpath='{.status.readyReplicas} {.status.replicas}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E cilium status --wait=false >/dev/null || return 1
}

validate_stage() {
  [[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'verified artifact stage is missing or unsafe'
  [[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" ]] || fail 'stage manifest is missing or unsafe'
  [[ -f "${stage}/SHA256SUMS" && ! -L "${stage}/SHA256SUMS" ]] || fail 'stage checksum inventory is missing or unsafe'
  [[ -f "${artifact}" && ! -L "${artifact}" && -x "${artifact}" ]] || fail 'enforcespike artifact is missing or unsafe'
  local artifact_metadata actual_artifact_size actual_artifact_sha256
  artifact_metadata="$({
    awk -F '\t' -v p="${artifact_relative}" '
      $1 == "artifact" && $4 == p {
        count++
        size = $5
        digest = $6
      }
      END {
        if (count != 1) exit 1
        print size "\t" digest
      }
    ' "${stage}/manifest.tsv"
  })" || fail 'stage manifest does not name exactly one enforcespike artifact'
  IFS=$'\t' read -r artifact_size artifact_sha256 <<<"${artifact_metadata}"
  [[ "${artifact_size}" =~ ^[0-9]+$ ]] || fail 'artifact size metadata is malformed'
  [[ "${artifact_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact checksum metadata is malformed'
  (cd "${stage}" && sha256sum -c SHA256SUMS >/dev/null) || fail 'stage checksum verification failed'
  actual_artifact_size="$(stat -c %s "${artifact}")"
  actual_artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
  [[ "${actual_artifact_size}" == "${artifact_size}" ]] || fail 'artifact size changed after stage verification'
  [[ "${actual_artifact_sha256}" == "${artifact_sha256}" ]] || fail 'artifact checksum changed after stage verification'
}

validate_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'evidence directory is missing or unsafe'
  [[ "$(stat -c %a "${evidence}")" == '700' ]] || fail 'evidence directory mode must be 0700'
  local files
  files="$(find "${evidence}" -mindepth 1 -maxdepth 1 -printf '%y:%f\n' | LC_ALL=C sort)"
  [[ "${files}" == $'f:result.tsv\nf:stderr.log\nf:stdout.log' ]] || fail 'evidence inventory is not exact'
  local f
  for f in result.tsv stderr.log stdout.log; do
    [[ ! -L "${evidence}/${f}" && "$(stat -c %a "${evidence}/${f}")" == '600' ]] || fail "unsafe evidence file: ${f}"
    [[ "$(stat -c %s "${evidence}/${f}")" -le 1048576 ]] || fail "oversized evidence file: ${f}"
  done
  awk -F '\t' -v run="${run_id}" '
    $1 == "run_id" { r++; if ($2 != run) exit 1 }
    $1 == "status" { s++; if ($2 != "PASS") exit 1 }
    $1 == "attach_scope" { a++; if ($2 != "run-owned-child-cgroup") exit 1 }
    $1 == "runtime_cleanup" { c++; if ($2 != "PASS") exit 1 }
    $1 == "created_at_utc" { created++; if ($2 !~ /^[0-9TZ:-]+$/) exit 1 }
    $1 == "completed_at_utc" { completed++; if ($2 !~ /^[0-9TZ:-]+$/) exit 1 }
    $1 == "expires_at_utc" { expires++; if ($2 !~ /^[0-9TZ:-]+$/) exit 1 }
    END {
      if (r != 1 || s != 1 || a != 1 || c != 1 || created != 1 || completed != 1 || expires != 1) exit 1
    }
  ' "${evidence}/result.tsv" || fail 'evidence result schema is invalid'
  local expires_at expires_epoch now_epoch
  expires_at="$(awk -F '\t' '$1 == "expires_at_utc" { print $2 }' "${evidence}/result.tsv")"
  expires_epoch="$(date -u -d "${expires_at}" +%s)" || fail 'evidence expiration is invalid'
  now_epoch="$(date -u +%s)"
  [[ "${expires_epoch}" -gt "${now_epoch}" ]] || fail 'evidence expired; exact cleanup is required'
  local marker
  for marker in \
    'PROOF missing_attribution=PASS' \
    'PROOF shared_destination=PASS' \
    'PROOF observe_before_enforce=PASS' \
    'PROOF canary_touch=PASS' \
    'PROOF target_programmed=PASS' \
    'PROOF target_only_enforcement=PASS' \
    'PROOF bystander_fail_open=PASS' \
    'PROOF release_restore=PASS' \
    'PROOF attach_scope_observed=PASS' \
    'PROOF cilium_active_window=PASS' \
    'PROOF runtime_cleanup=PASS' \
    'RESULT PASS proof=precise-cookie-enforcement'; do
    grep -Fq "${marker}" "${evidence}/stdout.log" || fail "missing proof marker: ${marker}"
  done
}

validate_cleanup_evidence() {
  local evidence_dir="$1" entry name type owner
  [[ -d "${evidence_dir}" && ! -L "${evidence_dir}" && -O "${evidence_dir}" ]] || fail 'cleanup evidence directory is missing or unsafe'
  while IFS= read -r entry; do
    name="${entry##*/}"
    case "${name}" in result.tsv|stderr.log|stdout.log) ;; *) fail 'cleanup evidence has an unexpected entry' ;; esac
    type="$(stat -c %F "${entry}")"
    owner="$(stat -c %u "${entry}")"
    [[ "${type}" == 'regular file' && "${owner}" == "$(id -u)" ]] || fail 'cleanup evidence entry is unsafe'
  done < <(find "${evidence_dir}" -mindepth 1 -maxdepth 1 -print)
}

cleanup_evidence() {
  local evidence_name="enforcespike-${run_id}"
  local quarantine_name=".cleanup-${evidence_name}"
  [[ "${evidence}" == "${root}/${evidence_name}" && "${evidence_name}" != */* ]] || fail 'cleanup evidence is outside the fixed run scope'
  [[ "${evidence_quarantine}" == "${root}/${quarantine_name}" && "${quarantine_name}" != */* ]] || fail 'cleanup quarantine is outside the fixed run scope'
  if [[ ! -e "${root}" && ! -L "${root}" ]]; then
    printf 'absent'
    return
  fi
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'cleanup root is missing or unsafe'

  (
    cd -P -- "${root}" || fail 'could not enter cleanup root'
    [[ "$(pwd -P)" == "${root}" && ! -L "${root}" && . -ef "${root}" ]] || fail 'cleanup root is not physically anchored'
    local removed='no'
    while [[ -e "${evidence_name}" || -L "${evidence_name}" || -e "${quarantine_name}" || -L "${quarantine_name}" ]]; do
      if [[ ! -e "${quarantine_name}" && ! -L "${quarantine_name}" ]]; then
        validate_cleanup_evidence "${evidence_name}"
        mv -T -- "${evidence_name}" "${quarantine_name}" || fail 'could not quarantine exact evidence'
      fi
      [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" && -O "${quarantine_name}" ]] || fail 'quarantined evidence is unsafe'
      (
        cd -P -- "./${quarantine_name}" || fail 'could not enter quarantined evidence'
        [[ "$(pwd -P)" == "${root}/${quarantine_name}" ]] || fail 'quarantined evidence escaped the fixed root'
        [[ ! -L "${root}/${quarantine_name}" && . -ef "${root}/${quarantine_name}" ]] || fail 'quarantined evidence changed before cleanup'
        validate_cleanup_evidence .
        for file in result.tsv stderr.log stdout.log; do
          if [[ -e "${file}" || -L "${file}" ]]; then
            rm -- "${file}" || fail "could not remove allowlisted evidence file: ${file}"
          fi
        done
      ) || fail 'anchored evidence-file cleanup failed'
      [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" && -O "${quarantine_name}" ]] || fail 'quarantined evidence changed after cleanup'
      rmdir -- "${quarantine_name}" || fail 'could not remove empty evidence quarantine'
      removed='yes'
    done
    [[ "${removed}" == 'yes' ]] && printf 'removed' || printf 'absent'
  )
}

cleanup_runtime_residue() {
  if sudo -n test -e "${cgroup}"; then
    [[ "$(sudo -n awk 'NF { n++ } END { print n+0 }' "${cgroup}/cgroup.procs")" == '0' ]] || fail 'run-owned cgroup contains a process'
    sudo -n rmdir "${cgroup}"
  fi
  if sudo -n test -e "${snapshot}"; then
    sudo -n test -d "${snapshot}" || fail 'snapshot residue is not a directory'
    sudo -n test ! -L "${snapshot}" || fail 'snapshot residue is a symlink'
    snapshot_inventory="$(sudo -n find "${snapshot}" -mindepth 1 -maxdepth 1 -printf '%y:%f\n' | LC_ALL=C sort)"
    case "${snapshot_inventory}" in ''|'f:.enforcespike.tmp'|'f:enforcespike') ;; *) fail 'snapshot inventory is unsafe' ;; esac
    for proc_exe in /proc/[0-9]*/exe; do
      [[ "$(sudo -n readlink "${proc_exe}" 2>/dev/null || true)" != "${snapshot}/enforcespike" ]] || fail 'privileged snapshot is still executing'
    done
    sudo -n rm -f "${snapshot}/.enforcespike.tmp" "${snapshot}/enforcespike"
    sudo -n rmdir "${snapshot}"
  fi
  if sudo -n test -d "${cgroup_parent}"; then sudo -n rmdir "${cgroup_parent}" 2>/dev/null || true; fi
  if sudo -n test -d "${snapshot_root}"; then sudo -n rmdir "${snapshot_root}" 2>/dev/null || true; fi
}

if [[ "${mode}" == 'inspect' ]]; then
  [[ ! -e "${evidence_quarantine}" && ! -L "${evidence_quarantine}" ]] || fail 'interrupted evidence quarantine remains; run cleanup'
  validate_evidence
  bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state'
  [[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state remains'
  sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup remains'
  sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot remains'
  printf 'mode=inspect\nrun_id=%s\nevidence=PASS\nruntime_residue=none\n' "${run_id}"
  exit 0
fi

if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_runtime_residue
  bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state after cleanup'
  [[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state remains after cleanup'
  evidence_state="$(cleanup_evidence)" || fail 'anchored evidence cleanup failed'
  printf 'mode=cleanup\nrun_id=%s\nevidence=%s\nruntime_residue=none\n' "${run_id}" "${evidence_state}"
  exit 0
fi

validate_stage
readonly artifact_size artifact_sha256
[[ ! -e "${evidence}" && ! -L "${evidence}" && ! -e "${evidence_quarantine}" && ! -L "${evidence_quarantine}" ]] || fail 'proof evidence or interrupted quarantine already exists'
sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup already exists'
sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot already exists'
bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state before proof'
[[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state exists before proof'
assert_platform_healthy || fail 'K3s node or Cilium is unhealthy before proof'

root_before="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_before="$(bpf_ids)"
bpf_before_sha="$(printf '%s\n' "${bpf_before}" | sha256sum | awk '{print $1}')"
created_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -m 0700 "${evidence}"
: >"${evidence}/stdout.log"
: >"${evidence}/stderr.log"
chmod 0600 "${evidence}/stdout.log" "${evidence}/stderr.log"

set +e
(
  ulimit -f 1024
  sudo -n bash -s -- "${artifact}" "${artifact_size}" "${artifact_sha256}" "${run_id}" >"${evidence}/stdout.log" 2>"${evidence}/stderr.log" <<'PROOF'
set -euo pipefail
artifact="$1"
expected_size="$2"
expected_sha="$3"
run_id="$4"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot="${snapshot_root}/enforcespike-${run_id}"
snapshot_artifact="${snapshot}/enforcespike"
readonly artifact expected_size expected_sha run_id cgroup_parent cgroup snapshot_root snapshot snapshot_artifact

proof_fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
platform_healthy() {
  local ready desired
  systemctl is-active --quiet k3s || return 1
  [[ "$(k3s kubectl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" == 'True' ]] || return 1
  read -r ready desired <<<"$(k3s kubectl -n kube-system get daemonset cilium -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  read -r ready desired <<<"$(k3s kubectl -n kube-system get daemonset cilium-envoy -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  read -r ready desired <<<"$(k3s kubectl -n kube-system get deployment cilium-operator -o jsonpath='{.status.readyReplicas} {.status.replicas}')" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml cilium status --wait=false >/dev/null || return 1
}
cleanup() {
  local failed=0
  if [[ -d "${cgroup}" && ! -L "${cgroup}" ]]; then
    if [[ -z "$(awk 'NF { print; exit }' "${cgroup}/cgroup.procs")" ]]; then rmdir "${cgroup}" || failed=1; else failed=1; fi
  fi
  if [[ -d "${snapshot}" && ! -L "${snapshot}" ]]; then
    rm -f "${snapshot_artifact}" || failed=1
    rmdir "${snapshot}" || failed=1
  fi
  [[ ! -e "${cgroup}" && ! -L "${cgroup}" && ! -e "${snapshot}" && ! -L "${snapshot}" ]] || failed=1
  rmdir "${cgroup_parent}" 2>/dev/null || true
  rmdir "${snapshot_root}" 2>/dev/null || true
  if [[ "${failed}" -eq 0 ]]; then printf 'PROOF runtime_cleanup=PASS cgroup=absent snapshot=absent\n'; else printf 'FAIL: runtime cleanup incomplete\n' >&2; fi
  return "${failed}"
}
trap cleanup EXIT INT TERM

[[ "$(id -u)" == '0' ]] || proof_fail 'helper is not root'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || proof_fail 'invalid run ID'
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || proof_fail 'cgroup v2 is required'
[[ "$(stat -c %u:%a /var/tmp)" == '0:1777' ]] || proof_fail '/var/tmp must be root-owned mode 1777'
[[ ! -e "${snapshot}" && ! -L "${snapshot}" && ! -e "${cgroup}" && ! -L "${cgroup}" ]] || proof_fail 'run-owned runtime state already exists'

if [[ -e "${snapshot_root}" || -L "${snapshot_root}" ]]; then
  [[ -d "${snapshot_root}" && ! -L "${snapshot_root}" && -O "${snapshot_root}" && "$(stat -c %a "${snapshot_root}")" == '700' ]] || proof_fail 'unsafe snapshot root'
else
  mkdir -m 0700 "${snapshot_root}"
fi
mkdir -m 0700 "${snapshot}"
exec 5<"${artifact}" || proof_fail 'could not open staged artifact'
[[ "$(stat -Lc %F:%s /proc/self/fd/5)" == "regular file:${expected_size}" ]] || proof_fail 'staged artifact descriptor changed'
tmp="${snapshot}/.enforcespike.tmp"
cp --reflink=never --sparse=never /proc/self/fd/5 "${tmp}"
chmod 0500 "${tmp}"
[[ "$(stat -c %s "${tmp}")" == "${expected_size}" ]] || proof_fail 'snapshot size mismatch'
[[ "$(sha256sum "${tmp}" | awk '{print $1}')" == "${expected_sha}" ]] || proof_fail 'snapshot checksum mismatch'
mv -T "${tmp}" "${snapshot_artifact}"
printf 'PROOF privileged_artifact=PASS sha256=%s\n' "${expected_sha}"

if [[ -e "${cgroup_parent}" || -L "${cgroup_parent}" ]]; then
  [[ -d "${cgroup_parent}" && ! -L "${cgroup_parent}" && -O "${cgroup_parent}" ]] || proof_fail 'unsafe cgroup parent'
else
  mkdir "${cgroup_parent}"
fi
mkdir "${cgroup}"
(
  printf '%s\n' "${BASHPID}" >"${cgroup}/cgroup.procs"
  exec timeout --signal=TERM --kill-after=3s 15s "${snapshot_artifact}" -cgroup "${cgroup}" -proof
) &
proof_pid=$!
attach='FAIL'
cilium_window='FAIL'
for _ in $(seq 1 150); do
  child="$(bpftool cgroup show "${cgroup}" 2>/dev/null)" || proof_fail 'could not inventory child cgroup attachments'
  if grep -q 'canary_sockops' <<<"${child}" && grep -q 'enforce_egress' <<<"${child}" && grep -q 'enforce_release' <<<"${child}"; then
    parent="$(bpftool cgroup show "${cgroup_parent}" 2>/dev/null)" || proof_fail 'could not inventory parent cgroup attachments'
    root="$(bpftool cgroup show /sys/fs/cgroup 2>/dev/null)" || proof_fail 'could not inventory root cgroup attachments'
    if ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${parent}" && ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${root}"; then
      if platform_healthy; then
        child_after_health="$(bpftool cgroup show "${cgroup}" 2>/dev/null)" || proof_fail 'could not recheck child attachments after Cilium health'
        if grep -q 'canary_sockops' <<<"${child_after_health}" && grep -q 'enforce_egress' <<<"${child_after_health}" && grep -q 'enforce_release' <<<"${child_after_health}"; then
          attach='PASS'
          cilium_window='PASS'
          break
        fi
      fi
    fi
  fi
  kill -0 "${proof_pid}" 2>/dev/null || break
  sleep 0.02
done
wait "${proof_pid}"
proof_status=$?
printf 'PROOF attach_scope_observed=%s child=%s parent=absent root=absent programs=sockops,enforce,release\n' "${attach}" "${cgroup}"
printf 'PROOF cilium_active_window=%s node=spark-5343 attachments=live\n' "${cilium_window}"
[[ "${proof_status}" -eq 0 ]] || proof_fail "proof exited ${proof_status}"
[[ "${attach}" == 'PASS' ]] || proof_fail 'exact child attachment scope was not observed'
[[ "${cilium_window}" == 'PASS' ]] || proof_fail 'K3s node and Cilium health were not proven during live attachment'
PROOF
)
proof_exit=$?
set -e

root_after="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_after="$(bpf_ids)"
bpf_after_sha="$(printf '%s\n' "${bpf_after}" | sha256sum | awk '{print $1}')"
completed_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
expires_at_utc="$(date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ)"
assert_platform_healthy || fail 'K3s node or Cilium is unhealthy after proof'
runtime_cleanup='FAIL'
bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state after proof'
if [[ "${proof_exit}" -eq 0 && "${root_before}" == "${root_after}" && "${bpf_before}" == "${bpf_after}" && "${bpf_state}" == 'none' ]] &&
   sudo -n test ! -e "${cgroup}" && sudo -n test ! -e "${snapshot}"; then
  runtime_cleanup='PASS'
fi

status='FAIL'
if [[ "${runtime_cleanup}" == 'PASS' ]] && grep -Fq 'RESULT PASS proof=precise-cookie-enforcement' "${evidence}/stdout.log"; then
  status='PASS'
fi
{
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'status\t%s\n' "${status}"
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'attach_scope\trun-owned-child-cgroup\n'
  printf 'runtime_cleanup\t%s\n' "${runtime_cleanup}"
  printf 'root_attachments_before_sha256\t%s\n' "${root_before}"
  printf 'root_attachments_after_sha256\t%s\n' "${root_after}"
  printf 'bpf_inventory_before_sha256\t%s\n' "${bpf_before_sha}"
  printf 'bpf_inventory_after_sha256\t%s\n' "${bpf_after_sha}"
  printf 'created_at_utc\t%s\n' "${created_at_utc}"
  printf 'completed_at_utc\t%s\n' "${completed_at_utc}"
  printf 'expires_at_utc\t%s\n' "${expires_at_utc}"
  printf 'retention\trun-through-cleanup-with-24-hour-maximum\n'
  printf 'legal_hold\tunsupported\n'
  printf 'deletion\texact-run-cleanup\n'
  printf 'residency\tDGX-host-filesystem\n'
  printf 'encryption_boundary\toperator-managed-host\n'
  printf 'model_use\tprohibited\n'
  printf 'derivation_lineage\tartifact-checksum-plus-synthetic-proof\n'
  printf 'estimated_storage_impact\tless-than-3MiB\n'
} >"${evidence}/result.tsv"
chmod 0600 "${evidence}/result.tsv"

[[ "${status}" == 'PASS' ]] || fail "proof failed; inspect ${evidence}"
validate_evidence
printf 'mode=run\nrun_id=%s\nstatus=PASS\nevidence=%s\nruntime_residue=none\n' "${run_id}" "${evidence}"
REMOTE

if [[ "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${cleanup_script}" --run-id "${run_id}"
fi
if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${check_script}"
  printf 'post_mutation_check=PASS\n'
fi
