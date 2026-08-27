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
  "${check_script}"
  printf 'pre_mutation_check=PASS\n'
fi
if [[ "${mode}" == 'run' ]]; then
  "${copy_script}" --verify-only --run-id "${run_id}"
fi

ssh -T "${remote_alias}" bash -s -- "${mode}" "${run_id}" <<'REMOTE'
set -euo pipefail

mode="$1"
run_id="$2"
root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/enforcespike-${run_id}"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot="${snapshot_root}/enforcespike-${run_id}"
artifact_relative='test/enforcespike'
artifact="${stage}/${artifact_relative}"
readonly mode run_id root stage evidence cgroup_parent cgroup snapshot_root snapshot artifact_relative artifact

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
  local state
  state="$({
    sudo -n bpftool prog show 2>/dev/null
    sudo -n bpftool map show 2>/dev/null
    sudo -n bpftool link show 2>/dev/null
  } | grep -E 'canary_sockops|enforce_(egress|release)|flow_cookies|verdict_map' || true)"
  [[ -z "${state}" ]] && printf 'none' || printf 'present'
}

bpf_ids() {
  local kind
  for kind in prog map link; do
    sudo -n bpftool "${kind}" show 2>/dev/null |
      awk -v kind="${kind}" '/^[0-9]+:/ { id=$1; sub(/:$/, "", id); print kind ":" id }'
  done | LC_ALL=C sort
}

validate_stage() {
  [[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'verified artifact stage is missing or unsafe'
  [[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" ]] || fail 'stage manifest is missing or unsafe'
  [[ -f "${stage}/SHA256SUMS" && ! -L "${stage}/SHA256SUMS" ]] || fail 'stage checksum inventory is missing or unsafe'
  [[ -f "${artifact}" && ! -L "${artifact}" && -x "${artifact}" ]] || fail 'enforcespike artifact is missing or unsafe'
  local count
  count="$(awk -F '\t' -v p="${artifact_relative}" '$1 == "artifact" && $4 == p { count++ } END { print count+0 }' "${stage}/manifest.tsv")"
  [[ "${count}" == '1' ]] || fail 'stage manifest does not name exactly one enforcespike artifact'
  (cd "${stage}" && sha256sum -c SHA256SUMS >/dev/null) || fail 'stage checksum verification failed'
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
    END { if (r != 1 || s != 1 || a != 1 || c != 1) exit 1 }
  ' "${evidence}/result.tsv" || fail 'evidence result schema is invalid'
  local marker
  for marker in \
    'PROOF missing_attribution=PASS' \
    'PROOF observe_before_enforce=PASS' \
    'PROOF canary_touch=PASS' \
    'PROOF target_programmed=PASS' \
    'PROOF target_only_enforcement=PASS' \
    'PROOF bystander_fail_open=PASS' \
    'PROOF release_restore=PASS' \
    'PROOF attach_scope_observed=PASS' \
    'PROOF runtime_cleanup=PASS' \
    'RESULT PASS proof=precise-cookie-enforcement'; do
    grep -Fq "${marker}" "${evidence}/stdout.log" || fail "missing proof marker: ${marker}"
  done
}

validate_cleanup_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'cleanup evidence directory is missing or unsafe'
  local entry name type owner size
  while IFS= read -r entry; do
    name="$(basename "${entry}")"
    case "${name}" in result.tsv|stderr.log|stdout.log) ;; *) fail 'cleanup evidence has an unexpected entry' ;; esac
    type="$(stat -c %F "${entry}")"
    owner="$(stat -c %u "${entry}")"
    size="$(stat -c %s "${entry}")"
    [[ "${type}" == 'regular file' && "${owner}" == "$(id -u)" && "${size}" -le 1048576 ]] || fail 'cleanup evidence entry is unsafe'
  done < <(find "${evidence}" -mindepth 1 -maxdepth 1 -print)
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
  validate_evidence
  [[ "$(named_bpf_state)" == 'none' ]] || fail 'named CanarySting BPF state remains'
  sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup remains'
  sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot remains'
  printf 'mode=inspect\nrun_id=%s\nevidence=PASS\nruntime_residue=none\n' "${run_id}"
  exit 0
fi

if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_runtime_residue
  [[ "$(named_bpf_state)" == 'none' ]] || fail 'named CanarySting BPF state remains after cleanup'
  if [[ -e "${evidence}" || -L "${evidence}" ]]; then
    validate_cleanup_evidence
    rm -f "${evidence}/result.tsv" "${evidence}/stderr.log" "${evidence}/stdout.log"
    rmdir "${evidence}"
  fi
  printf 'mode=cleanup\nrun_id=%s\nevidence=absent\nruntime_residue=none\n' "${run_id}"
  exit 0
fi

validate_stage
[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'proof evidence already exists'
sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup already exists'
sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot already exists'
[[ "$(named_bpf_state)" == 'none' ]] || fail 'named CanarySting BPF state exists before proof'

artifact_size="$(stat -c %s "${artifact}")"
artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
root_before="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_before="$(bpf_ids)"
bpf_before_sha="$(printf '%s\n' "${bpf_before}" | sha256sum | awk '{print $1}')"
mkdir -m 0700 "${evidence}"
: >"${evidence}/stdout.log"
: >"${evidence}/stderr.log"
chmod 0600 "${evidence}/stdout.log" "${evidence}/stderr.log"

set +e
(
  ulimit -f 2048
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
for _ in $(seq 1 150); do
  child="$(bpftool cgroup show "${cgroup}" 2>/dev/null || true)"
  if grep -q 'canary_sockops' <<<"${child}" && grep -q 'enforce_egress' <<<"${child}" && grep -q 'enforce_release' <<<"${child}"; then
    parent="$(bpftool cgroup show "${cgroup_parent}" 2>/dev/null || true)"
    root="$(bpftool cgroup show /sys/fs/cgroup 2>/dev/null || true)"
    if ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${parent}" && ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${root}"; then
      attach='PASS'
      break
    fi
  fi
  kill -0 "${proof_pid}" 2>/dev/null || break
  sleep 0.02
done
wait "${proof_pid}"
proof_status=$?
printf 'PROOF attach_scope_observed=%s child=%s parent=absent root=absent programs=sockops,enforce,release\n' "${attach}" "${cgroup}"
[[ "${proof_status}" -eq 0 ]] || proof_fail "proof exited ${proof_status}"
[[ "${attach}" == 'PASS' ]] || proof_fail 'exact child attachment scope was not observed'
PROOF
)
proof_exit=$?
set -e

root_after="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_after="$(bpf_ids)"
bpf_after_sha="$(printf '%s\n' "${bpf_after}" | sha256sum | awk '{print $1}')"
runtime_cleanup='FAIL'
if [[ "${proof_exit}" -eq 0 && "${root_before}" == "${root_after}" && "${bpf_before}" == "${bpf_after}" && "$(named_bpf_state)" == 'none' ]] &&
   sudo -n test ! -e "${cgroup}" && sudo -n test ! -e "${snapshot}"; then
  runtime_cleanup='PASS'
fi

status='FAIL'
if [[ "${runtime_cleanup}" == 'PASS' ]] && grep -Fq 'RESULT PASS proof=precise-cookie-enforcement' "${evidence}/stdout.log"; then
  status='PASS'
fi
{
  printf 'run_id\t%s\n' "${run_id}"
  printf 'status\t%s\n' "${status}"
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'attach_scope\trun-owned-child-cgroup\n'
  printf 'runtime_cleanup\t%s\n' "${runtime_cleanup}"
  printf 'root_attachments_before_sha256\t%s\n' "${root_before}"
  printf 'root_attachments_after_sha256\t%s\n' "${root_after}"
  printf 'bpf_inventory_before_sha256\t%s\n' "${bpf_before_sha}"
  printf 'bpf_inventory_after_sha256\t%s\n' "${bpf_after_sha}"
  printf 'retention\trun-through-inspect-and-cleanup\n'
  printf 'legal_hold\tunsupported\n'
  printf 'residency\tDGX-host-filesystem\n'
  printf 'encryption_boundary\toperator-managed-host\n'
  printf 'model_use\tprohibited\n'
} >"${evidence}/result.tsv"
chmod 0600 "${evidence}/result.tsv"

[[ "${status}" == 'PASS' ]] || fail "proof failed; inspect ${evidence}"
validate_evidence
printf 'mode=run\nrun_id=%s\nstatus=PASS\nevidence=%s\nruntime_residue=none\n' "${run_id}" "${evidence}"
REMOTE

if [[ "${mode}" == 'cleanup' ]]; then
  "${cleanup_script}" --run-id "${run_id}"
fi
if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  "${check_script}"
  printf 'post_mutation_check=PASS\n'
fi
