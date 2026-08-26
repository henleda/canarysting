#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="falcon1"
readonly remote_root="/var/tmp/canarysting"
readonly cgroup_parent="/sys/fs/cgroup/canarysting-dgx"
readonly -a ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=12
  -o StrictHostKeyChecking=yes
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
cleanup_script="${script_dir}/cleanup.sh"
check_script="${script_dir}/check.sh"
readonly copy_script cleanup_script check_script

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/cookiespike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run one fixed, observe-only socket-cookie proof from the checksum-verified stage
/var/tmp/canarysting/ID. The proof attaches only to the exact run-owned child
cgroup /sys/fs/cgroup/canarysting-dgx/ID, creates one loopback TCP flow, compares
the Envoy tuple resolver with SO_COOKIE, proves an unattributable MISS, and exits.

Evidence is bounded to stdout.log, stderr.log, and result.tsv beneath
/var/tmp/canarysting/cookiespike-ID. --inspect validates it without mutation.
--cleanup removes that exact evidence/cgroup state, delegates artifact-stage
cleanup to cleanup.sh, and is idempotent. --dry-run never accesses the DGX.

No arbitrary command, path, cgroup, timeout, attach scope, or privilege is
accepted. This proof never loads an enforcement program.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

run_id=''
mode='run'

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ "$#" -ge 2 ]] || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run)
      [[ "${mode}" == 'run' ]] || fail '--dry-run, --inspect, and --cleanup are mutually exclusive and may appear only once'
      mode='dry-run'
      shift
      ;;
    --inspect)
      [[ "${mode}" == 'run' ]] || fail '--dry-run, --inspect, and --cleanup are mutually exclusive and may appear only once'
      mode='inspect'
      shift
      ;;
    --cleanup)
      [[ "${mode}" == 'run' ]] || fail '--dry-run, --inspect, and --cleanup are mutually exclusive and may appear only once'
      mode='cleanup'
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
validate_run_id "${run_id}"
readonly run_id mode

readonly remote_stage="${remote_root}/${run_id}"
readonly remote_evidence="${remote_root}/cookiespike-${run_id}"
readonly remote_cgroup="${cgroup_parent}/${run_id}"

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: socket-cookie proof contract passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'run_id=%s\n' "${run_id}"
  printf 'remote_stage=%s\n' "${remote_stage}"
  printf 'remote_evidence=%s\n' "${remote_evidence}"
  printf 'remote_cgroup=%s\n' "${remote_cgroup}"
  printf 'artifact=test/cookiespike\n'
  printf 'timeout_seconds=15\n'
  printf 'attach_scope=run-owned-child-cgroup\n'
  printf 'traffic=loopback-only\n'
  printf 'enforcement=none\n'
  exit 0
fi

for required in ssh "${check_script}" "${cleanup_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -x "${required}" ]] || fail "required script is missing or not executable: ${required}"
  else
    command -v "${required}" >/dev/null 2>&1 || fail "required tool not found: ${required}"
  fi
done

if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  printf 'pre_mutation_check=begin\n'
  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
  printf 'pre_mutation_check=PASS\n'
fi

if [[ "${mode}" == 'run' || "${mode}" == 'inspect' ]]; then
  [[ -x "${copy_script}" ]] || fail "copy verifier is missing or not executable: ${copy_script}"
  "${copy_script}" --verify-only --run-id "${run_id}"
fi

ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" <<'REMOTE'
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
[[ "$(hostname)" == 'spark-5343' ]] || fail "unexpected hostname: $(hostname)"
[[ "$(uname -m)" == 'aarch64' ]] || fail "unexpected architecture: $(uname -m)"
for tool in awk bash bpftool date env find grep hostname id mkdir mv readlink rm rmdir sha256sum sort stat sudo timeout uname; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/cookiespike-${run_id}"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
artifact_relative='test/cookiespike'
artifact="${stage}/${artifact_relative}"
readonly root stage evidence cgroup_parent cgroup artifact_relative artifact

process_state() {
  local artifact_path="$1"
  local resolved proc_exe
  [[ -e "${artifact_path}" ]] || {
    printf 'absent'
    return
  }
  resolved="$(readlink -f "${artifact_path}")"
  for proc_exe in /proc/[0-9]*/exe; do
    if [[ "$(readlink -f "${proc_exe}" 2>/dev/null || true)" == "${resolved}" ]]; then
      printf 'present'
      return
    fi
  done
  printf 'none'
}

named_bpf_state() {
  if sudo -n bpftool prog show 2>/dev/null | grep -qi canary; then
    printf 'present'
  else
    printf 'none'
  fi
}

validate_evidence() {
  local require_complete="$1"
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] ||
    fail "evidence must be an owned, non-symlink directory: ${evidence}"
  local unsupported unowned entry size actual_files expected_stdout_sha256 expected_stderr_sha256
  unsupported="$(find "${evidence}" -mindepth 1 ! -type f -print -quit)"
  [[ -z "${unsupported}" ]] || fail "evidence contains a symlink or unsupported entry: ${unsupported}"
  unowned="$(find "${evidence}" -mindepth 1 ! -user "$(id -un)" -print -quit)"
  [[ -z "${unowned}" ]] || fail "evidence contains an entry not owned by the current user: ${unowned}"
  while IFS= read -r entry; do
    case "${entry}" in
      stdout.log|stderr.log|result.tsv|.result.tsv.tmp) ;;
      *) fail "evidence contains an undeclared entry: ${evidence}/${entry}" ;;
    esac
    size="$(stat -c %s "${evidence}/${entry}")"
    [[ "${size}" -le 1048576 ]] || fail "evidence file exceeds 1048576 bytes: ${entry}"
  done < <(find "${evidence}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)

  if [[ "${require_complete}" == 'yes' ]]; then
    [[ -f "${evidence}/stdout.log" && -f "${evidence}/stderr.log" && -f "${evidence}/result.tsv" ]] ||
      fail 'complete evidence must contain stdout.log, stderr.log, and result.tsv'
    actual_files="$(find "${evidence}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
    [[ "${actual_files}" == $'result.tsv\nstderr.log\nstdout.log' ]] || fail 'complete evidence inventory is not exact'
    awk -F '\t' -v expected="${run_id}" '
      NR == 1 { if ($0 != "key\tvalue") exit 1; next }
      NF != 2 || $1 == "" { exit 1 }
      $1 == "run_id" { run_count++; if ($2 != expected) exit 1 }
      $1 == "status" { status_count++; if ($2 != "PASS") exit 1 }
      $1 == "enforcement" { enforcement_count++; if ($2 != "none") exit 1 }
      $1 == "attach_scope" { attach_count++; if ($2 != "run-owned-child-cgroup") exit 1 }
      $1 == "traffic" { traffic_count++; if ($2 != "loopback-only") exit 1 }
      $1 == "tuple_semantics" { tuple_semantics_count++; if ($2 != "remote-to-local") exit 1 }
      $1 == "missing_attribution" { missing_count++; if ($2 != "PASS") exit 1 }
      $1 == "tuple_direction" { tuple_count++; if ($2 != "PASS") exit 1 }
      $1 == "flow_identity" { identity_count++; if ($2 != "PASS") exit 1 }
      $1 == "close_delete" { close_count++; if ($2 != "PASS") exit 1 }
      $1 == "cgroup_cleanup" { cleanup_count++; if ($2 != "PASS") exit 1 }
      $1 == "process_residue" { process_count++; if ($2 != "none") exit 1 }
      $1 == "bpf_residue" { bpf_count++; if ($2 != "none") exit 1 }
      $1 == "cgroup_residue" { cgroup_count++; if ($2 != "none") exit 1 }
      $1 == "root_attachments_before_sha256" { before_count++; before = $2 }
      $1 == "root_attachments_after_sha256" { after_count++; after = $2 }
      END {
        if (run_count != 1 || status_count != 1 || enforcement_count != 1 ||
            attach_count != 1 || traffic_count != 1 || tuple_semantics_count != 1 ||
            missing_count != 1 || tuple_count != 1 || identity_count != 1 ||
            close_count != 1 || cleanup_count != 1 || process_count != 1 ||
            bpf_count != 1 || cgroup_count != 1 || before_count != 1 || after_count != 1 ||
            length(before) != 64 || before ~ /[^0-9a-f]/ || after != before) exit 1
      }
    ' "${evidence}/result.tsv" || fail "evidence result is malformed, failed, or belongs to another run"
    expected_stdout_sha256="$(awk -F '\t' '$1 == "stdout_sha256" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "${evidence}/result.tsv")" ||
      fail 'evidence result must contain one stdout checksum'
    expected_stderr_sha256="$(awk -F '\t' '$1 == "stderr_sha256" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "${evidence}/result.tsv")" ||
      fail 'evidence result must contain one stderr checksum'
    [[ "${expected_stdout_sha256}" =~ ^[0-9a-f]{64}$ && "${expected_stderr_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
      fail 'evidence result contains a malformed log checksum'
    [[ "$(sha256sum "${evidence}/stdout.log" | awk '{print $1}')" == "${expected_stdout_sha256}" ]] ||
      fail 'stdout evidence checksum mismatch'
    [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "${expected_stderr_sha256}" ]] ||
      fail 'stderr evidence checksum mismatch'
  elif [[ -f "${evidence}/result.tsv" ]]; then
    awk -F '\t' -v expected="${run_id}" '
      NR == 1 { if ($0 != "key\tvalue") exit 1; next }
      NF != 2 || $1 == "" { exit 1 }
      $1 == "run_id" { count++; if ($2 != expected) exit 1 }
      END { if (count != 1) exit 1 }
    ' "${evidence}/result.tsv" || fail "partial evidence result does not belong to run ${run_id}"
  fi
}

if [[ "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]]; then
  process_residue="$(process_state "${artifact}")"
  [[ "${process_residue}" != 'present' ]] || fail 'cookiespike process residue is present'
  bpf_residue="$(named_bpf_state)"
  [[ "${bpf_residue}" == 'none' ]] || fail 'named CanarySting BPF state is present; refusing implicit detach'

  cgroup_state='absent'
  if sudo -n test -e "${cgroup}"; then
    cgroup_state='present'
    if [[ "${mode}" == 'inspect' ]]; then
      fail "run-owned cgroup residue is present: ${cgroup}"
    fi
    cgroup_processes="$(sudo -n awk 'NF { count++ } END { print count+0 }' "${cgroup}/cgroup.procs")"
    [[ "${cgroup_processes}" == '0' ]] || fail 'run-owned cgroup contains a process; refusing cleanup'
    sudo -n rmdir "${cgroup}"
    cgroup_state='removed'
  fi

  evidence_state='absent'
  if [[ -e "${evidence}" || -L "${evidence}" ]]; then
    if [[ "${mode}" == 'inspect' ]]; then
      validate_evidence yes
      evidence_state='validated'
      awk -F '\t' '
        $1 == "artifact_sha256" || $1 == "attach_scope" || $1 == "traffic" ||
        $1 == "enforcement" || $1 == "missing_attribution" || $1 == "tuple_semantics" ||
        $1 == "tuple_direction" || $1 == "flow_identity" || $1 == "close_delete" ||
        $1 == "cgroup_cleanup" || $1 == "process_residue" || $1 == "bpf_residue" ||
        $1 == "cgroup_residue" || $1 == "root_attachments_before_sha256" ||
        $1 == "root_attachments_after_sha256" || $1 == "status" || $1 == "diagnostic" {
          print "evidence_" $1 "=" $2
        }
      ' "${evidence}/result.tsv"
    else
      validate_evidence no
      for file in .result.tsv.tmp result.tsv stderr.log stdout.log; do
        [[ ! -e "${evidence}/${file}" && ! -L "${evidence}/${file}" ]] || rm -- "${evidence}/${file}"
      done
      rmdir "${evidence}"
      evidence_state='removed'
    fi
  elif [[ "${mode}" == 'inspect' ]]; then
    fail "evidence is absent: ${evidence}"
  fi

  if [[ "${mode}" == 'cleanup' ]] && sudo -n test -d "${cgroup_parent}"; then
    sudo -n rmdir "${cgroup_parent}" 2>/dev/null || true
  fi
  printf 'mode=%s\nrun_id=%s\nevidence=%s\ncgroup=%s\nprocess_residue=%s\nbpf_residue=%s\n' \
    "${mode}" "${run_id}" "${evidence_state}" "${cgroup_state}" "${process_residue}" "${bpf_residue}"
  [[ "${mode}" == 'cleanup' ]] && printf 'postcondition=m1c-candidates-absent\n'
  exit 0
fi

[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] ||
  fail "remote root must be an owned, writable, non-symlink directory: ${root}"
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] ||
  fail "artifact stage must be an owned, non-symlink directory: ${stage}"
[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail "proof evidence already exists: ${evidence}"
sudo -n test ! -e "${cgroup}" || fail "run-owned cgroup already exists: ${cgroup}"
[[ "$(process_state "${artifact}")" == 'none' ]] || fail 'cookiespike process is already running'
[[ "$(named_bpf_state)" == 'none' ]] || fail 'named CanarySting BPF state exists before proof'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] ||
  fail 'verified stage manifest is missing or not owned'

artifact_metadata="$({
  awk -F '\t' -v path="${artifact_relative}" '
    $1 == "artifact" && $4 == path {
      count++
      size = $5
      digest = $6
    }
    END {
      if (count != 1) exit 1
      print size "\t" digest
    }
  ' "${stage}/manifest.tsv"
})" || fail "manifest must contain exactly one ${artifact_relative} artifact"
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ ]] || fail 'artifact size metadata is malformed'
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact checksum metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] ||
  fail "artifact must be an owned regular executable: ${artifact_relative}"
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'artifact size changed after stage verification'
artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
[[ "${artifact_sha256}" == "${expected_sha256}" ]] || fail 'artifact checksum changed after stage verification'

root_attachments_before="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"

set +e
sudo -n bash -s -- "${artifact}" "${cgroup_parent}" "${cgroup}" <<'ROOT' >"${stdout_log}" 2>"${stderr_log}"
set -euo pipefail

artifact="$1"
cgroup_parent="$2"
cgroup="$3"
[[ "$(id -u)" == '0' ]] || { echo 'FAIL: privileged proof helper is not root' >&2; exit 1; }
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || { echo 'FAIL: cgroup v2 unified hierarchy is required' >&2; exit 1; }
[[ "${cgroup}" == "${cgroup_parent}/"* && "${cgroup}" != "${cgroup_parent}/" ]] || {
  echo 'FAIL: unsafe proof cgroup path' >&2
  exit 1
}
[[ -f "${artifact}" && ! -L "${artifact}" && -x "${artifact}" ]] || {
  echo 'FAIL: proof artifact is invalid' >&2
  exit 1
}

cleanup_cgroup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -d "${cgroup}" && ! -L "${cgroup}" ]]; then
    if [[ -z "$(awk 'NF { print; exit }' "${cgroup}/cgroup.procs")" ]]; then
      rmdir "${cgroup}"
    else
      echo 'FAIL: proof cgroup still contains a process' >&2
      exit_code=1
    fi
  fi
  if [[ -d "${cgroup_parent}" && ! -L "${cgroup_parent}" ]]; then
    rmdir "${cgroup_parent}" 2>/dev/null || true
  fi
  if [[ ! -e "${cgroup}" && ! -L "${cgroup}" ]]; then
    echo 'PROOF cgroup_cleanup=PASS residue=none'
  else
    echo 'FAIL: proof cgroup remains after cleanup' >&2
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup_cgroup EXIT INT TERM

if [[ -e "${cgroup_parent}" || -L "${cgroup_parent}" ]]; then
  [[ -d "${cgroup_parent}" && ! -L "${cgroup_parent}" && -O "${cgroup_parent}" ]] || {
    echo 'FAIL: cgroup parent is not a root-owned non-symlink directory' >&2
    exit 1
  }
else
  mkdir "${cgroup_parent}"
fi
[[ ! -e "${cgroup}" && ! -L "${cgroup}" ]] || { echo 'FAIL: proof cgroup already exists' >&2; exit 1; }
mkdir "${cgroup}"

(
  printf '%s\n' "${BASHPID}" >"${cgroup}/cgroup.procs"
  ulimit -c 0
  exec timeout --signal=TERM --kill-after=2s 15s \
    env -i LANG=C PATH=/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC \
    "${artifact}" -cgroup "${cgroup}" -proof
)
ROOT
exit_code=$?
set -e

finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stdout_bytes="$(stat -c %s "${stdout_log}")"
stderr_bytes="$(stat -c %s "${stderr_log}")"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
root_attachments_after="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
process_residue="$(process_state "${artifact}")"
bpf_residue="$(named_bpf_state)"
cgroup_residue='none'
sudo -n test ! -e "${cgroup}" || cgroup_residue='present'

missing_proof='FAIL'
tuple_proof='FAIL'
identity_proof='FAIL'
close_proof='FAIL'
cgroup_cleanup='FAIL'
grep -Fx 'PROOF missing_attribution=PASS result=MISS enforcement=refused' "${stdout_log}" >/dev/null && missing_proof='PASS'
grep -F 'PROOF tuple_direction=PASS semantics=remote-to-local tuple=' "${stdout_log}" >/dev/null && tuple_proof='PASS'
grep -F 'PROOF flow_identity=PASS socket_cookie=' "${stdout_log}" >/dev/null && identity_proof='PASS'
grep -Fx 'PROOF close_delete=PASS result=MISS' "${stdout_log}" >/dev/null && close_proof='PASS'
grep -Fx 'PROOF cgroup_cleanup=PASS residue=none' "${stdout_log}" >/dev/null && cgroup_cleanup='PASS'

status='PASS'
diagnostic='all-proof-criteria-passed'
if [[ "${exit_code}" -ne 0 ]]; then
  status='FAIL'
  diagnostic="proof-exit-${exit_code}"
elif [[ "${stdout_bytes}" -gt 1048576 || "${stderr_bytes}" -gt 1048576 ]]; then
  status='FAIL'
  diagnostic='proof-log-exceeded-1048576-bytes'
elif [[ "${missing_proof}/${tuple_proof}/${identity_proof}/${close_proof}/${cgroup_cleanup}" != 'PASS/PASS/PASS/PASS/PASS' ]]; then
  status='FAIL'
  diagnostic='required-proof-marker-missing'
elif ! grep -Fx 'RESULT PASS' "${stdout_log}" >/dev/null; then
  status='FAIL'
  diagnostic='explicit-result-pass-missing'
elif grep -F 'RESULT FAIL' "${stdout_log}" >/dev/null; then
  status='FAIL'
  diagnostic='explicit-result-fail-observed'
elif [[ "${process_residue}" != 'none' || "${bpf_residue}" != 'none' || "${cgroup_residue}" != 'none' ]]; then
  status='FAIL'
  diagnostic='run-owned-runtime-residue-present'
elif [[ "${root_attachments_before}" != "${root_attachments_after}" ]]; then
  status='FAIL'
  diagnostic='root-cgroup-attachments-changed'
fi

result_tmp="${evidence}/.result.tsv.tmp"
result="${evidence}/result.tsv"
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'artifact\t%s\n' "${artifact_relative}"
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'attach_scope\trun-owned-child-cgroup\n'
  printf 'traffic\tloopback-only\n'
  printf 'enforcement\tnone\n'
  printf 'tuple_semantics\tremote-to-local\n'
  printf 'timeout_seconds\t15\n'
  printf 'exit_code\t%s\n' "${exit_code}"
  printf 'missing_attribution\t%s\n' "${missing_proof}"
  printf 'tuple_direction\t%s\n' "${tuple_proof}"
  printf 'flow_identity\t%s\n' "${identity_proof}"
  printf 'close_delete\t%s\n' "${close_proof}"
  printf 'cgroup_cleanup\t%s\n' "${cgroup_cleanup}"
  printf 'process_residue\t%s\n' "${process_residue}"
  printf 'bpf_residue\t%s\n' "${bpf_residue}"
  printf 'cgroup_residue\t%s\n' "${cgroup_residue}"
  printf 'root_attachments_before_sha256\t%s\n' "${root_attachments_before}"
  printf 'root_attachments_after_sha256\t%s\n' "${root_attachments_after}"
  printf 'stdout_bytes\t%s\n' "${stdout_bytes}"
  printf 'stderr_bytes\t%s\n' "${stderr_bytes}"
  printf 'stdout_sha256\t%s\n' "${stdout_sha256}"
  printf 'stderr_sha256\t%s\n' "${stderr_sha256}"
  printf 'started_utc\t%s\n' "${started_utc}"
  printf 'finished_utc\t%s\n' "${finished_utc}"
  printf 'status\t%s\n' "${status}"
  printf 'diagnostic\t%s\n' "${diagnostic}"
} >"${result_tmp}"
mv "${result_tmp}" "${result}"

printf 'remote_evidence=%s\n' "${evidence}"
printf 'run_id=%s\n' "${run_id}"
printf 'artifact_sha256=%s\n' "${artifact_sha256}"
printf 'attach_scope=run-owned-child-cgroup\n'
printf 'enforcement=none\n'
printf 'missing_attribution=%s\n' "${missing_proof}"
printf 'tuple_direction=%s\n' "${tuple_proof}"
printf 'flow_identity=%s\n' "${identity_proof}"
printf 'close_delete=%s\n' "${close_proof}"
printf 'cgroup_cleanup=%s\n' "${cgroup_cleanup}"
printf 'process_residue=%s\n' "${process_residue}"
printf 'bpf_residue=%s\n' "${bpf_residue}"
printf 'cgroup_residue=%s\n' "${cgroup_residue}"
printf 'root_attachments_unchanged=%s\n' "$([[ "${root_attachments_before}" == "${root_attachments_after}" ]] && printf PASS || printf FAIL)"
printf 'status=%s\n' "${status}"
printf 'diagnostic=%s\n' "${diagnostic}"

[[ "${status}" == 'PASS' ]] || exit 1
REMOTE

if [[ "${mode}" == 'run' ]]; then
  printf 'post_proof_check=begin\n'
  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
  printf 'post_proof_check=PASS\n'
  printf 'PASS: observe-only DGX socket-cookie proof completed\n'
elif [[ "${mode}" == 'cleanup' ]]; then
  "${cleanup_script}" --run-id "${run_id}"
  printf 'PASS: exact M1C and artifact-stage cleanup completed\n'
else
  printf 'PASS: M1C evidence and no-residue state validated read-only\n'
fi
