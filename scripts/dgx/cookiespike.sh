#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="falcon1"
readonly remote_root="/var/tmp/canarysting"
readonly cgroup_parent="/sys/fs/cgroup/canarysting-dgx"
readonly privileged_runtime_root="/var/tmp/canarysting-privileged"
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
The privileged helper copies the artifact into a root-owned, checksum-verified
/var/tmp/canarysting-privileged/cookiespike-ID snapshot and executes only that snapshot.

Evidence is bounded to stdout.log, stderr.log, and result.tsv beneath
/var/tmp/canarysting/cookiespike-ID. --inspect validates it without mutation.
--cleanup removes that exact evidence/cgroup/snapshot state, delegates artifact-
stage cleanup to cleanup.sh, and is idempotent. --dry-run never accesses the DGX.

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
readonly remote_privileged_snapshot="${privileged_runtime_root}/cookiespike-${run_id}"

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: socket-cookie proof contract passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'run_id=%s\n' "${run_id}"
  printf 'remote_stage=%s\n' "${remote_stage}"
  printf 'remote_evidence=%s\n' "${remote_evidence}"
  printf 'remote_cgroup=%s\n' "${remote_cgroup}"
  printf 'remote_privileged_snapshot=%s\n' "${remote_privileged_snapshot}"
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
for tool in awk bash bpftool chmod cp date dd env find grep head hostname id mkdir mv readlink rm rmdir sha256sum sleep sort stat sudo timeout uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/cookiespike-${run_id}"
evidence_quarantine="${root}/.cleanup-cookiespike-${run_id}"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot_dir="${snapshot_root}/cookiespike-${run_id}"
snapshot_artifact="${snapshot_dir}/cookiespike"
artifact_relative='test/cookiespike'
artifact="${stage}/${artifact_relative}"
readonly root stage evidence evidence_quarantine cgroup_parent cgroup snapshot_root snapshot_dir snapshot_artifact artifact_relative artifact

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

privileged_snapshot_state() {
  local requested_mode="$1"
  [[ "${requested_mode}" == 'inspect' || "${requested_mode}" == 'cleanup' ]] ||
    fail 'invalid privileged snapshot mode'
  sudo -n bash -s -- "${run_id}" "${requested_mode}" <<'SNAPSHOT'
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid privileged snapshot run ID'
[[ "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid privileged snapshot mode'

snapshot_root='/var/tmp/canarysting-privileged'
snapshot_parent="${snapshot_root%/*}"
snapshot_name="cookiespike-${run_id}"
snapshot_dir="${snapshot_root}/${snapshot_name}"
snapshot_artifact="${snapshot_dir}/cookiespike"
snapshot_tmp="${snapshot_dir}/.cookiespike.tmp"
readonly snapshot_root snapshot_parent snapshot_name snapshot_dir snapshot_artifact snapshot_tmp

[[ "${snapshot_parent}" == '/var/tmp' && -d "${snapshot_parent}" && ! -L "${snapshot_parent}" &&
  -O "${snapshot_parent}" && "$(stat -c %a "${snapshot_parent}")" == '1777' ]] ||
  fail 'privileged snapshot parent must be the root-owned mode-1777 /var/tmp directory'

if [[ ! -e "${snapshot_root}" && ! -L "${snapshot_root}" ]]; then
  printf 'absent\n'
  exit 0
fi
[[ -d "${snapshot_root}" && ! -L "${snapshot_root}" && -O "${snapshot_root}" ]] ||
  fail 'privileged snapshot root is not a root-owned, non-symlink directory'
[[ "$(stat -c %a "${snapshot_root}")" == '700' ]] || fail 'privileged snapshot root mode must be 0700'

if [[ ! -e "${snapshot_dir}" && ! -L "${snapshot_dir}" ]]; then
  printf 'absent\n'
  exit 0
fi
[[ -d "${snapshot_dir}" && ! -L "${snapshot_dir}" && -O "${snapshot_dir}" ]] ||
  fail 'privileged snapshot is not a root-owned, non-symlink directory'
[[ "$(stat -c %a "${snapshot_dir}")" == '700' ]] || fail 'privileged snapshot directory mode must be 0700'

for path in "${snapshot_dir}"/* "${snapshot_dir}"/.[!.]* "${snapshot_dir}"/..?*; do
  [[ -e "${path}" || -L "${path}" ]] || continue
  [[ "${path}" == "${snapshot_artifact}" || "${path}" == "${snapshot_tmp}" ]] ||
    fail 'privileged snapshot contains an undeclared entry'
  [[ -f "${path}" && ! -L "${path}" && -O "${path}" ]] ||
    fail 'privileged snapshot contains an unsafe entry'
  resolved="$(readlink -f "${path}")"
  for proc_exe in /proc/[0-9]*/exe; do
    [[ "$(readlink -f "${proc_exe}" 2>/dev/null || true)" != "${resolved}" ]] ||
      fail 'privileged snapshot is still executing; refusing cleanup'
  done
done

[[ "${mode}" == 'cleanup' ]] || fail 'privileged artifact snapshot residue is present'
for path in "${snapshot_tmp}" "${snapshot_artifact}"; do
  if [[ -e "${path}" || -L "${path}" ]]; then
    rm -- "${path}" || fail 'could not remove exact privileged snapshot file'
  fi
done
rmdir -- "${snapshot_dir}" || fail 'could not remove exact privileged snapshot directory'
rmdir -- "${snapshot_root}" 2>/dev/null || true
printf 'removed\n'
SNAPSHOT
}

canarysting_bpf_state() {
  local kind output
  for kind in prog map link; do
    if ! output="$(sudo -n bpftool "${kind}" show 2>&1)"; then
      printf 'inventory-error'
      return 1
    fi
    if grep -Eqi 'canary|flow_cookies' <<<"${output}"; then
      printf 'present'
      return 0
    fi
  done
  printf 'none'
}

bpf_object_ids() {
  local kind output
  for kind in prog map link; do
    output="$(sudo -n bpftool "${kind}" show 2>&1)" || return 1
    awk -v kind="${kind}" '
      /^[0-9]+:/ {
        id = $1
        sub(/:$/, "", id)
        print kind "\t" id
      }
    ' <<<"${output}"
  done
}

bounded_capture() {
  local destination="$1"
  local state_file="$2"
  local capture_status=0 count_status=0 discarded=''
  dd bs=1048576 count=1 iflag=fullblock status=none >"${destination}" || capture_status=$?
  discarded="$(wc -c | awk '{ print $1 }')" || count_status=$?
  if [[ "${capture_status}" -ne 0 || "${count_status}" -ne 0 || ! "${discarded}" =~ ^[0-9]+$ ]]; then
    printf 'error\n' >"${state_file}"
    return 1
  fi
  if [[ "${discarded}" == '0' ]]; then
    printf 'complete\n' >"${state_file}"
  else
    printf 'truncated\n' >"${state_file}"
  fi
}

validate_evidence() {
  local require_complete="$1"
  local evidence_dir="${2:-${evidence}}"
  [[ -d "${evidence_dir}" && ! -L "${evidence_dir}" && -O "${evidence_dir}" ]] ||
    fail "evidence must be an owned, non-symlink directory: ${evidence_dir}"
  local path entry size actual_files expected_stdout_sha256 expected_stderr_sha256
  local expected_artifact_sha256 actual_stdout_bytes actual_stderr_bytes
  for path in "${evidence_dir}"/* "${evidence_dir}"/.[!.]* "${evidence_dir}"/..?*; do
    [[ -e "${path}" || -L "${path}" ]] || continue
    [[ -f "${path}" && ! -L "${path}" ]] || fail "evidence contains a symlink or unsupported entry: ${path}"
    [[ -O "${path}" ]] || fail "evidence contains an entry not owned by the current user: ${path}"
    entry="${path##*/}"
    case "${entry}" in
      stdout.log|stderr.log|result.tsv|.result.tsv.tmp|.stdout.capture|.stderr.capture) ;;
      *) fail "evidence contains an undeclared entry: ${evidence_dir}/${entry}" ;;
    esac
    if [[ "${require_complete}" == 'yes' ]]; then
      size="$(stat -c %s "${path}")"
      [[ "${size}" -le 1048576 ]] || fail "evidence file exceeds 1048576 bytes: ${entry}"
    fi
  done

  if [[ "${require_complete}" == 'yes' ]]; then
    [[ -f "${evidence_dir}/stdout.log" && -f "${evidence_dir}/stderr.log" && -f "${evidence_dir}/result.tsv" ]] ||
      fail 'complete evidence must contain stdout.log, stderr.log, and result.tsv'
    actual_files="$(find "${evidence_dir}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
    [[ "${actual_files}" == $'result.tsv\nstderr.log\nstdout.log' ]] || fail 'complete evidence inventory is not exact'
    [[ "$(stat -c %a "${evidence_dir}")" == '700' ]] || fail 'complete evidence directory mode must be 0700'
    for entry in stdout.log stderr.log result.tsv; do
      [[ "$(stat -c %a "${evidence_dir}/${entry}")" == '600' ]] || fail "complete evidence file mode must be 0600: ${entry}"
    done
    [[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" ]] || fail 'verified artifact is unavailable during evidence inspection'
    expected_artifact_sha256="$(sha256sum "${artifact}" | awk '{ print $1 }')"
    actual_stdout_bytes="$(stat -c %s "${evidence_dir}/stdout.log")"
    actual_stderr_bytes="$(stat -c %s "${evidence_dir}/stderr.log")"
    awk -F '\t' -v expected="${run_id}" -v expected_artifact="${artifact_relative}" \
      -v expected_artifact_sha256="${expected_artifact_sha256}" \
      -v actual_stdout_bytes="${actual_stdout_bytes}" -v actual_stderr_bytes="${actual_stderr_bytes}" '
      NR == 1 { if ($0 != "key\tvalue") exit 1; next }
      NF != 2 || $1 == "" { exit 1 }
      $1 == "format_version" { version_count++; if ($2 != "1") exit 1 }
      $1 == "run_id" { run_count++; if ($2 != expected) exit 1 }
      $1 == "artifact" { artifact_count++; if ($2 != expected_artifact) exit 1 }
      $1 == "artifact_sha256" { artifact_sha_count++; if ($2 != expected_artifact_sha256) exit 1 }
      $1 == "privileged_artifact" { privileged_artifact_count++; if ($2 != "PASS") exit 1 }
      $1 == "privileged_snapshot_cleanup" { privileged_cleanup_count++; if ($2 != "PASS") exit 1 }
      $1 == "privileged_snapshot_residue" { privileged_residue_count++; if ($2 != "none") exit 1 }
      $1 == "status" { status_count++; if ($2 != "PASS") exit 1 }
      $1 == "enforcement" { enforcement_count++; if ($2 != "none") exit 1 }
      $1 == "attach_scope" { attach_count++; if ($2 != "run-owned-child-cgroup") exit 1 }
      $1 == "attach_scope_observed" { attach_observed_count++; if ($2 != "PASS") exit 1 }
      $1 == "traffic" { traffic_count++; if ($2 != "loopback-only") exit 1 }
      $1 == "tuple_semantics" { tuple_semantics_count++; if ($2 != "remote-to-local") exit 1 }
      $1 == "timeout_seconds" { timeout_count++; if ($2 != "15") exit 1 }
      $1 == "exit_code" { exit_count++; if ($2 != "0") exit 1 }
      $1 == "missing_attribution" { missing_count++; if ($2 != "PASS") exit 1 }
      $1 == "tuple_direction" { tuple_count++; if ($2 != "PASS") exit 1 }
      $1 == "flow_identity" { identity_count++; if ($2 != "PASS") exit 1 }
      $1 == "close_delete" { close_count++; if ($2 != "PASS") exit 1 }
      $1 == "cgroup_cleanup" { cleanup_count++; if ($2 != "PASS") exit 1 }
      $1 == "process_residue" { process_count++; if ($2 != "none") exit 1 }
      $1 == "bpf_residue" { bpf_count++; if ($2 != "none") exit 1 }
      $1 == "cgroup_residue" { cgroup_count++; if ($2 != "none") exit 1 }
      $1 == "stdout_capture" { stdout_capture_count++; if ($2 != "complete") exit 1 }
      $1 == "stderr_capture" { stderr_capture_count++; if ($2 != "complete") exit 1 }
      $1 == "stdout_bytes" { stdout_bytes_count++; if ($2 != actual_stdout_bytes) exit 1 }
      $1 == "stderr_bytes" { stderr_bytes_count++; if ($2 != actual_stderr_bytes) exit 1 }
      $1 == "root_attachments_before_sha256" { before_count++; before = $2 }
      $1 == "root_attachments_after_sha256" { after_count++; after = $2 }
      $1 == "bpf_inventory_before_sha256" { bpf_before_count++; bpf_before = $2 }
      $1 == "bpf_inventory_after_sha256" { bpf_after_count++; bpf_after = $2 }
      $1 == "started_utc" { started_count++; if ($2 !~ /^[0-9T:Z-]+$/) exit 1 }
      $1 == "finished_utc" { finished_count++; if ($2 !~ /^[0-9T:Z-]+$/) exit 1 }
      END {
        if (version_count != 1 || run_count != 1 || artifact_count != 1 || artifact_sha_count != 1 ||
            privileged_artifact_count != 1 || privileged_cleanup_count != 1 || privileged_residue_count != 1 ||
            status_count != 1 || enforcement_count != 1 || attach_count != 1 || attach_observed_count != 1 ||
            traffic_count != 1 || tuple_semantics_count != 1 || timeout_count != 1 || exit_count != 1 ||
            missing_count != 1 || tuple_count != 1 || identity_count != 1 ||
            close_count != 1 || cleanup_count != 1 || process_count != 1 ||
            bpf_count != 1 || cgroup_count != 1 || stdout_capture_count != 1 || stderr_capture_count != 1 ||
            stdout_bytes_count != 1 || stderr_bytes_count != 1 || before_count != 1 || after_count != 1 ||
            bpf_before_count != 1 || bpf_after_count != 1 || started_count != 1 || finished_count != 1 ||
            length(before) != 64 || before ~ /[^0-9a-f]/ || after != before ||
            length(bpf_before) != 64 || bpf_before ~ /[^0-9a-f]/ || bpf_after != bpf_before) exit 1
      }
    ' "${evidence_dir}/result.tsv" || fail "evidence result is malformed, failed, or belongs to another run"
    expected_stdout_sha256="$(awk -F '\t' '$1 == "stdout_sha256" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "${evidence_dir}/result.tsv")" ||
      fail 'evidence result must contain one stdout checksum'
    expected_stderr_sha256="$(awk -F '\t' '$1 == "stderr_sha256" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "${evidence_dir}/result.tsv")" ||
      fail 'evidence result must contain one stderr checksum'
    [[ "${expected_stdout_sha256}" =~ ^[0-9a-f]{64}$ && "${expected_stderr_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
      fail 'evidence result contains a malformed log checksum'
    [[ "$(sha256sum "${evidence_dir}/stdout.log" | awk '{print $1}')" == "${expected_stdout_sha256}" ]] ||
      fail 'stdout evidence checksum mismatch'
    [[ "$(sha256sum "${evidence_dir}/stderr.log" | awk '{print $1}')" == "${expected_stderr_sha256}" ]] ||
      fail 'stderr evidence checksum mismatch'
  fi
}

require_no_quarantined_evidence() {
  local quarantine_path="$1"
  [[ ! -e "${quarantine_path}" && ! -L "${quarantine_path}" ]] ||
    fail "quarantined proof evidence already exists; run cleanup first: ${quarantine_path}"
}

require_fresh_evidence_state() {
  local live_path="$1"
  local quarantine_path="$2"
  [[ ! -e "${live_path}" && ! -L "${live_path}" ]] ||
    fail "proof evidence already exists: ${live_path}"
  require_no_quarantined_evidence "${quarantine_path}"
}

cleanup_evidence() {
  local root_dir="$1"
  local evidence_name="$2"
  local quarantine_name=".cleanup-${evidence_name}"
  [[ "${evidence_name}" == "cookiespike-${run_id}" && "${evidence_name}" != */* ]] ||
    fail 'cleanup evidence name is outside the fixed run scope'
  [[ "${quarantine_name}" != */* ]] || fail 'cleanup quarantine name is unsafe'

  if [[ ! -e "${root_dir}" && ! -L "${root_dir}" ]]; then
    printf 'absent\n'
    return
  fi
  [[ -d "${root_dir}" && ! -L "${root_dir}" && -O "${root_dir}" ]] ||
    fail "cleanup root must be an owned, non-symlink directory: ${root_dir}"

  (
    cd -P -- "${root_dir}" || fail "could not enter cleanup root: ${root_dir}"
    [[ "$(pwd -P)" == "${root_dir}" && ! -L "${root_dir}" && . -ef "${root_dir}" ]] ||
      fail "cleanup root is not anchored at the fixed path: ${root_dir}"
    local_removed='no'
    while [[ -e "${evidence_name}" || -L "${evidence_name}" ||
      -e "${quarantine_name}" || -L "${quarantine_name}" ]]; do
      if [[ ! -e "${quarantine_name}" && ! -L "${quarantine_name}" ]]; then
        validate_evidence no "${evidence_name}"
        mv -T -- "${evidence_name}" "${quarantine_name}" ||
          fail 'could not quarantine exact evidence before cleanup'
      fi

      [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" && -O "${quarantine_name}" ]] ||
        fail 'quarantined evidence is not an owned, non-symlink directory'
      (
        cd -P -- "./${quarantine_name}" || fail 'could not enter quarantined evidence directory'
        [[ "$(pwd -P)" == "${root_dir}/${quarantine_name}" ]] ||
          fail 'quarantined evidence resolved outside the fixed cleanup root'
        [[ ! -L "${root_dir}/${quarantine_name}" && . -ef "${root_dir}/${quarantine_name}" ]] ||
          fail 'quarantined evidence changed before anchored cleanup'
        validate_evidence no .
        for file in .stdout.capture .stderr.capture .result.tsv.tmp result.tsv stderr.log stdout.log; do
          if [[ -e "${file}" || -L "${file}" ]]; then
            rm -- "${file}" || fail "could not remove allowlisted evidence file: ${file}"
          fi
        done
      ) || fail 'anchored evidence-file cleanup failed'
      [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" && -O "${quarantine_name}" ]] ||
        fail 'quarantined evidence changed after anchored cleanup'
      rmdir -- "${quarantine_name}" || fail 'could not remove empty quarantined evidence directory'
      local_removed='yes'
    done
    [[ "${local_removed}" == 'yes' ]] && printf 'removed\n' || printf 'absent\n'
  )
}

if [[ "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]]; then
  snapshot_state="$(privileged_snapshot_state "${mode}")" || fail 'privileged snapshot inspection or cleanup failed'
  process_residue="$(process_state "${artifact}")"
  [[ "${process_residue}" != 'present' ]] || fail 'cookiespike process residue is present'
  bpf_residue="$(canarysting_bpf_state)" || fail 'could not complete program/map/link BPF inventory'
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
  if [[ "${mode}" == 'inspect' ]]; then
    require_no_quarantined_evidence "${evidence_quarantine}"
    if [[ -e "${evidence}" || -L "${evidence}" ]]; then
      validate_evidence yes
      evidence_state='validated'
      awk -F '\t' '
        $1 == "artifact_sha256" || $1 == "privileged_artifact" || $1 == "privileged_snapshot_cleanup" ||
        $1 == "privileged_snapshot_residue" || $1 == "attach_scope" || $1 == "attach_scope_observed" || $1 == "traffic" ||
        $1 == "enforcement" || $1 == "missing_attribution" || $1 == "tuple_semantics" ||
        $1 == "tuple_direction" || $1 == "flow_identity" || $1 == "close_delete" ||
        $1 == "cgroup_cleanup" || $1 == "process_residue" || $1 == "bpf_residue" ||
        $1 == "cgroup_residue" || $1 == "stdout_capture" || $1 == "stderr_capture" ||
        $1 == "root_attachments_before_sha256" || $1 == "root_attachments_after_sha256" ||
        $1 == "bpf_inventory_before_sha256" || $1 == "bpf_inventory_after_sha256" ||
        $1 == "status" || $1 == "diagnostic" {
          print "evidence_" $1 "=" $2
        }
      ' "${evidence}/result.tsv"
    else
      fail "evidence is absent: ${evidence}"
    fi
  else
    # Rename into a fixed run-scoped quarantine before the second validation,
    # then delete only relative to anchored physical working directories. This
    # keeps oversized/malformed recovery exact without following ancestor or
    # leaf substitutions between validation and deletion.
    evidence_state="$(cleanup_evidence "${root}" "cookiespike-${run_id}")" ||
      fail 'anchored evidence cleanup failed'
  fi

  if [[ "${mode}" == 'cleanup' ]] && sudo -n test -d "${cgroup_parent}"; then
    sudo -n rmdir "${cgroup_parent}" 2>/dev/null || true
  fi
  printf 'mode=%s\nrun_id=%s\nevidence=%s\ncgroup=%s\nprivileged_snapshot=%s\nprocess_residue=%s\nbpf_residue=%s\n' \
    "${mode}" "${run_id}" "${evidence_state}" "${cgroup_state}" "${snapshot_state}" "${process_residue}" "${bpf_residue}"
  [[ "${mode}" == 'cleanup' ]] && printf 'postcondition=m1c-candidates-absent\n'
  exit 0
fi

[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] ||
  fail "remote root must be an owned, writable, non-symlink directory: ${root}"
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] ||
  fail "artifact stage must be an owned, non-symlink directory: ${stage}"
require_fresh_evidence_state "${evidence}" "${evidence_quarantine}"
[[ "$(privileged_snapshot_state inspect)" == 'absent' ]] || fail 'privileged snapshot preflight did not prove absence'
sudo -n test ! -e "${cgroup}" || fail "run-owned cgroup already exists: ${cgroup}"
[[ "$(process_state "${artifact}")" == 'none' ]] || fail 'cookiespike process is already running'
preexisting_bpf_state="$(canarysting_bpf_state)" || fail 'could not complete pre-proof program/map/link BPF inventory'
[[ "${preexisting_bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state exists before proof'
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
bpf_inventory_before="$(bpf_object_ids)" || fail 'could not snapshot pre-proof program/map/link BPF IDs'
bpf_inventory_before_sha256="$(printf '%s\n' "${bpf_inventory_before}" | sha256sum | awk '{print $1}')"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
stdout_capture_state_file="${evidence}/.stdout.capture"
stderr_capture_state_file="${evidence}/.stderr.capture"

set +e
exec 3> >(bounded_capture "${stdout_log}" "${stdout_capture_state_file}")
stdout_capture_pid=$!
exec 4> >(bounded_capture "${stderr_log}" "${stderr_capture_state_file}")
stderr_capture_pid=$!
sudo -n bash -s -- "${artifact}" "${cgroup_parent}" "${cgroup}" "${run_id}" \
  "${snapshot_root}" "${snapshot_dir}" "${snapshot_artifact}" "${expected_size}" "${expected_sha256}" >&3 2>&4 <<'ROOT'
set -euo pipefail

artifact="$1"
cgroup_parent="$2"
cgroup="$3"
run_id="$4"
snapshot_root="$5"
snapshot_dir="$6"
snapshot_artifact="$7"
expected_size="$8"
expected_sha256="$9"
snapshot_tmp="${snapshot_artifact}.tmp"
snapshot_parent="${snapshot_root%/*}"
readonly artifact cgroup_parent cgroup run_id snapshot_root snapshot_parent snapshot_dir snapshot_artifact snapshot_tmp expected_size expected_sha256

proof_fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" == '0' ]] || { echo 'FAIL: privileged proof helper is not root' >&2; exit 1; }
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || { echo 'FAIL: cgroup v2 unified hierarchy is required' >&2; exit 1; }
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || proof_fail 'invalid privileged proof run ID'
[[ "${cgroup}" == "${cgroup_parent}/"* && "${cgroup}" != "${cgroup_parent}/" ]] || {
  echo 'FAIL: unsafe proof cgroup path' >&2
  exit 1
}
[[ "${snapshot_root}" == '/var/tmp/canarysting-privileged' ]] || proof_fail 'unsafe privileged snapshot root'
[[ "${snapshot_parent}" == '/var/tmp' && -d "${snapshot_parent}" && ! -L "${snapshot_parent}" &&
  -O "${snapshot_parent}" && "$(stat -c %a "${snapshot_parent}")" == '1777' ]] ||
  proof_fail 'privileged snapshot parent must be the root-owned mode-1777 /var/tmp directory'
[[ "${snapshot_dir}" == "${snapshot_root}/cookiespike-${run_id}" ]] || proof_fail 'unsafe privileged snapshot directory'
[[ "${snapshot_artifact}" == "${snapshot_dir}/cookiespike" ]] || proof_fail 'unsafe privileged snapshot artifact path'
[[ "${expected_size}" =~ ^[0-9]+$ ]] || proof_fail 'invalid privileged snapshot size'
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || proof_fail 'invalid privileged snapshot checksum'

prepare_verified_snapshot() {
  local source_path="$1"
  local source_fd source_fd_path actual_size actual_sha256

  [[ ! -e "${snapshot_tmp}" && ! -L "${snapshot_tmp}" && ! -e "${snapshot_artifact}" && ! -L "${snapshot_artifact}" ]] ||
    proof_fail 'privileged snapshot artifact already exists'
  exec 5<"${source_path}" || proof_fail 'could not open staged artifact for privileged snapshot'
  source_fd=5
  source_fd_path="/proc/self/fd/${source_fd}"
  [[ "$(stat -Lc %F "${source_fd_path}")" == 'regular file' ]] || {
    exec 5<&-
    proof_fail 'staged artifact descriptor is not a regular file'
  }
  if ! timeout --signal=TERM --kill-after=1s 5s \
    cp --no-preserve=mode,ownership,timestamps -- "${source_fd_path}" "${snapshot_tmp}"; then
    exec 5<&-
    proof_fail 'could not create bounded privileged artifact snapshot'
  fi
  exec 5<&-

  [[ -f "${snapshot_tmp}" && ! -L "${snapshot_tmp}" && -O "${snapshot_tmp}" ]] ||
    proof_fail 'privileged artifact snapshot is not a root-owned regular file'
  chmod 0500 "${snapshot_tmp}" || proof_fail 'could not lock privileged artifact snapshot mode'
  actual_size="$(stat -c %s "${snapshot_tmp}")"
  actual_sha256="$(sha256sum "${snapshot_tmp}" | awk '{ print $1 }')"
  [[ "${actual_size}" == "${expected_size}" ]] || proof_fail 'privileged artifact snapshot size mismatch'
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || proof_fail 'privileged artifact snapshot checksum mismatch'
  mv -T -- "${snapshot_tmp}" "${snapshot_artifact}" || proof_fail 'could not publish privileged artifact snapshot'
  [[ -f "${snapshot_artifact}" && ! -L "${snapshot_artifact}" && -O "${snapshot_artifact}" ]] ||
    proof_fail 'published privileged artifact snapshot is unsafe'
  [[ "$(stat -c %a "${snapshot_artifact}")" == '500' ]] || proof_fail 'published privileged artifact snapshot mode must be 0500'
  [[ "$(stat -c %s "${snapshot_artifact}")" == "${expected_size}" ]] || proof_fail 'published privileged artifact snapshot size changed'
  [[ "$(sha256sum "${snapshot_artifact}" | awk '{ print $1 }')" == "${expected_sha256}" ]] ||
    proof_fail 'published privileged artifact snapshot checksum changed'
}

snapshot_process_state() {
  local path="$1"
  local resolved proc_exe
  [[ -e "${path}" ]] || {
    printf 'none'
    return
  }
  resolved="$(readlink -f "${path}")"
  for proc_exe in /proc/[0-9]*/exe; do
    if [[ "$(readlink -f "${proc_exe}" 2>/dev/null || true)" == "${resolved}" ]]; then
      printf 'present'
      return
    fi
  done
  printf 'none'
}

cleanup_runtime() {
  local exit_code=$?
  local snapshot_cleanup_failed=0
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

  if [[ -e "${snapshot_dir}" || -L "${snapshot_dir}" ]]; then
    if [[ ! -d "${snapshot_root}" || -L "${snapshot_root}" || ! -O "${snapshot_root}" ||
      ! -d "${snapshot_dir}" || -L "${snapshot_dir}" || ! -O "${snapshot_dir}" ||
      "$(stat -c %a "${snapshot_root}")" != '700' || "$(stat -c %a "${snapshot_dir}")" != '700' ]]; then
      echo 'FAIL: privileged snapshot path changed before cleanup' >&2
      exit_code=1
      snapshot_cleanup_failed=1
    elif [[ "$(snapshot_process_state "${snapshot_artifact}")" == 'present' ]]; then
      echo 'FAIL: privileged snapshot process remains after proof' >&2
      exit_code=1
      snapshot_cleanup_failed=1
    else
      for path in "${snapshot_dir}"/* "${snapshot_dir}"/.[!.]* "${snapshot_dir}"/..?*; do
        [[ -e "${path}" || -L "${path}" ]] || continue
        if [[ "${path}" != "${snapshot_artifact}" && "${path}" != "${snapshot_tmp}" ]] ||
          [[ ! -f "${path}" || -L "${path}" || ! -O "${path}" ]]; then
          echo 'FAIL: privileged snapshot contains an unsafe cleanup entry' >&2
          exit_code=1
          snapshot_cleanup_failed=1
          continue
        fi
        if ! rm -- "${path}"; then
          exit_code=1
          snapshot_cleanup_failed=1
        fi
      done
      if [[ "${snapshot_cleanup_failed}" -eq 0 ]]; then
        if ! rmdir -- "${snapshot_dir}"; then
          exit_code=1
          snapshot_cleanup_failed=1
        fi
        rmdir -- "${snapshot_root}" 2>/dev/null || true
      fi
    fi
  fi
  if [[ ! -e "${snapshot_dir}" && ! -L "${snapshot_dir}" ]]; then
    echo 'PROOF privileged_snapshot_cleanup=PASS residue=none'
  else
    echo 'FAIL: privileged artifact snapshot remains after cleanup' >&2
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup_runtime EXIT INT TERM

if [[ -e "${snapshot_root}" || -L "${snapshot_root}" ]]; then
  [[ -d "${snapshot_root}" && ! -L "${snapshot_root}" && -O "${snapshot_root}" ]] ||
    proof_fail 'privileged snapshot root is unsafe'
  [[ "$(stat -c %a "${snapshot_root}")" == '700' ]] || proof_fail 'privileged snapshot root mode must be 0700'
else
  umask 077
  mkdir -m 0700 "${snapshot_root}" || proof_fail 'could not create privileged snapshot root'
fi
[[ ! -e "${snapshot_dir}" && ! -L "${snapshot_dir}" ]] || proof_fail 'privileged snapshot directory already exists'
mkdir -m 0700 "${snapshot_dir}" || proof_fail 'could not create privileged snapshot directory'
prepare_verified_snapshot "${artifact}"
printf 'PROOF privileged_artifact=PASS sha256=%s source=verified-root-snapshot\n' "${expected_sha256}"

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
    "${snapshot_artifact}" -cgroup "${cgroup}" -proof
) &
proof_pid=$!

attach_scope_observed='FAIL'
for _ in {1..100}; do
  if child_attachments="$(bpftool cgroup show "${cgroup}" 2>&1)" &&
    grep -q 'canary_sockops' <<<"${child_attachments}"; then
    if parent_attachments="$(bpftool cgroup show "${cgroup_parent}" 2>&1)" &&
      ! grep -q 'canary_sockops' <<<"${parent_attachments}" &&
      root_attachments="$(bpftool cgroup show /sys/fs/cgroup 2>&1)" &&
      ! grep -q 'canary_sockops' <<<"${root_attachments}"; then
      attach_scope_observed='PASS'
    fi
    break
  fi
  kill -0 "${proof_pid}" 2>/dev/null || break
  sleep 0.01
done

set +e
wait "${proof_pid}"
proof_exit=$?
set -e
printf 'PROOF attach_scope=%s child=%s parent=absent root=absent\n' "${attach_scope_observed}" "${cgroup}"
exit "${proof_exit}"
ROOT
exit_code=$?
exec 3>&-
exec 4>&-
stdout_capture_exit=0
stderr_capture_exit=0
wait "${stdout_capture_pid}" || stdout_capture_exit=$?
wait "${stderr_capture_pid}" || stderr_capture_exit=$?
set -e

stdout_capture='missing'
stderr_capture='missing'
[[ ! -f "${stdout_capture_state_file}" ]] || IFS= read -r stdout_capture <"${stdout_capture_state_file}"
[[ ! -f "${stderr_capture_state_file}" ]] || IFS= read -r stderr_capture <"${stderr_capture_state_file}"
rm -f -- "${stdout_capture_state_file}" "${stderr_capture_state_file}"

finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stdout_bytes="$(stat -c %s "${stdout_log}")"
stderr_bytes="$(stat -c %s "${stderr_log}")"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
root_attachments_after="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
process_residue="$(process_state "${artifact}")"
bpf_residue='inventory-error'
canarysting_bpf_state_after='inventory-error'
if canarysting_bpf_state_after="$(canarysting_bpf_state)"; then
  bpf_residue="${canarysting_bpf_state_after}"
fi
bpf_inventory_after=''
bpf_inventory_after_sha256='unavailable'
bpf_inventory_after_state='inventory-error'
if bpf_inventory_after="$(bpf_object_ids)"; then
  bpf_inventory_after_sha256="$(printf '%s\n' "${bpf_inventory_after}" | sha256sum | awk '{print $1}')"
  bpf_inventory_after_state='complete'
fi
cgroup_residue='none'
sudo -n test ! -e "${cgroup}" || cgroup_residue='present'
privileged_snapshot_residue='present-or-invalid'
if snapshot_post_state="$(privileged_snapshot_state inspect)" && [[ "${snapshot_post_state}" == 'absent' ]]; then
  privileged_snapshot_residue='none'
fi

missing_proof='FAIL'
attach_proof='FAIL'
tuple_proof='FAIL'
identity_proof='FAIL'
close_proof='FAIL'
cgroup_cleanup='FAIL'
privileged_artifact='FAIL'
privileged_snapshot_cleanup='FAIL'
grep -Fx 'PROOF missing_attribution=PASS result=MISS attribution=refused' "${stdout_log}" >/dev/null && missing_proof='PASS'
grep -Fx "PROOF attach_scope=PASS child=${cgroup} parent=absent root=absent" "${stdout_log}" >/dev/null && attach_proof='PASS'
grep -F 'PROOF tuple_direction=PASS semantics=remote-to-local tuple=' "${stdout_log}" >/dev/null && tuple_proof='PASS'
grep -F 'PROOF flow_identity=PASS socket_cookie=' "${stdout_log}" >/dev/null && identity_proof='PASS'
grep -Fx 'PROOF close_delete=PASS result=MISS' "${stdout_log}" >/dev/null && close_proof='PASS'
grep -Fx 'PROOF cgroup_cleanup=PASS residue=none' "${stdout_log}" >/dev/null && cgroup_cleanup='PASS'
grep -Fx "PROOF privileged_artifact=PASS sha256=${expected_sha256} source=verified-root-snapshot" "${stdout_log}" >/dev/null && privileged_artifact='PASS'
grep -Fx 'PROOF privileged_snapshot_cleanup=PASS residue=none' "${stdout_log}" >/dev/null && privileged_snapshot_cleanup='PASS'

status='PASS'
diagnostic='all-proof-criteria-passed'
if [[ "${exit_code}" -ne 0 ]]; then
  status='FAIL'
  diagnostic="proof-exit-${exit_code}"
elif [[ "${stdout_capture_exit}" -ne 0 || "${stderr_capture_exit}" -ne 0 ||
  "${stdout_capture}" == 'error' || "${stderr_capture}" == 'error' ||
  "${stdout_capture}" == 'missing' || "${stderr_capture}" == 'missing' ]]; then
  status='FAIL'
  diagnostic='proof-log-capture-failed'
elif [[ "${stdout_capture}" == 'truncated' || "${stderr_capture}" == 'truncated' ||
  "${stdout_bytes}" -gt 1048576 || "${stderr_bytes}" -gt 1048576 ]]; then
  status='FAIL'
  diagnostic='proof-log-exceeded-1048576-bytes'
elif [[ "${missing_proof}/${attach_proof}/${tuple_proof}/${identity_proof}/${close_proof}/${cgroup_cleanup}/${privileged_artifact}/${privileged_snapshot_cleanup}" != 'PASS/PASS/PASS/PASS/PASS/PASS/PASS/PASS' ]]; then
  status='FAIL'
  diagnostic='required-proof-marker-missing'
elif ! grep -Fx 'RESULT PASS' "${stdout_log}" >/dev/null; then
  status='FAIL'
  diagnostic='explicit-result-pass-missing'
elif grep -F 'RESULT FAIL' "${stdout_log}" >/dev/null; then
  status='FAIL'
  diagnostic='explicit-result-fail-observed'
elif [[ "${process_residue}" != 'none' || "${bpf_residue}" != 'none' || "${cgroup_residue}" != 'none' ||
  "${privileged_snapshot_residue}" != 'none' ]]; then
  status='FAIL'
  diagnostic='run-owned-runtime-residue-present'
elif [[ "${bpf_inventory_after_state}" != 'complete' || "${bpf_inventory_before}" != "${bpf_inventory_after}" ]]; then
  status='FAIL'
  diagnostic='program-map-link-inventory-changed'
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
  printf 'privileged_artifact\t%s\n' "${privileged_artifact}"
  printf 'privileged_snapshot_cleanup\t%s\n' "${privileged_snapshot_cleanup}"
  printf 'privileged_snapshot_residue\t%s\n' "${privileged_snapshot_residue}"
  printf 'attach_scope\trun-owned-child-cgroup\n'
  printf 'attach_scope_observed\t%s\n' "${attach_proof}"
  printf 'traffic\tloopback-only\n'
  printf 'enforcement\tnone\n'
  printf 'tuple_semantics\tremote-to-local\n'
  printf 'timeout_seconds\t15\n'
  printf 'exit_code\t%s\n' "${exit_code}"
  printf 'stdout_capture\t%s\n' "${stdout_capture}"
  printf 'stderr_capture\t%s\n' "${stderr_capture}"
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
  printf 'bpf_inventory_before_sha256\t%s\n' "${bpf_inventory_before_sha256}"
  printf 'bpf_inventory_after_sha256\t%s\n' "${bpf_inventory_after_sha256}"
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
printf 'privileged_artifact=%s\n' "${privileged_artifact}"
printf 'privileged_snapshot_cleanup=%s\n' "${privileged_snapshot_cleanup}"
printf 'privileged_snapshot_residue=%s\n' "${privileged_snapshot_residue}"
printf 'attach_scope=run-owned-child-cgroup\n'
printf 'attach_scope_observed=%s\n' "${attach_proof}"
printf 'enforcement=none\n'
printf 'missing_attribution=%s\n' "${missing_proof}"
printf 'tuple_direction=%s\n' "${tuple_proof}"
printf 'flow_identity=%s\n' "${identity_proof}"
printf 'close_delete=%s\n' "${close_proof}"
printf 'cgroup_cleanup=%s\n' "${cgroup_cleanup}"
printf 'process_residue=%s\n' "${process_residue}"
printf 'bpf_residue=%s\n' "${bpf_residue}"
printf 'cgroup_residue=%s\n' "${cgroup_residue}"
printf 'bpf_inventory_unchanged=%s\n' "$([[ "${bpf_inventory_after_state}" == 'complete' && "${bpf_inventory_before}" == "${bpf_inventory_after}" ]] && printf PASS || printf FAIL)"
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
