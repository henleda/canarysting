#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly expected_model='qwen3-coder:30b-a3b-q8_0'
readonly expected_model_id='7b438a19895a'
readonly minimum_available_memory_kib=41943040
readonly -a ssh_options=(-o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
check_script="${script_dir}/check.sh"
cleanup_script="${script_dir}/cleanup.sh"
preflight_script="${script_dir}/preflight-proof.sh"
attackercheck_script="${script_dir}/attackercheck.sh"
remote_proof_script="${script_dir}/attackerloopspike_remote.sh"
remote_finalize_script="${script_dir}/attackerloopspike_finalize_remote.sh"
lock_supervisor_script="${script_dir}/attackerloopspike_lock_remote.sh"
readonly copy_script check_script cleanup_script preflight_script attackercheck_script remote_proof_script remote_finalize_script lock_supervisor_script

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/attackerloopspike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2C.4 unprivileged Ollama/Qwen proof. The checksum-built binary
uses only the fixed loopback Ollama API and one process-lifetime loopback HTTP
fixture. The model sees opaque zero-argument handles; the executor retains all
target, operation, policy, fixture, credential, and budget authority. The proof
loads then explicitly unloads only the pinned model and owns only its verified
run stage, a transient run-owned model-load marker, and three bounded 24-hour
evidence files.
USAGE
}

fail() { printf 'attackerloopspike: %s\n' "$*" >&2; exit 1; }
validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}
validate_model_identity_report() {
  local report="$1"
  grep -Fqx 'ollama_listener_probe_status=ok' <<<"${report}" || return 1
  grep -Fqx 'ollama_binding=loopback_only' <<<"${report}" || return 1
  grep -Fqx 'ollama_api_probe_status=ok' <<<"${report}" || return 1
  grep -Fqx 'ollama_inventory_status=ok' <<<"${report}" || return 1
  grep -Fqx "expected_model=${expected_model}" <<<"${report}" || return 1
  grep -Fqx 'expected_model_present=true' <<<"${report}" || return 1
  grep -Fqx "expected_model_id=${expected_model_id}" <<<"${report}" || return 1
  grep -Fqx 'safety_status=safe' <<<"${report}" || return 1
  grep -Fqx 'm2c1_inspection=PASS' <<<"${report}" || return 1
}
validate_model_report() {
  local report="$1"
  validate_model_identity_report "${report}" || return 1
  grep -Fqx 'loaded_model_count=0' <<<"${report}" || return 1
  grep -Fqx 'ntp_synchronized=true' <<<"${report}" || return 1
  grep -Fqx 'gpu_probe_status=ok' <<<"${report}" || return 1
  awk -F= '$1 == "gpu_count" { count++; value=$2 } END { exit !(count == 1 && value ~ /^[1-9][0-9]*$/) }' <<<"${report}" || return 1
  awk -F= -v minimum="${minimum_available_memory_kib}" '$1 == "memory_available_kib" { count++; value=$2 } END { exit !(count == 1 && value ~ /^[0-9]+$/ && value + 0 >= minimum) }' <<<"${report}" || return 1
}
validate_model_unloaded_report() {
  local report="$1"
  validate_model_identity_report "${report}" || return 1
  grep -Fqx 'loaded_model_count=0' <<<"${report}" || return 1
}
cleanup_stage_from_inventory() {
  local inventory="$1" root_count=0 stage_count=0 stage_state='' line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    case "${line}" in
      root=absent) root_count=$((root_count + 1)) ;;
      stage=validated|stage=absent)
        stage_count=$((stage_count + 1))
        stage_state="${line}"
        ;;
      stage=*) return 1 ;;
    esac
  done <<<"${inventory}"
  if ((root_count == 1 && stage_count == 0)); then
    printf 'stage=absent\n'
    return 0
  fi
  if ((root_count == 0 && stage_count == 1)); then
    printf '%s\n' "${stage_state}"
    return 0
  fi
  return 1
}

model_lock_pid=''
model_lock_directory=''
model_lock_fifo=''
model_lock_report_file=''
model_lock_hold_open='false'
remote_proof_active='false'
model_lock_lost_during_execution='false'
terminate_remote_proof() {
  local attempt lock_status=0
  if [[ "${remote_proof_active}" == 'true' ]]; then
    if [[ "${model_lock_hold_open}" == 'true' ]]; then
      exec 9>&-
      model_lock_hold_open='false'
    fi
    if [[ -n "${model_lock_pid}" ]] && kill -0 "${model_lock_pid}" 2>/dev/null; then
      kill -TERM "${model_lock_pid}" 2>/dev/null || true
      for ((attempt = 0; attempt < 50; attempt++)); do
        kill -0 "${model_lock_pid}" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "${model_lock_pid}" 2>/dev/null; then
        kill -KILL "${model_lock_pid}" 2>/dev/null || true
      fi
    fi
    if [[ -n "${model_lock_pid}" ]]; then
      wait "${model_lock_pid}" || lock_status=$?
      model_lock_pid=''
    fi
    remote_proof_active='false'
  fi
  return "${lock_status}"
}
release_model_lock() {
  local lock_status=0
  trap - EXIT INT TERM
  terminate_remote_proof >/dev/null 2>&1 || true
  if [[ "${model_lock_hold_open}" == 'true' ]]; then
    exec 9>&-
    model_lock_hold_open='false'
  fi
  if [[ -n "${model_lock_pid}" ]]; then
    wait "${model_lock_pid}" || lock_status=$?
    model_lock_pid=''
  fi
  if [[ -n "${model_lock_fifo}" || -n "${model_lock_report_file}" ]]; then
    rm -f -- "${model_lock_fifo}" "${model_lock_report_file}"
    model_lock_fifo=''
    model_lock_report_file=''
  fi
  if [[ -n "${model_lock_directory}" ]]; then
    rmdir "${model_lock_directory}"
    model_lock_directory=''
  fi
  return "${lock_status}"
}
assert_model_lock_held() {
  [[ -n "${model_lock_pid}" ]] && kill -0 "${model_lock_pid}" 2>/dev/null
}
wait_for_remote_proof() {
  local proof_status='' status_count attempt
  [[ "${remote_proof_active}" == 'true' && -n "${model_lock_report_file}" ]] || return 1
  for ((attempt = 0; attempt < 36000; attempt++)); do
    status_count="$(grep -Ec '^remote_proof_status=[0-9]+$' "${model_lock_report_file}" || true)"
    if [[ "${status_count}" -eq 1 ]]; then
      proof_status="$(awk -F= '$1 == "remote_proof_status" { print $2 }' "${model_lock_report_file}")"
      break
    fi
    if [[ "${status_count}" -gt 1 ]] || ! assert_model_lock_held; then
      model_lock_lost_during_execution='true'
      remote_proof_active='false'
      return 1
    fi
    sleep 0.1
  done
  if [[ ! "${proof_status}" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
    model_lock_lost_during_execution='true'
    return 1
  fi
  sed -e '1{/^model_lock=acquired$/d;}' -e '/^remote_proof_status=[0-9][0-9]*$/d' "${model_lock_report_file}"
  remote_proof_active='false'
  return "${proof_status}"
}
start_locked_remote_proof() {
  local remote_proof_program program_bytes
  [[ -f "${remote_proof_script}" && ! -L "${remote_proof_script}" && -O "${remote_proof_script}" ]] ||
    fail 'remote proof program is missing or unsafe'
  remote_proof_program="$(<"${remote_proof_script}")"
  LC_ALL=C program_bytes="${#remote_proof_program}"
  [[ "${program_bytes}" -ge 1 && "${program_bytes}" -le 32768 ]] || fail 'remote proof program has unsafe size'
  assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before proof start'
  printf 'execute\t%s\t%s\t%s\t%s\tnone\t%s\n' \
    "${run_id}" "${mode}" "${expected_model}" "${expected_model_id}" "${program_bytes}" >&9 || return 1
  printf '%s' "${remote_proof_program}" >&9 || return 1
  remote_proof_active='true'
}
wait_for_remote_finalization() {
  local expected_marker_state="$1" finalize_status='' status_count attempt finalization_report marker_line
  [[ "${expected_marker_state}" == 'owned' || "${expected_marker_state}" == 'absent' ||
    "${expected_marker_state}" == 'either' ]] || return 1
  [[ "${remote_proof_active}" == 'true' && -n "${model_lock_report_file}" ]] || return 1
  for ((attempt = 0; attempt < 36000; attempt++)); do
    status_count="$(grep -Ec '^remote_finalize_status=[0-9]+$' "${model_lock_report_file}" || true)"
    if [[ "${status_count}" -eq 1 ]]; then
      finalize_status="$(awk -F= '$1 == "remote_finalize_status" { print $2 }' "${model_lock_report_file}")"
      break
    fi
    if [[ "${status_count}" -gt 1 ]] || ! assert_model_lock_held; then
      model_lock_lost_during_execution='true'
      remote_proof_active='false'
      return 1
    fi
    sleep 0.1
  done
  if [[ ! "${finalize_status}" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
    model_lock_lost_during_execution='true'
    return 1
  fi
  if grep -Eq '^remote_proof_status=[0-9]+$' "${model_lock_report_file}"; then
    finalization_report="$(awk '
      /^remote_proof_status=[0-9]+$/ { after_proof=1; next }
      /^remote_finalize_status=[0-9]+$/ { exit }
      after_proof { print }
    ' "${model_lock_report_file}")"
  else
    finalization_report="$(awk '
      /^model_lock=acquired$/ { after_lock=1; next }
      /^remote_finalize_status=[0-9]+$/ { exit }
      after_lock { print }
    ' "${model_lock_report_file}")"
  fi
  marker_line="$(sed -n '2p' <<<"${finalization_report}")"
  if [[ "${finalization_report}" != $'model_finalize=PASS\nmodel_load_marker=retired' &&
    "${finalization_report}" != $'model_finalize=PASS\nmodel_load_marker=absent' ]]; then
    finalize_status=77
  elif [[ "${expected_marker_state}" == 'owned' && "${marker_line}" != 'model_load_marker=retired' ]]; then
    finalize_status=77
  elif [[ "${expected_marker_state}" == 'absent' && "${marker_line}" != 'model_load_marker=absent' ]]; then
    finalize_status=77
  fi
  printf '%s\n' "${finalization_report}"
  remote_proof_active='false'
  return "${finalize_status}"
}
start_locked_remote_finalization() {
  local expected_marker_state="$1" remote_finalize_program program_bytes
  [[ "${expected_marker_state}" == 'owned' || "${expected_marker_state}" == 'absent' ||
    "${expected_marker_state}" == 'either' ]] || return 1
  [[ -f "${remote_finalize_script}" && ! -L "${remote_finalize_script}" && -O "${remote_finalize_script}" ]] ||
    fail 'remote finalization program is missing or unsafe'
  remote_finalize_program="$(<"${remote_finalize_script}")"
  LC_ALL=C program_bytes="${#remote_finalize_program}"
  [[ "${program_bytes}" -ge 1 && "${program_bytes}" -le 32768 ]] || fail 'remote finalization program has unsafe size'
  assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before finalization'
  printf 'finalize\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${run_id}" "${mode}" "${expected_model}" "${expected_model_id}" "${expected_marker_state}" "${program_bytes}" >&9 ||
    return 1
  printf '%s' "${remote_finalize_program}" >&9 || return 1
  remote_proof_active='true'
}
acquire_model_lock() {
  local remote_model_lock_program remote_model_lock_command model_lock_report='' attempt
  [[ -f "${lock_supervisor_script}" && ! -L "${lock_supervisor_script}" && -O "${lock_supervisor_script}" ]] ||
    fail 'remote lock supervisor is missing or unsafe'
  remote_model_lock_program="$(<"${lock_supervisor_script}")"
  [[ -n "${remote_model_lock_program}" && "${#remote_model_lock_program}" -le 16384 ]] ||
    fail 'remote lock supervisor has unsafe size'
  printf -v remote_model_lock_command 'bash -c %q' "${remote_model_lock_program}"
  model_lock_directory="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-ollama-lock.XXXXXX")"
  chmod 0700 "${model_lock_directory}"
  model_lock_fifo="${model_lock_directory}/hold"
  model_lock_report_file="${model_lock_directory}/report"
  mkfifo -m 0600 "${model_lock_fifo}"
  : >"${model_lock_report_file}"
  chmod 0600 "${model_lock_report_file}"
  exec 9<>"${model_lock_fifo}"
  model_lock_hold_open='true'
  (
    exec 9>&-
    ssh "${ssh_options[@]}" "${dgx_host}" "${remote_model_lock_command}" <"${model_lock_fifo}" >"${model_lock_report_file}"
  ) &
  model_lock_pid=$!
  for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -s "${model_lock_report_file}" ]]; then
      IFS= read -r model_lock_report <"${model_lock_report_file}"
      break
    fi
    kill -0 "${model_lock_pid}" 2>/dev/null || break
    sleep 0.1
  done
  if [[ -z "${model_lock_report}" ]]; then
    release_model_lock >/dev/null 2>&1 || true
    fail 'could not acquire the DGX host-global Ollama model lock'
  fi
  if [[ "${model_lock_report}" != 'model_lock=acquired' ]] || ! assert_model_lock_held; then
    release_model_lock >/dev/null 2>&1 || true
    fail 'the DGX host-global Ollama model lock is busy or unsafe'
  fi
  trap 'release_model_lock >/dev/null 2>&1 || true' EXIT
  trap 'exit 130' INT TERM
}

run_id=''
mode='run'
while (($#)); do
  case "$1" in
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run|--inspect|--cleanup)
      [[ "${mode}" == 'run' ]] || fail 'choose at most one mode'
      mode="${1#--}"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
validate_run_id "${run_id}"
readonly run_id mode

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: bounded Ollama planner proof contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/attackerloopspike\n' "${dgx_host}" "${run_id}"
  printf 'model=%s\nmodel_id=%s\nendpoint=http-loopback-fixed\n' "${expected_model}" "${expected_model_id}"
  printf 'mutation=run-owned-stage,evidence,transient-loopback-socket,transient-model-load\n'
  printf 'privilege=unprivileged\nmodel_lock=dgx-host-global-exclusive\nraw_model_output_emitted=false\ncleanup=exact-run-and-model-unload\n'
  exit 0
fi

for required in awk chmod grep kill mkfifo mktemp rm rmdir sed sleep ssh "${copy_script}" "${check_script}" "${cleanup_script}" "${preflight_script}" "${attackercheck_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
  else
    command -v "${required}" >/dev/null 2>&1 || fail "required tool is missing: ${required}"
  fi
done

run_preflight() {
  if [[ -n "${CANARYSTING_DGX_PREFLIGHT_PROOF:-}" ]]; then
    "${preflight_script}" --verify --run-id "${run_id}" --proof-file "${CANARYSTING_DGX_PREFLIGHT_PROOF}"
  else
    CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
  fi
}

run_preflight
acquire_model_lock
assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before inspection'
pre_model_report="$("${attackercheck_script}")"
cleanup_stage_state=''
cleanup_marker_state='absent'
if [[ "${mode}" == 'cleanup' ]]; then
  validate_model_identity_report "${pre_model_report}" || fail 'cleanup Ollama identity, binding, or inventory check failed'
  cleanup_inventory="$("${cleanup_script}" --run-id "${run_id}" --inspect)"
  cleanup_stage_state="$(cleanup_stage_from_inventory "${cleanup_inventory}")" ||
    fail 'cleanup inspection did not return one exact root/stage state'
  if grep -Fqx 'evidence=model-owned' <<<"${cleanup_inventory}"; then
    cleanup_marker_state='owned'
  fi
  if [[ "${cleanup_stage_state}" == 'stage=absent' ]]; then
    validate_model_unloaded_report "${pre_model_report}" || fail 'run stage is absent while a model remains loaded'
  fi
else
  validate_model_report "${pre_model_report}" || fail 'pre-run Ollama identity, binding, inventory, or unloaded-state check failed'
  printf 'pre_model_check=PASS\n'
  "${copy_script}" --verify-only --run-id "${run_id}"
fi

assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before execution'
remote_status=0
if [[ "${mode}" != 'cleanup' || "${cleanup_stage_state}" == 'stage=validated' ]]; then
  set +e
  start_locked_remote_proof
  start_status=$?
  if [[ "${start_status}" -eq 0 ]]; then
    wait_for_remote_proof
    remote_status=$?
  else
    remote_status="${start_status}"
  fi
  set -e
fi

[[ "${model_lock_lost_during_execution}" == 'false' ]] || fail 'DGX host-global Ollama model lock was lost during execution'
assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before finalization'
marker_retirement_expectation='absent'
if [[ "${mode}" == 'run' ]]; then
  marker_retirement_expectation='owned'
  if [[ "${remote_status}" -ne 0 ]]; then marker_retirement_expectation='either'; fi
elif [[ "${mode}" == 'cleanup' ]]; then
  marker_retirement_expectation="${cleanup_marker_state}"
fi
set +e
start_locked_remote_finalization "${marker_retirement_expectation}"
finalize_start_status=$?
finalize_status="${finalize_start_status}"
if [[ "${finalize_start_status}" -eq 0 ]]; then
  wait_for_remote_finalization "${marker_retirement_expectation}"
  finalize_status=$?
fi
set -e
[[ "${model_lock_lost_during_execution}" == 'false' ]] || fail 'DGX host-global Ollama model lock was lost during finalization'
[[ "${finalize_status}" -eq 0 ]] || fail 'lock-scoped model postcheck or marker retirement failed'
printf 'post_model_check=PASS\n'
[[ "${remote_status}" -eq 0 ]] || fail "remote proof failed with exit ${remote_status}"
release_model_lock || fail 'DGX host-global Ollama model lock session failed'
if [[ "${mode}" == 'cleanup' ]]; then
  "${cleanup_script}" --run-id "${run_id}"
  exit 0
fi
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_attacker_loop_check=PASS\n'
