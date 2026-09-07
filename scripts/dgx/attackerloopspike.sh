#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly expected_model='qwen3-coder:30b-a3b-q8_0'
readonly expected_model_id='7b438a19895a'
readonly -a ssh_options=(-o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
check_script="${script_dir}/check.sh"
cleanup_script="${script_dir}/cleanup.sh"
preflight_script="${script_dir}/preflight-proof.sh"
attackercheck_script="${script_dir}/attackercheck.sh"
readonly copy_script check_script cleanup_script preflight_script attackercheck_script

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/attackerloopspike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2C.4 unprivileged Ollama/Qwen proof. The checksum-built binary
uses only the fixed loopback Ollama API and one process-lifetime loopback HTTP
fixture. The model sees opaque zero-argument handles; the executor retains all
target, operation, policy, fixture, credential, and budget authority. The proof
loads then explicitly unloads only the pinned model and owns only its verified
run stage plus three bounded 24-hour evidence files.
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
release_model_lock() {
  local lock_status=0
  trap - EXIT INT TERM
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
acquire_model_lock() {
  local remote_model_lock_program remote_model_lock_command model_lock_report='' attempt
  remote_model_lock_program=$'set -euo pipefail\n'
  remote_model_lock_program+=$'[[ "$(hostname)" == "spark-5343" && "$(uname -m)" == "aarch64" ]] || exit 70\n'
  remote_model_lock_program+=$'for tool in cat flock hostname id stat uname; do command -v "${tool}" >/dev/null 2>&1 || exit 71; done\n'
  remote_model_lock_program+=$'lock_root="/run/user/$(id -u)"\n'
  remote_model_lock_program+=$'[[ -d "${lock_root}" && ! -L "${lock_root}" && -O "${lock_root}" && -w "${lock_root}" ]] || exit 72\n'
  remote_model_lock_program+=$'lock_file="${lock_root}/canarysting-ollama-qwen.lock"\n'
  remote_model_lock_program+=$'[[ ! -L "${lock_file}" ]] || exit 73\n'
  remote_model_lock_program+=$'exec 9>>"${lock_file}"\n'
  remote_model_lock_program+=$'[[ -f "${lock_file}" && ! -L "${lock_file}" && -O "${lock_file}" ]] || exit 74\n'
  remote_model_lock_program+=$'chmod 0600 "${lock_file}"\n'
  remote_model_lock_program+=$'if ! flock -n 9; then printf "model_lock=busy\\n"; exit 75; fi\n'
  remote_model_lock_program+=$'printf "model_lock=acquired\\n"\n'
  remote_model_lock_program+=$'cat >/dev/null\n'
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

for required in chmod grep mkfifo mktemp rm rmdir sleep ssh "${copy_script}" "${check_script}" "${cleanup_script}" "${preflight_script}" "${attackercheck_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
  else
    command -v "${required}" >/dev/null 2>&1 || fail "required tool is missing: ${required}"
  fi
done

acquire_model_lock
assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before inspection'
pre_model_report="$("${attackercheck_script}")"
cleanup_stage_state=''
if [[ "${mode}" == 'cleanup' ]]; then
  validate_model_identity_report "${pre_model_report}" || fail 'cleanup Ollama identity, binding, or inventory check failed'
  cleanup_inventory="$("${cleanup_script}" --run-id "${run_id}" --inspect)"
  cleanup_stage_state="$(cleanup_stage_from_inventory "${cleanup_inventory}")" ||
    fail 'cleanup inspection did not return one exact root/stage state'
  if [[ "${cleanup_stage_state}" == 'stage=absent' ]]; then
    validate_model_report "${pre_model_report}" || fail 'run stage is absent while a model remains loaded'
  fi
else
  validate_model_report "${pre_model_report}" || fail 'pre-run Ollama identity, binding, inventory, or unloaded-state check failed'
  printf 'pre_model_check=PASS\n'
  if [[ -n "${CANARYSTING_DGX_PREFLIGHT_PROOF:-}" ]]; then
    "${preflight_script}" --verify --run-id "${run_id}" --proof-file "${CANARYSTING_DGX_PREFLIGHT_PROOF}"
  else
    CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
  fi
  "${copy_script}" --verify-only --run-id "${run_id}"
fi

assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before execution'
remote_status=0
if [[ "${mode}" != 'cleanup' || "${cleanup_stage_state}" == 'stage=validated' ]]; then
set +e
ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" "${expected_model}" "${expected_model_id}" <<'REMOTE'
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
run_id="$1"
mode="$2"
expected_model="$3"
expected_model_id="$4"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
[[ "${expected_model}" == 'qwen3-coder:30b-a3b-q8_0' && "${expected_model_id}" == '7b438a19895a' ]] || fail 'unexpected model identity'
[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || fail 'unexpected proof host'
for tool in awk chmod date env find hostname mkdir mv sed sha256sum sort stat timeout tr uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
artifact_relative='test/attackerloopspike'
artifact="${stage}/${artifact_relative}"
scenario_id='m2c4-ollama-bounded-loop'
readonly root stage evidence artifact_relative artifact scenario_id

[[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'run stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'manifest is unsafe'
artifact_metadata="$(awk -F '\t' -v wanted="${artifact_relative}" '
  $1 == "artifact" && $4 == wanted { count++; size=$5; digest=$6 }
  END { if (count != 1) exit 1; print size "\t" digest }
' "${stage}/manifest.tsv")" || fail 'manifest must contain exactly one bounded-loop proof artifact'
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ && "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] || fail 'proof artifact is unsafe'
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'proof artifact size changed'
[[ "$(sha256sum "${artifact}" | awk '{print $1}')" == "${expected_sha256}" ]] || fail 'proof artifact checksum changed'

model_cleanup='PENDING'
cleanup_model() {
  if timeout --signal=TERM --kill-after=2s 25s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -cleanup-model >/dev/null 2>&1; then
    model_cleanup='PASS'
  else
    model_cleanup='FAIL'
  fi
}
cleanup_after_signal() {
  trap - EXIT INT TERM
  cleanup_model
  exit 130
}
if [[ "${mode}" == 'run' ]]; then
  trap cleanup_model EXIT
  trap cleanup_after_signal INT TERM
fi
if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_model
  [[ "${model_cleanup}" == 'PASS' ]] || fail 'fixed-model cleanup failed'
  printf 'PASS: fixed model unloaded before run-stage cleanup\n'
  exit 0
fi

manifest_value() {
  awk -F '\t' -v wanted="$1" '
    $1 == "metadata" && $2 == wanted { count++; value=$3 }
    END { if (count != 1) exit 1; print value }
  ' "${stage}/manifest.tsv"
}
source_revision="$(manifest_value source_revision)" || fail 'manifest source revision is missing or duplicated'
source_state="$(manifest_value source_state)" || fail 'manifest source state is missing or duplicated'
source_tree_sha256="$(manifest_value source_tree_sha256)" || fail 'manifest source-tree checksum is missing or duplicated'
[[ "${source_revision}" =~ ^[0-9a-f]{40}$ && "${source_state}" =~ ^(clean|dirty)$ && "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'manifest source lineage is malformed'
readonly source_revision source_state source_tree_sha256

result_value() {
  awk -F '\t' -v wanted="$2" '$1 == wanted { count++; value=$2 } END { if (count != 1) exit 1; print value }' "$1"
}
validate_fixed_output() {
  awk '
    NR == 1 { good=($0 == "PROOF model_identity=PASS provider=ollama model_id=7b438a19895a planner=bounded-qwen-planner-v1") }
    NR == 2 { good=good && ($0 == "PROOF loopback=PASS ollama_endpoint=fixed fixture=process-lifetime ambient_proxy=false") }
    NR == 3 { good=good && ($0 == "PROOF opacity=PASS zero_argument_handles=true target_policy_budget_model_visible=false") }
    NR == 4 { good=good && ($0 == "PROOF audit=PASS proposals=1 intents=1 actions=1 output=content-digest-only") }
    NR == 5 { good=good && ($0 == "PROOF execution=PASS reviewed_action=true response_bounded=true") }
    NR == 6 { good=good && ($0 == "PROOF budgets=PASS turns=1 tokens=true duration=true cancellation=external") }
    NR == 7 { good=good && ($0 == "PROOF stop=PASS reason=scenario_complete deterministic=true") }
    NR == 8 { good=good && ($0 == "PROOF cleanup=PASS fixture_listener_closed=true persistent_state=false") }
    NR > 8 { good=0 }
    END { exit !(good && NR == 8) }
  ' "$1"
}
validate_result_schema() {
  awk -F '\t' -v run="${run_id}" -v revision="${source_revision}" -v state="${source_state}" -v tree="${source_tree_sha256}" -v artifact="${expected_sha256}" '
    BEGIN { good=1 }
    NR == 1 { good=($0 == "key\tvalue"); next }
    { if (NF != 2 || seen[$1]++) { good=0; next } }
    NR == 2 { good=good && ($1 == "format_version" && $2 == "1"); next }
    NR == 3 { good=good && ($1 == "run_id" && $2 == run); next }
    NR == 4 { good=good && ($1 == "scenario_id" && $2 == "m2c4-ollama-bounded-loop"); next }
    NR == 5 { good=good && ($1 == "profile" && $2 == "attacker-bounded-ollama"); next }
    NR == 6 { good=good && ($1 == "model" && $2 == "qwen3-coder:30b-a3b-q8_0"); next }
    NR == 7 { good=good && ($1 == "model_id" && $2 == "7b438a19895a"); next }
    NR == 8 { good=good && ($1 == "planner_version" && $2 == "bounded-qwen-planner-v1"); next }
    NR == 9 { good=good && ($1 == "source_revision" && $2 == revision); next }
    NR == 10 { good=good && ($1 == "source_state" && $2 == state); next }
    NR == 11 { good=good && ($1 == "source_tree_sha256" && $2 == tree); next }
    NR == 12 { good=good && ($1 == "artifact_sha256" && $2 == artifact); next }
    NR == 13 { good=good && ($1 == "proof_line_count" && $2 == "8"); next }
    NR == 14 { good=good && ($1 == "raw_model_output_emitted" && $2 == "false"); next }
    NR == 15 { good=good && ($1 == "model_execution" && $2 == "true"); next }
    NR == 16 { good=good && ($1 == "model_cleanup" && $2 == "PASS"); next }
    NR == 17 { good=good && ($1 == "privilege" && $2 == "unprivileged"); next }
    NR == 18 { good=good && ($1 == "started_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 19 { good=good && ($1 == "finished_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 20 { good=good && ($1 == "expires_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 21 { good=good && ($1 == "stdout_sha256" && $2 ~ /^[0-9a-f]{64}$/); next }
    NR == 22 { good=good && ($1 == "stderr_sha256" && $2 ~ /^[0-9a-f]{64}$/); next }
    NR == 23 { good=good && ($1 == "exit_code" && $2 == "0"); next }
    NR == 24 { good=good && ($1 == "status" && $2 == "PASS"); next }
    { good=0 }
    END { exit !(good && NR == 24) }
  ' "$1"
}
validate_timestamps() {
  local started finished expires now
  started="$(date -u -d "$(result_value "$1" started_utc)" +%s)" || return 1
  finished="$(date -u -d "$(result_value "$1" finished_utc)" +%s)" || return 1
  expires="$(date -u -d "$(result_value "$1" expires_utc)" +%s)" || return 1
  now="$(date -u +%s)" || return 1
  ((started <= finished && finished - started <= 300 && expires - finished == 86400 && now < expires))
}
validate_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" && "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence is unsafe'
  [[ "$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | sort)" == $'f:result.tsv\nf:stderr.log\nf:stdout.log' ]] || fail 'published evidence inventory is not exact'
  for file in result.tsv stderr.log stdout.log; do
    [[ -f "${evidence}/${file}" && ! -L "${evidence}/${file}" && -O "${evidence}/${file}" ]] || fail "unsafe evidence file: ${file}"
    [[ "$(stat -c %a "${evidence}/${file}")" == '600' && "$(stat -c %s "${evidence}/${file}")" -le 1048576 ]] || fail "evidence file mode or size is unsafe: ${file}"
  done
  validate_result_schema "${evidence}/result.tsv" || fail 'result schema or lineage is invalid'
  validate_timestamps "${evidence}/result.tsv" || fail 'result timestamps or expiry are invalid'
  validate_fixed_output "${evidence}/stdout.log" || fail 'fixed proof output is invalid'
  [[ ! -s "${evidence}/stderr.log" ]] || fail 'proof emitted unexpected stderr'
  [[ "$(sha256sum "${evidence}/stdout.log" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" stdout_sha256)" ]] || fail 'stdout checksum mismatch'
  [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" stderr_sha256)" ]] || fail 'stderr checksum mismatch'
}
if [[ "${mode}" == 'inspect' ]]; then
  validate_evidence
  printf 'PASS: bounded Ollama planner evidence inspection passed\n'
  exit 0
fi

[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'published evidence already exists'
umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
started_epoch="$(date -u +%s)"
started_utc="$(date -u -d "@${started_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
set +e
(
  cd "${evidence}"
  ulimit -c 0
  ulimit -f 1024
  exec timeout --signal=TERM --kill-after=10s 250s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -selfcheck
) >"${stdout_log}" 2>"${stderr_log}"
exit_code=$?
set -e
cleanup_model
trap - EXIT INT TERM
finished_epoch="$(date -u +%s)"
finished_utc="$(date -u -d "@${finished_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
expires_utc="$(date -u -d "@$((finished_epoch + 86400))" +%Y-%m-%dT%H:%M:%SZ)"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
proof_line_count="$(wc -l <"${stdout_log}" | tr -d '[:space:]')"
status='FAIL'
if [[ "${exit_code}" -eq 0 && "${model_cleanup}" == 'PASS' && ! -s "${stderr_log}" ]] && validate_fixed_output "${stdout_log}"; then status='PASS'; fi
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\nrun_id\t%s\nscenario_id\t%s\nprofile\tattacker-bounded-ollama\n' "${run_id}" "${scenario_id}"
  printf 'model\t%s\nmodel_id\t%s\nplanner_version\tbounded-qwen-planner-v1\n' "${expected_model}" "${expected_model_id}"
  printf 'source_revision\t%s\nsource_state\t%s\nsource_tree_sha256\t%s\nartifact_sha256\t%s\n' "${source_revision}" "${source_state}" "${source_tree_sha256}" "${expected_sha256}"
  printf 'proof_line_count\t%s\nraw_model_output_emitted\tfalse\nmodel_execution\ttrue\nmodel_cleanup\t%s\nprivilege\tunprivileged\n' "${proof_line_count}" "${model_cleanup}"
  printf 'started_utc\t%s\nfinished_utc\t%s\nexpires_utc\t%s\nstdout_sha256\t%s\nstderr_sha256\t%s\nexit_code\t%s\nstatus\t%s\n' \
    "${started_utc}" "${finished_utc}" "${expires_utc}" "${stdout_sha256}" "${stderr_sha256}" "${exit_code}" "${status}"
} >"${evidence}/.result.tsv.tmp"
mv "${evidence}/.result.tsv.tmp" "${evidence}/result.tsv"
chmod 0600 "${evidence}/stdout.log" "${evidence}/stderr.log" "${evidence}/result.tsv"
if [[ "${status}" != 'PASS' ]]; then
  sed -n '1,5p' "${stderr_log}" >&2
  fail "proof artifact or model cleanup failed with exit ${exit_code}"
fi
validate_evidence
printf 'PASS: DGX bounded Ollama planner proof completed\n'
printf 'evidence=%s\n' "${evidence}"
REMOTE
remote_status=$?
set -e
fi

assert_model_lock_held || fail 'DGX host-global Ollama model lock was lost before post-run inspection'
post_model_report="$("${attackercheck_script}")"
validate_model_report "${post_model_report}" || fail 'post-run Ollama identity, binding, inventory, or unloaded-state check failed'
printf 'post_model_check=PASS\n'
[[ "${remote_status}" -eq 0 ]] || fail "remote proof failed with exit ${remote_status}"
release_model_lock || fail 'DGX host-global Ollama model lock session failed'
if [[ "${mode}" == 'cleanup' ]]; then
  "${cleanup_script}" --run-id "${run_id}"
  exit 0
fi
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_attacker_loop_check=PASS\n'
