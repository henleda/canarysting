#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/attackerloopspike.sh"
pr_script="${script_dir}/pr.sh"
remote_proof_script="${script_dir}/attackerloopspike_remote.sh"
remote_finalize_script="${script_dir}/attackerloopspike_finalize_remote.sh"
lock_supervisor_script="${script_dir}/attackerloopspike_lock_remote.sh"
readonly proof_script pr_script remote_proof_script remote_finalize_script lock_supervisor_script
readonly -a proof_sources=("${proof_script}" "${remote_proof_script}" "${remote_finalize_script}" "${lock_supervisor_script}")

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then fail "${name} unexpectedly succeeded"; fi
  [[ "${output}" == *"${expected}"* ]] || fail "${name} did not report ${expected}: ${output}"
}

[[ -x "${proof_script}" ]] || fail "proof script is missing or not executable: ${proof_script}"
for script in "${proof_sources[@]}"; do
  [[ -f "${script}" && ! -L "${script}" && -O "${script}" ]] || fail "proof source is missing or unsafe: ${script}"
  bash -n "${script}" || fail "proof source has invalid Bash syntax: ${script}"
done
output="$(${proof_script} --run-id m2c4-contract --dry-run)"
[[ "${output}" == *'bounded Ollama planner proof contract passed; DGX was not accessed'* ]] || fail 'dry run did not remain local'
[[ "${output}" == *'artifact=test/attackerloopspike'* ]] || fail 'dry run omitted its fixed artifact'
[[ "${output}" == *'model=qwen3-coder:30b-a3b-q8_0'* && "${output}" == *'model_id=7b438a19895a'* ]] || fail 'dry run omitted pinned model provenance'
[[ "${output}" == *'endpoint=http-loopback-fixed'* && "${output}" == *'privilege=unprivileged'* ]] || fail 'dry run omitted network or privilege boundary'
[[ "${output}" == *'model_lock=dgx-host-global-exclusive'* ]] || fail 'dry run omitted shared-model serialization boundary'
[[ "${output}" == *'raw_model_output_emitted=false'* && "${output}" == *'cleanup=exact-run-and-model-unload'* ]] || fail 'dry run omitted minimization or cleanup boundary'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2c4-modes --dry-run --inspect
expect_failure arbitrary_prompt 'unknown argument: --prompt' "${proof_script}" --run-id m2c4-prompt --prompt ignore --dry-run
expect_failure arbitrary_model 'unknown argument: --model' "${proof_script}" --run-id m2c4-model --model other --dry-run
expect_failure arbitrary_endpoint 'unknown argument: --endpoint' "${proof_script}" --run-id m2c4-endpoint --endpoint http://example.invalid --dry-run
expect_failure arbitrary_command 'unknown argument: --command' "${proof_script}" --run-id m2c4-command --command id --dry-run

for marker in \
  'expected_model='"'"'qwen3-coder:30b-a3b-q8_0'"'" \
  'expected_model_id='"'"'7b438a19895a'"'" \
  'loaded_model_count=0' \
  'ntp_synchronized=true' \
  'gpu_probe_status=ok' \
  'minimum_available_memory_kib=41943040' \
  'zero_argument_handles=true target_policy_budget_model_visible=false' \
  'output=content-digest-only' \
  'reason=scenario_complete deterministic=true' \
  'env -i LANG=C PATH=/usr/bin:/bin TZ=UTC' \
  'timeout --foreground --signal=TERM' \
  '"${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -cleanup-model' \
  'trap cleanup_after_signal HUP INT TERM' \
  'if ! flock -n 9; then' \
  'wait_for_remote_proof' \
  'assert_model_lock_held || fail' \
  'expires - finished == 86400'; do
  grep -F "${marker}" "${proof_sources[@]}" >/dev/null || fail "proof safety marker missing: ${marker}"
done
if grep -E '(^|[[:space:]])(sudo|kubectl|bpftool|systemctl|iptables|nft|docker|curl)([[:space:]]|$)' \
  "${proof_script}" "${remote_proof_script}" "${lock_supervisor_script}" >/dev/null; then
  fail 'unprivileged planner proof contains a privileged, control-plane, or alternate HTTP command'
fi
grep -F 'timeout --foreground --signal=TERM --kill-after=2s 8s sudo -n ss -H -lntp' "${remote_finalize_script}" >/dev/null ||
  fail 'lock-scoped finalizer is missing its exact read-only listener inspection'
[[ "$(grep -Ec '(^|[[:space:]])sudo([[:space:]]|$)' "${remote_finalize_script}")" == '2' ]] ||
  fail 'lock-scoped finalizer contains unreviewed sudo authority'
if grep -E '(^|[[:space:]])(kubectl|bpftool|iptables|nft|docker|curl)([[:space:]]|$)' "${remote_finalize_script}" >/dev/null; then
  fail 'lock-scoped finalizer contains control-plane, datapath, or alternate HTTP authority'
fi

report_definition="$(awk '/^validate_model_report\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
identity_report_definition="$(awk '/^validate_model_identity_report\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
unloaded_report_definition="$(awk '/^validate_model_unloaded_report\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
marker_state_definition="$(awk '/^model_load_marker_state\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_proof_script}")"
cleanup_model_definition="$(awk '/^cleanup_model\(\) \{/ { capture=1 } /^cleanup_after_signal\(\) \{/ { exit } capture { print }' "${remote_proof_script}")"
schema_definition="$(awk '/^validate_result_schema\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_proof_script}")"
value_definition="$(awk '/^result_value\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_proof_script}")"
timestamp_definition="$(awk '/^validate_timestamps\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_proof_script}")"
cleanup_stage_definition="$(awk '/^cleanup_stage_from_inventory\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
terminate_proof_definition="$(awk '/^terminate_remote_proof\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
release_lock_definition="$(awk '/^release_model_lock\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
ssh_transport_definition="$(awk '/^ssh\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${pr_script}")"
assert_lock_definition="$(awk '/^assert_model_lock_held\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
wait_proof_definition="$(awk '/^wait_for_remote_proof\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
wait_finalize_definition="$(awk '/^wait_for_remote_finalization\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
supervisor_terminate_definition="$(awk '/^terminate_proof_group\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${lock_supervisor_script}")"
supervise_program_definition="$(awk '/^supervise_program\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${lock_supervisor_script}")"
finalize_marker_state_definition="$(awk '/^model_load_marker_state\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_finalize_script}")"
[[ -n "${identity_report_definition}" && -n "${report_definition}" && -n "${unloaded_report_definition}" && -n "${marker_state_definition}" && -n "${cleanup_model_definition}" && -n "${schema_definition}" && -n "${value_definition}" && -n "${timestamp_definition}" && -n "${cleanup_stage_definition}" && -n "${terminate_proof_definition}" && -n "${release_lock_definition}" && -n "${ssh_transport_definition}" && -n "${assert_lock_definition}" && -n "${wait_proof_definition}" && -n "${wait_finalize_definition}" && -n "${supervisor_terminate_definition}" && -n "${supervise_program_definition}" && -n "${finalize_marker_state_definition}" ]] || fail 'proof validators are not independently testable'
grep -Fq 'CANARYSTING_DGX_SSH_EXEC_CHILD=1' "${proof_script}" ||
  fail 'model-lock client does not request directly owned SSH execution'
grep -Fq 'exec "${dgx_ssh_command[@]}"' "${pr_script}" ||
  fail 'coordinator SSH wrapper cannot replace the asynchronous client process'
grep -Fq "trap 'release_model_lock || true' EXIT" "${proof_script}" ||
  fail 'production EXIT cleanup suppresses model-lock cleanup diagnostics'
if grep -Fq 'release_model_lock >/dev/null 2>&1' "${proof_script}"; then
  fail 'production model-lock cleanup still suppresses retained-path diagnostics'
fi

valid_report=$'memory_available_kib=83886080\ngpu_count=1\ngpu_probe_status=ok\nntp_synchronized=true\nollama_listener_probe_status=ok\nollama_binding=loopback_only\nollama_api_probe_status=ok\nollama_inventory_status=ok\nexpected_model=qwen3-coder:30b-a3b-q8_0\nexpected_model_present=true\nexpected_model_id=7b438a19895a\nloaded_model_count=0\nsafety_status=safe\nm2c1_inspection=PASS'
report_program="${identity_report_definition}"$'\n'"${unloaded_report_definition}"$'\n'"${report_definition}"$'\n''expected_model=qwen3-coder:30b-a3b-q8_0 expected_model_id=7b438a19895a minimum_available_memory_kib=41943040'
bash -c "${report_program}"$'\n''validate_model_report "$1"' -- "${valid_report}" || fail 'valid model report was rejected'
bad_report="${valid_report/loaded_model_count=0/loaded_model_count=1}"
if bash -c "${report_program}"$'\n''validate_model_report "$1"' -- "${bad_report}"; then
  fail 'model report accepted an already-loaded model'
fi
bash -c "${identity_report_definition}"$'\n''expected_model=qwen3-coder:30b-a3b-q8_0 expected_model_id=7b438a19895a validate_model_identity_report "$1"' -- "${bad_report}" || fail 'cleanup identity validator rejected an otherwise safe loaded-model report'
if bash -c "${report_program}"$'\n''validate_model_unloaded_report "$1"' -- "${bad_report}"; then
  fail 'cleanup unloaded-state validator accepted a loaded model'
fi
for unsafe_report in \
  "${valid_report/ntp_synchronized=true/ntp_synchronized=false}" \
  "${valid_report/gpu_probe_status=ok/gpu_probe_status=unavailable}" \
  "${valid_report/gpu_count=1/gpu_count=0}" \
  "${valid_report/memory_available_kib=83886080/memory_available_kib=1024}"; do
  if bash -c "${report_program}"$'\n''validate_model_report "$1"' -- "${unsafe_report}"; then
    fail 'model report accepted unsafe clock, GPU, or memory readiness'
  fi
done

for inventory in \
  $'mode=inspect\nrun_id=m2c4-clean\nroot=absent\npostcondition=all-candidates-absent' \
  $'mode=inspect\nrun_id=m2c4-clean\nincoming=absent\nstage=absent\nevidence=absent\nmutation=none' \
  $'mode=inspect\nrun_id=m2c4-clean\nincoming=absent\nstage=validated\nevidence=validated\nmutation=none' \
  $'mode=inspect\nrun_id=m2c4-clean\nincoming=absent\nstage=validated\nevidence=model-owned\nmutation=none'; do
  cleanup_state="$(bash -c "${cleanup_stage_definition}"$'\n''cleanup_stage_from_inventory "$1"' -- "${inventory}")" || fail 'valid cleanup inventory was rejected'
  if [[ "${inventory}" == *'stage=validated'* ]]; then
    [[ "${cleanup_state}" == 'stage=validated' ]] || fail 'validated stage state was not preserved'
  else
    [[ "${cleanup_state}" == 'stage=absent' ]] || fail 'absent root/stage was not treated as clean'
  fi
done
for inventory in $'root=absent\nstage=absent' $'stage=absent\nstage=validated' $'stage=unsafe'; do
  if bash -c "${cleanup_stage_definition}"$'\n''cleanup_stage_from_inventory "$1"' -- "${inventory}" >/dev/null; then
    fail 'ambiguous or unsafe cleanup inventory was accepted'
  fi
done

cleanup_inspect_line="$(grep -nF 'cleanup_inventory="$("${cleanup_script}" --run-id "${run_id}" --inspect)"' "${proof_script}" | cut -d: -f1)"
remote_cleanup_line="$(grep -nF '[[ "${model_cleanup}" == '\''PASS'\'' || "${model_cleanup}" == '\''NOT_REQUIRED'\'' ]] || fail '\''fixed-model cleanup failed'\''' "${remote_proof_script}" | cut -d: -f1)"
finalize_start_line="$(grep -nFx 'start_locked_remote_finalization "${marker_retirement_expectation}"' "${proof_script}" | cut -d: -f1)"
finalize_wait_line="$(grep -nFx '  wait_for_remote_finalization "${marker_retirement_expectation}"' "${proof_script}" | cut -d: -f1)"
generic_cleanup_line="$(grep -nF '"${cleanup_script}" --run-id "${run_id}"' "${proof_script}" | tail -n1 | cut -d: -f1)"
finalizer_postcheck_line="$(grep -nF '[[ "${snapshot_after}" == "${snapshot_before}" ]]' "${remote_finalize_script}" | cut -d: -f1)"
finalizer_retirement_line="$(grep -nF 'rm -f -- "${model_load_marker}"' "${remote_finalize_script}" | cut -d: -f1)"
[[ "${cleanup_inspect_line}" =~ ^[0-9]+$ && "${remote_cleanup_line}" =~ ^[0-9]+$ && "${finalize_start_line}" =~ ^[0-9]+$ && "${finalize_wait_line}" =~ ^[0-9]+$ && "${generic_cleanup_line}" =~ ^[0-9]+$ && "${finalizer_postcheck_line}" =~ ^[0-9]+$ && "${finalizer_retirement_line}" =~ ^[0-9]+$ ]] || fail 'cleanup recovery ordering markers are missing'
((cleanup_inspect_line < finalize_start_line && finalize_start_line < finalize_wait_line && finalize_wait_line < generic_cleanup_line)) || fail 'cleanup can remove the stage before lock-scoped finalization'
((finalizer_postcheck_line < finalizer_retirement_line)) || fail 'finalizer can retire recovery authority before its exact unloaded-state postcheck'
if grep -F 'rm -f -- "${model_load_marker}"' <<<"${cleanup_model_definition}" >/dev/null; then
  fail 'Ollama unload acknowledgement can retire the recovery marker before independent verification'
fi
if grep -F 'rm -f -- "${model_load_marker}"' "${proof_script}" "${remote_proof_script}" >/dev/null; then
  fail 'marker retirement exists outside the lock-scoped finalizer'
fi

lock_acquire_line="$(grep -nFx 'acquire_model_lock' "${proof_script}" | cut -d: -f1)"
preflight_line="$(grep -nFx 'run_preflight' "${proof_script}" | cut -d: -f1)"
pre_model_line="$(grep -nF 'pre_model_report="$("${attackercheck_script}")"' "${proof_script}" | cut -d: -f1)"
proof_start_line="$(grep -nFx '  start_locked_remote_proof' "${proof_script}" | cut -d: -f1)"
lock_release_line="$(grep -nF 'release_model_lock || fail' "${proof_script}" | cut -d: -f1)"
[[ "${preflight_line}" =~ ^[0-9]+$ && "${lock_acquire_line}" =~ ^[0-9]+$ && "${pre_model_line}" =~ ^[0-9]+$ && "${proof_start_line}" =~ ^[0-9]+$ && "${finalize_start_line}" =~ ^[0-9]+$ && "${finalize_wait_line}" =~ ^[0-9]+$ && "${lock_release_line}" =~ ^[0-9]+$ ]] || fail 'host-global model lock ordering markers are missing'
((preflight_line < lock_acquire_line && lock_acquire_line < pre_model_line && pre_model_line < proof_start_line && proof_start_line < finalize_start_line && finalize_start_line < finalize_wait_line && finalize_wait_line < lock_release_line)) || fail 'preflight and host-global model lock ordering is unsafe'

supervisor_flock_line="$(grep -nF 'if ! flock -n 9; then' "${lock_supervisor_script}" | cut -d: -f1)"
supervisor_start_line="$(grep -nF 'setsid bash -c "${proof_program}"' "${lock_supervisor_script}" | head -n1 | cut -d: -f1)"
supervisor_wait_line="$(grep -nF 'wait "${proof_pid}"' "${lock_supervisor_script}" | tail -n1 | cut -d: -f1)"
supervisor_status_line="$(grep -nF "printf 'remote_%s_status=%s\\n'" "${lock_supervisor_script}" | cut -d: -f1)"
supervisor_hold_line="$(grep -nFx 'cat >/dev/null' "${lock_supervisor_script}" | cut -d: -f1)"
[[ "${supervisor_flock_line}" =~ ^[0-9]+$ && "${supervisor_start_line}" =~ ^[0-9]+$ && "${supervisor_wait_line}" =~ ^[0-9]+$ && "${supervisor_status_line}" =~ ^[0-9]+$ && "${supervisor_hold_line}" =~ ^[0-9]+$ ]] || fail 'remote lock-supervisor ordering markers are missing'
((supervisor_flock_line < supervisor_start_line && supervisor_start_line < supervisor_wait_line && supervisor_wait_line < supervisor_status_line && supervisor_status_line < supervisor_hold_line)) || fail 'remote proof lifetime is not bounded by its flock-owning supervisor'
grep -Fq "status_name='proof'" "${lock_supervisor_script}" || fail 'execute completion is not mapped to the proof protocol status'
grep -Fq "if [[ \"\${action}\" == 'finalize' ]]; then status_name='finalize'; fi" "${lock_supervisor_script}" ||
  fail 'finalization completion is not mapped to the finalization protocol status'
grep -F 'kill -TERM -- "-${proof_pid}"' "${lock_supervisor_script}" >/dev/null || fail 'remote supervisor cannot terminate the complete proof process group'
if grep -E 'remote_(proof|finalize)_status=' "${remote_proof_script}" "${remote_finalize_script}" >/dev/null; then
  fail 'a streamed remote program can forge the lock-supervisor completion record'
fi
timeout_foreground_count="$(grep -Ec '(^|[[:space:]])timeout --foreground --signal=TERM' "${remote_proof_script}")"
[[ "${timeout_foreground_count}" == '2' ]] || fail 'every bounded proof command must remain in the supervisor process group'
if grep -E '(^|[[:space:]])timeout --signal=' "${remote_proof_script}" >/dev/null; then
  fail 'bounded proof command can escape into a timeout-owned process group'
fi
if grep -E '(^|[[:space:]])timeout --signal=' "${remote_finalize_script}" >/dev/null; then
  fail 'lock-scoped finalization command can escape into a timeout-owned process group'
fi

monitor_definitions="${assert_lock_definition}"$'\n'"${wait_proof_definition}"$'\n'"${wait_finalize_definition}"
monitor_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-attacker-loop-monitor.XXXXXX")"
printf 'model_lock=acquired\nproof-output\nremote_proof_status=0\n' >"${monitor_root}/report"
bash -c "${monitor_definitions}"$'\n''
model_lock_lost_during_execution=false
model_lock_report_file="$1"
remote_proof_active=true
sleep 2 & model_lock_pid=$!
wait_for_remote_proof >"$2"
proof_status=$?
kill -TERM "${model_lock_pid}" 2>/dev/null || true
wait "${model_lock_pid}" 2>/dev/null || true
[[ "${proof_status}" -eq 0 && "${model_lock_lost_during_execution}" == false && "${remote_proof_active}" == false ]]
' -- "${monitor_root}/report" "${monitor_root}/output" || fail 'proof monitor rejected a completion record while the model lock remained held'
[[ "$(<"${monitor_root}/output")" == 'proof-output' ]] || fail 'proof monitor did not preserve bounded proof output'
printf 'model_lock=acquired\n' >"${monitor_root}/report"
bash -c "${monitor_definitions}"$'\n''
model_lock_lost_during_execution=false
model_lock_report_file="$1"
remote_proof_active=true
sleep 0.01 & model_lock_pid=$!
wait "${model_lock_pid}" 2>/dev/null || true
wait_for_remote_proof
proof_status=$?
[[ "${proof_status}" -ne 0 && "${model_lock_lost_during_execution}" == true && "${remote_proof_active}" == false ]]
' -- "${monitor_root}/report" || fail 'proof monitor accepted completion after its lock-owning supervisor exited'

printf 'model_lock=acquired\nproof-output\nremote_proof_status=0\nmodel_finalize=PASS\nmodel_load_marker=retired\nremote_finalize_status=0\n' >"${monitor_root}/report"
bash -c "${monitor_definitions}"$'\n''
model_lock_lost_during_execution=false
model_lock_report_file="$1"
remote_proof_active=true
sleep 2 & model_lock_pid=$!
wait_for_remote_finalization owned >"$2"
finalize_status=$?
kill -TERM "${model_lock_pid}" 2>/dev/null || true
wait "${model_lock_pid}" 2>/dev/null || true
[[ "${finalize_status}" -eq 0 && "${model_lock_lost_during_execution}" == false && "${remote_proof_active}" == false ]]
' -- "${monitor_root}/report" "${monitor_root}/finalize-output" || fail 'finalization monitor rejected a valid lock-scoped completion record'
[[ "$(<"${monitor_root}/finalize-output")" == $'model_finalize=PASS\nmodel_load_marker=retired' ]] ||
  fail 'finalization monitor did not preserve the fixed completion report'

printf 'model_lock=acquired\nmodel_finalize=PASS\nmodel_load_marker=absent\nremote_finalize_status=0\n' >"${monitor_root}/report"
bash -c "${monitor_definitions}"$'\n''
model_lock_lost_during_execution=false
model_lock_report_file="$1"
remote_proof_active=true
sleep 2 & model_lock_pid=$!
wait_for_remote_finalization absent >/dev/null
finalize_status=$?
kill -TERM "${model_lock_pid}" 2>/dev/null || true
wait "${model_lock_pid}" 2>/dev/null || true
[[ "${finalize_status}" -eq 0 && "${model_lock_lost_during_execution}" == false && "${remote_proof_active}" == false ]]
' -- "${monitor_root}/report" || fail 'finalization monitor rejected finalize-first cleanup completion'

lock_client_probe="${monitor_root}/lock-client-probe"
cat >"${lock_client_probe}" <<'PROBE'
#!/usr/bin/env bash
trap 'printf "TERM\n" >"${LOCK_CLIENT_SIGNAL_FILE}"; exit 143' TERM
printf '%s\n' "$$" >"${LOCK_CLIENT_ACTUAL_PID_FILE}"
printf 'ready\n' >"${LOCK_CLIENT_READY_FILE}"
while :; do :; done
PROBE
chmod 0700 "${lock_client_probe}"
for signal_name in INT TERM; do
  lock_client_root="${monitor_root}/lock-client-${signal_name}"
  mkdir -m 0700 "${lock_client_root}"
  mkfifo -m 0600 "${lock_client_root}/hold"
  : >"${lock_client_root}/report"
  chmod 0600 "${lock_client_root}/report"
  lock_client_recorded_pid_file="${monitor_root}/lock-client-${signal_name}-recorded-pid"
  lock_client_actual_pid_file="${monitor_root}/lock-client-${signal_name}-actual-pid"
  lock_client_ready_file="${monitor_root}/lock-client-${signal_name}-ready"
  lock_client_signal_file="${monitor_root}/lock-client-${signal_name}-signal"
  set +e
  LOCK_CLIENT_ACTUAL_PID_FILE="${lock_client_actual_pid_file}" \
  LOCK_CLIENT_READY_FILE="${lock_client_ready_file}" \
  LOCK_CLIENT_SIGNAL_FILE="${lock_client_signal_file}" \
    bash -c "${ssh_transport_definition}"$'\n'"${terminate_proof_definition}"$'\n'"${release_lock_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2/unused-control"
model_lock_directory="$2"
model_lock_fifo="$2/hold"
model_lock_report_file="$2/report"
model_lock_hold_open=true
remote_proof_active=true
exec 9<>"${model_lock_fifo}"
CANARYSTING_DGX_SSH_EXEC_CHILD=1 ssh falcon1 ignored <"${model_lock_fifo}" >"${model_lock_report_file}" 9>&- &
model_lock_pid=$!
printf "%s\n" "${model_lock_pid}" >"$3"
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s "$4" ]] && break
  kill -0 "${model_lock_pid}" 2>/dev/null || break
  sleep 0.01
done
[[ -s "$4" && "$(<"$5")" == "${model_lock_pid}" ]]
trap "release_model_lock || true" EXIT
trap "exit 130" INT TERM
kill -s "$6" "$$"
' -- "${lock_client_probe}" "${lock_client_root}" "${lock_client_recorded_pid_file}" \
      "${lock_client_ready_file}" "${lock_client_actual_pid_file}" "${signal_name}"
  lock_client_status=$?
  set -e
  lock_client_pid="$(<"${lock_client_recorded_pid_file}")"
  [[ "${lock_client_status}" -eq 130 && "${lock_client_pid}" == "$(<"${lock_client_actual_pid_file}")" &&
    "$(<"${lock_client_signal_file}")" == 'TERM' && ! -e "${lock_client_root}" && ! -L "${lock_client_root}" ]] ||
    fail "${signal_name} cancellation did not reap the directly owned SSH lock client and clean local state"
  if kill -0 "${lock_client_pid}" 2>/dev/null; then
    fail "${signal_name} cancellation left the directly owned SSH lock client alive"
  fi
done

release_rm_root="${monitor_root}/release-rm-failure"
release_rm_error="${monitor_root}/release-rm-failure.err"
mkdir -m 0700 "${release_rm_root}"
mkfifo -m 0600 "${release_rm_root}/hold"
: >"${release_rm_root}/report"
release_rm_state="$(bash -c "${terminate_proof_definition}"$'\n'"${release_lock_definition}"$'\n''
rm() { return 88; }
model_lock_directory="$1"
model_lock_fifo="$1/hold"
model_lock_report_file="$1/report"
model_lock_hold_open=false
model_lock_pid=""
remote_proof_active=false
set +e
release_model_lock
release_status=$?
set -e
printf "%s\t%s\t%s\t%s\n" "${release_status}" "${model_lock_directory}" "${model_lock_fifo}" "${model_lock_report_file}"
' -- "${release_rm_root}" 2>"${release_rm_error}")"
[[ "${release_rm_state}" == "88"$'\t'"${release_rm_root}"$'\t'"${release_rm_root}/hold"$'\t'"${release_rm_root}/report" &&
  -p "${release_rm_root}/hold" && -f "${release_rm_root}/report" ]] ||
  fail 'model-lock cleanup masked file-removal failure or discarded retry paths'
[[ "$(<"${release_rm_error}")" == "attackerloopspike: local model-lock cleanup failed with exit 88; retained_directory=${release_rm_root}; retained_fifo=${release_rm_root}/hold; retained_report=${release_rm_root}/report" ]] ||
  fail 'model-lock file cleanup failure did not report every retained exact path'

release_rmdir_root="${monitor_root}/release-rmdir-failure"
release_rmdir_error="${monitor_root}/release-rmdir-failure.err"
mkdir -m 0700 "${release_rmdir_root}"
mkfifo -m 0600 "${release_rmdir_root}/hold"
: >"${release_rmdir_root}/report"
release_rmdir_state="$(bash -c "${terminate_proof_definition}"$'\n'"${release_lock_definition}"$'\n''
rmdir() { return 89; }
model_lock_directory="$1"
model_lock_fifo="$1/hold"
model_lock_report_file="$1/report"
model_lock_hold_open=false
model_lock_pid=""
remote_proof_active=false
set +e
release_model_lock
release_status=$?
set -e
printf "%s\t%s\t%s\t%s\n" "${release_status}" "${model_lock_directory}" "${model_lock_fifo}" "${model_lock_report_file}"
' -- "${release_rmdir_root}" 2>"${release_rmdir_error}")"
[[ "${release_rmdir_state}" == "89"$'\t'"${release_rmdir_root}"$'\t\t' &&
  -d "${release_rmdir_root}" && ! -e "${release_rmdir_root}/hold" && ! -e "${release_rmdir_root}/report" ]] ||
  fail 'model-lock cleanup masked directory-removal failure or discarded its retry path'
[[ "$(<"${release_rmdir_error}")" == "attackerloopspike: local model-lock cleanup failed with exit 89; retained_directory=${release_rmdir_root}; retained_fifo=none; retained_report=none" ]] ||
  fail 'model-lock directory cleanup failure did not report its retained exact path'

for caller_case in 'acquire 1' 'normal 1' 'exit 42' 'INT 130' 'TERM 130'; do
  read -r caller_name expected_status <<<"${caller_case}"
  caller_root="${monitor_root}/caller-${caller_name}"
  caller_error="${monitor_root}/caller-${caller_name}.err"
  mkdir -m 0700 "${caller_root}"
  mkfifo -m 0600 "${caller_root}/hold"
  : >"${caller_root}/report"
  set +e
  bash -c "${terminate_proof_definition}"$'\n'"${release_lock_definition}"$'\n''
rm() { return 88; }
fail() { printf "attackerloopspike: %s\n" "$*" >&2; exit 1; }
model_lock_directory="$1"
model_lock_fifo="$1/hold"
model_lock_report_file="$1/report"
model_lock_hold_open=false
model_lock_pid=""
remote_proof_active=false
case "$2" in
  acquire)
    release_model_lock || true
    fail "could not acquire the DGX host-global Ollama model lock"
    ;;
  normal)
    release_model_lock || fail "DGX host-global Ollama model lock session failed"
    ;;
  exit)
    trap "release_model_lock || true" EXIT
    exit 42
    ;;
  INT|TERM)
    trap "release_model_lock || true" EXIT
    trap "exit 130" INT TERM
    kill -s "$2" "$$"
    ;;
esac
' -- "${caller_root}" "${caller_name}" 2>"${caller_error}"
  caller_status=$?
  set -e
  [[ "${caller_status}" -eq "${expected_status}" && -d "${caller_root}" &&
    -p "${caller_root}/hold" && -f "${caller_root}/report" ]] ||
    fail "production ${caller_name} cleanup caller masked status or discarded retry state"
  grep -Fqx "attackerloopspike: local model-lock cleanup failed with exit 88; retained_directory=${caller_root}; retained_fifo=${caller_root}/hold; retained_report=${caller_root}/report" \
    "${caller_error}" || fail "production ${caller_name} cleanup caller hid its exact retry paths"
done

if command -v flock >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  supervisor_fifo="${monitor_root}/supervisor-input"
  supervisor_lock="${monitor_root}/model.lock"
  supervisor_ready="${monitor_root}/ready"
  supervisor_report="${monitor_root}/supervisor-report"
  mkfifo -m 0600 "${supervisor_fifo}"
  exec 8<>"${supervisor_fifo}"
  supervisor_program=$'set -euo pipefail\nfail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\nproof_pid=""\nsupervised_action=""\n'"${supervisor_terminate_definition}"$'\n'"${supervise_program_definition}"$'\nsupervise_program'
  (
    exec 8>&-
    exec 9>>"${supervisor_lock}"
    flock 9
    printf 'ready\n' >"${supervisor_ready}"
    exec bash -c "${supervisor_program}" <"${supervisor_fifo}" >"${supervisor_report}"
  ) &
  supervisor_pid=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s "${supervisor_ready}" ]] && break
    kill -0 "${supervisor_pid}" 2>/dev/null || break
    sleep 0.01
  done
  [[ -s "${supervisor_ready}" ]] || fail 'local lock-supervisor lifetime fixture did not start'
  lifetime_proof='exec timeout --foreground --signal=TERM --kill-after=1s 2s sleep 1'
  LC_ALL=C lifetime_proof_bytes="${#lifetime_proof}"
  printf 'execute\tm2c4-lifetime\trun\tqwen3-coder:30b-a3b-q8_0\t7b438a19895a\tnone\t%s\n' "${lifetime_proof_bytes}" >&8
  printf '%s' "${lifetime_proof}" >&8
  exec 8>&-
  sleep 0.1
  if flock -n "${supervisor_lock}" -c true; then
    fail 'proof continued after client EOF without its supervisor lock'
  fi
  wait "${supervisor_pid}" || fail 'local lock-supervisor lifetime fixture failed'
  flock -n "${supervisor_lock}" -c true || fail 'lock supervisor did not release after proof termination'
  [[ "$(<"${supervisor_report}")" == 'remote_proof_status=0' ]] || fail 'lock supervisor emitted an invalid completion record'

  finalize_fifo="${monitor_root}/finalize-input"
  finalize_lock="${monitor_root}/finalize.lock"
  finalize_ready="${monitor_root}/finalize-ready"
  finalize_report="${monitor_root}/finalize-report"
  mkfifo -m 0600 "${finalize_fifo}"
  exec 8<>"${finalize_fifo}"
  (
    exec 8>&-
    exec 9>>"${finalize_lock}"
    flock 9
    printf 'ready\n' >"${finalize_ready}"
    exec bash -c "${supervisor_program}" <"${finalize_fifo}" >"${finalize_report}"
  ) &
  finalize_pid=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s "${finalize_ready}" ]] && break
    kill -0 "${finalize_pid}" 2>/dev/null || break
    sleep 0.01
  done
  [[ -s "${finalize_ready}" ]] || fail 'local finalization EOF fixture did not start'
  lifetime_finalize='exec timeout --foreground --signal=TERM --kill-after=1s 2s sleep 1'
  LC_ALL=C lifetime_finalize_bytes="${#lifetime_finalize}"
  printf 'finalize\tm2c4-finalize-eof\trun\tqwen3-coder:30b-a3b-q8_0\t7b438a19895a\tabsent\t%s\n' \
    "${lifetime_finalize_bytes}" >&8
  printf '%s' "${lifetime_finalize}" >&8
  exec 8>&-
  sleep 0.1
  if flock -n "${finalize_lock}" -c true; then
    fail 'finalization continued after client EOF without its supervisor lock'
  fi
  wait "${finalize_pid}" || fail 'local finalization EOF fixture failed'
  flock -n "${finalize_lock}" -c true || fail 'finalization supervisor did not release after its child terminated'
  [[ "$(<"${finalize_report}")" == 'remote_finalize_status=0' ]] || fail 'finalization supervisor emitted an invalid completion record'

  signal_fifo="${monitor_root}/finalize-signal-input"
  signal_lock="${monitor_root}/finalize-signal.lock"
  signal_ready="${monitor_root}/finalize-signal-ready"
  signal_report="${monitor_root}/finalize-signal-report"
  mkfifo -m 0600 "${signal_fifo}"
  exec 8<>"${signal_fifo}"
  (
    exec 8>&-
    exec 9>>"${signal_lock}"
    flock 9
    printf 'ready\n' >"${signal_ready}"
    exec bash -c "${supervisor_program}" <"${signal_fifo}" >"${signal_report}"
  ) &
  signal_pid=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s "${signal_ready}" ]] && break
    kill -0 "${signal_pid}" 2>/dev/null || break
    sleep 0.01
  done
  [[ -s "${signal_ready}" ]] || fail 'local finalization signal fixture did not start'
  signal_finalize='printf "finalizer_started\\n"; trap '\''sleep 1; exit 130'\'' TERM; timeout --foreground --signal=TERM --kill-after=1s 30s sleep 30 & wait'
  LC_ALL=C signal_finalize_bytes="${#signal_finalize}"
  printf 'finalize\tm2c4-finalize-signal\trun\tqwen3-coder:30b-a3b-q8_0\t7b438a19895a\tabsent\t%s\n' \
    "${signal_finalize_bytes}" >&8
  printf '%s' "${signal_finalize}" >&8
  for ((attempt = 0; attempt < 100; attempt++)); do
    grep -Fqx 'finalizer_started' "${signal_report}" && break
    kill -0 "${signal_pid}" 2>/dev/null || break
    sleep 0.01
  done
  grep -Fqx 'finalizer_started' "${signal_report}" || fail 'local finalization signal fixture did not enter its supervised child'
  kill -TERM "${signal_pid}"
  sleep 0.1
  if flock -n "${signal_lock}" -c true; then
    fail 'finalization supervisor released its lock before signal cleanup completed'
  fi
  set +e
  wait "${signal_pid}"
  signal_status=$?
  set -e
  exec 8>&-
  [[ "${signal_status}" -eq 130 ]] || fail 'signalled finalization supervisor did not report cancellation'
  flock -n "${signal_lock}" -c true || fail 'signalled finalization supervisor did not release after child termination'
fi
rm -rf -- "${monitor_root}"

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-attacker-loop-schema.XXXXXX")"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
evidence="${fixture_root}/evidence"
model_load_marker="${evidence}/model-load-owned"
marker_test_program=$'evidence="$1"\nmodel_load_marker="$2"\ntest_marker_mode="${3:-600}"\ntest_marker_size="${4:-32}"\nstat() {\n  local format="$2" path="$3"\n  if [[ "${format}" == "%a" && "${path}" == "${evidence}" ]]; then printf "700\\n"; return 0; fi\n  if [[ "${format}" == "%a" && "${path}" == "${model_load_marker}" ]]; then printf "%s\\n" "${test_marker_mode}"; return 0; fi\n  if [[ "${format}" == "%s" && "${path}" == "${model_load_marker}" ]]; then printf "%s\\n" "${test_marker_size}"; return 0; fi\n  return 1\n}\n'"${marker_state_definition}"$'\nmodel_load_marker_state'
[[ "$(bash -c "${marker_test_program}" -- "${evidence}" "${model_load_marker}")" == 'absent' ]] || fail 'absent model-load marker was not recognized'
cleanup_test_program="${marker_test_program%model_load_marker_state}"$'\n'"${cleanup_model_definition}"$'\nartifact=unused\nrun_id=m2c4-marker\nscenario_id=m2c4-ollama-bounded-loop'
cleanup_without_marker="$(bash -c "${cleanup_test_program}"$'\ntimeout() { return 99; }\nmodel_cleanup=PENDING\ncleanup_model\nprintf "%s\\n" "${model_cleanup}"' -- "${evidence}" "${model_load_marker}")"
[[ "${cleanup_without_marker}" == 'NOT_REQUIRED' ]] || fail 'cleanup without a run-owned marker attempted model unload'
mkdir -m 0700 "${evidence}"
printf 'canarysting-model-load-owned-v1\n' >"${model_load_marker}"
chmod 0600 "${model_load_marker}"
[[ "$(bash -c "${marker_test_program}" -- "${evidence}" "${model_load_marker}")" == 'owned' ]] || fail 'safe model-load ownership marker was rejected'
cleanup_with_marker="$(bash -c "${cleanup_test_program}"$'\ntimeout() { return 0; }\nmodel_cleanup=PENDING\ncleanup_model\nprintf "%s:%s\\n" "${model_cleanup}" "$([[ ! -e "${model_load_marker}" ]] && printf removed || printf present)"' -- "${evidence}" "${model_load_marker}")"
[[ "${cleanup_with_marker}" == 'PASS:present' ]] || fail 'run-owned model cleanup did not retain recovery authority pending independent verification'
printf 'canarysting-model-load-owned-v1\n' >"${model_load_marker}"
chmod 0644 "${model_load_marker}"
if bash -c "${marker_test_program}" -- "${evidence}" "${model_load_marker}" 644 >/dev/null; then
  fail 'unsafe model-load marker mode was accepted'
fi
chmod 0600 "${model_load_marker}"
if bash -c "${marker_test_program}" -- "${evidence}" "${model_load_marker}" 600 31 >/dev/null; then
  fail 'malformed model-load marker size was accepted'
fi
rm -f -- "${model_load_marker}"
ln -s missing "${model_load_marker}"
if bash -c "${marker_test_program}" -- "${evidence}" "${model_load_marker}" >/dev/null; then
  fail 'symlink model-load marker was accepted'
fi
rm -f -- "${model_load_marker}"

marker_create_line="$(grep -nF "printf 'canarysting-model-load-owned-v1\\n' >\"\${model_load_marker}\"" "${remote_proof_script}" | cut -d: -f1)"
model_execute_line="$(grep -nF '"${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -selfcheck' "${remote_proof_script}" | cut -d: -f1)"
[[ "${marker_create_line}" =~ ^[0-9]+$ && "${model_execute_line}" =~ ^[0-9]+$ ]] || fail 'model-load ownership ordering markers are missing'
((marker_create_line < model_execute_line)) || fail 'model execution can begin before its run-owned load marker exists'

result_file="${fixture_root}/result.tsv"
write_valid_result() {
  cat >"${result_file}" <<'RESULT'
key	value
format_version	1
run_id	m2c4-schema
scenario_id	m2c4-ollama-bounded-loop
profile	attacker-bounded-ollama
model	qwen3-coder:30b-a3b-q8_0
model_id	7b438a19895a
planner_version	bounded-qwen-planner-v1
source_revision	1111111111111111111111111111111111111111
source_state	clean
source_tree_sha256	2222222222222222222222222222222222222222222222222222222222222222
artifact_sha256	3333333333333333333333333333333333333333333333333333333333333333
proof_line_count	8
raw_model_output_emitted	false
model_execution	true
model_cleanup	PASS
privilege	unprivileged
started_utc	2026-09-07T12:00:00Z
finished_utc	2026-09-07T12:00:30Z
expires_utc	2026-09-08T12:00:30Z
stdout_sha256	4444444444444444444444444444444444444444444444444444444444444444
stderr_sha256	5555555555555555555555555555555555555555555555555555555555555555
exit_code	0
status	PASS
RESULT
}
run_schema_validator() {
  bash -c "${schema_definition}"$'\n''run_id=m2c4-schema source_revision=1111111111111111111111111111111111111111 source_state=clean source_tree_sha256=2222222222222222222222222222222222222222222222222222222222222222 expected_sha256=3333333333333333333333333333333333333333333333333333333333333333 validate_result_schema "$1"' -- "${result_file}"
}
run_timestamp_validator() {
  local program
  program="${value_definition}"$'\n'"${timestamp_definition}"$'\n''
date() {
  case "$*" in
    "-u -d 2026-09-07T12:00:00Z +%s") printf "100\n" ;;
    "-u -d 2026-09-07T12:00:30Z +%s") printf "130\n" ;;
    "-u -d 2026-09-08T12:00:30Z +%s") printf "86530\n" ;;
    "-u +%s") printf "200\n" ;;
    *) return 1 ;;
  esac
}
validate_timestamps "$1"'
  bash -c "${program}" -- "${result_file}"
}

write_valid_result
run_schema_validator || fail 'complete bounded-loop result schema was rejected'
run_timestamp_validator || fail 'valid bounded-loop timestamps were rejected'
sed 's/^model_id\t.*/model_id\twrong/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted a different model ID'; fi
write_valid_result
sed 's/^model_cleanup\t.*/model_cleanup\tFAIL/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted failed model cleanup'; fi
write_valid_result
grep -v $'^raw_model_output_emitted\t' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted missing raw-output boundary'; fi
write_valid_result
printf 'unexpected\tvalue\n' >>"${result_file}"
if run_schema_validator; then fail 'schema accepted an unexpected field'; fi
write_valid_result
sed 's/^expires_utc\t.*/expires_utc\t2026-09-07T12:00:31Z/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_timestamp_validator; then fail 'timestamp validator accepted non-24-hour expiry'; fi

printf 'PASS: DGX bounded Ollama planner proof harness contract\n'
