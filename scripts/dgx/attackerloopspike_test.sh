#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/attackerloopspike.sh"
remote_proof_script="${script_dir}/attackerloopspike_remote.sh"
lock_supervisor_script="${script_dir}/attackerloopspike_lock_remote.sh"
readonly proof_script remote_proof_script lock_supervisor_script
readonly -a proof_sources=("${proof_script}" "${remote_proof_script}" "${lock_supervisor_script}")

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
awk '/retirement_report=.*<<.REMOTE./ { capture=1; next } /^REMOTE$/ { if (capture) exit } capture { print }' "${proof_script}" |
  bash -n || fail 'embedded marker-retirement program has invalid Bash syntax'

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
  '"${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -cleanup-model' \
  'trap cleanup_after_signal HUP INT TERM' \
  'if ! flock -n 9; then' \
  'wait_for_remote_proof' \
  'assert_model_lock_held || fail' \
  'expires - finished == 86400'; do
  grep -F "${marker}" "${proof_sources[@]}" >/dev/null || fail "proof safety marker missing: ${marker}"
done
if grep -E '(^|[[:space:]])(sudo|kubectl|bpftool|systemctl|iptables|nft|docker|curl)([[:space:]]|$)' "${proof_sources[@]}" >/dev/null; then
  fail 'unprivileged planner proof contains a privileged, control-plane, or alternate HTTP command'
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
assert_lock_definition="$(awk '/^assert_model_lock_held\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
wait_proof_definition="$(awk '/^wait_for_remote_proof\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
supervisor_terminate_definition="$(awk '/^terminate_proof_group\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${lock_supervisor_script}")"
supervise_proof_definition="$(awk '/^supervise_proof\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${lock_supervisor_script}")"
[[ -n "${identity_report_definition}" && -n "${report_definition}" && -n "${unloaded_report_definition}" && -n "${marker_state_definition}" && -n "${cleanup_model_definition}" && -n "${schema_definition}" && -n "${value_definition}" && -n "${timestamp_definition}" && -n "${cleanup_stage_definition}" && -n "${terminate_proof_definition}" && -n "${assert_lock_definition}" && -n "${wait_proof_definition}" && -n "${supervisor_terminate_definition}" && -n "${supervise_proof_definition}" ]] || fail 'proof validators are not independently testable'

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
post_check_line="$(grep -nF 'validate_model_report "${post_model_report}"' "${proof_script}" | cut -d: -f1)"
marker_retirement_line="$(grep -nF 'retire_verified_model_marker "${marker_retirement_expectation}" || fail' "${proof_script}" | cut -d: -f1)"
generic_cleanup_line="$(grep -nF '"${cleanup_script}" --run-id "${run_id}"' "${proof_script}" | tail -n1 | cut -d: -f1)"
[[ "${cleanup_inspect_line}" =~ ^[0-9]+$ && "${remote_cleanup_line}" =~ ^[0-9]+$ && "${post_check_line}" =~ ^[0-9]+$ && "${marker_retirement_line}" =~ ^[0-9]+$ && "${generic_cleanup_line}" =~ ^[0-9]+$ ]] || fail 'cleanup recovery ordering markers are missing'
((cleanup_inspect_line < post_check_line && post_check_line < marker_retirement_line && marker_retirement_line < generic_cleanup_line)) || fail 'cleanup can remove recovery authority or the stage before fixed-model unload verification'
if grep -F 'rm -f -- "${model_load_marker}"' <<<"${cleanup_model_definition}" >/dev/null; then
  fail 'Ollama unload acknowledgement can retire the recovery marker before independent verification'
fi
grep -F 'rm -f -- "${model_load_marker}"' "${proof_script}" >/dev/null || fail 'verified marker retirement is missing'

lock_acquire_line="$(grep -nFx 'acquire_model_lock' "${proof_script}" | cut -d: -f1)"
preflight_line="$(grep -nFx 'run_preflight' "${proof_script}" | cut -d: -f1)"
pre_model_line="$(grep -nF 'pre_model_report="$("${attackercheck_script}")"' "${proof_script}" | cut -d: -f1)"
proof_start_line="$(grep -nFx '  start_locked_remote_proof' "${proof_script}" | cut -d: -f1)"
lock_release_line="$(grep -nF 'release_model_lock || fail' "${proof_script}" | cut -d: -f1)"
[[ "${preflight_line}" =~ ^[0-9]+$ && "${lock_acquire_line}" =~ ^[0-9]+$ && "${pre_model_line}" =~ ^[0-9]+$ && "${proof_start_line}" =~ ^[0-9]+$ && "${lock_release_line}" =~ ^[0-9]+$ ]] || fail 'host-global model lock ordering markers are missing'
((preflight_line < lock_acquire_line && lock_acquire_line < pre_model_line && pre_model_line < proof_start_line && proof_start_line < post_check_line && post_check_line < marker_retirement_line && marker_retirement_line < lock_release_line)) || fail 'preflight and host-global model lock ordering is unsafe'

supervisor_flock_line="$(grep -nF 'if ! flock -n 9; then' "${lock_supervisor_script}" | cut -d: -f1)"
supervisor_start_line="$(grep -nF 'setsid bash -c "${proof_program}"' "${lock_supervisor_script}" | cut -d: -f1)"
supervisor_wait_line="$(grep -nF 'wait "${proof_pid}"' "${lock_supervisor_script}" | tail -n1 | cut -d: -f1)"
supervisor_status_line="$(grep -nF "printf 'remote_proof_status=%s\\n'" "${lock_supervisor_script}" | cut -d: -f1)"
supervisor_hold_line="$(grep -nFx '  cat >/dev/null' "${lock_supervisor_script}" | cut -d: -f1)"
[[ "${supervisor_flock_line}" =~ ^[0-9]+$ && "${supervisor_start_line}" =~ ^[0-9]+$ && "${supervisor_wait_line}" =~ ^[0-9]+$ && "${supervisor_status_line}" =~ ^[0-9]+$ && "${supervisor_hold_line}" =~ ^[0-9]+$ ]] || fail 'remote lock-supervisor ordering markers are missing'
((supervisor_flock_line < supervisor_start_line && supervisor_start_line < supervisor_wait_line && supervisor_wait_line < supervisor_status_line && supervisor_status_line < supervisor_hold_line)) || fail 'remote proof lifetime is not bounded by its flock-owning supervisor'
grep -F 'kill -TERM -- "-${proof_pid}"' "${lock_supervisor_script}" >/dev/null || fail 'remote supervisor cannot terminate the complete proof process group'
if grep -F 'remote_proof_status=' "${remote_proof_script}" >/dev/null; then
  fail 'remote proof can forge the lock-supervisor completion record'
fi

monitor_definitions="${assert_lock_definition}"$'\n'"${wait_proof_definition}"
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

if command -v flock >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1; then
  supervisor_fifo="${monitor_root}/supervisor-input"
  supervisor_lock="${monitor_root}/model.lock"
  supervisor_ready="${monitor_root}/ready"
  supervisor_report="${monitor_root}/supervisor-report"
  mkfifo -m 0600 "${supervisor_fifo}"
  exec 8<>"${supervisor_fifo}"
  supervisor_program=$'set -euo pipefail\nfail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\nproof_pid=""\n'"${supervisor_terminate_definition}"$'\n'"${supervise_proof_definition}"$'\nsupervise_proof'
  (
    exec 8>&-
    exec 9>>"${supervisor_lock}"
    flock 9
    printf 'ready\n' >"${supervisor_ready}"
    bash -c "${supervisor_program}" <"${supervisor_fifo}" >"${supervisor_report}"
  ) &
  supervisor_pid=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s "${supervisor_ready}" ]] && break
    kill -0 "${supervisor_pid}" 2>/dev/null || break
    sleep 0.01
  done
  [[ -s "${supervisor_ready}" ]] || fail 'local lock-supervisor lifetime fixture did not start'
  lifetime_proof='sleep 1'
  LC_ALL=C lifetime_proof_bytes="${#lifetime_proof}"
  printf 'execute\tm2c4-lifetime\trun\tqwen3-coder:30b-a3b-q8_0\t7b438a19895a\t%s\n' "${lifetime_proof_bytes}" >&8
  printf '%s' "${lifetime_proof}" >&8
  exec 8>&-
  sleep 0.1
  if flock -n "${supervisor_lock}" -c true; then
    fail 'proof continued after client EOF without its supervisor lock'
  fi
  wait "${supervisor_pid}" || fail 'local lock-supervisor lifetime fixture failed'
  flock -n "${supervisor_lock}" -c true || fail 'lock supervisor did not release after proof termination'
  [[ "$(<"${supervisor_report}")" == 'remote_proof_status=0' ]] || fail 'lock supervisor emitted an invalid completion record'
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
