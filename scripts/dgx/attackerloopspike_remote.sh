#!/usr/bin/env bash
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
for tool in awk chmod date env find hostname mkdir mv rm sed sha256sum sort stat timeout tr uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
model_load_marker="${evidence}/model-load-owned"
artifact_relative='test/attackerloopspike'
artifact="${stage}/${artifact_relative}"
scenario_id='m2c4-ollama-bounded-loop'
readonly root stage evidence model_load_marker artifact_relative artifact scenario_id

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
model_load_marker_state() {
  if [[ ! -e "${model_load_marker}" && ! -L "${model_load_marker}" ]]; then
    printf 'absent\n'
    return 0
  fi
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" && "$(stat -c %a "${evidence}")" == '700' ]] || return 1
  [[ -f "${model_load_marker}" && ! -L "${model_load_marker}" && -O "${model_load_marker}" &&
    "$(stat -c %a "${model_load_marker}")" == '600' && "$(stat -c %s "${model_load_marker}")" == '32' ]] || return 1
  [[ "$(<"${model_load_marker}")" == 'canarysting-model-load-owned-v1' ]] || return 1
  printf 'owned\n'
}
cleanup_model() {
  local marker_state
  marker_state="$(model_load_marker_state)" || {
    model_cleanup='FAIL'
    return 1
  }
  if [[ "${marker_state}" == 'absent' ]]; then
    model_cleanup='NOT_REQUIRED'
    return 0
  fi
  if timeout --signal=TERM --kill-after=2s 25s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -cleanup-model >/dev/null 2>&1; then
    model_cleanup='PASS'
  else
    model_cleanup='FAIL'
  fi
}
cleanup_after_signal() {
  trap - EXIT HUP INT TERM
  cleanup_model
  exit 130
}
if [[ "${mode}" == 'run' ]]; then
  trap cleanup_model EXIT
  trap cleanup_after_signal HUP INT TERM
fi
if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_model
  [[ "${model_cleanup}" == 'PASS' || "${model_cleanup}" == 'NOT_REQUIRED' ]] || fail 'fixed-model cleanup failed'
  if [[ "${model_cleanup}" == 'PASS' ]]; then
    printf 'PASS: run-owned fixed model unloaded before run-stage cleanup\n'
  else
    printf 'PASS: model unload skipped because this run has no load-ownership marker\n'
  fi
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
  local expected_inventory
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" && "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence is unsafe'
  expected_inventory=$'f:result.tsv\nf:stderr.log\nf:stdout.log'
  if [[ "${mode}" == 'run' ]]; then
    expected_inventory=$'f:model-load-owned\nf:result.tsv\nf:stderr.log\nf:stdout.log'
    [[ "$(model_load_marker_state)" == 'owned' ]] || fail 'model-load ownership marker is unsafe'
  fi
  [[ "$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | sort)" == "${expected_inventory}" ]] || fail 'published evidence inventory is not exact'
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
printf 'canarysting-model-load-owned-v1\n' >"${model_load_marker}"
chmod 0600 "${model_load_marker}"
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
trap - EXIT HUP INT TERM
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
