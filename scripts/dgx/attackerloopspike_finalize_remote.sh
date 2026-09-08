#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
run_id="$1"
mode="$2"
expected_model="$3"
expected_model_id="$4"
expected_marker_state="$5"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
[[ "${expected_model}" == 'qwen3-coder:30b-a3b-q8_0' && "${expected_model_id}" == '7b438a19895a' ]] ||
  fail 'unexpected model identity'
[[ "${expected_marker_state}" == 'owned' || "${expected_marker_state}" == 'absent' ||
  "${expected_marker_state}" == 'either' ]] || fail 'invalid expected marker state'
[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || fail 'unexpected finalization host'
for tool in awk chmod env grep hostname ollama paste rm sort stat sudo systemctl timeout uname; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing finalization prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
evidence="${root}/execution-${run_id}"
model_load_marker="${evidence}/model-load-owned"
readonly root evidence model_load_marker

systemctl_read() {
  if [[ $# -eq 2 && "${1-}" == 'is-active' && "${2-}" == 'ollama' ]]; then
    :
  elif [[ $# -eq 5 && "${1-}" == 'show' && "${2-}" == 'ollama' && "${3-}" == '-p' &&
    ("${4-}" == 'MainPID' || "${4-}" == 'InvocationID') && "${5-}" == '--value' ]]; then
    :
  else
    return 64
  fi
  timeout --foreground --signal=TERM --kill-after=2s 8s systemctl "$@"
}
listener_inventory() {
  [[ $# -eq 0 ]] || return 64
  timeout --foreground --signal=TERM --kill-after=2s 8s sudo -n ss -H -lntp
}
stable_ollama_snapshot() {
  local active_before pid_before invocation_before listener_lines listener_csv
  local active_after pid_after invocation_after
  active_before="$(systemctl_read is-active ollama 2>/dev/null)" || return 1
  pid_before="$(systemctl_read show ollama -p MainPID --value 2>/dev/null)" || return 1
  invocation_before="$(systemctl_read show ollama -p InvocationID --value 2>/dev/null)" || return 1
  [[ "${active_before}" == 'active' && "${pid_before}" =~ ^[1-9][0-9]*$ &&
    "${invocation_before}" =~ ^[0-9A-Fa-f]{32}$ ]] || return 1
  listener_lines="$(listener_inventory | awk -v wanted="${pid_before}" 'index($0, "pid=" wanted ",") {print $4}' | sort -u)" ||
    return 1
  [[ -n "${listener_lines}" ]] || return 1
  while IFS= read -r listener; do
    [[ "${listener}" =~ ^127\.0\.0\.1:[0-9]+$ || "${listener}" =~ ^\[::1\]:[0-9]+$ ]] || return 1
  done <<<"${listener_lines}"
  grep -Fqx '127.0.0.1:11434' <<<"${listener_lines}" || return 1
  listener_csv="$(paste -sd, <<<"${listener_lines}")"
  active_after="$(systemctl_read is-active ollama 2>/dev/null)" || return 1
  pid_after="$(systemctl_read show ollama -p MainPID --value 2>/dev/null)" || return 1
  invocation_after="$(systemctl_read show ollama -p InvocationID --value 2>/dev/null)" || return 1
  [[ "${active_after}" == 'active' && "${pid_after}" == "${pid_before}" &&
    "${invocation_after}" == "${invocation_before}" ]] || return 1
  printf '%s|%s|%s\n' "${pid_before}" "${invocation_before}" "${listener_csv}"
}
ollama_local() {
  [[ $# -eq 1 && ("${1-}" == 'list' || "${1-}" == 'ps') ]] || return 64
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
    OLLAMA_HOST=http://127.0.0.1:11434 \
    timeout --foreground --signal=TERM --kill-after=2s 8s ollama "$@"
}
model_load_marker_state() {
  if [[ ! -e "${model_load_marker}" && ! -L "${model_load_marker}" ]]; then
    printf 'absent\n'
    return 0
  fi
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || return 1
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" &&
    "$(stat -c %a "${evidence}")" == '700' ]] || return 1
  [[ -f "${model_load_marker}" && ! -L "${model_load_marker}" && -O "${model_load_marker}" &&
    "$(stat -c %a "${model_load_marker}")" == '600' && "$(stat -c %s "${model_load_marker}")" == '32' ]] ||
    return 1
  [[ "$(<"${model_load_marker}")" == 'canarysting-model-load-owned-v1' ]] || return 1
  printf 'owned\n'
}

marker_state="$(model_load_marker_state)" || fail 'model-load ownership marker is unsafe'
case "${expected_marker_state}:${marker_state}" in
  owned:owned|absent:absent|either:owned|either:absent) ;;
  *) fail 'model-load ownership marker state changed' ;;
esac

snapshot_before="$(stable_ollama_snapshot)" || fail 'Ollama identity or loopback binding is unsafe'
inventory_model_id="$(ollama_local list 2>/dev/null | awk -v wanted="${expected_model}" '
  $1 == wanted { count++; value=$2 }
  END { if (count != 1) exit 1; print value }
')" || fail 'expected model inventory is missing or ambiguous'
[[ "${inventory_model_id}" == "${expected_model_id}" ]] || fail 'expected model ID changed'
loaded_model_count="$(ollama_local ps 2>/dev/null | awk 'NR > 1 && NF {count++} END {print count+0}')" ||
  fail 'Ollama loaded-model inventory failed'
[[ "${loaded_model_count}" == '0' ]] || fail 'a model remains loaded'
snapshot_after="$(stable_ollama_snapshot)" || fail 'Ollama identity or loopback binding postcheck failed'
[[ "${snapshot_after}" == "${snapshot_before}" ]] || fail 'Ollama service identity or listeners changed'

marker_result='absent'
if [[ "${marker_state}" == 'owned' ]]; then
  rm -f -- "${model_load_marker}"
  [[ ! -e "${model_load_marker}" && ! -L "${model_load_marker}" ]] || fail 'model-load ownership marker remains'
  marker_result='retired'
fi
printf 'model_finalize=PASS\n'
printf 'model_load_marker=%s\n' "${marker_result}"
