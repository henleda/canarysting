#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly expected_host='spark-5343'
readonly expected_arch='aarch64'
readonly expected_model='qwen3-coder:30b-a3b-q8_0'

fail() {
  printf 'attackercheck: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/attackercheck.sh [--dry-run] [--summary]

Performs one fixed, read-only inspection of the DGX CanaryAttacker laboratory.
It never runs a model, sends a prompt, pulls a model, changes a service, reads a
Kubernetes Secret, or mutates Kubernetes, Cilium, BPF, firewall, or host state.
USAGE
}

dry_run=0
summary=0
while (($#)); do
  case "$1" in
    --dry-run)
      dry_run=1
      shift
      ;;
    --summary)
      summary=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if ((dry_run)); then
  printf 'host=%s\nexpected_hostname=%s\nexpected_architecture=%s\nexpected_model=%s\n' \
    "${dgx_host}" "${expected_host}" "${expected_arch}" "${expected_model}"
  printf 'mode=read-only\nmodel_execution=disabled\nremote_mutation=none\n'
  printf 'DRY RUN: attacker-lab inspection contract passed; DGX was not accessed\n'
  exit 0
fi

command -v ssh >/dev/null 2>&1 || fail 'ssh is required'

work_root="$(mktemp -d '/tmp/canarysting-attackercheck.XXXXXX')"
[[ "${work_root}" == /tmp/canarysting-attackercheck.* ]] || fail 'unsafe temporary work root'
report_file="${work_root}/report"
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -d "${work_root}" && ! -L "${work_root}" && "${work_root}" == /tmp/canarysting-attackercheck.* ]]; then
    rm -rf -- "${work_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

local_before_epoch="$(date -u +%s)"
ssh -o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=yes "${dgx_host}" \
  'timeout --signal=TERM --kill-after=5s 45s bash -s' >"${report_file}" <<'REMOTE'
set -euo pipefail

readonly expected_model='qwen3-coder:30b-a3b-q8_0'

have() { command -v "$1" >/dev/null 2>&1; }
systemctl_read() {
  if [[ $# -eq 2 && "${1-}" == 'is-active' && ("${2-}" == 'ollama' || "${2-}" == 'k3s') ]]; then
    :
  elif [[ $# -eq 2 && "${1-}" == 'is-enabled' && "${2-}" == 'ollama' ]]; then
    :
  elif [[ $# -eq 5 && "${1-}" == 'show' && "${2-}" == 'ollama' && "${3-}" == '-p' && \
    ("${4-}" == 'User' || "${4-}" == 'MainPID') && "${5-}" == '--value' ]]; then
    :
  else
    return 64
  fi
  timeout --signal=TERM --kill-after=2s 8s systemctl "$@"
}
kctl() {
  if [[ $# -eq 5 && "${1-}" == 'get' && "${2-}" == 'node' && "${3-}" == 'spark-5343' && \
    "${4-}" == '-o' && "${5-}" == 'jsonpath={range .status.conditions[?(@.type=="Ready")]}{.status}{end}' ]]; then
    :
  elif [[ $# -eq 7 && "${1-}" == '-n' && "${2-}" == 'kube-system' && "${3-}" == 'get' && \
    "${4-}" == 'daemonset' && ("${5-}" == 'cilium' || "${5-}" == 'cilium-envoy') && "${6-}" == '-o' && \
    ("${7-}" == 'jsonpath={.status.desiredNumberScheduled}' || "${7-}" == 'jsonpath={.status.numberReady}') ]]; then
    :
  elif [[ $# -eq 7 && "${1-}" == '-n' && "${2-}" == 'kube-system' && "${3-}" == 'get' && \
    "${4-}" == 'deployment' && ("${5-}" == 'cilium-operator' || "${5-}" == 'hubble-relay') && "${6-}" == '-o' && \
    ("${7-}" == 'jsonpath={.spec.replicas}' || "${7-}" == 'jsonpath={.status.readyReplicas}') ]]; then
    :
  else
    return 64
  fi
  timeout --signal=TERM --kill-after=2s 8s sudo -n k3s kubectl --request-timeout=5s "$@"
}
ollama_local() {
  [[ $# -eq 1 && ("${1-}" == '--version' || "${1-}" == 'list' || "${1-}" == 'ps') ]] || return 64
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
    OLLAMA_HOST=http://127.0.0.1:11434 \
    timeout --signal=TERM --kill-after=2s 8s ollama "$@"
}
curl_local() {
  [[ $# -eq 1 && "${1-}" == 'http://127.0.0.1:11434/api/version' ]] || return 64
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
    timeout --signal=TERM --kill-after=2s 8s \
    curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
      --noproxy '*' --proto '=http' "$@"
}
listener_inventory() {
  [[ $# -eq 1 && "${1-}" =~ ^[1-9][0-9]*$ ]] || return 64
  timeout --signal=TERM --kill-after=2s 8s sudo -n ss -H -lntp
}
owned_listener_addresses() {
  local service_pid="${1-}"
  [[ $# -eq 1 && "${service_pid}" =~ ^[1-9][0-9]*$ ]] || return 64
  listener_inventory "${service_pid}" | \
    awk -v wanted="${service_pid}" 'index($0, "pid=" wanted ",") {print $4}' | sort -u
}
timedate_read() {
  [[ $# -eq 1 && ("${1-}" == 'NTPSynchronized' || "${1-}" == 'Timezone') ]] || return 64
  timeout --signal=TERM --kill-after=2s 8s timedatectl show -p "$1" --value
}
gpu_inventory() {
  [[ $# -eq 0 ]] || return 64
  timeout --signal=TERM --kill-after=2s 8s \
    nvidia-smi --query-gpu=name,driver_version,memory.total,memory.free --format=csv,noheader,nounits
}
trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}
daemonset_ready() {
  local name="$1" desired ready
  desired="$(kctl -n kube-system get daemonset "${name}" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || true)"
  ready="$(kctl -n kube-system get daemonset "${name}" -o jsonpath='{.status.numberReady}' 2>/dev/null || true)"
  if [[ "${desired}" =~ ^[0-9]+$ && "${ready}" =~ ^[0-9]+$ ]]; then
    printf '%s/%s' "${ready}" "${desired}"
  else
    printf 'unavailable'
  fi
}
deployment_ready() {
  local name="$1" desired ready
  desired="$(kctl -n kube-system get deployment "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  ready="$(kctl -n kube-system get deployment "${name}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  if [[ "${desired}" =~ ^[0-9]+$ && "${ready}" =~ ^[0-9]+$ ]]; then
    printf '%s/%s' "${ready}" "${desired}"
  else
    printf 'unavailable'
  fi
}
pair_ready() {
  local pair="$1" ready desired
  [[ "${pair}" == */* ]] || return 1
  ready="${pair%/*}"
  desired="${pair#*/}"
  [[ "${ready}" =~ ^[0-9]+$ && "${desired}" =~ ^[0-9]+$ && "${desired}" -gt 0 && "${ready}" -eq "${desired}" ]]
}
append_blocker() {
  if [[ -n "${blockers}" ]]; then
    blockers="${blockers},$1"
  else
    blockers="$1"
  fi
}

. /etc/os-release
hostname_value="$(hostname)"
architecture="$(uname -m)"
kernel="$(uname -r)"
os_id="${ID:-unknown}-${VERSION_ID:-unknown}"
inspection_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
inspection_epoch="$(date -u +%s)"
ntp_synchronized="$(timedate_read NTPSynchronized 2>/dev/null || true)"
case "${ntp_synchronized,,}" in
  yes|true) ntp_synchronized='true' ;;
  no|false) ntp_synchronized='false' ;;
  *) ntp_synchronized='unknown' ;;
esac
timezone="$(timedate_read Timezone 2>/dev/null || true)"
[[ -n "${timezone}" ]] || timezone='unknown'
cpu_count="$(nproc)"
memory_total_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
memory_available_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
root_available_kib="$(df -Pk / | awk 'NR==2 {print $4}')"

gpu_count=0
gpu_name='unavailable'
gpu_driver_version='unavailable'
gpu_memory_total_mib='unavailable'
gpu_memory_free_mib='unavailable'
gpu_probe_status='unavailable'
if have nvidia-smi; then
  if gpu_lines="$(gpu_inventory 2>/dev/null)"; then
    gpu_probe_status='ok'
    gpu_count="$(awk 'NF {count++} END {print count+0}' <<<"${gpu_lines}")"
    if ((gpu_count > 0)); then
      first_gpu="$(awk 'NF {print; exit}' <<<"${gpu_lines}")"
      IFS=',' read -r raw_gpu_name raw_driver raw_total raw_free <<<"${first_gpu}"
      gpu_name="$(trim "${raw_gpu_name}")"
      gpu_driver_version="$(trim "${raw_driver}")"
      gpu_memory_total_mib="$(trim "${raw_total}")"
      gpu_memory_free_mib="$(trim "${raw_free}")"
      [[ "${gpu_memory_total_mib}" =~ ^[0-9]+$ ]] || gpu_memory_total_mib='unavailable'
      [[ "${gpu_memory_free_mib}" =~ ^[0-9]+$ ]] || gpu_memory_free_mib='unavailable'
    fi
  else
    gpu_probe_status='error'
  fi
fi

ollama_cli_path='missing'
ollama_cli_version='unavailable'
ollama_service_active="$(systemctl_read is-active ollama 2>/dev/null || true)"
ollama_service_enabled="$(systemctl_read is-enabled ollama 2>/dev/null || true)"
ollama_service_user="$(systemctl_read show ollama -p User --value 2>/dev/null || true)"
ollama_service_main_pid="$(systemctl_read show ollama -p MainPID --value 2>/dev/null || true)"
[[ -n "${ollama_service_active}" ]] || ollama_service_active='unknown'
[[ -n "${ollama_service_enabled}" ]] || ollama_service_enabled='unknown'
[[ -n "${ollama_service_user}" ]] || ollama_service_user='unknown'
ollama_listener_addresses='unavailable'
ollama_listener_probe_status='error'
ollama_binding='probe_error'
ollama_api_version='unavailable'
ollama_api_probe_status='not_queried'
ollama_inventory_status='not_queried'
expected_model_present='false'
expected_model_id='absent'
expected_model_size='absent'
loaded_model_count='unavailable'

if have ollama; then
  ollama_cli_path="$(command -v ollama)"
  ollama_version_output="$(ollama_local --version 2>/dev/null || true)"
  ollama_cli_version="$(awk 'NF {value=$NF} END {print value}' <<<"${ollama_version_output}")"
  [[ -n "${ollama_cli_version}" ]] || ollama_cli_version='unavailable'
fi

if have ss && [[ "${ollama_service_main_pid}" =~ ^[1-9][0-9]*$ ]] && \
  listener_lines="$(owned_listener_addresses "${ollama_service_main_pid}" 2>/dev/null)"; then
  ollama_listener_probe_status='ok'
  if [[ -n "${listener_lines}" ]]; then
    ollama_listener_addresses="$(paste -sd, <<<"${listener_lines}")"
    ollama_binding='loopback_only'
    while IFS= read -r listener; do
      if [[ ! "${listener}" =~ ^127\.0\.0\.1:[0-9]+$ && ! "${listener}" =~ ^\[::1\]:[0-9]+$ ]]; then
        ollama_binding='unsafe_non_loopback'
      fi
    done <<<"${listener_lines}"
  else
    ollama_listener_addresses='none'
    ollama_binding='not_listening'
  fi
fi

if [[ "${ollama_binding}" == 'loopback_only' ]]; then
  if have curl && api_json="$(curl_local http://127.0.0.1:11434/api/version 2>/dev/null)"; then
    if [[ "${api_json}" =~ \"version\"[[:space:]]*:[[:space:]]*\"([0-9A-Za-z._+-]+)\" ]]; then
      ollama_api_version="${BASH_REMATCH[1]}"
      ollama_api_probe_status='ok'
    else
      ollama_api_probe_status='error'
    fi
  else
    ollama_api_probe_status='error'
  fi
fi

if have ollama && [[ "${ollama_api_version}" != 'unavailable' ]]; then
  if model_list="$(ollama_local list 2>/dev/null)" && loaded_models="$(ollama_local ps 2>/dev/null)"; then
    ollama_inventory_status='ok'
    model_line="$(awk -v wanted="${expected_model}" '$1 == wanted {print; exit}' <<<"${model_list}")"
    if [[ -n "${model_line}" ]]; then
      expected_model_present='true'
      expected_model_id="$(awk '{print $2}' <<<"${model_line}")"
      expected_model_size="$(awk '{print $3 $4}' <<<"${model_line}")"
    fi
    loaded_model_count="$(awk 'NR > 1 && NF {count++} END {print count+0}' <<<"${loaded_models}")"
  else
    ollama_inventory_status='error'
  fi
fi

k3s_service_active="$(systemctl_read is-active k3s 2>/dev/null || true)"
[[ -n "${k3s_service_active}" ]] || k3s_service_active='unknown'
node_ready='unknown'
cilium_daemonset_ready='unavailable'
cilium_operator_ready='unavailable'
cilium_envoy_ready='unavailable'
hubble_relay_ready='unavailable'
if have k3s && [[ "${k3s_service_active}" == 'active' ]]; then
  node_ready="$(kctl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' 2>/dev/null || true)"
  case "${node_ready}" in
    True) node_ready='true' ;;
    False) node_ready='false' ;;
    *) node_ready='unknown' ;;
  esac
  cilium_daemonset_ready="$(daemonset_ready cilium)"
  cilium_operator_ready="$(deployment_ready cilium-operator)"
  cilium_envoy_ready="$(daemonset_ready cilium-envoy)"
  hubble_relay_ready="$(deployment_ready hubble-relay)"
fi

target_lab_status='unconfigured'

if [[ "${k3s_service_active}" == 'active' && "${node_ready}" == 'true' ]] && \
  pair_ready "${cilium_daemonset_ready}" && pair_ready "${cilium_operator_ready}" && pair_ready "${cilium_envoy_ready}"; then
  telemetry_state='core_ready_partial_sources'
else
  telemetry_state='core_unready'
fi

blockers=''
[[ "${ollama_service_active}" == 'active' ]] || append_blocker 'ollama_service_not_active'
[[ "${ollama_listener_probe_status}" == 'ok' ]] || append_blocker 'ollama_listener_probe_failed'
[[ "${ollama_binding}" == 'loopback_only' ]] || append_blocker "ollama_binding_${ollama_binding}"
[[ "${ollama_api_version}" != 'unavailable' ]] || append_blocker 'ollama_api_unavailable'
[[ "${ollama_api_probe_status}" == 'ok' ]] || append_blocker "ollama_api_${ollama_api_probe_status}"
[[ "${expected_model_present}" == 'true' ]] || append_blocker 'expected_model_absent'
[[ "${ollama_inventory_status}" == 'ok' ]] || append_blocker "ollama_inventory_${ollama_inventory_status}"
if [[ "${loaded_model_count}" =~ ^[0-9]+$ ]] && ((loaded_model_count > 0)); then
  append_blocker 'models_already_loaded'
fi
[[ "${ntp_synchronized}" == 'true' ]] || append_blocker 'clock_not_synchronized'
[[ "${gpu_probe_status}" == 'ok' ]] || append_blocker "gpu_probe_${gpu_probe_status}"
((gpu_count > 0)) || append_blocker 'gpu_unavailable'
append_blocker 'target_lab_unconfigured'
pair_ready "${hubble_relay_ready}" || append_blocker 'hubble_relay_unready'
append_blocker 'canarysting_runtime_unconfigured'
[[ "${telemetry_state}" == 'core_ready_partial_sources' ]] || append_blocker 'core_telemetry_unready'
append_blocker 'bounded_attacker_harness_unimplemented'
execution_blockers="${blockers}"
live_scenario_ready='false'

case "${ollama_listener_probe_status}:${ollama_binding}" in
  error:*) safety_status='safety_unverified' ;;
  ok:unsafe_non_loopback) safety_status='unsafe_exposure' ;;
  ok:loopback_only) safety_status='safe' ;;
  *) safety_status='safe_not_ready' ;;
esac

printf 'report_version=2\n'
printf 'hostname=%s\n' "${hostname_value}"
printf 'architecture=%s\n' "${architecture}"
printf 'os_id=%s\n' "${os_id}"
printf 'kernel=%s\n' "${kernel}"
printf 'inspection_utc=%s\n' "${inspection_utc}"
printf 'inspection_epoch=%s\n' "${inspection_epoch}"
printf 'ntp_synchronized=%s\n' "${ntp_synchronized}"
printf 'timezone=%s\n' "${timezone}"
printf 'cpu_count=%s\n' "${cpu_count}"
printf 'memory_total_kib=%s\n' "${memory_total_kib}"
printf 'memory_available_kib=%s\n' "${memory_available_kib}"
printf 'root_available_kib=%s\n' "${root_available_kib}"
printf 'gpu_count=%s\n' "${gpu_count}"
printf 'gpu_name=%s\n' "${gpu_name}"
printf 'gpu_driver_version=%s\n' "${gpu_driver_version}"
printf 'gpu_memory_total_mib=%s\n' "${gpu_memory_total_mib}"
printf 'gpu_memory_free_mib=%s\n' "${gpu_memory_free_mib}"
printf 'gpu_probe_status=%s\n' "${gpu_probe_status}"
printf 'ollama_cli_path=%s\n' "${ollama_cli_path}"
printf 'ollama_cli_version=%s\n' "${ollama_cli_version}"
printf 'ollama_service_active=%s\n' "${ollama_service_active}"
printf 'ollama_service_enabled=%s\n' "${ollama_service_enabled}"
printf 'ollama_service_user=%s\n' "${ollama_service_user}"
printf 'ollama_listener_addresses=%s\n' "${ollama_listener_addresses}"
printf 'ollama_listener_probe_status=%s\n' "${ollama_listener_probe_status}"
printf 'ollama_binding=%s\n' "${ollama_binding}"
printf 'ollama_api_version=%s\n' "${ollama_api_version}"
printf 'ollama_api_probe_status=%s\n' "${ollama_api_probe_status}"
printf 'ollama_inventory_status=%s\n' "${ollama_inventory_status}"
printf 'expected_model=%s\n' "${expected_model}"
printf 'expected_model_present=%s\n' "${expected_model_present}"
printf 'expected_model_id=%s\n' "${expected_model_id}"
printf 'expected_model_size=%s\n' "${expected_model_size}"
printf 'loaded_model_count=%s\n' "${loaded_model_count}"
printf 'k3s_service_active=%s\n' "${k3s_service_active}"
printf 'node_ready=%s\n' "${node_ready}"
printf 'cilium_daemonset_ready=%s\n' "${cilium_daemonset_ready}"
printf 'cilium_operator_ready=%s\n' "${cilium_operator_ready}"
printf 'cilium_envoy_ready=%s\n' "${cilium_envoy_ready}"
printf 'hubble_relay_ready=%s\n' "${hubble_relay_ready}"
printf 'target_lab_status=%s\n' "${target_lab_status}"
printf 'telemetry_state=%s\n' "${telemetry_state}"
printf 'live_scenario_ready=%s\n' "${live_scenario_ready}"
printf 'execution_blockers=%s\n' "${execution_blockers}"
printf 'safety_status=%s\n' "${safety_status}"
REMOTE
local_after_epoch="$(date -u +%s)"
chmod 0600 "${report_file}"

readonly expected_keys=(
  report_version hostname architecture os_id kernel inspection_utc inspection_epoch ntp_synchronized timezone
  cpu_count memory_total_kib memory_available_kib root_available_kib gpu_count gpu_name gpu_driver_version
  gpu_memory_total_mib gpu_memory_free_mib gpu_probe_status ollama_cli_path ollama_cli_version
  ollama_service_active ollama_service_enabled ollama_service_user ollama_listener_addresses
  ollama_listener_probe_status ollama_binding ollama_api_version ollama_api_probe_status
  ollama_inventory_status expected_model
  expected_model_present expected_model_id expected_model_size loaded_model_count k3s_service_active node_ready
  cilium_daemonset_ready cilium_operator_ready cilium_envoy_ready hubble_relay_ready target_lab_status
  telemetry_state live_scenario_ready execution_blockers safety_status
)
values=()
index=0
while IFS= read -r line || [[ -n "${line}" ]]; do
  [[ "${line}" == *=* ]] || fail 'remote report contains a malformed line'
  key="${line%%=*}"
  value="${line#*=}"
  ((index < ${#expected_keys[@]})) || fail 'remote report contains unexpected fields'
  [[ "${key}" == "${expected_keys[index]}" ]] || fail "remote report field ${index} is ${key}, want ${expected_keys[index]}"
  [[ -n "${value}" && ${#value} -le 512 ]] || fail "remote report field ${key} is empty or oversized"
  [[ "${value}" != *$'\t'* && "${value}" != *$'\r'* ]] || fail "remote report field ${key} contains control characters"
  values[index]="${value}"
  index=$((index + 1))
done <"${report_file}"
((index == ${#expected_keys[@]})) || fail "remote report has ${index} fields, want ${#expected_keys[@]}"

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
is_bool() { [[ "$1" == 'true' || "$1" == 'false' ]]; }
is_ready_pair() { [[ "$1" =~ ^[0-9]+/[0-9]+$ || "$1" == 'unavailable' ]]; }
ready_pair_complete() {
  local pair="$1" ready desired
  [[ "${pair}" == */* ]] || return 1
  ready="${pair%/*}"
  desired="${pair#*/}"
  [[ "${ready}" =~ ^[0-9]+$ && "${desired}" =~ ^[0-9]+$ && "${desired}" -gt 0 && "${ready}" -eq "${desired}" ]]
}
append_expected_blocker() {
  if [[ -n "${expected_blockers}" ]]; then
    expected_blockers="${expected_blockers},$1"
  else
    expected_blockers="$1"
  fi
}

[[ "${values[0]}" == '2' ]] || fail 'unsupported report version'
[[ "${values[1]}" == "${expected_host}" ]] || fail "unexpected DGX hostname ${values[1]}"
[[ "${values[2]}" == "${expected_arch}" ]] || fail "unexpected DGX architecture ${values[2]}"
[[ "${values[5]}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail 'inspection timestamp is not UTC RFC3339'
is_uint "${values[6]}" || fail 'inspection epoch is not numeric'
((values[6] >= local_before_epoch - 30 && values[6] <= local_after_epoch + 30)) || fail 'DGX clock is outside the bounded workstation observation window'
[[ "${values[7]}" == 'true' || "${values[7]}" == 'false' || "${values[7]}" == 'unknown' ]] || fail 'invalid NTP synchronization state'
for numeric_index in 9 10 11 12 13; do
  is_uint "${values[numeric_index]}" || fail "${expected_keys[numeric_index]} is not numeric"
done
for gpu_index in 16 17; do
  is_uint "${values[gpu_index]}" || [[ "${values[gpu_index]}" == 'unavailable' ]] || fail "${expected_keys[gpu_index]} is invalid"
done
[[ "${values[18]}" == 'ok' || "${values[18]}" == 'unavailable' || "${values[18]}" == 'error' ]] || fail 'invalid GPU probe status'
[[ "${values[21]}" == 'active' || "${values[21]}" == 'inactive' || "${values[21]}" == 'failed' || "${values[21]}" == 'activating' || "${values[21]}" == 'deactivating' || "${values[21]}" == 'reloading' || "${values[21]}" == 'unknown' ]] || fail 'invalid Ollama service state'
[[ "${values[22]}" == 'enabled' || "${values[22]}" == 'disabled' || "${values[22]}" == 'static' || "${values[22]}" == 'indirect' || "${values[22]}" == 'masked' || "${values[22]}" == 'generated' || "${values[22]}" == 'unknown' ]] || fail 'invalid Ollama enablement state'
[[ "${values[25]}" == 'ok' || "${values[25]}" == 'error' ]] || fail 'invalid Ollama listener probe status'
[[ "${values[26]}" == 'loopback_only' || "${values[26]}" == 'not_listening' || "${values[26]}" == 'unsafe_non_loopback' || "${values[26]}" == 'probe_error' ]] || fail 'invalid Ollama binding classification'
[[ "${values[28]}" == 'ok' || "${values[28]}" == 'not_queried' || "${values[28]}" == 'error' ]] || fail 'invalid Ollama API probe status'
[[ "${values[29]}" == 'ok' || "${values[29]}" == 'not_queried' || "${values[29]}" == 'error' ]] || fail 'invalid Ollama inventory status'
[[ "${values[30]}" == "${expected_model}" ]] || fail 'remote report changed the expected model'
is_bool "${values[31]}" || fail 'invalid expected-model presence state'
if [[ "${values[29]}" == 'ok' ]]; then
  is_uint "${values[34]}" || fail 'loaded model count is not numeric for a successful inventory'
else
  [[ "${values[34]}" == 'unavailable' ]] || fail 'unavailable Ollama inventory reported a loaded-model count'
fi
[[ "${values[35]}" == 'active' || "${values[35]}" == 'inactive' || "${values[35]}" == 'failed' || "${values[35]}" == 'activating' || "${values[35]}" == 'deactivating' || "${values[35]}" == 'reloading' || "${values[35]}" == 'unknown' ]] || fail 'invalid K3s service state'
[[ "${values[36]}" == 'true' || "${values[36]}" == 'false' || "${values[36]}" == 'unknown' ]] || fail 'invalid node readiness state'
for pair_index in 37 38 39 40; do
  is_ready_pair "${values[pair_index]}" || fail "${expected_keys[pair_index]} is invalid"
done
[[ "${values[41]}" == 'unconfigured' ]] || fail 'M2C.1 must not infer a target lab from cluster-wide names or labels'
[[ "${values[42]}" == 'core_ready_partial_sources' || "${values[42]}" == 'core_unready' ]] || fail 'invalid telemetry state'
[[ "${values[43]}" == 'false' ]] || fail 'M2C.1 must never authorize a live scenario'
[[ "${values[45]}" == 'safe' || "${values[45]}" == 'safe_not_ready' || "${values[45]}" == 'unsafe_exposure' || "${values[45]}" == 'safety_unverified' ]] || fail 'invalid safety status'

if [[ "${values[25]}" == 'error' ]]; then
  [[ "${values[24]}" == 'unavailable' && "${values[26]}" == 'probe_error' ]] || fail 'failed listener probe reported a derived listener classification'
else
  [[ "${values[24]}" != 'unavailable' && "${values[26]}" != 'probe_error' ]] || fail 'successful listener probe reported unavailable results'
fi
if [[ "${values[26]}" == 'not_listening' ]]; then
  [[ "${values[24]}" == 'none' ]] || fail 'not-listening classification contains listener addresses'
elif [[ "${values[26]}" == 'loopback_only' ]]; then
  [[ "${values[24]}" != 'none' && "${values[24]}" != 'unavailable' ]] || fail 'loopback classification has no listener'
  old_ifs="${IFS}"
  IFS=','
  read -r -a listeners <<<"${values[24]}"
  IFS="${old_ifs}"
  for listener in "${listeners[@]}"; do
    if [[ ! "${listener}" =~ ^127\.0\.0\.1:[0-9]+$ && ! "${listener}" =~ ^\[::1\]:[0-9]+$ ]]; then
      fail "non-loopback Ollama listener ${listener} was classified as safe"
    fi
  done
fi
if [[ "${values[26]}" == 'unsafe_non_loopback' ]]; then
  [[ "${values[24]}" != 'none' && "${values[24]}" != 'unavailable' ]] || fail 'unsafe listener classification has no listener'
fi
if [[ "${values[28]}" == 'ok' ]]; then
  [[ "${values[26]}" == 'loopback_only' && "${values[27]}" != 'unavailable' ]] || fail 'successful Ollama API probe lacks loopback version evidence'
else
  [[ "${values[27]}" == 'unavailable' ]] || fail 'unsuccessful Ollama API probe reported a version'
fi
[[ "${values[28]}" != 'not_queried' || "${values[26]}" != 'loopback_only' ]] || fail 'loopback-only Ollama listener was not probed'
if [[ "${values[31]}" == 'true' ]]; then
  [[ "${values[29]}" == 'ok' && "${values[32]}" != 'absent' && "${values[33]}" != 'absent' ]] || fail 'present expected model lacks successful inventory evidence'
else
  [[ "${values[32]}" == 'absent' && "${values[33]}" == 'absent' ]] || fail 'absent expected model contains identity or size evidence'
fi
if [[ "${values[29]}" == 'ok' || "${values[29]}" == 'error' ]]; then
  [[ "${values[28]}" == 'ok' && "${values[19]}" != 'missing' ]] || fail 'Ollama inventory did not follow a successful fixed-endpoint API probe'
else
  [[ "${values[31]}" == 'false' ]] || fail 'unqueried Ollama inventory reported the expected model present'
fi
if [[ "${values[18]}" != 'ok' ]]; then
  ((values[13] == 0)) || fail 'failed or unavailable GPU probe reported GPUs'
fi

expected_telemetry='core_unready'
if [[ "${values[35]}" == 'active' && "${values[36]}" == 'true' ]] && \
  ready_pair_complete "${values[37]}" && ready_pair_complete "${values[38]}" && ready_pair_complete "${values[39]}"; then
  expected_telemetry='core_ready_partial_sources'
fi
[[ "${values[42]}" == "${expected_telemetry}" ]] || fail 'telemetry state contradicts its readiness evidence'

expected_safety='safe_not_ready'
if [[ "${values[25]}" == 'error' ]]; then
  expected_safety='safety_unverified'
elif [[ "${values[26]}" == 'unsafe_non_loopback' ]]; then
  expected_safety='unsafe_exposure'
elif [[ "${values[26]}" == 'loopback_only' ]]; then
  expected_safety='safe'
fi
[[ "${values[45]}" == "${expected_safety}" ]] || fail 'safety status contradicts the listener evidence'

expected_blockers=''
[[ "${values[21]}" == 'active' ]] || append_expected_blocker 'ollama_service_not_active'
[[ "${values[25]}" == 'ok' ]] || append_expected_blocker 'ollama_listener_probe_failed'
[[ "${values[26]}" == 'loopback_only' ]] || append_expected_blocker "ollama_binding_${values[26]}"
[[ "${values[27]}" != 'unavailable' ]] || append_expected_blocker 'ollama_api_unavailable'
[[ "${values[28]}" == 'ok' ]] || append_expected_blocker "ollama_api_${values[28]}"
[[ "${values[31]}" == 'true' ]] || append_expected_blocker 'expected_model_absent'
[[ "${values[29]}" == 'ok' ]] || append_expected_blocker "ollama_inventory_${values[29]}"
if is_uint "${values[34]}" && ((values[34] > 0)); then
  append_expected_blocker 'models_already_loaded'
fi
[[ "${values[7]}" == 'true' ]] || append_expected_blocker 'clock_not_synchronized'
[[ "${values[18]}" == 'ok' ]] || append_expected_blocker "gpu_probe_${values[18]}"
((values[13] > 0)) || append_expected_blocker 'gpu_unavailable'
append_expected_blocker 'target_lab_unconfigured'
ready_pair_complete "${values[40]}" || append_expected_blocker 'hubble_relay_unready'
append_expected_blocker 'canarysting_runtime_unconfigured'
[[ "${values[42]}" == 'core_ready_partial_sources' ]] || append_expected_blocker 'core_telemetry_unready'
append_expected_blocker 'bounded_attacker_harness_unimplemented'
[[ "${values[44]}" == "${expected_blockers}" ]] || fail 'execution blockers do not exactly match the observed prerequisites'

if ((summary)); then
  printf 'report_version=%s\n' "${values[0]}"
  printf 'inspection_utc=%s\n' "${values[5]}"
  printf 'ollama_listener_probe_status=%s\n' "${values[25]}"
  printf 'ollama_binding=%s\n' "${values[26]}"
  printf 'ollama_api_probe_status=%s\n' "${values[28]}"
  printf 'ollama_inventory_status=%s\n' "${values[29]}"
  printf 'expected_model_present=%s\n' "${values[31]}"
  printf 'loaded_model_count=%s\n' "${values[34]}"
  printf 'target_lab_status=%s\n' "${values[41]}"
  printf 'telemetry_state=%s\n' "${values[42]}"
  printf 'live_scenario_ready=%s\n' "${values[43]}"
  printf 'execution_blockers=%s\n' "${values[44]}"
  printf 'safety_status=%s\n' "${values[45]}"
else
  cat "${report_file}"
fi

[[ "${values[25]}" != 'error' ]] || fail 'Ollama listener probe failed; exposure safety is unverified'
[[ "${values[26]}" != 'unsafe_non_loopback' ]] || fail 'Ollama is exposed beyond loopback; live execution is blocked'
[[ "${values[28]}" != 'error' ]] || fail 'Ollama API probe failed; readiness is unverified'
[[ "${values[29]}" != 'error' ]] || fail 'Ollama inventory failed; readiness is unverified'
[[ "${values[18]}" != 'error' ]] || fail 'GPU inventory failed; readiness is unverified'
printf 'm2c1_inspection=PASS\n'
