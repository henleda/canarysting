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
  scripts/dgx/attackercheck.sh [--dry-run]

Performs one fixed, read-only inspection of the DGX CanaryAttacker laboratory.
It never runs a model, sends a prompt, pulls a model, changes a service, reads a
Kubernetes Secret, or mutates Kubernetes, Cilium, BPF, firewall, or host state.
USAGE
}

dry_run=0
while (($#)); do
  case "$1" in
    --dry-run)
      dry_run=1
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
ssh -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes "${dgx_host}" 'bash -s' >"${report_file}" <<'REMOTE'
set -euo pipefail

readonly expected_model='qwen3-coder:30b-a3b-q8_0'

have() { command -v "$1" >/dev/null 2>&1; }
kctl() { sudo -n k3s kubectl "$@"; }
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
  blockers+=("$1")
}

. /etc/os-release
hostname_value="$(hostname)"
architecture="$(uname -m)"
kernel="$(uname -r)"
os_id="${ID:-unknown}-${VERSION_ID:-unknown}"
inspection_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
inspection_epoch="$(date -u +%s)"
ntp_synchronized="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
case "${ntp_synchronized,,}" in
  yes|true) ntp_synchronized='true' ;;
  no|false) ntp_synchronized='false' ;;
  *) ntp_synchronized='unknown' ;;
esac
timezone="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
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
if have nvidia-smi; then
  gpu_lines="$(nvidia-smi --query-gpu=name,driver_version,memory.total,memory.free --format=csv,noheader,nounits 2>/dev/null || true)"
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
fi

ollama_cli_path='missing'
ollama_cli_version='unavailable'
ollama_service_active="$(systemctl is-active ollama 2>/dev/null || true)"
ollama_service_enabled="$(systemctl is-enabled ollama 2>/dev/null || true)"
ollama_service_user="$(systemctl show ollama -p User --value 2>/dev/null || true)"
[[ -n "${ollama_service_active}" ]] || ollama_service_active='unknown'
[[ -n "${ollama_service_enabled}" ]] || ollama_service_enabled='unknown'
[[ -n "${ollama_service_user}" ]] || ollama_service_user='unknown'
ollama_listener_addresses='none'
ollama_binding='not_listening'
ollama_api_version='unavailable'
expected_model_present='false'
expected_model_id='absent'
expected_model_size='absent'
loaded_model_count=0

if have ollama; then
  ollama_cli_path="$(command -v ollama)"
  ollama_cli_version="$(ollama --version 2>/dev/null | tail -n1 | awk '{print $NF}' || true)"
  [[ -n "${ollama_cli_version}" ]] || ollama_cli_version='unavailable'
fi

listener_lines="$(ss -H -lnt 'sport = :11434' 2>/dev/null | awk '{print $4}' | sort -u || true)"
if [[ -n "${listener_lines}" ]]; then
  ollama_listener_addresses="$(paste -sd, <<<"${listener_lines}")"
  ollama_binding='loopback_only'
  while IFS= read -r listener; do
    case "${listener}" in
      127.0.0.1:11434|'[::1]:11434') ;;
      *) ollama_binding='unsafe_non_loopback' ;;
    esac
  done <<<"${listener_lines}"
fi

if [[ "${ollama_binding}" == 'loopback_only' ]] && have curl; then
  api_json="$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1:11434/api/version 2>/dev/null || true)"
  if [[ "${api_json}" =~ \"version\"[[:space:]]*:[[:space:]]*\"([0-9A-Za-z._+-]+)\" ]]; then
    ollama_api_version="${BASH_REMATCH[1]}"
  fi
fi

if have ollama && [[ "${ollama_api_version}" != 'unavailable' ]]; then
  model_line="$(ollama list 2>/dev/null | awk -v wanted="${expected_model}" '$1 == wanted {print; exit}' || true)"
  if [[ -n "${model_line}" ]]; then
    expected_model_present='true'
    expected_model_id="$(awk '{print $2}' <<<"${model_line}")"
    expected_model_size="$(awk '{print $3 $4}' <<<"${model_line}")"
  fi
  loaded_model_count="$(ollama ps 2>/dev/null | awk 'NR > 1 && NF {count++} END {print count+0}' || true)"
  [[ "${loaded_model_count}" =~ ^[0-9]+$ ]] || loaded_model_count=0
fi

k3s_service_active="$(systemctl is-active k3s 2>/dev/null || true)"
[[ -n "${k3s_service_active}" ]] || k3s_service_active='unknown'
node_ready='unknown'
cilium_daemonset_ready='unavailable'
cilium_operator_ready='unavailable'
cilium_envoy_ready='unavailable'
hubble_relay_present='false'
canarysting_resource_count=0
matching_test_pod_count=0
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
  if kctl -n kube-system get deployment hubble-relay >/dev/null 2>&1; then
    hubble_relay_present='true'
  fi
  canarysting_resource_count="$(kctl get all,networkpolicy -A -l app.kubernetes.io/part-of=canarysting -o name 2>/dev/null | awk 'NF {count++} END {print count+0}')"
  matching_test_pod_count="$(kctl get pods -A -o custom-columns=NAME:.metadata.name --no-headers 2>/dev/null | awk 'tolower($0) ~ /(canary|attacker|test|curl|netshoot)/ {count++} END {print count+0}')"
fi

if ((canarysting_resource_count == 0 && matching_test_pod_count == 0)); then
  target_lab_status='not_provisioned'
else
  target_lab_status='present_requires_scope_review'
fi

if [[ "${k3s_service_active}" == 'active' && "${node_ready}" == 'true' ]] && \
  pair_ready "${cilium_daemonset_ready}" && pair_ready "${cilium_operator_ready}" && pair_ready "${cilium_envoy_ready}"; then
  telemetry_state='core_ready_partial_sources'
else
  telemetry_state='core_unready'
fi

blockers=()
[[ "${ollama_service_active}" == 'active' ]] || append_blocker 'ollama_service_not_active'
[[ "${ollama_binding}" == 'loopback_only' ]] || append_blocker "ollama_binding_${ollama_binding}"
[[ "${ollama_api_version}" != 'unavailable' ]] || append_blocker 'ollama_api_unavailable'
[[ "${expected_model_present}" == 'true' ]] || append_blocker 'expected_model_absent'
[[ "${ntp_synchronized}" == 'true' ]] || append_blocker 'clock_not_synchronized'
((gpu_count > 0)) || append_blocker 'gpu_unavailable'
[[ "${target_lab_status}" == 'not_provisioned' ]] && append_blocker 'target_lab_not_provisioned'
[[ "${hubble_relay_present}" == 'true' ]] || append_blocker 'hubble_relay_absent'
((canarysting_resource_count > 0)) || append_blocker 'canarysting_runtime_absent'
[[ "${telemetry_state}" == 'core_ready_partial_sources' ]] || append_blocker 'core_telemetry_unready'
append_blocker 'bounded_attacker_harness_unimplemented'
execution_blockers="$(IFS=,; printf '%s' "${blockers[*]}")"
live_scenario_ready='false'

case "${ollama_binding}" in
  unsafe_non_loopback) safety_status='unsafe_exposure' ;;
  loopback_only) safety_status='safe' ;;
  *) safety_status='safe_not_ready' ;;
esac

printf 'report_version=1\n'
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
printf 'ollama_cli_path=%s\n' "${ollama_cli_path}"
printf 'ollama_cli_version=%s\n' "${ollama_cli_version}"
printf 'ollama_service_active=%s\n' "${ollama_service_active}"
printf 'ollama_service_enabled=%s\n' "${ollama_service_enabled}"
printf 'ollama_service_user=%s\n' "${ollama_service_user}"
printf 'ollama_listener_addresses=%s\n' "${ollama_listener_addresses}"
printf 'ollama_binding=%s\n' "${ollama_binding}"
printf 'ollama_api_version=%s\n' "${ollama_api_version}"
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
printf 'hubble_relay_present=%s\n' "${hubble_relay_present}"
printf 'canarysting_resource_count=%s\n' "${canarysting_resource_count}"
printf 'matching_test_pod_count=%s\n' "${matching_test_pod_count}"
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
  gpu_memory_total_mib gpu_memory_free_mib ollama_cli_path ollama_cli_version ollama_service_active
  ollama_service_enabled ollama_service_user ollama_listener_addresses ollama_binding ollama_api_version
  expected_model expected_model_present expected_model_id expected_model_size loaded_model_count k3s_service_active
  node_ready cilium_daemonset_ready cilium_operator_ready cilium_envoy_ready hubble_relay_present
  canarysting_resource_count matching_test_pod_count target_lab_status telemetry_state live_scenario_ready
  execution_blockers safety_status
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

[[ "${values[0]}" == '1' ]] || fail 'unsupported report version'
[[ "${values[1]}" == "${expected_host}" ]] || fail "unexpected DGX hostname ${values[1]}"
[[ "${values[2]}" == "${expected_arch}" ]] || fail "unexpected DGX architecture ${values[2]}"
[[ "${values[5]}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail 'inspection timestamp is not UTC RFC3339'
is_uint "${values[6]}" || fail 'inspection epoch is not numeric'
((values[6] >= local_before_epoch - 30 && values[6] <= local_after_epoch + 30)) || fail 'DGX clock is outside the bounded workstation observation window'
[[ "${values[7]}" == 'true' || "${values[7]}" == 'false' || "${values[7]}" == 'unknown' ]] || fail 'invalid NTP synchronization state'
for numeric_index in 9 10 11 12 13 30 37 38; do
  is_uint "${values[numeric_index]}" || fail "${expected_keys[numeric_index]} is not numeric"
done
for gpu_index in 16 17; do
  is_uint "${values[gpu_index]}" || [[ "${values[gpu_index]}" == 'unavailable' ]] || fail "${expected_keys[gpu_index]} is invalid"
done
[[ "${values[20]}" == 'active' || "${values[20]}" == 'inactive' || "${values[20]}" == 'failed' || "${values[20]}" == 'unknown' ]] || fail 'invalid Ollama service state'
[[ "${values[21]}" == 'enabled' || "${values[21]}" == 'disabled' || "${values[21]}" == 'static' || "${values[21]}" == 'indirect' || "${values[21]}" == 'unknown' ]] || fail 'invalid Ollama enablement state'
[[ "${values[24]}" == 'loopback_only' || "${values[24]}" == 'not_listening' || "${values[24]}" == 'unsafe_non_loopback' ]] || fail 'invalid Ollama binding classification'
[[ "${values[26]}" == "${expected_model}" ]] || fail 'remote report changed the expected model'
is_bool "${values[27]}" || fail 'invalid expected-model presence state'
[[ "${values[31]}" == 'active' || "${values[31]}" == 'inactive' || "${values[31]}" == 'failed' || "${values[31]}" == 'unknown' ]] || fail 'invalid K3s service state'
[[ "${values[32]}" == 'true' || "${values[32]}" == 'false' || "${values[32]}" == 'unknown' ]] || fail 'invalid node readiness state'
for pair_index in 33 34 35; do
  is_ready_pair "${values[pair_index]}" || fail "${expected_keys[pair_index]} is invalid"
done
is_bool "${values[36]}" || fail 'invalid Hubble Relay state'
[[ "${values[39]}" == 'not_provisioned' || "${values[39]}" == 'present_requires_scope_review' ]] || fail 'invalid target-lab state'
[[ "${values[40]}" == 'core_ready_partial_sources' || "${values[40]}" == 'core_unready' ]] || fail 'invalid telemetry state'
[[ "${values[41]}" == 'false' ]] || fail 'M2C.1 must never authorize a live scenario'
[[ "${values[43]}" == 'safe' || "${values[43]}" == 'safe_not_ready' || "${values[43]}" == 'unsafe_exposure' ]] || fail 'invalid safety status'

if [[ "${values[24]}" == 'loopback_only' ]]; then
  [[ "${values[23]}" != 'none' ]] || fail 'loopback classification has no listener'
  old_ifs="${IFS}"
  IFS=','
  read -r -a listeners <<<"${values[23]}"
  IFS="${old_ifs}"
  for listener in "${listeners[@]}"; do
    case "${listener}" in
      127.0.0.1:11434|'[::1]:11434') ;;
      *) fail "non-loopback Ollama listener ${listener} was classified as safe" ;;
    esac
  done
fi

cat "${report_file}"
[[ "${values[24]}" != 'unsafe_non_loopback' && "${values[43]}" != 'unsafe_exposure' ]] || fail 'Ollama is exposed beyond loopback; live execution is blocked'
printf 'm2c1_inspection=PASS\n'
