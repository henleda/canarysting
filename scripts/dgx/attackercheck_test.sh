#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
mkdir -p "${fixture_root}/bin"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cat >"${fixture_root}/bin/ssh" <<'FAKE_SSH'
#!/usr/bin/env bash
set -euo pipefail
: "${CANARYSTING_ATTACKERCHECK_FIXTURE:?fixture is required}"
if [[ -n "${CANARYSTING_ATTACKERCHECK_SSH_MARKER:-}" ]]; then
  printf 'invoked\n' >>"${CANARYSTING_ATTACKERCHECK_SSH_MARKER}"
fi
if [[ -n "${CANARYSTING_ATTACKERCHECK_SSH_ARGS:-}" ]]; then
  printf '%s\n' "$*" >"${CANARYSTING_ATTACKERCHECK_SSH_ARGS}"
fi
if [[ -n "${CANARYSTING_ATTACKERCHECK_REMOTE_BODY:-}" ]]; then
  tee "${CANARYSTING_ATTACKERCHECK_REMOTE_BODY}" >/dev/null
else
  cat >/dev/null
fi
cat -- "${CANARYSTING_ATTACKERCHECK_FIXTURE}"
FAKE_SSH
chmod +x "${fixture_root}/bin/ssh"

write_safe_fixture() {
  local destination="$1" epoch timestamp
  epoch="$(date -u +%s)"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat >"${destination}" <<EOF
report_version=2
hostname=spark-5343
architecture=aarch64
os_id=ubuntu-24.04
kernel=6.17.0-1032-nvidia
inspection_utc=${timestamp}
inspection_epoch=${epoch}
ntp_synchronized=true
timezone=America/Chicago
cpu_count=20
memory_total_kib=125000000
memory_available_kib=100000000
root_available_kib=3500000000
gpu_count=1
gpu_name=NVIDIA GB10
gpu_driver_version=580.95.05
gpu_memory_total_mib=unavailable
gpu_memory_free_mib=unavailable
gpu_probe_status=ok
ollama_cli_path=/usr/local/bin/ollama
ollama_cli_version=0.11.10
ollama_service_active=active
ollama_service_enabled=enabled
ollama_service_user=ollama
ollama_listener_addresses=127.0.0.1:11434
ollama_listener_probe_status=ok
ollama_binding=loopback_only
ollama_api_version=0.11.10
ollama_api_probe_status=ok
ollama_inventory_status=ok
expected_model=qwen3-coder:30b-a3b-q8_0
expected_model_present=true
expected_model_id=abc123
expected_model_size=32GB
loaded_model_count=0
k3s_service_active=active
node_ready=true
cilium_daemonset_ready=1/1
cilium_operator_ready=1/1
cilium_envoy_ready=1/1
hubble_relay_ready=1/1
target_lab_status=unconfigured
telemetry_state=core_ready_partial_sources
live_scenario_ready=false
execution_blockers=target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented
safety_status=safe
EOF
}

safe_fixture="${fixture_root}/safe.report"
write_safe_fixture "${safe_fixture}"

ssh_marker="${fixture_root}/ssh.marker"
dry_output="$(PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${safe_fixture}" CANARYSTING_ATTACKERCHECK_SSH_MARKER="${ssh_marker}" "${script_dir}/attackercheck.sh" --dry-run)"
grep -Fqx 'model_execution=disabled' <<<"${dry_output}"
grep -Fqx 'remote_mutation=none' <<<"${dry_output}"
grep -Fq 'DGX was not accessed' <<<"${dry_output}"
[[ ! -e "${ssh_marker}" ]] || { echo 'FAIL: dry run invoked SSH' >&2; exit 1; }

ssh_args="${fixture_root}/ssh.args"
remote_body="${fixture_root}/remote.sh"
safe_output="$(PATH="${fixture_root}/bin:${PATH}" \
  CANARYSTING_ATTACKERCHECK_FIXTURE="${safe_fixture}" \
  CANARYSTING_ATTACKERCHECK_SSH_ARGS="${ssh_args}" \
  CANARYSTING_ATTACKERCHECK_REMOTE_BODY="${remote_body}" \
  "${script_dir}/attackercheck.sh")"
grep -Fqx 'expected_model_present=true' <<<"${safe_output}"
grep -Fqx 'loaded_model_count=0' <<<"${safe_output}"
grep -Fqx 'live_scenario_ready=false' <<<"${safe_output}"
grep -Fqx 'm2c1_inspection=PASS' <<<"${safe_output}"

bash -n "${remote_body}"
readonly approved_remote_body_sha256='162d72cb1554a809e8c69da7723b395c29290a12e45fc84013b5717895406826'
[[ "$(sha256_file "${remote_body}")" == "${approved_remote_body_sha256}" ]] || {
  echo 'FAIL: captured remote program differs from the exact reviewed body' >&2
  exit 1
}
grep -Fq 'ServerAliveInterval=5' "${ssh_args}"
grep -Fq 'ServerAliveCountMax=3' "${ssh_args}"
grep -Fq 'timeout --signal=TERM --kill-after=5s 45s bash -s' "${ssh_args}"
grep -Fq 'OLLAMA_HOST=http://127.0.0.1:11434' "${remote_body}"
grep -Fq -- "--noproxy '*' --proto '=http'" "${remote_body}"
grep -Fq 'curl -q --fail --silent --show-error' "${remote_body}"
grep -Fq 'kubectl --request-timeout=5s' "${remote_body}"
grep -Fq 'ollama_local list' "${remote_body}"
grep -Fq 'ollama_local ps' "${remote_body}"
grep -Fq 'systemctl_read show ollama -p MainPID --value' "${remote_body}"
grep -Fq 'systemctl_read show ollama -p InvocationID --value' "${remote_body}"
grep -Fq 'stable_ollama_snapshot' "${remote_body}"
grep -Fq 'collect_ollama_endpoint_evidence' "${remote_body}"
grep -Fq 'invalidate_ollama_evidence state_changed' "${remote_body}"
grep -Fq 'timeout --signal=TERM --kill-after=2s 8s sudo -n ss -H -lntp' "${remote_body}"
grep -Fq 'index($0, "pid=" wanted ",") {print $4}' "${remote_body}"
grep -Fq "target_lab_status='unconfigured'" "${remote_body}"

extract_sensitive_calls() {
  LC_ALL=C grep -E '(^|[^[:alnum:]_])(systemctl_read|kctl|ollama_local|curl_local|listener_inventory|owned_listener_addresses|stable_ollama_snapshot|collect_ollama_endpoint_evidence|timedate_read|gpu_inventory|systemctl|kubectl|ollama|curl|ss|timedatectl|nvidia-smi|bpftool|cilium|iptables|nft|sudo|env|timeout)([^[:alnum:]_]|$)' "$1"
}

sensitive_calls="${fixture_root}/sensitive-calls.actual"
extract_sensitive_calls "${remote_body}" >"${sensitive_calls}"
sensitive_calls_expected="${fixture_root}/sensitive-calls.expected"
cat >"${sensitive_calls_expected}" <<'SENSITIVE_CALLS'
systemctl_read() {
  if [[ $# -eq 2 && "${1-}" == 'is-active' && ("${2-}" == 'ollama' || "${2-}" == 'k3s') ]]; then
  elif [[ $# -eq 2 && "${1-}" == 'is-enabled' && "${2-}" == 'ollama' ]]; then
  elif [[ $# -eq 5 && "${1-}" == 'show' && "${2-}" == 'ollama' && "${3-}" == '-p' && \
  timeout --signal=TERM --kill-after=2s 8s systemctl "$@"
kctl() {
    "${4-}" == 'daemonset' && ("${5-}" == 'cilium' || "${5-}" == 'cilium-envoy') && "${6-}" == '-o' && \
    "${4-}" == 'deployment' && ("${5-}" == 'cilium-operator' || "${5-}" == 'hubble-relay') && "${6-}" == '-o' && \
  timeout --signal=TERM --kill-after=2s 8s sudo -n k3s kubectl --request-timeout=5s "$@"
ollama_local() {
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    timeout --signal=TERM --kill-after=2s 8s ollama "$@"
curl_local() {
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    timeout --signal=TERM --kill-after=2s 8s \
    curl -q --fail --silent --show-error --connect-timeout 2 --max-time 5 \
listener_inventory() {
  timeout --signal=TERM --kill-after=2s 8s sudo -n ss -H -lntp
owned_listener_addresses() {
  listener_inventory "${service_pid}" | \
stable_ollama_snapshot() {
  active_before="$(systemctl_read is-active ollama 2>/dev/null)" || return 75
  pid_before="$(systemctl_read show ollama -p MainPID --value 2>/dev/null)" || return 75
  invocation_before="$(systemctl_read show ollama -p InvocationID --value 2>/dev/null)" || return 75
  listener_lines="$(owned_listener_addresses "${pid_before}")" || return 74
  active_after="$(systemctl_read is-active ollama 2>/dev/null)" || return 75
  pid_after="$(systemctl_read show ollama -p MainPID --value 2>/dev/null)" || return 75
  invocation_after="$(systemctl_read show ollama -p InvocationID --value 2>/dev/null)" || return 75
collect_ollama_endpoint_evidence() {
  if ! have ss; then
  if initial_snapshot="$(stable_ollama_snapshot 2>/dev/null)"; then
    elif have curl && api_json="$(curl_local http://127.0.0.1:11434/api/version 2>/dev/null)"; then
  if have ollama && [[ "${ollama_api_version}" != 'unavailable' ]]; then
    if model_list="$(ollama_local list 2>/dev/null)" && loaded_models="$(ollama_local ps 2>/dev/null)"; then
    if final_snapshot="$(stable_ollama_snapshot 2>/dev/null)"; then
timedate_read() {
  timeout --signal=TERM --kill-after=2s 8s timedatectl show -p "$1" --value
gpu_inventory() {
  timeout --signal=TERM --kill-after=2s 8s \
    nvidia-smi --query-gpu=name,driver_version,memory.total,memory.free --format=csv,noheader,nounits
  desired="$(kctl -n kube-system get daemonset "${name}" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || true)"
  ready="$(kctl -n kube-system get daemonset "${name}" -o jsonpath='{.status.numberReady}' 2>/dev/null || true)"
  desired="$(kctl -n kube-system get deployment "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  ready="$(kctl -n kube-system get deployment "${name}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
ntp_synchronized="$(timedate_read NTPSynchronized 2>/dev/null || true)"
timezone="$(timedate_read Timezone 2>/dev/null || true)"
if have nvidia-smi; then
  if gpu_lines="$(gpu_inventory 2>/dev/null)"; then
ollama_service_active="$(systemctl_read is-active ollama 2>/dev/null || true)"
ollama_service_enabled="$(systemctl_read is-enabled ollama 2>/dev/null || true)"
ollama_service_user="$(systemctl_read show ollama -p User --value 2>/dev/null || true)"
if have ollama; then
  ollama_cli_path="$(command -v ollama)"
  ollama_version_output="$(ollama_local --version 2>/dev/null || true)"
collect_ollama_endpoint_evidence
k3s_service_active="$(systemctl_read is-active k3s 2>/dev/null || true)"
  node_ready="$(kctl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' 2>/dev/null || true)"
  cilium_daemonset_ready="$(daemonset_ready cilium)"
  cilium_operator_ready="$(deployment_ready cilium-operator)"
  cilium_envoy_ready="$(daemonset_ready cilium-envoy)"
SENSITIVE_CALLS
if ! diff -u "${sensitive_calls_expected}" "${sensitive_calls}"; then
  echo 'FAIL: remote sensitive operations differ from the exact read-only call-site allowlist' >&2
  exit 1
fi
if LC_ALL=C grep -En '(^|[;&|()[:space:]/])(rm|mv|cp|install|mkdir|touch|truncate|tee|dd|chmod|chown|chgrp|systemd-run|service|pkill|mount|umount|sysctl|modprobe|insmod|rmmod)([;&|()[:space:]]|$)' "${remote_body}"; then
  echo 'FAIL: remote body contains a state-changing call outside the read-only allowlist' >&2
  exit 1
fi
unauthorized_remote="${fixture_root}/remote-unauthorized.sh"
cp "${remote_body}" "${unauthorized_remote}"
printf '%s\n' 'systemctl --user restart ollama' >>"${unauthorized_remote}"
extract_sensitive_calls "${unauthorized_remote}" >"${fixture_root}/sensitive-calls.unauthorized"
if cmp -s "${sensitive_calls_expected}" "${fixture_root}/sensitive-calls.unauthorized"; then
  echo 'FAIL: exact call-site allowlist accepted a direct sensitive command' >&2
  exit 1
fi
printf '%s\n' 'touch /tmp/canarysting-forbidden-mutation' >>"${unauthorized_remote}"
if ! LC_ALL=C grep -Eq '(^|[;&|()[:space:]/])(rm|mv|cp|install|mkdir|touch|truncate|tee|dd|chmod|chown|chgrp|systemd-run|service|pkill|mount|umount|sysctl|modprobe|insmod|rmmod)([;&|()[:space:]]|$)' "${unauthorized_remote}"; then
  echo 'FAIL: remote mutation guard accepted a direct state-changing command' >&2
  exit 1
fi
unlisted_executor_remote="${fixture_root}/remote-unlisted-executor.sh"
cp "${remote_body}" "${unlisted_executor_remote}"
printf '%s\n' 'python3 -c '\''open("/tmp/canarysting-forbidden-mutation","w").write("x")'\''' >>"${unlisted_executor_remote}"
[[ "$(sha256_file "${unlisted_executor_remote}")" != "${approved_remote_body_sha256}" ]] || {
  echo 'FAIL: exact reviewed-body guard accepted an unlisted mutating executor' >&2
  exit 1
}

extract_remote_function() {
  local function_name="$1" destination="$2"
  awk -v declaration="${function_name}() {" '
    $0 == declaration {inside=1}
    inside {print}
    inside && $0 == "}" {found=1; exit}
    END {if (!found) exit 1}
  ' "${remote_body}" >"${destination}"
  bash -n "${destination}"
}

policy_marker="${fixture_root}/policy.marker"
assert_policy_rejects() {
  local policy_function="$1"
  shift
  local function_file="${fixture_root}/${policy_function}.sh"
  extract_remote_function "${policy_function}" "${function_file}"
  : >"${policy_marker}"
  if (
    source "${function_file}"
    timeout() { printf 'timeout %s\n' "$*" >>"${policy_marker}"; return 0; }
    env() { printf 'env %s\n' "$*" >>"${policy_marker}"; return 0; }
    "${policy_function}" "$@"
  ); then
    printf 'FAIL: remote allowlist accepted: %s %s\n' "${policy_function}" "$*" >&2
    exit 1
  fi
  if [[ -s "${policy_marker}" ]]; then
    printf 'FAIL: rejected remote command reached an executable: %s %s\n' "${policy_function}" "$*" >&2
    exit 1
  fi
}

assert_policy_rejects systemctl_read --user restart ollama
assert_policy_rejects kctl -n default get secret/admin -o yaml
assert_policy_rejects kctl get --raw /api/v1/namespaces/default/secrets
assert_policy_rejects kctl -n x label pod p x=y
assert_policy_rejects kctl -n x run p --image=busybox
assert_policy_rejects ollama_local stop
assert_policy_rejects ollama_local pull qwen3-coder:30b-a3b-q8_0
assert_policy_rejects curl_local http://0.0.0.0:11434/api/version
assert_policy_rejects listener_inventory 0
assert_policy_rejects timedate_read Environment
assert_policy_rejects gpu_inventory --list-gpus

curl_function="${fixture_root}/curl_local.sh"
extract_remote_function curl_local "${curl_function}"
hostile_curl_home="${fixture_root}/hostile-curl-home"
mkdir -p "${hostile_curl_home}"
printf '%s\n' 'url = http://127.0.0.1:65535/alternate' >"${hostile_curl_home}/.curlrc"
hostile_curl_marker="${fixture_root}/hostile-curl.marker"
curl_fixture_bin="${fixture_root}/curl-bin"
mkdir -p "${curl_fixture_bin}"
cat >"${curl_fixture_bin}/timeout" <<'FAKE_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
while [[ "${1-}" != 'curl' ]]; do shift; done
exec "$@"
FAKE_TIMEOUT
cat >"${curl_fixture_bin}/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f "${HOSTILE_CURL_CONFIG}" && \
  ("${1-}" != '-q' || -n "${CURL_HOME+x}" || -n "${XDG_CONFIG_HOME+x}") ]]; then
  : >"${HOSTILE_CURL_MARKER}"
fi
printf '%s\n' '{"version":"0.11.10"}'
FAKE_CURL
chmod +x "${curl_fixture_bin}/timeout" "${curl_fixture_bin}/curl"
curl_output="$({
  source "${curl_function}"
  PATH="${curl_fixture_bin}:${PATH}" CURL_HOME="${hostile_curl_home}" XDG_CONFIG_HOME="${hostile_curl_home}" \
    HOSTILE_CURL_CONFIG="${hostile_curl_home}/.curlrc" \
    HOSTILE_CURL_MARKER="${hostile_curl_marker}" \
    curl_local http://127.0.0.1:11434/api/version
})"
[[ "${curl_output}" == '{"version":"0.11.10"}' ]] || {
  echo 'FAIL: fixed curl wrapper did not complete its read-only probe' >&2
  exit 1
}
[[ ! -e "${hostile_curl_marker}" ]] || {
  echo 'FAIL: ambient curl configuration changed the fixed read-only transfer' >&2
  exit 1
}

owned_listener_function="${fixture_root}/owned_listener_addresses.sh"
extract_remote_function owned_listener_addresses "${owned_listener_function}"
alternate_port_listeners="$(
  source "${owned_listener_function}"
  listener_inventory() {
    printf '%s\n' \
      'LISTEN 0 4096 0.0.0.0:22434 0.0.0.0:* users:(("ollama",pid=4242,fd=3))' \
      'LISTEN 0 4096 127.0.0.1:11434 0.0.0.0:* users:(("ollama",pid=4242,fd=4))' \
      'LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:(("other",pid=4243,fd=5))'
  }
  owned_listener_addresses 4242
)"
[[ "${alternate_port_listeners}" == $'0.0.0.0:22434\n127.0.0.1:11434' ]] || {
  echo 'FAIL: process-owned listener discovery missed an alternate Ollama port or included another PID' >&2
  exit 1
}

stable_listener_function="${fixture_root}/stable_ollama_snapshot.sh"
extract_remote_function stable_ollama_snapshot "${stable_listener_function}"
pid_turnover_marker="${fixture_root}/pid-turnover.marker"
set +e
turnover_output="$({
  source "${stable_listener_function}"
  systemctl_read() {
    if [[ "$*" == 'is-active ollama' ]]; then
      printf '%s\n' active
    elif [[ "$*" == 'show ollama -p MainPID --value' ]]; then
      if [[ -e "${pid_turnover_marker}" ]]; then
        printf '%s\n' 5252
      else
        : >"${pid_turnover_marker}"
        printf '%s\n' 4242
      fi
    elif [[ "$*" == 'show ollama -p InvocationID --value' ]]; then
      printf '%s\n' 0123456789abcdef0123456789abcdef
    else
      return 64
    fi
  }
  owned_listener_addresses() { printf '%s\n' '127.0.0.1:11434'; }
  stable_ollama_snapshot
})"
turnover_status=$?
set -e
[[ -z "${turnover_output}" && "${turnover_status}" == '75' ]] || {
  echo 'FAIL: Ollama PID turnover did not invalidate the listener snapshot' >&2
  exit 1
}

invalidate_function="${fixture_root}/invalidate_ollama_evidence.sh"
collect_endpoint_function="${fixture_root}/collect_ollama_endpoint_evidence.sh"
extract_remote_function invalidate_ollama_evidence "${invalidate_function}"
extract_remote_function collect_ollama_endpoint_evidence "${collect_endpoint_function}"
query_window_marker="${fixture_root}/query-window.marker"
query_turnover_output="$({
  source "${invalidate_function}"
  source "${collect_endpoint_function}"
  expected_model='qwen3-coder:30b-a3b-q8_0'
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
  ollama_fixed_api_socket_owned='false'
  ollama_snapshot_pid='unavailable'
  ollama_snapshot_invocation='unavailable'
  have() { [[ "$1" == 'ss' || "$1" == 'curl' || "$1" == 'ollama' ]]; }
  stable_ollama_snapshot() {
    if [[ -e "${query_window_marker}" ]]; then
      printf '%s\n' '5252|fedcba9876543210fedcba9876543210|0.0.0.0:22434,127.0.0.1:11434'
    else
      printf '%s\n' '4242|0123456789abcdef0123456789abcdef|127.0.0.1:11434'
    fi
  }
  curl_local() {
    : >"${query_window_marker}"
    printf '%s\n' '{"version":"0.11.10"}'
  }
  ollama_local() {
    if [[ "$1" == 'list' ]]; then
      printf '%s\n' 'NAME ID SIZE' 'qwen3-coder:30b-a3b-q8_0 abc123 32 GB'
    elif [[ "$1" == 'ps' ]]; then
      printf '%s\n' 'NAME ID SIZE PROCESSOR UNTIL'
    else
      return 64
    fi
  }
  collect_ollama_endpoint_evidence
  printf '%s\n' "${ollama_listener_probe_status}" "${ollama_binding}" \
    "${ollama_api_probe_status}" "${ollama_inventory_status}" \
    "${expected_model_present}" "${loaded_model_count}"
})"
[[ "${query_turnover_output}" == $'state_changed\nprobe_error\ninvalidated\ninvalidated\nfalse\nunavailable' ]] || {
  echo 'FAIL: Ollama turnover during API/model queries did not invalidate the full evidence window' >&2
  exit 1
}

summary_output="$(PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${safe_fixture}" "${script_dir}/attackercheck.sh" --summary)"
grep -Fqx 'report_version=2' <<<"${summary_output}"
grep -Fqx 'safety_status=safe' <<<"${summary_output}"
grep -Fqx 'm2c1_inspection=PASS' <<<"${summary_output}"
[[ "$(wc -l <<<"${summary_output}" | tr -d ' ')" == '14' ]] || { echo 'FAIL: CI summary is not minimized to 14 lines' >&2; exit 1; }
if grep -Eq '^(hostname|expected_model_id|ollama_service_user|canarysting_resource_count|matching_test_pod_count)=' <<<"${summary_output}"; then
  echo 'FAIL: CI summary includes full inventory details' >&2
  exit 1
fi

not_ready_fixture="${fixture_root}/not-ready.report"
awk '
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^execution_blockers=/ {$0="execution_blockers=expected_model_absent,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  {print}
' "${safe_fixture}" >"${not_ready_fixture}"
not_ready_output="$(PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${not_ready_fixture}" "${script_dir}/attackercheck.sh")"
grep -Fqx 'expected_model_present=false' <<<"${not_ready_output}"
grep -Fqx 'm2c1_inspection=PASS' <<<"${not_ready_output}"

unsafe_fixture="${fixture_root}/unsafe.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=0.0.0.0:22434"}
  /^ollama_binding=/ {$0="ollama_binding=unsafe_non_loopback"}
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=not_queried"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=not_queried"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_binding_unsafe_non_loopback,ollama_api_unavailable,ollama_api_not_queried,expected_model_absent,ollama_inventory_not_queried,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  /^safety_status=/ {$0="safety_status=unsafe_exposure"}
  {print}
' "${safe_fixture}" >"${unsafe_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${unsafe_fixture}" "${script_dir}/attackercheck.sh" >"${fixture_root}/unsafe.out" 2>"${fixture_root}/unsafe.err"; then
  echo 'FAIL: unsafe Ollama exposure was accepted' >&2
  exit 1
fi
grep -Fq 'live execution is blocked' "${fixture_root}/unsafe.err"

probe_error_fixture="${fixture_root}/probe-error.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=unavailable"}
  /^ollama_listener_probe_status=/ {$0="ollama_listener_probe_status=error"}
  /^ollama_binding=/ {$0="ollama_binding=probe_error"}
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=not_queried"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=not_queried"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_listener_probe_failed,ollama_binding_probe_error,ollama_api_unavailable,ollama_api_not_queried,expected_model_absent,ollama_inventory_not_queried,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  /^safety_status=/ {$0="safety_status=safety_unverified"}
  {print}
' "${safe_fixture}" >"${probe_error_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${probe_error_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/probe-error.err"; then
  echo 'FAIL: failed listener probe was accepted' >&2
  exit 1
fi
grep -Fq 'exposure safety is unverified' "${fixture_root}/probe-error.err"

inventory_error_fixture="${fixture_root}/inventory-error.report"
awk '
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=error"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=expected_model_absent,ollama_inventory_error,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  {print}
' "${safe_fixture}" >"${inventory_error_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${inventory_error_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/inventory-error.err"; then
  echo 'FAIL: failed Ollama inventory was accepted' >&2
  exit 1
fi
grep -Fq 'Ollama inventory failed' "${fixture_root}/inventory-error.err"

api_error_fixture="${fixture_root}/api-error.report"
awk '
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=error"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=not_queried"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_api_unavailable,ollama_api_error,expected_model_absent,ollama_inventory_not_queried,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  {print}
' "${safe_fixture}" >"${api_error_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${api_error_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/api-error.err"; then
  echo 'FAIL: failed Ollama API probe was accepted' >&2
  exit 1
fi
grep -Fq 'Ollama API probe failed' "${fixture_root}/api-error.err"

api_ownership_fixture="${fixture_root}/api-ownership.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=127.0.0.1:22434"}
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=ownership_mismatch"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=not_queried"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_api_unavailable,ollama_api_ownership_mismatch,expected_model_absent,ollama_inventory_not_queried,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  {print}
' "${safe_fixture}" >"${api_ownership_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${api_ownership_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/api-ownership.err"; then
  echo 'FAIL: fixed Ollama API endpoint owned by another process was accepted' >&2
  exit 1
fi
grep -Fq 'fixed Ollama API socket is not owned by the inspected service' "${fixture_root}/api-ownership.err"

identity_changed_fixture="${fixture_root}/identity-changed.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=unavailable"}
  /^ollama_listener_probe_status=/ {$0="ollama_listener_probe_status=identity_changed"}
  /^ollama_binding=/ {$0="ollama_binding=probe_error"}
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=not_queried"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=not_queried"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_listener_probe_failed,ollama_binding_probe_error,ollama_api_unavailable,ollama_api_not_queried,expected_model_absent,ollama_inventory_not_queried,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  /^safety_status=/ {$0="safety_status=safety_unverified"}
  {print}
' "${safe_fixture}" >"${identity_changed_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${identity_changed_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/identity-changed.err"; then
  echo 'FAIL: Ollama service identity turnover was accepted' >&2
  exit 1
fi
grep -Fq 'listener or service state changed' "${fixture_root}/identity-changed.err"

state_changed_fixture="${fixture_root}/state-changed.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=unavailable"}
  /^ollama_listener_probe_status=/ {$0="ollama_listener_probe_status=state_changed"}
  /^ollama_binding=/ {$0="ollama_binding=probe_error"}
  /^ollama_api_version=/ {$0="ollama_api_version=unavailable"}
  /^ollama_api_probe_status=/ {$0="ollama_api_probe_status=invalidated"}
  /^ollama_inventory_status=/ {$0="ollama_inventory_status=invalidated"}
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^loaded_model_count=/ {$0="loaded_model_count=unavailable"}
  /^execution_blockers=/ {$0="execution_blockers=ollama_listener_probe_failed,ollama_binding_probe_error,ollama_api_unavailable,ollama_api_invalidated,expected_model_absent,ollama_inventory_invalidated,target_lab_unconfigured,canarysting_runtime_unconfigured,bounded_attacker_harness_unimplemented"}
  /^safety_status=/ {$0="safety_status=safety_unverified"}
  {print}
' "${safe_fixture}" >"${state_changed_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${state_changed_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>"${fixture_root}/state-changed.err"; then
  echo 'FAIL: Ollama state change across the API/model window was accepted' >&2
  exit 1
fi
grep -Fq 'service state changed' "${fixture_root}/state-changed.err"

contradictory_fixture="${fixture_root}/contradictory.report"
awk '/^ollama_listener_addresses=/ {$0="ollama_listener_addresses=0.0.0.0:22434"} {print}' "${safe_fixture}" >"${contradictory_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${contradictory_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>&1; then
  echo 'FAIL: non-loopback listener was accepted as loopback-only' >&2
  exit 1
fi

missing_blocker_fixture="${fixture_root}/missing-blocker.report"
awk '/^ntp_synchronized=/ {$0="ntp_synchronized=false"} {print}' "${safe_fixture}" >"${missing_blocker_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${missing_blocker_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>&1; then
  echo 'FAIL: report omitted a blocker required by its facts' >&2
  exit 1
fi

authorized_fixture="${fixture_root}/authorized.report"
awk '/^live_scenario_ready=/ {$0="live_scenario_ready=true"} {print}' "${safe_fixture}" >"${authorized_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${authorized_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>&1; then
  echo 'FAIL: M2C.1 accepted live-scenario authorization' >&2
  exit 1
fi

malformed_fixture="${fixture_root}/malformed.report"
awk 'NR == 2 {line=$0; next} NR == 3 {print; print line; next} {print}' "${safe_fixture}" >"${malformed_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${malformed_fixture}" "${script_dir}/attackercheck.sh" >/dev/null 2>&1; then
  echo 'FAIL: reordered report fields were accepted' >&2
  exit 1
fi

if "${script_dir}/attackercheck.sh" --unexpected >/dev/null 2>&1; then
  echo 'FAIL: unknown argument was accepted' >&2
  exit 1
fi

printf 'PASS: read-only CanaryAttacker lab inspection contract\n'
