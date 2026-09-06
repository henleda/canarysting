#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
mkdir -p "${fixture_root}/bin"

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
grep -Fq 'ServerAliveInterval=5' "${ssh_args}"
grep -Fq 'ServerAliveCountMax=3' "${ssh_args}"
grep -Fq 'timeout --signal=TERM --kill-after=5s 45s bash -s' "${ssh_args}"
grep -Fq 'OLLAMA_HOST=http://127.0.0.1:11434' "${remote_body}"
grep -Fq -- "--noproxy '*' --proto '=http'" "${remote_body}"
grep -Fq 'kubectl --request-timeout=5s' "${remote_body}"
grep -Fq 'ollama_local list' "${remote_body}"
grep -Fq 'ollama_local ps' "${remote_body}"
grep -Fq "target_lab_status='unconfigured'" "${remote_body}"
if grep -Eq 'bpftool|feature[[:space:]]+probe|/sys/fs/bpf' "${remote_body}"; then
  echo 'FAIL: passive inspection contains a BPF probe or pin-path access' >&2
  exit 1
fi
if grep -Eq '(^|[;&|[:space:]])ollama[[:space:]]+(list|ps|run|pull|create|rm|serve)([[:space:]]|$)' "${remote_body}"; then
  echo 'FAIL: remote checker bypasses the loopback-pinned Ollama wrapper or mutates model state' >&2
  exit 1
fi
if grep -Eq 'systemctl[[:space:]]+(start|stop|restart|reload|enable|disable|mask|unmask)([[:space:]]|$)' "${remote_body}"; then
  echo 'FAIL: remote checker contains a service mutation command' >&2
  exit 1
fi
if grep -Eq 'kctl([^[:alnum:]_]|$).*(^|[[:space:]])(apply|create|delete|edit|patch|replace|rollout|scale|set)([[:space:]]|$)' "${remote_body}"; then
  echo 'FAIL: remote checker contains an option-bearing Kubernetes mutation command' >&2
  exit 1
fi
if grep -Eqi '(kctl|kubectl).*([[:space:]]secret(s)?([[:space:]]|$)|kubeconfig)|/etc/rancher/k3s/k3s\.yaml' "${remote_body}"; then
  echo 'FAIL: remote checker attempts to read credentials or Secret data' >&2
  exit 1
fi
if grep -Eq '(^|[;&|[:space:]])(rm|mv|cp|chmod|chown|mkdir|rmdir|touch|truncate|mount|umount|iptables|nft|bpftool)([[:space:]]|$)' "${remote_body}"; then
  echo 'FAIL: remote checker contains a host, filesystem, firewall, or BPF mutation command' >&2
  exit 1
fi

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
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=0.0.0.0:11434"}
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

contradictory_fixture="${fixture_root}/contradictory.report"
awk '/^ollama_listener_addresses=/ {$0="ollama_listener_addresses=0.0.0.0:11434"} {print}' "${safe_fixture}" >"${contradictory_fixture}"
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
