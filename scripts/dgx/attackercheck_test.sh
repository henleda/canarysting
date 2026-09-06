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
cat -- "${CANARYSTING_ATTACKERCHECK_FIXTURE}"
FAKE_SSH
chmod +x "${fixture_root}/bin/ssh"

write_safe_fixture() {
  local destination="$1" epoch timestamp
  epoch="$(date -u +%s)"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat >"${destination}" <<EOF
report_version=1
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
ollama_cli_path=/usr/local/bin/ollama
ollama_cli_version=0.11.10
ollama_service_active=active
ollama_service_enabled=enabled
ollama_service_user=ollama
ollama_listener_addresses=127.0.0.1:11434
ollama_binding=loopback_only
ollama_api_version=0.11.10
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
hubble_relay_present=false
canarysting_resource_count=0
matching_test_pod_count=0
target_lab_status=not_provisioned
telemetry_state=core_ready_partial_sources
live_scenario_ready=false
execution_blockers=target_lab_not_provisioned,hubble_relay_absent,canarysting_runtime_absent,bounded_attacker_harness_unimplemented
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

safe_output="$(PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${safe_fixture}" "${script_dir}/attackercheck.sh")"
grep -Fqx 'expected_model_present=true' <<<"${safe_output}"
grep -Fqx 'loaded_model_count=0' <<<"${safe_output}"
grep -Fqx 'live_scenario_ready=false' <<<"${safe_output}"
grep -Fqx 'm2c1_inspection=PASS' <<<"${safe_output}"

not_ready_fixture="${fixture_root}/not-ready.report"
awk '
  /^expected_model_present=/ {$0="expected_model_present=false"}
  /^expected_model_id=/ {$0="expected_model_id=absent"}
  /^expected_model_size=/ {$0="expected_model_size=absent"}
  /^execution_blockers=/ {$0="execution_blockers=expected_model_absent,bounded_attacker_harness_unimplemented"}
  /^safety_status=/ {$0="safety_status=safe_not_ready"}
  {print}
' "${safe_fixture}" >"${not_ready_fixture}"
not_ready_output="$(PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${not_ready_fixture}" "${script_dir}/attackercheck.sh")"
grep -Fqx 'expected_model_present=false' <<<"${not_ready_output}"
grep -Fqx 'm2c1_inspection=PASS' <<<"${not_ready_output}"

unsafe_fixture="${fixture_root}/unsafe.report"
awk '
  /^ollama_listener_addresses=/ {$0="ollama_listener_addresses=0.0.0.0:11434"}
  /^ollama_binding=/ {$0="ollama_binding=unsafe_non_loopback"}
  /^safety_status=/ {$0="safety_status=unsafe_exposure"}
  {print}
' "${safe_fixture}" >"${unsafe_fixture}"
if PATH="${fixture_root}/bin:${PATH}" CANARYSTING_ATTACKERCHECK_FIXTURE="${unsafe_fixture}" "${script_dir}/attackercheck.sh" >"${fixture_root}/unsafe.out" 2>"${fixture_root}/unsafe.err"; then
  echo 'FAIL: unsafe Ollama exposure was accepted' >&2
  exit 1
fi
grep -Fq 'live execution is blocked' "${fixture_root}/unsafe.err"

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

if grep -Eq 'ollama[[:space:]]+(run|pull|create|rm|serve)([[:space:]]|$)' "${script_dir}/attackercheck.sh"; then
  echo 'FAIL: checker contains an Ollama mutation or model-execution command' >&2
  exit 1
fi
if grep -Eq 'systemctl[[:space:]]+(start|stop|restart|reload|enable|disable|mask|unmask)([[:space:]]|$)' "${script_dir}/attackercheck.sh"; then
  echo 'FAIL: checker contains a service mutation command' >&2
  exit 1
fi
if grep -Eq 'kctl[[:space:]]+(apply|create|delete|edit|patch|replace|rollout|scale|set)([[:space:]]|$)' "${script_dir}/attackercheck.sh"; then
  echo 'FAIL: checker contains a Kubernetes mutation command' >&2
  exit 1
fi
if grep -Eqi 'kubectl[^\n]*(secret|kubeconfig)|/etc/rancher/k3s/k3s\.yaml' "${script_dir}/attackercheck.sh"; then
  echo 'FAIL: checker attempts to read credentials or Secret data' >&2
  exit 1
fi

printf 'PASS: read-only CanaryAttacker lab inspection contract\n'
