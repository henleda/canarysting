#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fixture_root="$(mktemp -d)"
batch_fixture="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
trap 'rm -rf -- "${fixture_root}" "${batch_fixture}"' EXIT INT TERM
proof_file="${fixture_root}/preflight.proof"
revision="$(git -C "${script_dir}/../.." rev-parse --verify HEAD)"
printf 'proof_version\t1\nrun_id\tci-risk-proof\nhost\tfalcon1\nsource_revision\t%s\ncreated_epoch\t%s\n' \
  "${revision}" "$(date +%s)" >"${proof_file}"
chmod 0600 "${proof_file}"
"${script_dir}/preflight-proof.sh" --verify --run-id ci-risk-proof --proof-file "${proof_file}" >/dev/null
printf 'unexpected\tfield\n' >>"${proof_file}"
if "${script_dir}/preflight-proof.sh" --verify --run-id ci-risk-proof --proof-file "${proof_file}" >/dev/null 2>&1; then
  echo 'FAIL: malformed shared preflight proof was accepted' >&2
  exit 1
fi

preflight_output="$("${script_dir}/pr.sh" --profile preflight --run-id ci-preflight-dry-run --dry-run)"
grep -Fqx 'profile=preflight' <<<"${preflight_output}"
grep -Fqx 'read_only_check_count=0' <<<"${preflight_output}"
grep -Fqx 'artifact_build_count=0' <<<"${preflight_output}"
grep -Fqx 'artifact_transfer_count=0' <<<"${preflight_output}"
grep -Fq 'DGX was not accessed' <<<"${preflight_output}"

output="$("${script_dir}/pr.sh" --profile kernel-full --run-id ci-risk-dry-run --dry-run)"
grep -Fqx 'preflight_count=1' <<<"${output}"
grep -Fqx 'artifact_build_count=1' <<<"${output}"
grep -Fqx 'artifact_transfer_count=1' <<<"${output}"
grep -Fq 'socket-cookie proof contract passed; DGX was not accessed' <<<"${output}"
grep -Fq 'precise-enforcement proof contract passed; DGX was not accessed' <<<"${output}"

stack_output="$("${script_dir}/pr.sh" --profile stack --run-id ci-stack-dry-run --dry-run)"
grep -Fqx 'profile=stack' <<<"${stack_output}"
grep -Fqx 'artifact_build_count=1' <<<"${stack_output}"
grep -Fq 'DGX-stack proof contract passed; DGX was not accessed' <<<"${stack_output}"

correlation_output="$("${script_dir}/pr.sh" --profile correlation --run-id ci-correlation-dry-run --dry-run)"
grep -Fqx 'profile=correlation' <<<"${correlation_output}"
grep -Fqx 'artifact_build_count=1' <<<"${correlation_output}"
grep -Fq 'correlation proof contract passed; DGX was not accessed' <<<"${correlation_output}"

trace_output="$("${script_dir}/pr.sh" --profile trace --run-id ci-trace-dry-run --dry-run)"
grep -Fqx 'profile=trace' <<<"${trace_output}"
grep -Fqx 'artifact_build_count=1' <<<"${trace_output}"
grep -Fq 'trace proof contract passed; DGX was not accessed' <<<"${trace_output}"

attacker_executor_output="$("${script_dir}/pr.sh" --profile attacker-executor --run-id ci-attacker-executor --dry-run)"
grep -Fqx 'profile=attacker-executor' <<<"${attacker_executor_output}"
grep -Fqx 'preflight_count=1' <<<"${attacker_executor_output}"
grep -Fqx 'artifact_build_count=1' <<<"${attacker_executor_output}"
grep -Fqx 'artifact_transfer_count=1' <<<"${attacker_executor_output}"
grep -Fq 'bounded attacker executor proof contract passed; DGX was not accessed' <<<"${attacker_executor_output}"

attacker_loop_output="$("${script_dir}/pr.sh" --profile attacker-loop --run-id ci-attacker-loop --dry-run)"
grep -Fqx 'profile=attacker-loop' <<<"${attacker_loop_output}"
grep -Fqx 'preflight_count=1' <<<"${attacker_loop_output}"
grep -Fqx 'artifact_build_count=1' <<<"${attacker_loop_output}"
grep -Fqx 'artifact_transfer_count=1' <<<"${attacker_loop_output}"
grep -Fq 'bounded Ollama planner proof contract passed; DGX was not accessed' <<<"${attacker_loop_output}"

attacker_scenario_output="$("${script_dir}/pr.sh" --profile attacker-scenarios --run-id ci-attacker-scenarios --dry-run)"
grep -Fqx 'profile=attacker-scenarios' <<<"${attacker_scenario_output}"
grep -Fqx 'preflight_count=1' <<<"${attacker_scenario_output}"
grep -Fqx 'artifact_build_count=1' <<<"${attacker_scenario_output}"
grep -Fqx 'artifact_transfer_count=1' <<<"${attacker_scenario_output}"
grep -Fq 'reproducible attacker scenario contract passed; DGX was not accessed' <<<"${attacker_scenario_output}"

attacker_check_output="$("${script_dir}/pr.sh" --profile attacker-check --run-id ci-attacker-check --dry-run)"
grep -Fqx 'profile=attacker-check' <<<"${attacker_check_output}"
grep -Fqx 'preflight_count=0' <<<"${attacker_check_output}"
grep -Fqx 'read_only_check_count=1' <<<"${attacker_check_output}"
grep -Fqx 'artifact_build_count=0' <<<"${attacker_check_output}"
grep -Fqx 'artifact_transfer_count=0' <<<"${attacker_check_output}"
grep -Fq 'attacker-lab inspection contract passed; DGX was not accessed' <<<"${attacker_check_output}"

cleanup_policy_definition="$(awk '/^should_run_generic_cleanup\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
[[ -n "${cleanup_policy_definition}" ]] || { echo 'FAIL: DGX cleanup policy is not independently testable' >&2; exit 1; }
bash -c "${cleanup_policy_definition}"$'\n''should_run_generic_cleanup attacker-loop 0'
if bash -c "${cleanup_policy_definition}"$'\n''should_run_generic_cleanup attacker-loop 1'; then
  echo 'FAIL: attacker-loop cleanup failure permits generic stage deletion' >&2
  exit 1
fi
bash -c "${cleanup_policy_definition}"$'\n''should_run_generic_cleanup kernel-full 1'
grep -Fq 'if should_run_generic_cleanup "${profile}" "${scenario_cleanup_failed}"; then' "${script_dir}/pr.sh"

ssh_transport_definition="$(awk '/^ssh\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
scp_transport_definition="$(awk '/^scp\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
close_transport_definition="$(awk '/^close_ssh_control\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
configure_transport_definition="$(awk '/^configure_ssh_control\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
directory_mode_definition="$(awk '/^directory_mode\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
fail_definition="$(awk '/^fail\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
control_operation_definition="$(awk '/^dgx_run_ssh_control_operation\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
retry_wait_definition="$(awk '/^dgx_wait_before_ssh_retry\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
remove_control_definition="$(awk '/^dgx_remove_ssh_control_socket\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
terminate_master_definition="$(awk '/^dgx_terminate_ssh_master\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
close_control_definition="$(awk '/^dgx_close_ssh_control\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
[[ -n "${ssh_transport_definition}" && -n "${scp_transport_definition}" && -n "${close_transport_definition}" && -n "${configure_transport_definition}" && -n "${directory_mode_definition}" && -n "${fail_definition}" && -n "${control_operation_definition}" && -n "${retry_wait_definition}" && -n "${remove_control_definition}" && -n "${terminate_master_definition}" && -n "${close_control_definition}" ]] || {
  echo 'FAIL: shared DGX transport functions are not independently testable' >&2
  exit 1
}
grep -Fqx 'unset CANARYSTING_DGX_SSH_EXEC_CHILD' "${script_dir}/pr.sh" || {
  echo 'FAIL: ambient state can opt ordinary child SSH calls into process replacement' >&2
  exit 1
}
transport_probe="${fixture_root}/transport-probe"
cat >"${transport_probe}" <<'PROBE'
#!/usr/bin/env bash
if [[ -n "${TRANSPORT_HOLD_PID_FILE:-}" ]]; then
  trap 'printf "TERM\n" >"${TRANSPORT_HOLD_SIGNAL_FILE}"; exit 143' TERM
  printf '%s\n' "$$" >"${TRANSPORT_HOLD_PID_FILE}"
  printf 'ready\n' >"${TRANSPORT_HOLD_READY_FILE}"
  while :; do :; done
fi
if [[ -n "${TRANSPORT_PROBE_LOG:-}" ]]; then
  printf '%s\n' "$@" >"${TRANSPORT_PROBE_LOG}"
  if [[ -n "${TRANSPORT_MASTER_PID:-}" ]]; then
    kill -TERM "${TRANSPORT_MASTER_PID}" 2>/dev/null || true
  fi
  exit 0
fi
printf '%s\n' "$@"
PROBE
chmod 0700 "${transport_probe}"
control_path="${fixture_root}/ssh-control"
if ! bash -c "${remove_control_definition}"$'\n''dgx_remove_ssh_control_socket "$1"' -- "${control_path}"; then
  echo 'FAIL: absent socket in a private owned root was not accepted' >&2
  exit 1
fi
unsafe_control_root="${fixture_root}/unsafe-control-root"
mkdir -m 0700 "${unsafe_control_root}"
printf 'not a socket\n' >"${unsafe_control_root}/ssh-control"
if bash -c "${remove_control_definition}"$'\n''dgx_remove_ssh_control_socket "$1"' -- "${unsafe_control_root}/ssh-control"; then
  echo 'FAIL: non-socket control-path entry was removed or accepted' >&2
  exit 1
fi
[[ -f "${unsafe_control_root}/ssh-control" && ! -L "${unsafe_control_root}/ssh-control" ]] || {
  echo 'FAIL: non-socket control-path entry was mutated' >&2
  exit 1
}
rm -f -- "${unsafe_control_root}/ssh-control"
ln -s /tmp "${unsafe_control_root}/ssh-control"
if bash -c "${remove_control_definition}"$'\n''dgx_remove_ssh_control_socket "$1"' -- "${unsafe_control_root}/ssh-control"; then
  echo 'FAIL: symlink control-path entry was removed or accepted' >&2
  exit 1
fi
[[ -L "${unsafe_control_root}/ssh-control" ]] || {
  echo 'FAIL: symlink control-path entry was mutated' >&2
  exit 1
}
ssh_arguments="$(bash -c "${ssh_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2"
ssh -o BatchMode=yes falcon1 true
' -- "${transport_probe}" "${control_path}")"
scp_arguments="$(bash -c "${scp_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SCP="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2"
scp -o BatchMode=yes source falcon1:/target
' -- "${transport_probe}" "${control_path}")"
expected_prefix=$'-o\nControlMaster=no\n-o\nControlPath='"${control_path}"$'\n-o\nProxyCommand=/usr/bin/false\n-o\nClearAllForwardings=yes\n-o\nForwardAgent=no\n-o\nForwardX11=no\n-o\nGSSAPIDelegateCredentials=no\n-o\nTunnel=no\n-o\nPermitLocalCommand=no\n-o\nRequestTTY=no\n-o\nForkAfterAuthentication=no\n-o\nServerAliveInterval=5\n-o\nServerAliveCountMax=3'
[[ "${ssh_arguments}" == "${expected_prefix}"$'\n-o\nBatchMode=yes\nfalcon1\ntrue' ]] || {
  echo 'FAIL: SSH does not prepend the bounded shared-control options' >&2
  exit 1
}
transport_hold_pid_file="${fixture_root}/transport-hold-pid"
transport_hold_recorded_pid_file="${fixture_root}/transport-hold-recorded-pid"
transport_hold_ready_file="${fixture_root}/transport-hold-ready"
transport_hold_signal_file="${fixture_root}/transport-hold-signal"
TRANSPORT_HOLD_PID_FILE="${transport_hold_pid_file}" \
TRANSPORT_HOLD_READY_FILE="${transport_hold_ready_file}" \
TRANSPORT_HOLD_SIGNAL_FILE="${transport_hold_signal_file}" \
  bash -c "${ssh_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2"
CANARYSTING_DGX_SSH_EXEC_CHILD=1 ssh -o BatchMode=yes falcon1 true &
owned_pid=$!
printf "%s\n" "${owned_pid}" >"$3"
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s "$4" ]] && break
  kill -0 "${owned_pid}" 2>/dev/null || break
  sleep 0.01
done
[[ -s "$4" && "$(<"$5")" == "${owned_pid}" ]]
kill -TERM "${owned_pid}"
set +e
wait "${owned_pid}"
hold_status=$?
set -e
[[ "${hold_status}" -eq 143 ]]
' -- "${transport_probe}" "${control_path}" "${transport_hold_recorded_pid_file}" \
    "${transport_hold_ready_file}" "${transport_hold_pid_file}"
transport_hold_pid="$(<"${transport_hold_recorded_pid_file}")"
[[ "${transport_hold_pid}" == "$(<"${transport_hold_pid_file}")" &&
  "$(<"${transport_hold_signal_file}")" == 'TERM' ]] || {
  echo 'FAIL: executable SSH child mode did not expose the directly owned client PID' >&2
  exit 1
}
if kill -0 "${transport_hold_pid}" 2>/dev/null; then
  echo 'FAIL: executable SSH child mode left its owned client alive' >&2
  exit 1
fi
[[ "${scp_arguments}" == "${expected_prefix}"$'\n-o\nBatchMode=yes\nsource\nfalcon1:/target' ]] || {
  echo 'FAIL: SCP does not reuse the bounded shared-control options' >&2
  exit 1
}
close_arguments_file="${fixture_root}/close-arguments"
TRANSPORT_PROBE_LOG="${close_arguments_file}" bash -c "${control_operation_definition}"$'\n'"${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${close_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2"
bash -c "trap '\''exit 0'\'' TERM; while :; do sleep 1; done" &
CANARYSTING_DGX_SSH_MASTER_PID=$!
TRANSPORT_MASTER_PID="${CANARYSTING_DGX_SSH_MASTER_PID}"
export TRANSPORT_MASTER_PID
close_ssh_control
[[ -z "${CANARYSTING_DGX_SSH_MASTER_PID}" ]]
' -- "${transport_probe}" "${control_path}"
expected_close=$'-o\nBatchMode=yes\n-o\nConnectTimeout=5\n-o\nConnectionAttempts=1\n-o\nStrictHostKeyChecking=yes\n-o\nProxyCommand=/usr/bin/false\n-o\nClearAllForwardings=yes\n-o\nForwardAgent=no\n-o\nForwardX11=no\n-o\nGSSAPIDelegateCredentials=no\n-o\nTunnel=no\n-o\nPermitLocalCommand=no\n-o\nRequestTTY=no\n-o\nForkAfterAuthentication=no\n-o\nControlPath='"${control_path}"$'\n-O\nexit\nfalcon1'
[[ "$(<"${close_arguments_file}")" == "${expected_close}" ]] || {
  echo 'FAIL: coordinator cleanup does not close the exact run-scoped SSH control connection' >&2
  exit 1
}

hostile_ssh_config="${fixture_root}/hostile-ssh-config"
cat >"${hostile_ssh_config}" <<'CONFIG'
Host falcon1
  HostName 127.0.0.1
  LocalForward 127.0.0.1:40101 127.0.0.1:1
  RemoteForward 127.0.0.1:40102 127.0.0.1:1
  DynamicForward 127.0.0.1:40103
  ForwardAgent yes
  ForwardX11 yes
  GSSAPIDelegateCredentials yes
  Tunnel yes
  PermitLocalCommand yes
  LocalCommand /usr/bin/false
  RequestTTY force
  ForkAfterAuthentication yes
CONFIG
effective_ssh_config="$(/usr/bin/ssh -G -F "${hostile_ssh_config}" \
  -o ClearAllForwardings=yes \
  -o ForwardAgent=no \
  -o ForwardX11=no \
  -o GSSAPIDelegateCredentials=no \
  -o Tunnel=no \
  -o PermitLocalCommand=no \
  -o RequestTTY=no \
  -o ForkAfterAuthentication=no \
  falcon1 2>/dev/null)"
for required_setting in 'clearallforwardings yes' 'forwardagent no' 'forwardx11 no' \
  'gssapidelegatecredentials no' \
  'tunnel false' 'permitlocalcommand no' 'requesttty false' 'forkafterauthentication no'; do
  grep -Fqx "${required_setting}" <<<"${effective_ssh_config}" || {
    echo "FAIL: hostile SSH configuration retained ${required_setting}" >&2
    exit 1
  }
done
if grep -Eq '^(localforward|remoteforward|dynamicforward) ' <<<"${effective_ssh_config}"; then
  echo 'FAIL: hostile SSH configuration retained a configured forwarding channel' >&2
  exit 1
fi

bootstrap_definition="$(awk '/^dgx_open_ssh_control\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/ssh-control.sh")"
[[ -n "${bootstrap_definition}" ]] || {
  echo 'FAIL: DGX transport bootstrap is not independently testable' >&2
  exit 1
}
bootstrap_probe="${fixture_root}/bootstrap-probe"
cat >"${bootstrap_probe}" <<'PROBE'
#!/usr/bin/env bash
operation=''
previous=''
for argument in "$@"; do
  if [[ "${previous}" == '-O' ]]; then
    operation="${argument}"
  fi
  previous="${argument}"
done
if [[ "${operation}" == 'check' || "${operation}" == 'exit' ]]; then
  printf 'CONTROL_%s\n' "${operation}" >>"${BOOTSTRAP_CONTROL_LOG}"
  printf '%s\n' "$@" >>"${BOOTSTRAP_CONTROL_LOG}"
  if [[ "${operation}" == 'exit' && -s "${BOOTSTRAP_MASTER_PID_FILE}" ]]; then
    kill -TERM "$(<"${BOOTSTRAP_MASTER_PID_FILE}")" 2>/dev/null || true
  fi
  [[ -s "${BOOTSTRAP_MASTER_PID_FILE}" ]] && kill -0 "$(<"${BOOTSTRAP_MASTER_PID_FILE}")" 2>/dev/null
  exit
fi
: >"${BOOTSTRAP_MASTER_PID_FILE}"
count=0
if [[ -s "${BOOTSTRAP_PROBE_COUNT}" ]]; then
  count="$(<"${BOOTSTRAP_PROBE_COUNT}")"
fi
count=$((count + 1))
printf '%s\n' "${count}" >"${BOOTSTRAP_PROBE_COUNT}"
printf '%s\n' "$$" >>"${BOOTSTRAP_MASTER_PIDS}"
printf 'CALL\n' >>"${BOOTSTRAP_PROBE_LOG}"
printf '%s\n' "$@" >>"${BOOTSTRAP_PROBE_LOG}"
((count > BOOTSTRAP_PROBE_FAILURES)) || exit 1
printf '%s\n' "$$" >"${BOOTSTRAP_MASTER_PID_FILE}"
trap 'exit 0' TERM INT
while :; do sleep 1; done
PROBE
chmod 0700 "${bootstrap_probe}"
bootstrap_count="${fixture_root}/bootstrap-count"
bootstrap_log="${fixture_root}/bootstrap-log"
bootstrap_control_log="${fixture_root}/bootstrap-control-log"
bootstrap_master_pid_file="${fixture_root}/bootstrap-master-pid"
bootstrap_master_pids="${fixture_root}/bootstrap-master-pids"
bash -c "${control_operation_definition}"$'\n'"${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${bootstrap_definition}"$'\n''
dgx_wait_before_ssh_retry() { :; }
CANARYSTING_DGX_REAL_SSH="$1"
BOOTSTRAP_PROBE_COUNT="$2"
BOOTSTRAP_PROBE_LOG="$3"
BOOTSTRAP_PROBE_FAILURES=2
BOOTSTRAP_CONTROL_LOG="$4"
BOOTSTRAP_MASTER_PID_FILE="$6"
BOOTSTRAP_MASTER_PIDS="$7"
export BOOTSTRAP_PROBE_COUNT BOOTSTRAP_PROBE_LOG BOOTSTRAP_PROBE_FAILURES BOOTSTRAP_CONTROL_LOG BOOTSTRAP_MASTER_PID_FILE BOOTSTRAP_MASTER_PIDS
dgx_open_ssh_control "$5"
dgx_close_ssh_control "$5"
[[ -z "${CANARYSTING_DGX_SSH_MASTER_PID}" ]]
' -- "${bootstrap_probe}" "${bootstrap_count}" "${bootstrap_log}" "${bootstrap_control_log}" "${control_path}" "${bootstrap_master_pid_file}" "${bootstrap_master_pids}" 2>/dev/null
[[ "$(<"${bootstrap_count}")" == '3' ]] || {
  echo 'FAIL: DGX transport bootstrap did not make exactly three bounded pre-mutation attempts' >&2
  exit 1
}
for required_option in 'BatchMode=yes' 'ConnectTimeout=20' 'ConnectionAttempts=1' \
  'StrictHostKeyChecking=yes' 'ClearAllForwardings=yes' 'ForwardAgent=no' \
  'ForwardX11=no' 'GSSAPIDelegateCredentials=no' 'Tunnel=no' 'PermitLocalCommand=no' 'RequestTTY=no' \
  'ForkAfterAuthentication=no' \
  'ControlMaster=yes' 'ControlPersist=no' \
  "ControlPath=${control_path}" 'ServerAliveInterval=5' 'ServerAliveCountMax=3'; do
  [[ "$(grep -Fxc -- "${required_option}" "${bootstrap_log}")" == '3' ]] || {
    echo "FAIL: DGX transport bootstrap did not apply ${required_option} to every attempt" >&2
    exit 1
  }
done
[[ "$(grep -Fxc -- 'ControlPersist=1200' "${bootstrap_log}" || true)" == '0' ]] || {
  echo 'FAIL: DGX transport bootstrap can self-daemonize through ControlPersist' >&2
  exit 1
}
[[ "$(grep -Fxc -- '-n' "${bootstrap_log}")" == '3' && "$(grep -Fxc -- '-N' "${bootstrap_log}")" == '3' &&
  "$(grep -Fxc -- '-f' "${bootstrap_log}")" == '0' ]] || {
  echo 'FAIL: DGX transport bootstrap did not retain ownership of its no-command master process' >&2
  exit 1
}
for required_option in 'BatchMode=yes' 'ConnectTimeout=5' 'ConnectionAttempts=1' \
  'StrictHostKeyChecking=yes' 'ProxyCommand=/usr/bin/false' \
  'ClearAllForwardings=yes' 'ForwardAgent=no' 'ForwardX11=no' 'GSSAPIDelegateCredentials=no' 'Tunnel=no' \
  'PermitLocalCommand=no' 'RequestTTY=no' 'ForkAfterAuthentication=no' "ControlPath=${control_path}"; do
  grep -Fqx -- "${required_option}" "${bootstrap_control_log}" || {
    echo "FAIL: bounded mux operations did not force ${required_option}" >&2
    exit 1
  }
done
[[ "$(grep -Fxc 'CONTROL_exit' "${bootstrap_control_log}")" == '1' && "$(grep -Fxc 'CONTROL_check' "${bootstrap_control_log}")" -ge 1 ]] || {
  echo 'FAIL: bootstrap did not verify and close its successful owned master' >&2
  exit 1
}
while IFS= read -r bootstrap_master_pid; do
  if kill -0 "${bootstrap_master_pid}" 2>/dev/null; then
    echo 'FAIL: bootstrap left an attempted master process alive' >&2
    exit 1
  fi
done <"${bootstrap_master_pids}"
bootstrap_failure_count="${fixture_root}/bootstrap-failure-count"
bootstrap_failure_log="${fixture_root}/bootstrap-failure-log"
bootstrap_failure_control_log="${fixture_root}/bootstrap-failure-control-log"
bootstrap_failure_master_pid_file="${fixture_root}/bootstrap-failure-master-pid"
bootstrap_failure_master_pids="${fixture_root}/bootstrap-failure-master-pids"
if bash -c "${control_operation_definition}"$'\n'"${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${bootstrap_definition}"$'\n''
dgx_wait_before_ssh_retry() { :; }
CANARYSTING_DGX_REAL_SSH="$1"
BOOTSTRAP_PROBE_COUNT="$2"
BOOTSTRAP_PROBE_LOG="$3"
BOOTSTRAP_PROBE_FAILURES=3
BOOTSTRAP_CONTROL_LOG="$4"
BOOTSTRAP_MASTER_PID_FILE="$6"
BOOTSTRAP_MASTER_PIDS="$7"
export BOOTSTRAP_PROBE_COUNT BOOTSTRAP_PROBE_LOG BOOTSTRAP_PROBE_FAILURES BOOTSTRAP_CONTROL_LOG BOOTSTRAP_MASTER_PID_FILE BOOTSTRAP_MASTER_PIDS
dgx_open_ssh_control "$5"
' -- "${bootstrap_probe}" "${bootstrap_failure_count}" "${bootstrap_failure_log}" "${bootstrap_failure_control_log}" "${control_path}" "${bootstrap_failure_master_pid_file}" "${bootstrap_failure_master_pids}" 2>/dev/null; then
  echo 'FAIL: DGX transport bootstrap did not fail closed after its bounded attempts' >&2
  exit 1
fi
[[ "$(<"${bootstrap_failure_count}")" == '3' ]] || {
  echo 'FAIL: DGX transport bootstrap exceeded or truncated its failure bound' >&2
  exit 1
}
while IFS= read -r bootstrap_master_pid; do
  if kill -0 "${bootstrap_master_pid}" 2>/dev/null; then
    echo 'FAIL: exhausted bootstrap left a failed master process alive' >&2
    exit 1
  fi
done <"${bootstrap_failure_master_pids}"

control_hang_probe="${fixture_root}/control-hang-probe"
cat >"${control_hang_probe}" <<'PROBE'
#!/usr/bin/env bash
printf '%s\n' "$$" >"${CONTROL_HANG_PID_FILE}"
trap '' TERM
while :; do :; done
PROBE
chmod 0700 "${control_hang_probe}"
for control_operation in check exit; do
  control_hang_pid_file="${fixture_root}/control-${control_operation}-hang-pid"
  control_started="$(date +%s)"
  set +e
  CONTROL_HANG_PID_FILE="${control_hang_pid_file}" bash -c "${control_operation_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
dgx_run_ssh_control_operation "$2" "$3" 1
' -- "${control_hang_probe}" "${control_path}" "${control_operation}" 2>/dev/null
  control_hang_status=$?
  set -e
  control_elapsed=$(( $(date +%s) - control_started ))
  [[ "${control_hang_status}" -ne 0 && "${control_elapsed}" -le 4 ]] || {
    echo "FAIL: wedged mux ${control_operation} did not fail within its watchdog bound" >&2
    exit 1
  }
  control_hang_pid="$(<"${control_hang_pid_file}")"
  if kill -0 "${control_hang_pid}" 2>/dev/null; then
    echo "FAIL: wedged mux ${control_operation} was not killed and reaped" >&2
    exit 1
  fi
done

surviving_master_pid_file="${fixture_root}/surviving-master-pid"
bash -c "${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n''
dgx_run_ssh_control_operation() { return 91; }
bash -c "trap '\''\'' TERM; while :; do :; done" &
CANARYSTING_DGX_SSH_MASTER_PID=$!
printf "%s\n" "${CANARYSTING_DGX_SSH_MASTER_PID}" >"$1"
set +e
dgx_close_ssh_control "$2"
close_status=$?
set -e
[[ "${close_status}" -eq 91 && -z "${CANARYSTING_DGX_SSH_MASTER_PID}" ]]
' -- "${surviving_master_pid_file}" "${control_path}" || {
  echo 'FAIL: failed mux shutdown did not terminate and reap its owned master' >&2
  exit 1
}
surviving_master_pid="$(<"${surviving_master_pid_file}")"
if kill -0 "${surviving_master_pid}" 2>/dev/null; then
  echo 'FAIL: failed mux shutdown left its owned master alive' >&2
  exit 1
fi

pr_cleanup_definition="$(awk '/^cleanup\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr.sh")"
batch_close_transport_definition="$(awk '/^close_profile_transport\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr-batch.sh")"
batch_cleanup_definition="$(awk '/^cleanup\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${script_dir}/pr-batch.sh")"
[[ -n "${pr_cleanup_definition}" && -n "${batch_close_transport_definition}" && -n "${batch_cleanup_definition}" ]] || {
  echo 'FAIL: coordinator cleanup functions are not independently testable' >&2
  exit 1
}

profile_close_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
profile_close_log="${fixture_root}/profile-close-log"
profile_close_state="$(TRANSPORT_PROBE_LOG="${profile_close_log}" bash -c \
  "${control_operation_definition}"$'\n'"${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${batch_close_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
transport_root="$2"
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-control"
bash -c "trap '\''exit 0'\'' TERM; while :; do sleep 1; done" &
CANARYSTING_DGX_SSH_MASTER_PID=$!
TRANSPORT_MASTER_PID="${CANARYSTING_DGX_SSH_MASTER_PID}"
export TRANSPORT_MASTER_PID
close_profile_transport
printf "%s\t%s\t%s\n" "${transport_root}" "${CANARYSTING_DGX_BATCH_CONTROL_PATH}" "${CANARYSTING_DGX_SSH_MASTER_PID}"
' -- "${transport_probe}" "${profile_close_root}")"
[[ "${profile_close_state}" == $'\t\t' && ! -e "${profile_close_root}" && ! -L "${profile_close_root}" ]] || {
  echo 'FAIL: completed profile transport was not closed, removed, and cleared before reuse' >&2
  exit 1
}

profile_unsafe_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
printf 'not a socket\n' >"${profile_unsafe_root}/ssh-control"
profile_unsafe_state="$(bash -c "${remove_control_definition}"$'\n'"${batch_close_transport_definition}"$'\n''
transport_root="$1"
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-control"
CANARYSTING_DGX_SSH_MASTER_PID=""
set +e
close_profile_transport 2>/dev/null
close_status=$?
set -e
printf "%s\t%s\t%s\n" "${close_status}" "${transport_root}" "${CANARYSTING_DGX_BATCH_CONTROL_PATH}"
' -- "${profile_unsafe_root}")"
[[ "${profile_unsafe_state}" == "1"$'\t'"${profile_unsafe_root}"$'\t'"${profile_unsafe_root}/ssh-control" &&
  -f "${profile_unsafe_root}/ssh-control" && ! -L "${profile_unsafe_root}/ssh-control" ]] || {
  echo 'FAIL: outer batch cleanup erased or forgot a refused control-path entry' >&2
  exit 1
}
rm -rf -- "${profile_unsafe_root}"

profile_sticky_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
profile_sticky_master_pid_file="${fixture_root}/profile-sticky-master-pid"
set +e
bash -c "${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${batch_close_transport_definition}"$'\n'"${batch_cleanup_definition}"$'\n''
dgx_run_ssh_control_operation() { return 91; }
transport_root="$1"
transport_cleanup_failed=0
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-control"
bash -c "trap '\''exit 0'\'' TERM; while :; do sleep 1; done" &
CANARYSTING_DGX_SSH_MASTER_PID=$!
printf "%s\n" "${CANARYSTING_DGX_SSH_MASTER_PID}" >"$2"
trap cleanup EXIT
close_profile_transport || exit 41
' -- "${profile_sticky_root}" "${profile_sticky_master_pid_file}" 2>/dev/null
profile_sticky_status=$?
set -e
[[ "${profile_sticky_status}" -eq 41 && -d "${profile_sticky_root}" && ! -L "${profile_sticky_root}" ]] || {
  echo 'FAIL: failed explicit batch close was not sticky across its EXIT cleanup' >&2
  exit 1
}
profile_sticky_master_pid="$(<"${profile_sticky_master_pid_file}")"
if kill -0 "${profile_sticky_master_pid}" 2>/dev/null; then
  echo 'FAIL: sticky failed-close cleanup left its owned master alive' >&2
  exit 1
fi
rm -rf -- "${profile_sticky_root}"

profile_removal_failure_state="$(bash -c "${remove_control_definition}"$'\n'"${batch_close_transport_definition}"$'\n''
rm() { return 88; }
transport_root="$1"
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-control"
CANARYSTING_DGX_SSH_MASTER_PID=""
set +e
close_profile_transport
close_status=$?
set -e
printf "%s\t%s\t%s\n" "${close_status}" "${transport_root}" "${CANARYSTING_DGX_BATCH_CONTROL_PATH}"
' -- "${batch_fixture}")"
[[ "${profile_removal_failure_state}" == "88"$'\t'"${batch_fixture}"$'\t'"${batch_fixture}/ssh-control" && -d "${batch_fixture}" && ! -L "${batch_fixture}" ]] || {
  echo 'FAIL: failed profile-root removal was reported as success or discarded cleanup state' >&2
  exit 1
}

standalone_unsafe_root="$(mktemp -d "/tmp/canarysting-dgx-pr.XXXXXX")"
printf 'not a socket\n' >"${standalone_unsafe_root}/ssh-control"
set +e
bash -c "${remove_control_definition}"$'\n'"${pr_cleanup_definition}"$'\n''
work_root="$1"
cleanup_required=0
CANARYSTING_DGX_SSH_CONTROL_OWNED=1
CANARYSTING_DGX_SSH_CONTROL_PATH="${work_root}/ssh-control"
CANARYSTING_DGX_SSH_MASTER_PID=""
cleanup
' -- "${standalone_unsafe_root}" 2>/dev/null
standalone_unsafe_status=$?
set -e
[[ "${standalone_unsafe_status}" -eq 1 && -f "${standalone_unsafe_root}/ssh-control" &&
  ! -L "${standalone_unsafe_root}/ssh-control" ]] || {
  echo 'FAIL: outer standalone cleanup erased or accepted a refused control-path entry' >&2
  exit 1
}
rm -rf -- "${standalone_unsafe_root}"

standalone_root="$(mktemp -d "/tmp/canarysting-dgx-pr.XXXXXX")"
standalone_count="${fixture_root}/standalone-bootstrap-count"
standalone_log="${fixture_root}/standalone-bootstrap-log"
standalone_control_log="${fixture_root}/standalone-control-log"
standalone_master_pid_file="${fixture_root}/standalone-master-pid"
standalone_master_pids="${fixture_root}/standalone-master-pids"
set +e
bash -c "${control_operation_definition}"$'\n'"${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${bootstrap_definition}"$'\n'"${close_transport_definition}"$'\n'"${cleanup_policy_definition}"$'\n'"${pr_cleanup_definition}"$'\n''
dgx_wait_before_ssh_retry() { :; }
work_root="$2"
artifact_dir="${work_root}/artifacts"
proof_file="${work_root}/preflight.proof"
cleanup_required=0
scenario_count=0
scenarios=()
profile=preflight
run_id=standalone-bootstrap-failure
script_dir="$3"
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="${work_root}/ssh-control"
CANARYSTING_DGX_SSH_CONTROL_OWNED=1
BOOTSTRAP_PROBE_COUNT="$4"
BOOTSTRAP_PROBE_LOG="$5"
BOOTSTRAP_CONTROL_LOG="$6"
BOOTSTRAP_PROBE_FAILURES=3
BOOTSTRAP_MASTER_PID_FILE="$7"
BOOTSTRAP_MASTER_PIDS="$8"
export BOOTSTRAP_PROBE_COUNT BOOTSTRAP_PROBE_LOG BOOTSTRAP_CONTROL_LOG BOOTSTRAP_PROBE_FAILURES BOOTSTRAP_MASTER_PID_FILE BOOTSTRAP_MASTER_PIDS
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
dgx_open_ssh_control "${CANARYSTING_DGX_SSH_CONTROL_PATH}" || exit 41
' -- "${bootstrap_probe}" "${standalone_root}" "${script_dir}" "${standalone_count}" "${standalone_log}" "${standalone_control_log}" "${standalone_master_pid_file}" "${standalone_master_pids}" 2>/dev/null
standalone_status=$?
set -e
[[ "${standalone_status}" -eq 41 && ! -e "${standalone_root}" && ! -L "${standalone_root}" ]] || {
  echo 'FAIL: exhausted standalone bootstrap did not fail and remove its exact private root' >&2
  exit 1
}
while IFS= read -r standalone_master_pid; do
  if kill -0 "${standalone_master_pid}" 2>/dev/null; then
    echo 'FAIL: exhausted standalone bootstrap cleanup left a master process alive' >&2
    exit 1
  fi
done <"${standalone_master_pids}"

signal_script_dir="${fixture_root}/signal-scripts"
mkdir -p "${signal_script_dir}"
for signal_script in scenario cleanup; do
  cat >"${signal_script_dir}/${signal_script}.sh" <<'PROBE'
#!/usr/bin/env bash
printf '%s\n' "$(basename "$0")" >>"${SIGNAL_CLEANUP_LOG}"
PROBE
  chmod 0700 "${signal_script_dir}/${signal_script}.sh"
done
for signal_case in 'INT 130' 'TERM 143'; do
  read -r signal_name expected_status <<<"${signal_case}"
  signal_root="$(mktemp -d "/tmp/canarysting-dgx-pr.XXXXXX")"
  signal_log="${fixture_root}/pr-${signal_name}-cleanup-log"
  set +e
  SIGNAL_CLEANUP_LOG="${signal_log}" bash -c "${cleanup_policy_definition}"$'\n'"${pr_cleanup_definition}"$'\n''
work_root="$1"
artifact_dir="${work_root}/artifacts"
proof_file="${work_root}/preflight.proof"
cleanup_required=1
scenario_count=1
scenarios=(scenario)
profile=kernel-full
run_id=signal-cleanup
script_dir="$2"
CANARYSTING_DGX_SSH_CONTROL_OWNED=0
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
kill -s "$3" "$$"
' -- "${signal_root}" "${signal_script_dir}" "${signal_name}"
  signal_status=$?
  set -e
  [[ "${signal_status}" -eq "${expected_status}" && ! -e "${signal_root}" && ! -L "${signal_root}" ]] || {
    echo "FAIL: ${signal_name} did not preserve failure status and exact local cleanup" >&2
    exit 1
  }
  [[ "$(<"${signal_log}")" == $'scenario.sh\ncleanup.sh' ]] || {
    echo "FAIL: ${signal_name} did not run exact scenario and generic remote cleanup" >&2
    exit 1
  }

  batch_signal_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
  batch_signal_pid_file="${fixture_root}/batch-${signal_name}-master-pid"
  set +e
  bash -c "${remove_control_definition}"$'\n'"${terminate_master_definition}"$'\n'"${close_control_definition}"$'\n'"${batch_close_transport_definition}"$'\n'"${batch_cleanup_definition}"$'\n''
dgx_run_ssh_control_operation() { return 91; }
transport_root="$1"
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-control"
bash -c "trap '\''\'' TERM; while :; do :; done" &
CANARYSTING_DGX_SSH_MASTER_PID=$!
printf "%s\n" "${CANARYSTING_DGX_SSH_MASTER_PID}" >"$3"
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
kill -s "$2" "$$"
' -- "${batch_signal_root}" "${signal_name}" "${batch_signal_pid_file}"
  batch_signal_status=$?
  set -e
  [[ "${batch_signal_status}" -eq "${expected_status}" && -d "${batch_signal_root}" && ! -L "${batch_signal_root}" ]] || {
    echo "FAIL: batch ${signal_name} did not preserve its signal status and failed-shutdown root" >&2
    exit 1
  }
  batch_signal_master_pid="$(<"${batch_signal_pid_file}")"
  if kill -0 "${batch_signal_master_pid}" 2>/dev/null; then
    echo "FAIL: batch ${signal_name} cleanup left its owned master alive" >&2
    exit 1
  fi
  rm -rf -- "${batch_signal_root}"
done

pr_trap_line="$(grep -nFx 'trap cleanup EXIT' "${script_dir}/pr.sh" | cut -d: -f1)"
standalone_initialize_line="$(grep -nF 'initialize_ssh_control "${work_root}"' "${script_dir}/pr.sh" | cut -d: -f1)"
[[ "${pr_trap_line}" =~ ^[0-9]+$ && "${standalone_initialize_line}" =~ ^[0-9]+$ ]] && \
  ((pr_trap_line < standalone_initialize_line)) || {
  echo 'FAIL: standalone cleanup trap is installed after fallible transport bootstrap' >&2
  exit 1
}
for coordinator in "${script_dir}/pr.sh" "${script_dir}/pr-batch.sh"; do
  grep -Fqx "trap 'exit 130' INT" "${coordinator}"
  grep -Fqx "trap 'exit 143' TERM" "${coordinator}"
  if grep -Fq 'trap cleanup EXIT INT TERM' "${coordinator}"; then
    echo "FAIL: coordinator can normalize an interrupt to successful cleanup: ${coordinator}" >&2
    exit 1
  fi
done
own_control="$(bash -c "${fail_definition}"$'\n'"${directory_mode_definition}"$'\n'"${configure_transport_definition}"$'\n''
configure_ssh_control "$1"
printf "%s\t%s\n" "${CANARYSTING_DGX_SSH_CONTROL_PATH}" "${CANARYSTING_DGX_SSH_CONTROL_OWNED}"
' -- "${fixture_root}")"
[[ "${own_control}" == "${fixture_root}/ssh-control"$'\t1' ]] || {
  echo 'FAIL: standalone coordinator does not own a private control path' >&2
  exit 1
}
shared_control_path="${batch_fixture}/ssh-control"
shared_control="$(bash -c "${fail_definition}"$'\n'"${directory_mode_definition}"$'\n'"${configure_transport_definition}"$'\n''
CANARYSTING_DGX_BATCH_CONTROL_PATH="$2"
configure_ssh_control "$1"
printf "%s\t%s\n" "${CANARYSTING_DGX_SSH_CONTROL_PATH}" "${CANARYSTING_DGX_SSH_CONTROL_OWNED}"
' -- "${fixture_root}" "${shared_control_path}")"
[[ "${shared_control}" == "${shared_control_path}"$'\t0' ]] || {
  echo 'FAIL: batch coordinator does not reuse its externally owned control path' >&2
  exit 1
}
if bash -c "${fail_definition}"$'\n'"${directory_mode_definition}"$'\n'"${configure_transport_definition}"$'\n''
CANARYSTING_DGX_BATCH_CONTROL_PATH="$2"
configure_ssh_control "$1"
' -- "${fixture_root}" "${fixture_root}/ssh-control" >/dev/null 2>&1; then
  echo 'FAIL: coordinator accepted a shared control path outside the bounded batch root' >&2
  exit 1
fi
chmod 0755 "${batch_fixture}"
if bash -c "${fail_definition}"$'\n'"${directory_mode_definition}"$'\n'"${configure_transport_definition}"$'\n''
CANARYSTING_DGX_BATCH_CONTROL_PATH="$2"
configure_ssh_control "$1"
' -- "${fixture_root}" "${shared_control_path}" >/dev/null 2>&1; then
  echo 'FAIL: coordinator accepted a non-private shared control root' >&2
  exit 1
fi
chmod 0700 "${batch_fixture}"
grep -Fq 'export -f ssh scp' "${script_dir}/pr.sh"
grep -Fqx '      if ! close_ssh_control; then' "${script_dir}/pr.sh"
grep -Fqx '  if ((transport_cleanup_failed != 0)); then' "${script_dir}/pr.sh"
bootstrap_line="$(grep -nF 'dgx_open_ssh_control "${CANARYSTING_DGX_BATCH_CONTROL_PATH}"' "${script_dir}/pr-batch.sh" | cut -d: -f1)"
profile_loop_line="$(grep -nF 'for index in "${!selected_profiles[@]}"; do' "${script_dir}/pr-batch.sh" | tail -1 | cut -d: -f1)"
profile_root_line="$(grep -nF 'transport_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"' "${script_dir}/pr-batch.sh" | cut -d: -f1)"
profile_run_line="$(grep -nF '"${script_dir}/pr.sh" --profile "${selected_profiles[index]}" --run-id "${run_id}"' "${script_dir}/pr-batch.sh" | tail -1 | cut -d: -f1)"
profile_close_line="$(grep -nF 'close_profile_transport || fail "unable to close DGX transport for completed profile ${selected_profiles[index]}"' "${script_dir}/pr-batch.sh" | cut -d: -f1)"
if [[ -z "${bootstrap_line}" || -z "${profile_loop_line}" || -z "${profile_root_line}" ||
  -z "${profile_run_line}" || -z "${profile_close_line}" ]] ||
  ((profile_loop_line >= profile_root_line || profile_root_line >= bootstrap_line ||
    bootstrap_line >= profile_run_line || profile_run_line >= profile_close_line)); then
  echo 'FAIL: each DGX profile does not receive a fresh verified transport that closes at its exact boundary' >&2
  exit 1
fi

batch_output="$("${script_dir}/pr-batch.sh" \
  --profiles 'attacker-executor attacker-loop attacker-scenarios preflight kernel-full' \
  --run-prefix ci-risk-batch \
  --dry-run)"
grep -Fqx 'batch_profile_count=5' <<<"${batch_output}"
grep -Fqx 'run_prefix=ci-risk-batch' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-1' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-2' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-3' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-4' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-5' <<<"${batch_output}"
grep -Fq 'DGX batch transport was not created' <<<"${batch_output}"
if "${script_dir}/pr-batch.sh" --profiles 'preflight preflight' --run-prefix ci-duplicate --dry-run >/dev/null 2>&1; then
  echo 'FAIL: DGX profile batch accepted a duplicate profile' >&2
  exit 1
fi
if "${script_dir}/pr-batch.sh" --profiles 'preflight arbitrary' --run-prefix ci-invalid --dry-run >/dev/null 2>&1; then
  echo 'FAIL: DGX profile batch accepted an unsupported profile' >&2
  exit 1
fi
if "${script_dir}/pr-batch.sh" --profiles '' --run-prefix ci-empty --dry-run >/dev/null 2>&1; then
  echo 'FAIL: DGX profile batch accepted an empty profile list' >&2
  exit 1
fi
if "${script_dir}/pr-batch.sh" --profiles $'preflight\nkernel-full' --run-prefix ci-multiline --dry-run >/dev/null 2>&1; then
  echo 'FAIL: DGX profile batch silently truncated a multiline profile list' >&2
  exit 1
fi

grep -Fq '"${script_dir}/${read_only_check}.sh" --summary' "${script_dir}/pr.sh"
summary_line="$(grep -nF '"${script_dir}/${read_only_check}.sh" --summary' "${script_dir}/pr.sh" | cut -d: -f1)"
work_root_line="$(grep -nF 'work_root="$(mktemp -d' "${script_dir}/pr.sh" | cut -d: -f1)"
preflight_line="$(grep -nF '"${script_dir}/preflight-proof.sh" --create' "${script_dir}/pr.sh" | cut -d: -f1)"
if [[ -z "${summary_line}" || -z "${work_root_line}" || -z "${preflight_line}" ]] || \
  ((summary_line >= work_root_line || summary_line >= preflight_line)); then
  echo 'FAIL: passive attacker inspection does not exit before general preflight setup' >&2
  exit 1
fi
if ! awk '
  /"\$\{script_dir\}\/\$\{read_only_check\}\.sh" --summary/ {seen=1; next}
  seen && /exit 0/ {found=1; exit}
  seen && /(preflight-proof|check\.sh|bpftool)/ {exit 1}
  END {if (!found) exit 1}
' "${script_dir}/pr.sh"; then
  echo 'FAIL: passive attacker inspection can fall through to the general or BPF preflight' >&2
  exit 1
fi

if "${script_dir}/pr.sh" --profile dgx-kubernetes --run-id ci-risk-dry-run --dry-run >/dev/null 2>&1; then
  echo 'FAIL: unsupported Kubernetes profile did not fail closed' >&2
  exit 1
fi
if "${script_dir}/pr.sh" --profile invalid --run-id ci-risk-dry-run --dry-run >/dev/null 2>&1; then
  echo 'FAIL: unknown profile was accepted' >&2
  exit 1
fi

printf 'PASS: risk-selected DGX coordinator contract\n'
