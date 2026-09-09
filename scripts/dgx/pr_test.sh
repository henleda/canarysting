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
[[ -n "${ssh_transport_definition}" && -n "${scp_transport_definition}" && -n "${close_transport_definition}" && -n "${configure_transport_definition}" && -n "${directory_mode_definition}" && -n "${fail_definition}" ]] || {
  echo 'FAIL: shared DGX transport functions are not independently testable' >&2
  exit 1
}
transport_probe="${fixture_root}/transport-probe"
cat >"${transport_probe}" <<'PROBE'
#!/usr/bin/env bash
if [[ -n "${TRANSPORT_PROBE_LOG:-}" ]]; then
  printf '%s\n' "$@" >"${TRANSPORT_PROBE_LOG}"
  exit 0
fi
printf '%s\n' "$@"
PROBE
chmod 0700 "${transport_probe}"
control_path="${fixture_root}/ssh-%C"
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
expected_prefix=$'-o\nControlMaster=auto\n-o\nControlPersist=1200\n-o\nControlPath='"${control_path}"$'\n-o\nServerAliveInterval=5\n-o\nServerAliveCountMax=3'
[[ "${ssh_arguments}" == "${expected_prefix}"$'\n-o\nBatchMode=yes\nfalcon1\ntrue' ]] || {
  echo 'FAIL: SSH does not prepend the bounded shared-control options' >&2
  exit 1
}
[[ "${scp_arguments}" == "${expected_prefix}"$'\n-o\nBatchMode=yes\nsource\nfalcon1:/target' ]] || {
  echo 'FAIL: SCP does not reuse the bounded shared-control options' >&2
  exit 1
}
close_arguments_file="${fixture_root}/close-arguments"
TRANSPORT_PROBE_LOG="${close_arguments_file}" bash -c "${close_transport_definition}"$'\n''
CANARYSTING_DGX_REAL_SSH="$1"
CANARYSTING_DGX_SSH_CONTROL_PATH="$2"
close_ssh_control
' -- "${transport_probe}" "${control_path}"
expected_close=$'-o\nControlPath='"${control_path}"$'\n-O\nexit\nfalcon1'
[[ "$(<"${close_arguments_file}")" == "${expected_close}" ]] || {
  echo 'FAIL: coordinator cleanup does not close the exact run-scoped SSH control connection' >&2
  exit 1
}
own_control="$(bash -c "${fail_definition}"$'\n'"${directory_mode_definition}"$'\n'"${configure_transport_definition}"$'\n''
configure_ssh_control "$1"
printf "%s\t%s\n" "${CANARYSTING_DGX_SSH_CONTROL_PATH}" "${CANARYSTING_DGX_SSH_CONTROL_OWNED}"
' -- "${fixture_root}")"
[[ "${own_control}" == "${fixture_root}/ssh-%C"$'\t1' ]] || {
  echo 'FAIL: standalone coordinator does not own a private control path' >&2
  exit 1
}
shared_control_path="${batch_fixture}/ssh-%C"
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
' -- "${fixture_root}" "${fixture_root}/ssh-%C" >/dev/null 2>&1; then
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
grep -Fqx '    close_ssh_control' "${script_dir}/pr.sh"

batch_output="$("${script_dir}/pr-batch.sh" \
  --profiles 'attacker-executor attacker-loop preflight kernel-full' \
  --run-prefix ci-risk-batch \
  --dry-run)"
grep -Fqx 'batch_profile_count=4' <<<"${batch_output}"
grep -Fqx 'run_prefix=ci-risk-batch' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-1' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-2' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-3' <<<"${batch_output}"
grep -Fqx 'run_id=ci-risk-batch-4' <<<"${batch_output}"
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
