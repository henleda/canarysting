#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
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

attacker_check_output="$("${script_dir}/pr.sh" --profile attacker-check --run-id ci-attacker-check --dry-run)"
grep -Fqx 'profile=attacker-check' <<<"${attacker_check_output}"
grep -Fqx 'preflight_count=0' <<<"${attacker_check_output}"
grep -Fqx 'read_only_check_count=1' <<<"${attacker_check_output}"
grep -Fqx 'artifact_build_count=0' <<<"${attacker_check_output}"
grep -Fqx 'artifact_transfer_count=0' <<<"${attacker_check_output}"
grep -Fq 'attacker-lab inspection contract passed; DGX was not accessed' <<<"${attacker_check_output}"

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
