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

if "${script_dir}/pr.sh" --profile dgx-kubernetes --run-id ci-risk-dry-run --dry-run >/dev/null 2>&1; then
  echo 'FAIL: unsupported Kubernetes profile did not fail closed' >&2
  exit 1
fi
if "${script_dir}/pr.sh" --profile invalid --run-id ci-risk-dry-run --dry-run >/dev/null 2>&1; then
  echo 'FAIL: unknown profile was accepted' >&2
  exit 1
fi

printf 'PASS: risk-selected DGX coordinator contract\n'
