#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/dgxstackspike.sh"
readonly proof_script

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then
    fail "${name} unexpectedly succeeded"
  fi
  [[ "${output}" == *"${expected}"* ]] || fail "${name} did not report ${expected}: ${output}"
}

[[ -x "${proof_script}" ]] || fail "proof script is missing or not executable: ${proof_script}"

awk '
  /^ssh .*<<.REMOTE./ { capture = 1; next }
  /^REMOTE$/ { capture = 0 }
  capture { print }
' "${proof_script}" | bash -n || fail 'embedded remote proof program has invalid Bash syntax'

output="$(${proof_script} --run-id m2b2-contract --dry-run)"
[[ "${output}" == *'DGX was not accessed'* ]] || fail 'dry run did not remain local'
[[ "${output}" == *'artifact=test/dgxstackspike'* ]] || fail 'dry run omitted its fixed artifact'
[[ "${output}" == *'sources=canarysting,canarysting-engine,kernel-ebpf,envoy,kubernetes,cilium,hubble'* ]] ||
  fail 'dry run omitted the exact source catalog'
[[ "${output}" == *'source_access=read-only'* ]] || fail 'dry run omitted read-only authority'
[[ "${output}" == *'raw_capture=ephemeral-hash-then-delete'* ]] || fail 'dry run omitted raw cleanup posture'
[[ "${output}" == *'synthetic=true'* ]] || fail 'dry run omitted synthetic isolation'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2b2-modes --dry-run --inspect
expect_failure arbitrary_argument 'unknown argument: --command' "${proof_script}" --run-id m2b2-command --command id --dry-run
expect_failure arbitrary_path 'unknown argument: --path' "${proof_script}" --run-id m2b2-path --path /tmp --dry-run

if grep -E 'kubectl[[:space:]]+(apply|create|delete|edit|patch|replace|scale)|bpftool[[:space:]]+(map update|prog load|cgroup attach)' "${proof_script}" >/dev/null; then
  fail 'proof script contains a source mutation command'
fi
for marker in \
  'raw_payload_retained\tfalse' \
  'raw_capture_removed\tPASS' \
  'find "${captures}" -mindepth 1 -maxdepth 1 -type f'; do
  grep -F "${marker}" "${proof_script}" >/dev/null || fail "proof safety marker missing: ${marker}"
done

printf 'PASS: DGX-stack source proof harness contract\n'
