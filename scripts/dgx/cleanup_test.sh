#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
cleanup_script="${script_dir}/cleanup.sh"
readonly cleanup_script

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
  [[ "${output}" == *"${expected}"* ]] ||
    fail "${name} did not report the expected refusal: ${output}"
}

[[ -x "${cleanup_script}" ]] || fail "cleanup script is missing or not executable: ${cleanup_script}"
grep -F 'f:test/correlationspike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits correlationspike'
grep -F 'test/correlationspike|test/tracespike|test/attackerexecutorspike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits correlationspike'
grep -F 'f:test/tracespike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits tracespike'
grep -F 'test/correlationspike|test/tracespike|test/attackerexecutorspike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits tracespike'
grep -F 'f:test/attackerexecutorspike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits attackerexecutorspike'
grep -F 'test/tracespike|test/attackerexecutorspike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits attackerexecutorspike'

awk '
  /^ssh .*<<.REMOTE./ { capture = 1; next }
  /^REMOTE$/ { capture = 0 }
  capture { print }
' "${cleanup_script}" | bash -n || fail 'embedded remote cleanup program has invalid Bash syntax'

output="$(${cleanup_script} --run-id cleanup-test-01 --dry-run)"
[[ "${output}" == *'DGX was not accessed'* ]] || fail 'dry run did not report its read-only boundary'
[[ "${output}" == *'candidate=/var/tmp/canarysting/.incoming-cleanup-test-01'* ]] ||
  fail 'dry run omitted the exact incoming candidate'
[[ "${output}" == *'candidate=/var/tmp/canarysting/cleanup-test-01'* ]] ||
  fail 'dry run omitted the exact published-stage candidate'
[[ "${output}" == *'candidate=/var/tmp/canarysting/execution-cleanup-test-01'* ]] ||
  fail 'dry run omitted the exact evidence candidate'
[[ "${output}" == *'excluded=Kubernetes,BPF,containers,images,system-config,product-deployments,historical-artifacts'* ]] ||
  fail 'dry run omitted excluded remote state'

expect_failure missing_run_id '--run-id is required' "${cleanup_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${cleanup_script}" --run-id '../escape' --dry-run
expect_failure uppercase_run_id 'run ID must be' "${cleanup_script}" --run-id Unsafe --dry-run
expect_failure duplicate_run_id '--run-id may be specified only once' \
  "${cleanup_script}" --run-id cleanup-a --run-id cleanup-b --dry-run
expect_failure conflicting_modes 'mutually exclusive' \
  "${cleanup_script}" --run-id cleanup-modes --inspect --dry-run
expect_failure duplicate_dry_run 'mutually exclusive' \
  "${cleanup_script}" --run-id cleanup-repeat --dry-run --dry-run
expect_failure arbitrary_path 'unknown argument: --path' \
  "${cleanup_script}" --run-id cleanup-path --path /var/tmp --dry-run
expect_failure broad_cleanup 'unknown argument: --all' \
  "${cleanup_script}" --run-id cleanup-all --all --dry-run
expect_failure historical_cleanup 'unknown argument: --historical' \
  "${cleanup_script}" --run-id cleanup-old --historical --dry-run
expect_failure privilege_escalation 'unknown argument: --sudo' \
  "${cleanup_script}" --run-id cleanup-sudo --sudo --dry-run

printf 'PASS: DGX exact-run cleanup local checks passed\n'
