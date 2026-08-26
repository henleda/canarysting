#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
run_script="${script_dir}/run.sh"
readonly run_script

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  if "$@" >"${tmp_root}/${name}.log" 2>&1; then
    fail "${name}: command unexpectedly succeeded"
  fi
  grep -F -- "${expected}" "${tmp_root}/${name}.log" >/dev/null ||
    fail "${name}: expected diagnostic not found: ${expected}"
}

tmp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly tmp_parent
tmp_root="$(mktemp -d "${tmp_parent}/canarysting-run-test.XXXXXX")"
cleanup() {
  if [[ -n "${tmp_root:-}" && -d "${tmp_root}" &&
    "${tmp_root}" == "${tmp_parent}/canarysting-run-test."* ]]; then
    rm -rf -- "${tmp_root}"
  fi
}
trap cleanup EXIT INT TERM

profile_list="$(${run_script} --list)"
[[ "${profile_list}" == *$'engine-selfcheck\tproduct/engine\t15\texit-zero\tunprivileged'* ]] ||
  fail 'self-check profile is missing or changed'
[[ "${profile_list}" == *$'engine-timeout-probe\tproduct/engine\t2\ttimeout\tunprivileged'* ]] ||
  fail 'timeout profile is missing or changed'

selfcheck_output="$(${run_script} --run-id run-test-selfcheck --profile engine-selfcheck --dry-run)"
[[ "${selfcheck_output}" == *'DGX was not accessed'* ]] || fail 'self-check dry run did not stay local'
[[ "${selfcheck_output}" == *'remote_stage=/var/tmp/canarysting/run-test-selfcheck'* ]] ||
  fail 'self-check dry run reported the wrong stage'
[[ "${selfcheck_output}" == *'remote_evidence=/var/tmp/canarysting/execution-run-test-selfcheck'* ]] ||
  fail 'self-check dry run reported the wrong evidence directory'
[[ "${selfcheck_output}" == *$'timeout_seconds=15\n'* ]] || fail 'self-check timeout is not fixed'
[[ "${selfcheck_output}" == *'privilege=unprivileged'* ]] || fail 'self-check privilege is not fixed'

timeout_output="$(${run_script} --run-id run-test-timeout --profile engine-timeout-probe --dry-run)"
[[ "${timeout_output}" == *$'expected_outcome=timeout\n'* ]] || fail 'timeout outcome is not fixed'
[[ "${timeout_output}" == *$'timeout_seconds=2\n'* ]] || fail 'timeout duration is not fixed'

expect_failure missing_run_id '--run-id is required' \
  "${run_script}" --profile engine-selfcheck --dry-run
expect_failure missing_profile '--profile is required' \
  "${run_script}" --run-id run-test-missing --dry-run
expect_failure invalid_run_id 'run ID must be' \
  "${run_script}" --run-id '../escape' --profile engine-selfcheck --dry-run
expect_failure unknown_profile 'unsupported profile' \
  "${run_script}" --run-id run-test-unknown --profile arbitrary-command --dry-run
expect_failure arbitrary_argument 'unknown argument: --arg' \
  "${run_script}" --run-id run-test-args --profile engine-selfcheck --arg value --dry-run
expect_failure privilege_escalation 'unknown argument: --sudo' \
  "${run_script}" --run-id run-test-sudo --profile engine-selfcheck --sudo --dry-run
expect_failure duplicate_profile '--profile may be specified only once' \
  "${run_script}" --run-id run-test-duplicate --profile engine-selfcheck --profile engine-selfcheck --dry-run
expect_failure list_combination '--list cannot be combined' \
  "${run_script}" --list --run-id run-test-list

printf 'PASS: DGX deterministic execution local checks passed\n'
