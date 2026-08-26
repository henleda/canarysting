#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/cookiespike.sh"
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
  [[ "${output}" == *"${expected}"* ]] ||
    fail "${name} did not report the expected refusal: ${output}"
}

[[ -x "${proof_script}" ]] || fail "proof script is missing or not executable: ${proof_script}"

awk '
  /^ssh .*<<.REMOTE./ { capture = 1; next }
  /^REMOTE$/ { capture = 0 }
  capture { print }
' "${proof_script}" | bash -n || fail 'embedded remote proof program has invalid Bash syntax'

awk '
  /^sudo -n bash .*<<.ROOT./ { capture = 1; next }
  /^ROOT$/ { capture = 0 }
  capture { print }
' "${proof_script}" | bash -n || fail 'embedded privileged proof helper has invalid Bash syntax'

output="$(${proof_script} --run-id m1c-local-test --dry-run)"
[[ "${output}" == *'DGX was not accessed'* ]] || fail 'dry run did not stay local'
[[ "${output}" == *'remote_stage=/var/tmp/canarysting/m1c-local-test'* ]] || fail 'dry run reported the wrong stage'
[[ "${output}" == *'remote_evidence=/var/tmp/canarysting/cookiespike-m1c-local-test'* ]] ||
  fail 'dry run reported the wrong evidence path'
[[ "${output}" == *'remote_cgroup=/sys/fs/cgroup/canarysting-dgx/m1c-local-test'* ]] ||
  fail 'dry run reported the wrong child cgroup'
[[ "${output}" == *$'attach_scope=run-owned-child-cgroup\n'* ]] || fail 'dry run omitted the minimal attach scope'
[[ "${output}" == *$'traffic=loopback-only\n'* ]] || fail 'dry run omitted the bounded traffic contract'
[[ "${output}" == *'enforcement=none'* ]] || fail 'dry run omitted the observe-only contract'
[[ "${output}" == *$'timeout_seconds=15\n'* ]] || fail 'dry run omitted the fixed timeout'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure uppercase_run_id 'run ID must be' "${proof_script}" --run-id Unsafe --dry-run
expect_failure duplicate_run_id '--run-id may be specified only once' \
  "${proof_script}" --run-id m1c-a --run-id m1c-b --dry-run
expect_failure conflicting_modes 'mutually exclusive' \
  "${proof_script}" --run-id m1c-modes --inspect --cleanup
expect_failure duplicate_dry_run 'mutually exclusive' \
  "${proof_script}" --run-id m1c-repeat --dry-run --dry-run
expect_failure arbitrary_path 'unknown argument: --cgroup' \
  "${proof_script}" --run-id m1c-path --cgroup /sys/fs/cgroup --dry-run
expect_failure arbitrary_command 'unknown argument: --command' \
  "${proof_script}" --run-id m1c-command --command id --dry-run
expect_failure arbitrary_timeout 'unknown argument: --timeout' \
  "${proof_script}" --run-id m1c-timeout --timeout 999 --dry-run
expect_failure broad_cleanup 'unknown argument: --all' \
  "${proof_script}" --run-id m1c-all --all --dry-run
expect_failure privilege_override 'unknown argument: --sudo' \
  "${proof_script}" --run-id m1c-sudo --sudo --dry-run

grep -F -- '-proof cannot be combined with -resolve' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike proof mode does not explicitly exclude manual resolve probes'
grep -F 'PROOF missing_attribution=PASS result=MISS enforcement=refused' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the unattributable-flow proof marker'
grep -F 'PROOF flow_identity=PASS socket_cookie=' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the flow-identity proof marker'
grep -F 'PROOF close_delete=PASS result=MISS' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the close-delete proof marker'

printf 'PASS: DGX socket-cookie proof local contract checks passed\n'
