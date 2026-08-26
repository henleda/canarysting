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

capture_definition="$(awk '
  /^bounded_capture\(\) \{$/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${capture_definition}" ]] || fail 'bounded log-capture implementation is missing'
capture_fixture="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-cookiespike-capture.XXXXXX")"
cleanup_fixture() {
  rm -rf -- "${capture_fixture}"
}
trap cleanup_fixture EXIT

printf 'bounded-output\n' | bash -c "${capture_definition}"$'\n''bounded_capture "$1" "$2"' -- \
  "${capture_fixture}/short.log" "${capture_fixture}/short.state"
[[ "$(<"${capture_fixture}/short.log")" == 'bounded-output' ]] || fail 'bounded capture changed short output'
[[ "$(<"${capture_fixture}/short.state")" == 'complete' ]] || fail 'bounded capture did not mark short output complete'

head -c 1048577 /dev/zero | bash -c "${capture_definition}"$'\n''bounded_capture "$1" "$2"' -- \
  "${capture_fixture}/large.log" "${capture_fixture}/large.state"
[[ "$(wc -c <"${capture_fixture}/large.log" | tr -d ' ')" == '1048576' ]] || fail 'bounded capture exceeded its 1 MiB file cap'
[[ "$(<"${capture_fixture}/large.state")" == 'truncated' ]] || fail 'bounded capture did not report discarded output'

validation_definition="$(awk '
  /^validate_evidence\(\) \{$/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${validation_definition}" ]] || fail 'evidence validation implementation is missing'
cleanup_evidence="${capture_fixture}/oversized-cleanup"
mkdir -m 700 "${cleanup_evidence}"
head -c 1048577 /dev/zero >"${cleanup_evidence}/stdout.log"
bash -c 'fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n'"${validation_definition}"$'\n''evidence="$1"; validate_evidence no' -- \
  "${cleanup_evidence}" || fail 'cleanup validation rejected exact owned evidence with an oversized legacy log'

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
grep -F 'PROOF missing_attribution=PASS result=MISS attribution=refused' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the unattributable-flow proof marker'
grep -F 'PROOF flow_identity=PASS socket_cookie=' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the flow-identity proof marker'
grep -F 'PROOF close_delete=PASS result=MISS' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'cookiespike binary is missing the close-delete proof marker'
grep -F 'res.ResolveChecked(tuple)' "${script_dir}/../../cmd/cookiespike/main.go" >/dev/null ||
  fail 'close-delete proof does not preserve map lookup errors'
grep -F 'for kind in prog map link' "${proof_script}" >/dev/null ||
  fail 'BPF residue inventory does not cover programs, maps, and links'
grep -F "PROOF attach_scope=%s child=%s parent=absent root=absent" "${proof_script}" >/dev/null ||
  fail 'proof harness does not record a live child-versus-parent/root attachment observation'

printf 'PASS: DGX socket-cookie proof local contract checks passed\n'
