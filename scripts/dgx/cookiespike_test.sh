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
cleanup_definition="$(awk '
  /^cleanup_evidence\(\) \{$/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${cleanup_definition}" ]] || fail 'anchored evidence cleanup implementation is missing'
cleanup_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'$'\n'"${validation_definition}"$'\n'"${cleanup_definition}"$'\n''run_id="$1"; cleanup_evidence "$2" "cookiespike-${run_id}"'

cleanup_root="${capture_fixture}/cleanup-root"
mkdir -m 700 "${cleanup_root}"
cleanup_root="$(cd -P "${cleanup_root}" && pwd -P)"
cleanup_run_id='m1c-oversized-test'
cleanup_evidence="${cleanup_root}/cookiespike-${cleanup_run_id}"
mkdir -m 700 "${cleanup_evidence}"
head -c 1048577 /dev/zero >"${cleanup_evidence}/stdout.log"
cleanup_state="$(bash -c "${cleanup_runner}" -- "${cleanup_run_id}" "${cleanup_root}")" ||
  fail 'anchored cleanup rejected exact owned evidence with an oversized legacy log'
[[ "${cleanup_state}" == 'removed' ]] || fail "oversized cleanup reported an unexpected state: ${cleanup_state}"
[[ ! -e "${cleanup_evidence}" && ! -L "${cleanup_evidence}" ]] || fail 'oversized evidence remains after cleanup'

redirect_target="${capture_fixture}/redirect-target"
mkdir -m 700 "${redirect_target}"
redirect_run_id='m1c-ancestor-test'
redirect_evidence="${redirect_target}/cookiespike-${redirect_run_id}"
mkdir -m 700 "${redirect_evidence}"
head -c 1048577 /dev/zero >"${redirect_evidence}/stdout.log"
redirect_root="${capture_fixture}/redirected-root"
ln -s "${redirect_target}" "${redirect_root}"
expect_failure ancestor_symlink 'cleanup root must be an owned, non-symlink directory' \
  bash -c "${cleanup_runner}" -- "${redirect_run_id}" "${redirect_root}"
[[ "$(wc -c <"${redirect_evidence}/stdout.log" | tr -d ' ')" == '1048577' ]] ||
  fail 'ancestor-symlink refusal changed redirected evidence'

leaf_root="${capture_fixture}/leaf-root"
leaf_target="${capture_fixture}/leaf-target"
mkdir -m 700 "${leaf_root}" "${leaf_target}"
leaf_root="$(cd -P "${leaf_root}" && pwd -P)"
leaf_run_id='m1c-leaf-test'
head -c 1048577 /dev/zero >"${leaf_target}/stdout.log"
ln -s "${leaf_target}" "${leaf_root}/cookiespike-${leaf_run_id}"
expect_failure leaf_symlink 'evidence must be an owned, non-symlink directory' \
  bash -c "${cleanup_runner}" -- "${leaf_run_id}" "${leaf_root}"
[[ "$(wc -c <"${leaf_target}/stdout.log" | tr -d ' ')" == '1048577' ]] ||
  fail 'leaf-symlink refusal changed redirected evidence'

grep -F 'cd -P -- "${root_dir}"' "${proof_script}" >/dev/null || fail 'cleanup does not anchor the physical root directory'
grep -F 'mv -T -- "${evidence_name}" "${quarantine_name}"' "${proof_script}" >/dev/null || fail 'cleanup quarantine rename may follow a substituted destination'
grep -F '. -ef "../${quarantine_name}"' "${proof_script}" >/dev/null || fail 'cleanup does not bind deletion to the quarantined directory inode'

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
