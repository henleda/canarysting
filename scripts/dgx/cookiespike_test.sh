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
  /<<.ROOT./ { capture = 1; next }
  /^ROOT$/ { capture = 0 }
  capture { print }
' "${proof_script}" | bash -n || fail 'embedded privileged proof helper has invalid Bash syntax'

awk '
  /<<.SNAPSHOT./ { capture = 1; next }
  /^SNAPSHOT$/ { capture = 0 }
  capture { print }
' "${proof_script}" | bash -n || fail 'embedded privileged snapshot cleanup helper has invalid Bash syntax'

capture_definition="$(awk '
  /^bounded_capture\(\) \{$/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${capture_definition}" ]] || fail 'bounded log-capture implementation is missing'
capture_runner='dd() { command dd bs=1 count=1048576 2>/dev/null; }'$'\n'"${capture_definition}"$'\n''bounded_capture "$1" "$2"'
capture_fixture="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-cookiespike-capture.XXXXXX")"
cleanup_fixture() {
  rm -rf -- "${capture_fixture}"
}
trap cleanup_fixture EXIT

snapshot_definition="$(awk '
  /^prepare_verified_snapshot\(\) \{$/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${snapshot_definition}" ]] || fail 'verified privileged snapshot implementation is missing'
snapshot_runner='proof_fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''timeout() { shift 3; "$@"; }'$'\n''cp() { [[ "$1" == --no-preserve=* && "$2" == "--" ]]; command cp -- "${test_source}" "$4"; }'$'\n''mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'$'\n''stat() { if [[ "$1" == "-Lc" && "$2" == "%F" ]]; then [[ -f "${test_source}" ]] && printf "regular file\n"; elif [[ "$1" == "-c" && "$2" == "%s" ]]; then wc -c <"$3" | tr -d " "; elif [[ "$1" == "-c" && "$2" == "%a" ]]; then command stat -c %a "$3" 2>/dev/null || command stat -f %Lp "$3"; else return 1; fi; }'$'\n'"${snapshot_definition}"$'\n''test_source="$1"; snapshot_artifact="$2/cookiespike"; snapshot_tmp="${snapshot_artifact}.tmp"; expected_size="$3"; expected_sha256="$4"; prepare_verified_snapshot "$1"'
snapshot_source="${capture_fixture}/snapshot-source"
snapshot_valid_dir="${capture_fixture}/snapshot-valid"
snapshot_invalid_dir="${capture_fixture}/snapshot-invalid"
printf 'verified artifact bytes\n' >"${snapshot_source}"
mkdir -m 700 "${snapshot_valid_dir}" "${snapshot_invalid_dir}"
snapshot_size="$(wc -c <"${snapshot_source}" | tr -d ' ')"
snapshot_sha256="$(sha256sum "${snapshot_source}" | awk '{ print $1 }')"
bash -c "${snapshot_runner}" -- "${snapshot_source}" "${snapshot_valid_dir}" "${snapshot_size}" "${snapshot_sha256}"
[[ "$(sha256sum "${snapshot_valid_dir}/cookiespike" | awk '{ print $1 }')" == "${snapshot_sha256}" ]] ||
  fail 'privileged snapshot changed verified artifact bytes'
printf 'tampered artifact bytes\n' >"${snapshot_source}"
expect_failure snapshot_checksum_mismatch 'privileged artifact snapshot checksum mismatch' \
  bash -c "${snapshot_runner}" -- "${snapshot_source}" "${snapshot_invalid_dir}" "${snapshot_size}" "${snapshot_sha256}"

printf 'bounded-output\n' | bash -c "${capture_runner}" -- \
  "${capture_fixture}/short.log" "${capture_fixture}/short.state"
[[ "$(<"${capture_fixture}/short.log")" == 'bounded-output' ]] || fail 'bounded capture changed short output'
[[ "$(<"${capture_fixture}/short.state")" == 'complete' ]] || fail 'bounded capture did not mark short output complete'

head -c 1048577 /dev/zero | bash -c "${capture_runner}" -- \
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
cleanup_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'$'\n'"${validation_definition}"$'\n'"${cleanup_definition}"$'\n''run_id="$1"; cleanup_result="$(cleanup_evidence "$2" "cookiespike-${run_id}")" || fail "anchored evidence cleanup failed"; printf "%s\n" "${cleanup_result}"'

preflight_definition="$(awk '
  /^require_no_quarantined_evidence\(\) \{$/ { capture = 1 }
  capture { print }
  /^require_fresh_evidence_state\(\) \{$/ { fresh = 1 }
  capture && fresh && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${preflight_definition}" ]] || fail 'proof evidence preflight implementation is missing'
preflight_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n'"${preflight_definition}"$'\n''require_fresh_evidence_state "$1" "$2"'
quarantine_check_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n'"${preflight_definition}"$'\n''require_no_quarantined_evidence "$1"'

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

cdpath_root="${capture_fixture}/cdpath-root"
cdpath_external="${capture_fixture}/cdpath-external"
mkdir -m 700 "${cdpath_root}" "${cdpath_external}"
cdpath_root="$(cd -P "${cdpath_root}" && pwd -P)"
cdpath_run_id='m1c-cdpath-test'
cdpath_quarantine=".cleanup-cookiespike-${cdpath_run_id}"
mkdir -m 700 "${cdpath_root}/${cdpath_quarantine}" "${cdpath_external}/${cdpath_quarantine}"
printf 'owned quarantine\n' >"${cdpath_root}/${cdpath_quarantine}/stdout.log"
printf 'external sentinel\n' >"${cdpath_external}/${cdpath_quarantine}/stdout.log"
cdpath_state="$(CDPATH="${cdpath_external}" bash -c "${cleanup_runner}" -- "${cdpath_run_id}" "${cdpath_root}")" ||
  fail 'anchored cleanup failed with an inherited CDPATH'
[[ "${cdpath_state}" == 'removed' ]] || fail "CDPATH cleanup reported an unexpected state: ${cdpath_state}"
[[ ! -e "${cdpath_root}/${cdpath_quarantine}" ]] || fail 'CDPATH cleanup left the run-owned quarantine'
[[ "$(<"${cdpath_external}/${cdpath_quarantine}/stdout.log")" == 'external sentinel' ]] ||
  fail 'CDPATH cleanup changed the external same-named quarantine'

swap_root="${capture_fixture}/swap-root"
swap_external="${capture_fixture}/swap-external"
mkdir -m 700 "${swap_root}" "${swap_external}"
swap_root="$(cd -P "${swap_root}" && pwd -P)"
swap_external="$(cd -P "${swap_external}" && pwd -P)"
swap_run_id='m1c-swap-test'
swap_quarantine=".cleanup-cookiespike-${swap_run_id}"
mkdir -m 700 "${swap_root}/${swap_quarantine}"
printf 'run-owned sentinel\n' >"${swap_root}/${swap_quarantine}/stdout.log"
printf 'external sentinel\n' >"${swap_external}/stdout.log"
swap_cleanup_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'$'\n''cd() { if [[ "$*" == *"./${SWAP_NAME}"* ]]; then command mv -- "${SWAP_ROOT}/${SWAP_NAME}" "${SWAP_ROOT}/${SWAP_NAME}.saved"; command ln -s "${SWAP_EXTERNAL}" "${SWAP_ROOT}/${SWAP_NAME}"; fi; builtin cd "$@"; }'$'\n'"${validation_definition}"$'\n'"${cleanup_definition}"$'\n''run_id="$1"; cleanup_result="$(cleanup_evidence "$2" "cookiespike-${run_id}")" || fail "anchored evidence cleanup failed"; printf "%s\n" "${cleanup_result}"'
expect_failure quarantine_swap 'quarantined evidence resolved outside the fixed cleanup root' \
  env SWAP_ROOT="${swap_root}" SWAP_EXTERNAL="${swap_external}" SWAP_NAME="${swap_quarantine}" \
  bash -c "${swap_cleanup_runner}" -- "${swap_run_id}" "${swap_root}"
[[ "$(<"${swap_external}/stdout.log")" == 'external sentinel' ]] ||
  fail 'quarantine-swap refusal changed external evidence'
[[ "$(<"${swap_root}/${swap_quarantine}.saved/stdout.log")" == 'run-owned sentinel' ]] ||
  fail 'quarantine-swap refusal changed run-owned evidence'

dual_root="${capture_fixture}/dual-root"
mkdir -m 700 "${dual_root}"
dual_root="$(cd -P "${dual_root}" && pwd -P)"
dual_run_id='m1c-dual-test'
dual_evidence="${dual_root}/cookiespike-${dual_run_id}"
dual_quarantine="${dual_root}/.cleanup-cookiespike-${dual_run_id}"
mkdir -m 700 "${dual_evidence}" "${dual_quarantine}"
printf 'live residue\n' >"${dual_evidence}/stdout.log"
printf 'interrupted cleanup residue\n' >"${dual_quarantine}/stderr.log"
dual_state="$(bash -c "${cleanup_runner}" -- "${dual_run_id}" "${dual_root}")" ||
  fail 'cleanup could not recover coexisting exact live and quarantined evidence'
[[ "${dual_state}" == 'removed' ]] || fail "dual-state cleanup reported an unexpected state: ${dual_state}"
[[ ! -e "${dual_evidence}" && ! -e "${dual_quarantine}" ]] ||
  fail 'cleanup left exact live or quarantined evidence after recovery'

preflight_root="${capture_fixture}/preflight-root"
mkdir -m 700 "${preflight_root}"
preflight_live="${preflight_root}/cookiespike-m1c-preflight-test"
preflight_quarantine="${preflight_root}/.cleanup-cookiespike-m1c-preflight-test"
mkdir -m 700 "${preflight_quarantine}"
expect_failure quarantine_preflight 'quarantined proof evidence already exists; run cleanup first' \
  bash -c "${preflight_runner}" -- "${preflight_live}" "${preflight_quarantine}"
expect_failure quarantine_inspect 'quarantined proof evidence already exists; run cleanup first' \
  bash -c "${quarantine_check_runner}" -- "${preflight_quarantine}"

failure_root="${capture_fixture}/failure-root"
mkdir -m 700 "${failure_root}"
failure_root="$(cd -P "${failure_root}" && pwd -P)"
failure_run_id='m1c-failure-test'
failure_quarantine="${failure_root}/.cleanup-cookiespike-${failure_run_id}"
mkdir -m 700 "${failure_quarantine}"
printf 'must remain after failed deletion\n' >"${failure_quarantine}/stdout.log"
chmod 500 "${failure_quarantine}"
expect_failure mutation_failure 'anchored evidence cleanup failed' \
  bash -c "${cleanup_runner}" -- "${failure_run_id}" "${failure_root}"
[[ -f "${failure_quarantine}/stdout.log" ]] || fail 'failed deletion removed or lost quarantined evidence'
chmod 700 "${failure_quarantine}"

grep -F 'cd -P -- "${root_dir}"' "${proof_script}" >/dev/null || fail 'cleanup does not anchor the physical root directory'
grep -F 'mv -T -- "${evidence_name}" "${quarantine_name}"' "${proof_script}" >/dev/null || fail 'cleanup quarantine rename may follow a substituted destination'
grep -F 'cd -P -- "./${quarantine_name}"' "${proof_script}" >/dev/null || fail 'cleanup quarantine entry may honor an inherited CDPATH'
grep -F '"$(pwd -P)" == "${root_dir}/${quarantine_name}"' "${proof_script}" >/dev/null ||
  fail 'cleanup does not bind the working directory to the fixed quarantine path'
grep -F '. -ef "${root_dir}/${quarantine_name}"' "${proof_script}" >/dev/null || fail 'cleanup does not bind deletion to the quarantined directory inode'
grep -F 'quarantined proof evidence already exists; run cleanup first' "${proof_script}" >/dev/null ||
  fail 'proof preflight does not block a same-ID rerun while quarantine exists'
grep -F 'require_no_quarantined_evidence "${evidence_quarantine}"' "${proof_script}" >/dev/null ||
  fail 'proof inspection does not reject interrupted quarantine residue'
grep -F 'evidence_state="$(cleanup_evidence "${root}" "cookiespike-${run_id}")" ||' "${proof_script}" >/dev/null ||
  fail 'cleanup caller does not explicitly propagate command-substitution failure'
grep -F '"${snapshot_artifact}" -cgroup "${cgroup}" -proof' "${proof_script}" >/dev/null ||
  fail 'privileged helper does not execute the verified root-owned snapshot'
if grep -F '"${artifact}" -cgroup "${cgroup}" -proof' "${proof_script}" >/dev/null; then
  fail 'privileged helper still executes the mutable staged artifact path'
fi
grep -F 'privileged_snapshot_residue' "${proof_script}" >/dev/null ||
  fail 'proof evidence does not record privileged snapshot cleanup'
[[ "$(grep -Fc "privileged snapshot parent must be the root-owned mode-1777 /var/tmp directory" "${proof_script}")" == '2' ]] ||
  fail 'privileged run and cleanup helpers do not both verify the sticky root-owned snapshot parent'

output="$(${proof_script} --run-id m1c-local-test --dry-run)"
[[ "${output}" == *'DGX was not accessed'* ]] || fail 'dry run did not stay local'
[[ "${output}" == *'remote_stage=/var/tmp/canarysting/m1c-local-test'* ]] || fail 'dry run reported the wrong stage'
[[ "${output}" == *'remote_evidence=/var/tmp/canarysting/cookiespike-m1c-local-test'* ]] ||
  fail 'dry run reported the wrong evidence path'
[[ "${output}" == *'remote_cgroup=/sys/fs/cgroup/canarysting-dgx/m1c-local-test'* ]] ||
  fail 'dry run reported the wrong child cgroup'
[[ "${output}" == *'remote_privileged_snapshot=/var/tmp/canarysting-privileged/cookiespike-m1c-local-test'* ]] ||
  fail 'dry run reported the wrong privileged snapshot path'
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
