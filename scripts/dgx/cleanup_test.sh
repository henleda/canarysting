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
grep -F 'test/correlationspike|test/tracespike|test/attackerexecutorspike|test/attackerloopspike|test/attackerscenariospike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits correlationspike'
grep -F 'f:test/tracespike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits tracespike'
grep -F 'test/correlationspike|test/tracespike|test/attackerexecutorspike|test/attackerloopspike|test/attackerscenariospike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits tracespike'
grep -F 'f:test/attackerexecutorspike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits attackerexecutorspike'
grep -F 'f:test/attackerloopspike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits attackerloopspike'
grep -F 'f:test/attackerscenariospike' "${cleanup_script}" >/dev/null ||
  fail 'cleanup artifact inventory omits attackerscenariospike'
grep -F 'f:model-load-owned)' "${cleanup_script}" >/dev/null ||
  fail 'generic inspector cannot recognize bounded-loop model ownership'
grep -F 'active model ownership marker requires attacker-loop cleanup' "${cleanup_script}" >/dev/null ||
  fail 'generic mutation does not refuse bounded-loop model ownership'
grep -F "evidence_state='model-owned'" "${cleanup_script}" >/dev/null ||
  fail 'generic inspector does not report bounded-loop model ownership'
grep -F 'test/tracespike|test/attackerexecutorspike|test/attackerloopspike|test/attackerscenariospike)' "${cleanup_script}" >/dev/null ||
  fail 'cleanup checksum inventory omits attackerexecutorspike'

marker_validator_definition="$(awk '/^validate_model_load_marker\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${cleanup_script}")"
evidence_validator_definition="$(awk '/^validate_evidence\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${cleanup_script}")"
[[ -n "${marker_validator_definition}" && -n "${evidence_validator_definition}" ]] ||
  fail 'model-owned recovery validators are not independently testable'
recovery_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-cleanup-marker.XXXXXX")"
trap 'rm -rf -- "${recovery_root}"' EXIT INT TERM
recovery_stage="${recovery_root}/stage"
recovery_evidence="${recovery_root}/evidence"
mkdir -m 0700 "${recovery_stage}" "${recovery_evidence}"
printf 'canarysting-model-load-owned-v1\n' >"${recovery_evidence}/model-load-owned"
chmod 0600 "${recovery_evidence}/model-load-owned"
recovery_program=$'set -euo pipefail\nmode="$1"\nstage="$2"\nevidence="$3"\nfail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\nvalidate_common() { return 0; }\nfind() { printf "f:model-load-owned\\n"; }\nstat() {\n  [[ "$1" == "-c" ]] || return 1\n  if [[ "$2" == "%a" && "$3" == "${evidence}" ]]; then printf "700\\n"; return 0; fi\n  if [[ "$2" == "%a" && "$3" == "${evidence}/model-load-owned" ]]; then printf "600\\n"; return 0; fi\n  if [[ "$2" == "%s" && "$3" == "${evidence}/model-load-owned" ]]; then printf "32\\n"; return 0; fi\n  return 1\n}\n'"${marker_validator_definition}"$'\n'"${evidence_validator_definition}"$'\nvalidate_evidence "${evidence}"'
bash -c "${recovery_program}" -- inspect "${recovery_stage}" "${recovery_evidence}" ||
  fail 'read-only inspection rejected an exact active model-ownership marker'
expect_failure active_model_owner 'active model ownership marker requires attacker-loop cleanup' \
  bash -c "${recovery_program}" -- cleanup "${recovery_stage}" "${recovery_evidence}"

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
