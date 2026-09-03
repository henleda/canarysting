#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/tracespike.sh"
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

output="$(${proof_script} --run-id m2b4-contract --dry-run)"
[[ "${output}" == *'trace proof contract passed; DGX was not accessed'* ]] || fail 'dry run did not remain local'
[[ "${output}" == *'artifact=test/tracespike'* ]] || fail 'dry run omitted its fixed artifact'
[[ "${output}" == *'mutation=run-owned-stage,evidence'* ]] || fail 'dry run omitted exact mutation scope'
[[ "${output}" == *'privilege=unprivileged'* ]] || fail 'dry run omitted privilege boundary'
[[ "${output}" == *'raw_identifiers_emitted=false'* ]] || fail 'dry run omitted minimization boundary'
[[ "${output}" == *'cleanup=exact-run'* ]] || fail 'dry run omitted cleanup contract'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2b4-modes --dry-run --inspect
expect_failure arbitrary_argument 'unknown argument: --command' "${proof_script}" --run-id m2b4-command --command id --dry-run
expect_failure arbitrary_path 'unknown argument: --path' "${proof_script}" --run-id m2b4-path --path /tmp --dry-run

for marker in \
  'passive_partial=PASS canary_touch_required=false' \
  'join_citations=PASS all_links_evidence_backed=true' \
  'broken_raw=PASS availability=INTEGRITY_MISMATCH' \
  'ambiguity=PASS candidates=2 chosen=false' \
  'fixed proof output is incomplete or contains extra data' \
  'env -i LANG=C PATH=/usr/bin:/bin TZ=UTC'; do
  grep -F "${marker}" "${proof_script}" >/dev/null || fail "proof safety marker missing: ${marker}"
done

if grep -E 'sudo|kubectl|bpftool|systemctl|iptables|nft[[:space:]]' "${proof_script}" >/dev/null; then
  fail 'unprivileged trace proof contains a privileged or control-plane command'
fi

printf 'PASS: DGX trace proof harness contract\n'
