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

validator_definition="$(awk '
  /^validate_trace_result_schema\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${validator_definition}" ]] || fail 'trace result-schema validator is not independently testable'
result_value_definition="$(awk '
  /^result_value\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
timestamp_validator_definition="$(awk '
  /^validate_trace_result_timestamps\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "${proof_script}")"
[[ -n "${result_value_definition}" && -n "${timestamp_validator_definition}" ]] ||
  fail 'trace timestamp validator is not independently testable'

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-trace-schema.XXXXXX")"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
result_file="${fixture_root}/result.tsv"
write_valid_result() {
  cat >"${result_file}" <<'RESULT'
key	value
format_version	1
run_id	m2b4-schema
scenario_id	m2b4-trace-construction-m2b4-schema
profile	trace-construction
source_revision	1111111111111111111111111111111111111111
source_state	clean
source_tree_sha256	2222222222222222222222222222222222222222222222222222222222222222
artifact_sha256	3333333333333333333333333333333333333333333333333333333333333333
proof_line_count	8
raw_identifiers_emitted	false
privilege	unprivileged
started_utc	2026-09-03T12:00:00Z
finished_utc	2026-09-03T12:00:01Z
expires_utc	2026-09-04T12:00:01Z
stdout_sha256	4444444444444444444444444444444444444444444444444444444444444444
stderr_sha256	5555555555555555555555555555555555555555555555555555555555555555
exit_code	0
status	PASS
RESULT
}
run_schema_validator() {
  bash -c "${validator_definition}"$'\n''validate_trace_result_schema "$@"' -- \
    "${result_file}" m2b4-schema m2b4-trace-construction-m2b4-schema \
    1111111111111111111111111111111111111111 clean \
    2222222222222222222222222222222222222222222222222222222222222222 \
    3333333333333333333333333333333333333333333333333333333333333333
}
run_timestamp_validator() {
  local test_program
  test_program="${result_value_definition}"$'\n'"${timestamp_validator_definition}"$'\n''
date() {
  case "$*" in
    "-u -d 2026-09-03T12:00:00Z +%s") printf "100\n" ;;
    "-u -d 2026-09-03T12:00:01Z +%s") printf "101\n" ;;
    "-u -d 2026-09-04T12:00:01Z +%s") printf "86501\n" ;;
    "-u -d 2026-09-03T12:00:02Z +%s") printf "102\n" ;;
    "-u +%s") printf "200\n" ;;
    *) return 1 ;;
  esac
}
validate_trace_result_timestamps "$1"'
  bash -c "${test_program}" -- "${result_file}"
}

write_valid_result
run_schema_validator || fail 'complete trace result schema was rejected'
run_timestamp_validator || fail 'valid trace result timestamps were rejected'
grep -v $'^scenario_id\t' "${result_file}" >"${result_file}.missing"
mv "${result_file}.missing" "${result_file}"
if run_schema_validator; then
  fail 'trace result schema accepted a missing scenario binding'
fi
write_valid_result
printf 'unexpected\tvalue\n' >>"${result_file}"
if run_schema_validator; then
  fail 'trace result schema accepted an unexpected field'
fi
write_valid_result
sed 's/^artifact_sha256\t.*/artifact_sha256\tffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' "${result_file}" >"${result_file}.wrong"
mv "${result_file}.wrong" "${result_file}"
if run_schema_validator; then
  fail 'trace result schema accepted a mismatched artifact binding'
fi
write_valid_result
sed 's/^started_utc\t.*/started_utc\t2026-09-03 12:00:00/' "${result_file}" >"${result_file}.malformed"
mv "${result_file}.malformed" "${result_file}"
if run_schema_validator; then
  fail 'trace result schema accepted a malformed timestamp'
fi
write_valid_result
sed 's/^expires_utc\t.*/expires_utc\t2026-09-03T12:00:02Z/' "${result_file}" >"${result_file}.expired"
mv "${result_file}.expired" "${result_file}"
if run_timestamp_validator; then
  fail 'trace timestamp validator accepted an expired or non-24-hour result'
fi

printf 'PASS: DGX trace proof harness contract\n'
