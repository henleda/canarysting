#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/attackerexecutorspike.sh"
readonly proof_script

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then fail "${name} unexpectedly succeeded"; fi
  [[ "${output}" == *"${expected}"* ]] || fail "${name} did not report ${expected}: ${output}"
}

[[ -x "${proof_script}" ]] || fail "proof script is missing or not executable: ${proof_script}"
awk '/^ssh .*<<.REMOTE./ { capture=1; next } /^REMOTE$/ { capture=0 } capture { print }' "${proof_script}" |
  bash -n || fail 'embedded remote proof program has invalid Bash syntax'

output="$(${proof_script} --run-id m2c3-contract --dry-run)"
[[ "${output}" == *'bounded attacker executor proof contract passed; DGX was not accessed'* ]] || fail 'dry run did not remain local'
[[ "${output}" == *'artifact=test/attackerexecutorspike'* ]] || fail 'dry run omitted its fixed artifact'
[[ "${output}" == *'mutation=run-owned-stage,evidence,transient-loopback-socket'* ]] || fail 'dry run omitted exact mutation scope'
[[ "${output}" == *'privilege=unprivileged'* && "${output}" == *'model_execution=false'* ]] || fail 'dry run omitted privilege/model boundaries'
[[ "${output}" == *'raw_identifiers_emitted=false'* && "${output}" == *'cleanup=exact-run'* ]] || fail 'dry run omitted minimization/cleanup boundaries'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2c3-modes --dry-run --inspect
expect_failure arbitrary_command 'unknown argument: --command' "${proof_script}" --run-id m2c3-command --command id --dry-run
expect_failure arbitrary_path 'unknown argument: --path' "${proof_script}" --run-id m2c3-path --path /tmp --dry-run

for marker in \
  'catalog=PASS tools=7 arbitrary_tools=false' \
  'intent_before_resolve_and_dial=true failures_terminal=true' \
  'http_dns_tcp=loopback_only exact_target=true ambient_proxy=false' \
  'redirects_followed=false dns_set_change_denied=true' \
  'exercised_bounds=PASS actions=true response=true pre_cancellation=audited' \
  'shell_kubernetes_docker_filesystem_control_plane=false audited=true' \
  'listener_closed=true persistent_state=false' \
  'env -i LANG=C PATH=/usr/bin:/bin TZ=UTC' \
  'expires - finished == 86400'; do
  grep -F "${marker}" "${proof_script}" >/dev/null || fail "proof safety marker missing: ${marker}"
done
if grep -F 'action_time_rate_concurrency_request_response_memory=true' "${proof_script}" >/dev/null; then
  fail 'remote evidence overclaims bounds that the artifact does not exercise'
fi
if grep -E '(^|[[:space:]])(sudo|kubectl|bpftool|systemctl|iptables|nft|docker)([[:space:]]|$)' "${proof_script}" >/dev/null; then
  fail 'unprivileged attacker executor proof contains a privileged or control-plane command'
fi

schema_definition="$(awk '/^validate_result_schema\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
value_definition="$(awk '/^result_value\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
timestamp_definition="$(awk '/^validate_timestamps\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
[[ -n "${schema_definition}" && -n "${value_definition}" && -n "${timestamp_definition}" ]] || fail 'result validators are not independently testable'

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-attacker-executor-schema.XXXXXX")"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
result_file="${fixture_root}/result.tsv"
write_valid_result() {
  cat >"${result_file}" <<'RESULT'
key	value
format_version	1
run_id	m2c3-schema
scenario_id	m2c3-bounded-executor
profile	attacker-bounded-executor
source_revision	1111111111111111111111111111111111111111
source_state	clean
source_tree_sha256	2222222222222222222222222222222222222222222222222222222222222222
artifact_sha256	3333333333333333333333333333333333333333333333333333333333333333
proof_line_count	8
raw_identifiers_emitted	false
model_execution	false
privilege	unprivileged
started_utc	2026-09-06T12:00:00Z
finished_utc	2026-09-06T12:00:01Z
expires_utc	2026-09-07T12:00:01Z
stdout_sha256	4444444444444444444444444444444444444444444444444444444444444444
stderr_sha256	5555555555555555555555555555555555555555555555555555555555555555
exit_code	0
status	PASS
RESULT
}
run_schema_validator() {
  bash -c "${schema_definition}"$'\n''run_id=m2c3-schema source_revision=1111111111111111111111111111111111111111 source_state=clean source_tree_sha256=2222222222222222222222222222222222222222222222222222222222222222 expected_sha256=3333333333333333333333333333333333333333333333333333333333333333 validate_result_schema "$1"' -- "${result_file}"
}
run_timestamp_validator() {
  local program
  program="${value_definition}"$'\n'"${timestamp_definition}"$'\n''
date() {
  case "$*" in
    "-u -d 2026-09-06T12:00:00Z +%s") printf "100\n" ;;
    "-u -d 2026-09-06T12:00:01Z +%s") printf "101\n" ;;
    "-u -d 2026-09-07T12:00:01Z +%s") printf "86501\n" ;;
    "-u +%s") printf "200\n" ;;
    *) return 1 ;;
  esac
}
validate_timestamps "$1"'
  bash -c "${program}" -- "${result_file}"
}

write_valid_result
run_schema_validator || fail 'complete bounded-executor result schema was rejected'
run_timestamp_validator || fail 'valid bounded-executor timestamps were rejected'
grep -v $'^model_execution\t' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted missing model-execution boundary'; fi
write_valid_result
sed 's/^scenario_id\t.*/scenario_id\twrong-scenario/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted a different scenario'; fi
write_valid_result
printf 'unexpected\tvalue\n' >>"${result_file}"
if run_schema_validator; then fail 'schema accepted an unexpected field'; fi
write_valid_result
sed 's/^artifact_sha256\t.*/artifact_sha256\tffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_schema_validator; then fail 'schema accepted a mismatched artifact'; fi
write_valid_result
sed 's/^expires_utc\t.*/expires_utc\t2026-09-06T12:00:02Z/' "${result_file}" >"${result_file}.bad" && mv "${result_file}.bad" "${result_file}"
if run_timestamp_validator; then fail 'timestamp validator accepted non-24-hour expiry'; fi

printf 'PASS: DGX bounded attacker executor proof harness contract\n'
