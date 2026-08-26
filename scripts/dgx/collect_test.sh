#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
collect_script="${script_dir}/collect.sh"
readonly collect_script

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
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

make_fixture() {
  local root="$1"
  local fixture_run_id="$2"
  mkdir -p "${root}/stage" "${root}/execution"
  local artifact_sha
  artifact_sha="$(printf 'fixture artifact\n' | if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | awk '{print $1}')"
  {
    printf 'record\tkind_or_key\tname_or_value\tpath\tsize_bytes\tsha256\n'
    printf 'metadata\tformat_version\t1\n'
    printf 'metadata\ttarget_os\tlinux\n'
    printf 'metadata\ttarget_arch\tarm64\n'
    printf 'metadata\ttarget_arm64\tv8.0\n'
    printf 'metadata\tcgo_enabled\t0\n'
    printf 'metadata\tsource_revision\t0123456789abcdef0123456789abcdef01234567\n'
    printf 'metadata\tsource_state\tclean\n'
    printf 'metadata\tsource_tree_sha256\t%s\n' "$(printf 'a%.0s' {1..64})"
    printf 'artifact\tproduct\tengine\tproduct/engine\t17\t%s\n' "${artifact_sha}"
  } >"${root}/stage/manifest.tsv"
  {
    printf '%s  product/engine\n' "${artifact_sha}"
    printf '%s  manifest.tsv' "$(sha256_file "${root}/stage/manifest.tsv")"
  } >"${root}/stage/SHA256SUMS"

  printf 'selfcheck verdict: allow\n' >"${root}/execution/stdout.log"
  printf 'engine lifecycle complete\n' >"${root}/execution/stderr.log"
  local stdout_bytes stderr_bytes
  stdout_bytes="$(wc -c <"${root}/execution/stdout.log" | tr -d '[:space:]')"
  stderr_bytes="$(wc -c <"${root}/execution/stderr.log" | tr -d '[:space:]')"
  {
    printf 'key\tvalue\n'
    printf 'format_version\t1\n'
    printf 'run_id\t%s\n' "${fixture_run_id}"
    printf 'profile\tengine-selfcheck\n'
    printf 'artifact\tproduct/engine\n'
    printf 'artifact_sha256\t%s\n' "${artifact_sha}"
    printf 'privilege\tunprivileged\n'
    printf 'timeout_seconds\t15\n'
    printf 'expected_outcome\texit-zero\n'
    printf 'exit_code\t0\n'
    printf 'process_residue\tnone\n'
    printf 'stdout_bytes\t%s\n' "${stdout_bytes}"
    printf 'stderr_bytes\t%s\n' "${stderr_bytes}"
    printf 'started_utc\t2026-08-26T12:00:00Z\n'
    printf 'finished_utc\t2026-08-26T12:00:01Z\n'
    printf 'status\tPASS\n'
    printf 'diagnostic\texpected outcome observed\n'
  } >"${root}/execution/result.tsv"
  {
    printf 'CanarySting DGX read-only check: falcon1\n\n'
    printf '[host]\nhostname=spark-5343\narchitecture=aarch64\n'
    printf '[kubernetes]\nnode=Ready\n'
    printf '[cilium]\nstatus=healthy\n'
    printf '[kernel_bpf]\nbpffs=/sys/fs/bpf\n'
    printf '[root_cgroup_attachments]\ncilium=present\n'
    printf '[security_observations]\nkubeconfig_mode=600\n'
  } >"${root}/dgx-check.txt"
}

tmp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly tmp_parent
tmp_root="$(mktemp -d "${tmp_parent}/canarysting-collect-test.XXXXXX")"
cleanup() {
  if [[ -n "${tmp_root:-}" && -d "${tmp_root}" && "${tmp_root}" == "${tmp_parent}/canarysting-collect-test."* ]]; then
    rm -rf -- "${tmp_root}"
  fi
}
trap cleanup EXIT INT TERM

[[ -x "${collect_script}" ]] || fail "collect script is missing or not executable: ${collect_script}"
awk '
  /^  ssh .*<<.REMOTE./ { capture = 1; next }
  /^REMOTE$/ { capture = 0 }
  capture { print }
' "${collect_script}" | bash -n || fail 'embedded remote collection program has invalid Bash syntax'

run_id='collect-test-01'
fixture="${tmp_root}/fixture"
output="${tmp_root}/output"
make_fixture "${fixture}" "${run_id}"

dry_output="$(${collect_script} --run-id "${run_id}" --output-dir "${tmp_root}/dry-output" --dry-run)"
[[ "${dry_output}" == *'DGX was not accessed'* ]] || fail 'dry run did not remain local'
[[ "${dry_output}" == *"remote_stage=/var/tmp/canarysting/${run_id}"* ]] || fail 'dry run omitted the exact stage'
[[ "${dry_output}" == *'sensitive_content_policy=refuse-before-transfer'* ]] || fail 'dry run omitted the sensitive-content policy'

collect_output="$(${collect_script} --run-id "${run_id}" --output-dir "${output}" --fixture-dir "${fixture}")"
[[ "${collect_output}" == *'PASS: collected bounded redacted DGX evidence'* ]] || fail 'fixture collection did not pass'
[[ -d "${output}" && ! -L "${output}" ]] || fail 'collection output is missing or unsafe'
[[ "$(stat -f '%Lp' "${output}" 2>/dev/null || stat -c '%a' "${output}")" == '700' ]] || fail 'collection output mode is not 0700'

expected_files=$'SHA256SUMS\nartifact-SHA256SUMS\nartifact-manifest.tsv\ncollection-manifest.tsv\ndgx-check.txt\nexecution-result.tsv\nstderr.log\nstdout.log'
actual_files="$(cd "${output}" && find . -mindepth 1 -type f -print | sed 's#^\./##' | LC_ALL=C sort)"
[[ "${actual_files}" == "${expected_files}" ]] || fail 'published collection has an unexpected file inventory'
(cd "${output}" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS >/dev/null; else shasum -a 256 -c SHA256SUMS >/dev/null; fi) ||
  fail 'published collection checksums failed'
grep -F $'metadata\trun_id\tcollect-test-01\t-' "${output}/collection-manifest.tsv" >/dev/null || fail 'collection manifest omitted run ID'
grep -F $'metadata\tretention_profile\tephemeral-72h\t-' "${output}/collection-manifest.tsv" >/dev/null || fail 'collection manifest omitted retention'
grep -F $'metadata\tmodel_use_policy\tprohibited\t-' "${output}/collection-manifest.tsv" >/dev/null || fail 'collection manifest omitted model-use prohibition'

expect_failure overwrite 'output directory already exists' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${output}" --fixture-dir "${fixture}"
expect_failure missing_run_id '--run-id is required' \
  "${collect_script}" --output-dir "${tmp_root}/missing-id" --dry-run
expect_failure unsafe_run_id 'run ID must be' \
  "${collect_script}" --run-id '../escape' --output-dir "${tmp_root}/unsafe" --dry-run
expect_failure relative_output '--output-dir must be an absolute path' \
  "${collect_script}" --run-id "${run_id}" --output-dir relative --dry-run
expect_failure fixture_dry_run 'cannot be combined' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/fixture-dry" --fixture-dir "${fixture}" --dry-run
expect_failure arbitrary_remote_path 'unknown argument: --remote-path' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/remote-path" --remote-path /etc --dry-run

secret_fixture="${tmp_root}/secret-fixture"
cp -R "${fixture}" "${secret_fixture}"
printf 'Authorization: Bearer should-never-cross-boundary\n' >>"${secret_fixture}/execution/stdout.log"
expect_failure bearer_secret 'contains prohibited credential-like material' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/secret-output" --fixture-dir "${secret_fixture}"
[[ ! -e "${tmp_root}/secret-output" ]] || fail 'secret-negative test published output'

kubeconfig_fixture="${tmp_root}/kubeconfig-fixture"
cp -R "${fixture}" "${kubeconfig_fixture}"
printf 'client-key-data: ZmFrZS1rZXktbWF0ZXJpYWw=\n' >>"${kubeconfig_fixture}/dgx-check.txt"
expect_failure kubeconfig_secret 'contains prohibited credential-like material' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/kubeconfig-output" --fixture-dir "${kubeconfig_fixture}"

wrong_run_fixture="${tmp_root}/wrong-run-fixture"
cp -R "${fixture}" "${wrong_run_fixture}"
sed 's/^run_id\tcollect-test-01$/run_id\tdifferent-run/' "${wrong_run_fixture}/execution/result.tsv" >"${wrong_run_fixture}/execution/result.new"
mv "${wrong_run_fixture}/execution/result.new" "${wrong_run_fixture}/execution/result.tsv"
expect_failure wrong_run 'belongs to a different run ID' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/wrong-run-output" --fixture-dir "${wrong_run_fixture}"

corrupt_manifest_fixture="${tmp_root}/corrupt-manifest-fixture"
cp -R "${fixture}" "${corrupt_manifest_fixture}"
printf '# drift\n' >>"${corrupt_manifest_fixture}/stage/manifest.tsv"
expect_failure manifest_drift 'artifact manifest has an unsupported schema or malformed row' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/manifest-output" --fixture-dir "${corrupt_manifest_fixture}"

symlink_fixture="${tmp_root}/symlink-fixture"
cp -R "${fixture}" "${symlink_fixture}"
ln -s stdout.log "${symlink_fixture}/execution/linked.log"
expect_failure symlink_source 'symlink or unsupported entry' \
  "${collect_script}" --run-id "${run_id}" --output-dir "${tmp_root}/symlink-output" --fixture-dir "${symlink_fixture}"

if grep -R -E -i -- 'should-never-cross-boundary|ZmFrZS1rZXktbWF0ZXJpYWw' "${output}" >/dev/null; then
  fail 'published collection contains a secret-negative fixture value'
fi

printf 'PASS: DGX redacted collection local checks passed\n'
