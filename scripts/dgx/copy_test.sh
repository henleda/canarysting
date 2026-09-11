#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
build_script="${script_dir}/build.sh"
copy_script="${script_dir}/copy.sh"
readonly build_script copy_script

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

copy_fixture() {
  cp -R "${valid}" "$1"
}

tmp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly tmp_parent
tmp_root="$(mktemp -d "${tmp_parent}/canarysting-copy-test.XXXXXX")"
cleanup() {
  if [[ -n "${tmp_root:-}" && -d "${tmp_root}" &&
    "${tmp_root}" == "${tmp_parent}/canarysting-copy-test."* ]]; then
    rm -rf -- "${tmp_root}"
  fi
}
trap cleanup EXIT INT TERM

valid="${tmp_root}/valid"
"${build_script}" --output-dir "${valid}" --target engine --target cookiespike --target correlationspike --target tracespike --target attackerexecutorspike --target attackerloopspike --target attackerscenariospike

dry_output="$(${copy_script} --artifact-dir "${valid}" --run-id copy-test-01 --dry-run)"
[[ "${dry_output}" == *'DRY RUN: local artifact inventory passed; DGX was not accessed'* ]] ||
  fail 'valid dry run did not report local-only success'
[[ "${dry_output}" == *'remote_stage=/var/tmp/canarysting/copy-test-01'* ]] ||
  fail 'valid dry run did not report the exact stage'
[[ "${dry_output}" == *'artifacts=7'* ]] || fail 'valid dry run reported the wrong artifact count'

expect_failure missing_run_id '--run-id is required' \
  "${copy_script}" --artifact-dir "${valid}" --dry-run
expect_failure missing_artifact_dir '--artifact-dir is required' \
  "${copy_script}" --run-id copy-test-01 --dry-run
expect_failure invalid_run_id 'run ID must be' \
  "${copy_script}" --artifact-dir "${valid}" --run-id '../escape' --dry-run
expect_failure uppercase_run_id 'run ID must be' \
  "${copy_script}" --artifact-dir "${valid}" --run-id 'Copy-Test' --dry-run

unexpected="${tmp_root}/unexpected"
copy_fixture "${unexpected}"
printf 'do-not-transfer\n' >"${unexpected}/credentials.txt"
expect_failure unexpected_file 'unexpected or missing file' \
  "${copy_script}" --artifact-dir "${unexpected}" --run-id copy-test-02 --dry-run

symlinked="${tmp_root}/symlinked"
copy_fixture "${symlinked}"
ln -s product/engine "${symlinked}/linked-engine"
expect_failure symlink 'symlink or unsupported filesystem entry' \
  "${copy_script}" --artifact-dir "${symlinked}" --run-id copy-test-03 --dry-run

corrupt="${tmp_root}/corrupt"
copy_fixture "${corrupt}"
printf 'corruption\n' >>"${corrupt}/test/cookiespike"
expect_failure corrupt_artifact 'artifact size mismatch: test/cookiespike' \
  "${copy_script}" --artifact-dir "${corrupt}" --run-id copy-test-04 --dry-run

missing="${tmp_root}/missing"
copy_fixture "${missing}"
rm -f -- "${missing}/product/engine"
expect_failure missing_artifact 'artifact must be a regular executable file: product/engine' \
  "${copy_script}" --artifact-dir "${missing}" --run-id copy-test-05 --dry-run

unsafe_path="${tmp_root}/unsafe-path"
copy_fixture "${unsafe_path}"
awk -F '\t' 'BEGIN { OFS = "\t" } $1 == "artifact" && $3 == "engine" { $4 = "../escape" } { print }' \
  "${unsafe_path}/manifest.tsv" >"${unsafe_path}/manifest.new"
mv "${unsafe_path}/manifest.new" "${unsafe_path}/manifest.tsv"
expect_failure unsafe_path 'artifact path does not match its approved kind/name: ../escape' \
  "${copy_script}" --artifact-dir "${unsafe_path}" --run-id copy-test-06 --dry-run

bad_inventory="${tmp_root}/bad-inventory"
copy_fixture "${bad_inventory}"
printf '0%.0s' {1..64} >"${bad_inventory}/SHA256SUMS"
printf '  manifest.tsv\n' >>"${bad_inventory}/SHA256SUMS"
expect_failure bad_inventory 'SHA256SUMS does not exactly match' \
  "${copy_script}" --artifact-dir "${bad_inventory}" --run-id copy-test-07 --dry-run

printf 'PASS: DGX isolated transfer local checks passed\n'
