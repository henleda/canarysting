#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
readonly repo_root
build_script="${script_dir}/build.sh"
readonly build_script

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

tmp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly tmp_parent
tmp_root="$(mktemp -d "${tmp_parent}/canarysting-build-test.XXXXXX")"
cleanup() {
  if [[ -n "${tmp_root:-}" && -d "${tmp_root}" &&
    "${tmp_root}" == "${tmp_parent}/canarysting-build-test."* ]]; then
    rm -rf -- "${tmp_root}"
  fi
}
trap cleanup EXIT INT TERM

target_list="$(${build_script} --list)"
[[ "${target_list}" == *$'product\tengine\t./cmd/engine'* ]] || fail 'product target catalog is incomplete'
[[ "${target_list}" == *$'test\tcookiespike\t./cmd/cookiespike'* ]] || fail 'test target catalog is incomplete'
[[ "${target_list}" == *$'test\tdgxstackspike\t./cmd/dgxstackspike'* ]] || fail 'DGX-stack proof target is missing'
[[ "${target_list}" == *$'test\tcorrelationspike\t./cmd/correlationspike'* ]] || fail 'correlation proof target is missing'
[[ "${target_list}" == *$'test\ttracespike\t./cmd/tracespike'* ]] || fail 'trace proof target is missing'
[[ "${target_list}" == *$'test\tattackerexecutorspike\t./cmd/attackerexecutorspike'* ]] || fail 'attacker executor proof target is missing'

if "${build_script}" --target cookiespike >"${tmp_root}/missing-output.log" 2>&1; then
  fail 'build unexpectedly accepted a missing --output-dir'
fi
if "${build_script}" --output-dir "${tmp_root}/invalid" --target not-a-target >"${tmp_root}/invalid-target.log" 2>&1; then
  fail 'build unexpectedly accepted an unknown target'
fi
if "${build_script}" --output-dir "${tmp_root}/duplicate" --target engine --target engine >"${tmp_root}/duplicate-target.log" 2>&1; then
  fail 'build unexpectedly accepted a duplicate target'
fi
if "${build_script}" --output-dir "${tmp_root}/missing/child" --target engine >"${tmp_root}/missing-parent.log" 2>&1; then
  fail 'build unexpectedly accepted a missing output parent'
fi
[[ ! -e "${tmp_root}/missing" ]] || fail 'missing output parent was created before refusal'
in_repo_output="${repo_root}/canarysting-build-test-output"
[[ ! -e "${in_repo_output}" ]] || fail "test output path already exists: ${in_repo_output}"
if "${build_script}" --output-dir "${in_repo_output}" --target engine >"${tmp_root}/in-repo.log" 2>&1; then
  fail 'build unexpectedly accepted an in-repository output path'
fi
[[ ! -e "${in_repo_output}" ]] || fail 'in-repository output was created before refusal'

first="${tmp_root}/first"
second="${tmp_root}/second"
"${build_script}" --output-dir "${first}" --target engine --target cookiespike --target dgxstackspike --target correlationspike --target tracespike --target attackerexecutorspike
"${build_script}" --output-dir "${second}" --target engine --target cookiespike --target dgxstackspike --target correlationspike --target tracespike --target attackerexecutorspike

for relative_path in product/engine test/cookiespike test/dgxstackspike test/correlationspike test/tracespike test/attackerexecutorspike manifest.tsv SHA256SUMS; do
  [[ -f "${first}/${relative_path}" ]] || fail "missing output: ${relative_path}"
  [[ -f "${second}/${relative_path}" ]] || fail "missing repeated output: ${relative_path}"
  cmp "${first}/${relative_path}" "${second}/${relative_path}" >/dev/null ||
    fail "repeated build changed ${relative_path}"
done

grep -F $'metadata\ttarget_arch\tarm64' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not record target architecture'
grep -F $'metadata\tsource_tree_sha256\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not record source tree fingerprint'
grep -F $'artifact\tproduct\tengine\tproduct/engine\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the product artifact'
grep -F $'artifact\ttest\tcookiespike\ttest/cookiespike\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the test artifact'
grep -F $'artifact\ttest\tdgxstackspike\ttest/dgxstackspike\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the DGX-stack proof artifact'
grep -F $'artifact\ttest\tcorrelationspike\ttest/correlationspike\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the correlation proof artifact'
grep -F $'artifact\ttest\ttracespike\ttest/tracespike\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the trace proof artifact'
grep -F $'artifact\ttest\tattackerexecutorspike\ttest/attackerexecutorspike\t' "${first}/manifest.tsv" >/dev/null ||
  fail 'manifest does not classify the attacker executor proof artifact'

while read -r expected relative_path; do
  [[ -n "${expected}" && -n "${relative_path}" ]] || fail 'malformed SHA256SUMS entry'
  actual="$(sha256_file "${first}/${relative_path}")"
  [[ "${actual}" == "${expected}" ]] || fail "checksum mismatch: ${relative_path}"
done <"${first}/SHA256SUMS"

file -b "${first}/product/engine" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'engine is not a Linux ARM64 ELF executable'
file -b "${first}/test/cookiespike" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'cookiespike is not a Linux ARM64 ELF executable'
file -b "${first}/test/dgxstackspike" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'dgxstackspike is not a Linux ARM64 ELF executable'
file -b "${first}/test/correlationspike" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'correlationspike is not a Linux ARM64 ELF executable'
file -b "${first}/test/tracespike" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'tracespike is not a Linux ARM64 ELF executable'
file -b "${first}/test/attackerexecutorspike" | grep -E 'ELF 64-bit.*ARM aarch64' >/dev/null ||
  fail 'attackerexecutorspike is not a Linux ARM64 ELF executable'

before_manifest="$(sha256_file "${first}/manifest.tsv")"
if "${build_script}" --output-dir "${first}" --target engine >"${tmp_root}/overwrite.log" 2>&1; then
  fail 'build unexpectedly overwrote an existing output directory'
fi
after_manifest="$(sha256_file "${first}/manifest.tsv")"
[[ "${before_manifest}" == "${after_manifest}" ]] || fail 'existing output changed after overwrite refusal'

printf 'PASS: DGX Linux/ARM64 build harness checks passed\n'
