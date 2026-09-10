#!/usr/bin/env bash
set -euo pipefail

readonly target_os="linux"
readonly target_arch="arm64"
readonly target_arm64="v8.0"

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/build.sh --output-dir DIR --target NAME [--target NAME ...]
  scripts/dgx/build.sh --output-dir DIR --all
  scripts/dgx/build.sh --list

Build allowlisted Linux/ARM64 CanarySting binaries with the local Go toolchain.
The output directory must be explicit, outside the repository, and absent; its
parent directory must already exist.
No dependency or toolchain downloads are allowed.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

target_record() {
  case "$1" in
    engine) printf 'product\tengine\t./cmd/engine\n' ;;
    canaryctl) printf 'product\tcanaryctl\t./cmd/canaryctl\n' ;;
    operator) printf 'product\toperator\t./cmd/operator\n' ;;
    envoy-adapter) printf 'product\tenvoy-adapter\t./cmd/envoy-adapter\n' ;;
    dashboard-backend) printf 'product\tdashboard-backend\t./cmd/dashboard-backend\n' ;;
    cookiespike) printf 'test\tcookiespike\t./cmd/cookiespike\n' ;;
    enforcespike) printf 'test\tenforcespike\t./cmd/enforcespike\n' ;;
    dgxstackspike) printf 'test\tdgxstackspike\t./cmd/dgxstackspike\n' ;;
    correlationspike) printf 'test\tcorrelationspike\t./cmd/correlationspike\n' ;;
    tracespike) printf 'test\ttracespike\t./cmd/tracespike\n' ;;
    attackerexecutorspike) printf 'test\tattackerexecutorspike\t./cmd/attackerexecutorspike\n' ;;
    attackerloopspike) printf 'test\tattackerloopspike\t./cmd/attackerloopspike\n' ;;
    attackerscenariospike) printf 'test\tattackerscenariospike\t./cmd/attackerscenariospike\n' ;;
    *) return 1 ;;
  esac
}

list_targets() {
  printf 'KIND\tNAME\tPACKAGE\n'
  local name
  for name in "${all_targets[@]}"; do
    target_record "${name}"
  done
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

source_tree_fingerprint() {
  {
    printf 'revision\0%s\0' "${source_revision}"
    git -C "${repo_root}" ls-files -z --cached --others --exclude-standard |
      while IFS= read -r -d '' path; do
        printf 'path\0%s\0' "${path}"
        if [[ -e "${repo_root}/${path}" || -L "${repo_root}/${path}" ]]; then
          git -C "${repo_root}" hash-object --no-filters -- "${path}"
        else
          printf 'DELETED\n'
        fi
      done
  } | sha256_stdin
}

readonly -a all_targets=(
  engine
  canaryctl
  operator
  envoy-adapter
  dashboard-backend
  cookiespike
  enforcespike
  dgxstackspike
  correlationspike
  tracespike
  attackerexecutorspike
  attackerloopspike
  attackerscenariospike
)

output_dir=""
build_all=0
list_only=0
declare -a selected_targets=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || fail '--output-dir requires a value'
      output_dir="$2"
      shift 2
      ;;
    --target)
      [[ "$#" -ge 2 ]] || fail '--target requires a value'
      selected_targets+=("$2")
      shift 2
      ;;
    --all)
      build_all=1
      shift
      ;;
    --list)
      list_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [[ "${list_only}" -eq 1 ]]; then
  [[ -z "${output_dir}" && "${build_all}" -eq 0 && "${#selected_targets[@]}" -eq 0 ]] ||
    fail '--list cannot be combined with build arguments'
  list_targets
  exit 0
fi

[[ -n "${output_dir}" ]] || fail '--output-dir is required'
[[ "${output_dir}" != *$'\n'* && "${output_dir}" != *$'\t'* ]] ||
  fail '--output-dir must not contain tabs or newlines'
if [[ "${build_all}" -eq 1 && "${#selected_targets[@]}" -ne 0 ]]; then
  fail '--all cannot be combined with --target'
fi
if [[ "${build_all}" -eq 1 ]]; then
  selected_targets=("${all_targets[@]}")
fi
[[ "${#selected_targets[@]}" -gt 0 ]] || fail 'select at least one --target or use --all'

declare -a unique_targets=()
seen_targets=$'\n'
for target in "${selected_targets[@]}"; do
  target_record "${target}" >/dev/null || {
    printf 'FAIL: unsupported target %q; use --list for the allowlist\n' "${target}" >&2
    exit 1
  }
  case "${seen_targets}" in
    *$'\n'"${target}"$'\n'*) fail "duplicate target: ${target}" ;;
  esac
  unique_targets+=("${target}")
  seen_targets+="${target}"$'\n'
done
selected_targets=("${unique_targets[@]}")

for required_tool in git go file mktemp awk wc mv chmod tr mkdir dirname basename uname rm; do
  command -v "${required_tool}" >/dev/null 2>&1 || fail "required tool not found: ${required_tool}"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail 'required checksum tool not found: provide existing sha256sum or shasum'
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
readonly repo_root
[[ "$(git -C "${repo_root}" rev-parse --show-toplevel)" == "${repo_root}" ]] ||
  fail "script location is not inside the expected Git worktree: ${repo_root}"
[[ -f "${repo_root}/go.mod" ]] || fail "go.mod not found at repository root: ${repo_root}"

[[ ! -e "${output_dir}" && ! -L "${output_dir}" ]] ||
  fail "output directory already exists; refusing to overwrite: ${output_dir}"
output_parent="$(dirname "${output_dir}")"
output_name="$(basename "${output_dir}")"
[[ "${output_name}" != '.' && "${output_name}" != '..' && -n "${output_name}" ]] ||
  fail "unsafe output directory: ${output_dir}"
[[ -d "${output_parent}" ]] ||
  fail "output parent directory must already exist: ${output_parent}"
output_parent="$(cd "${output_parent}" && pwd -P)"
readonly output_parent
output_dir="${output_parent}/${output_name}"
readonly output_dir
case "${output_dir}/" in
  "${repo_root}/"*) fail "output directory must be outside the source repository: ${output_dir}" ;;
esac

source_revision="$(git -C "${repo_root}" rev-parse --verify HEAD)"
readonly source_revision
if [[ -n "$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
  source_state="dirty"
else
  source_state="clean"
fi
readonly source_state
source_tree_sha256="$(source_tree_fingerprint)"
readonly source_tree_sha256
go_version="$(GOENV=off GOTOOLCHAIN=local go env GOVERSION)" ||
  fail 'the local Go toolchain is unavailable; downloads are disabled'
readonly go_version
builder_os="$(uname -s)"
builder_arch="$(uname -m)"
readonly builder_os builder_arch

staging_dir="$(mktemp -d "${output_parent}/.canarysting-build.XXXXXX")"
cleanup() {
  if [[ -n "${staging_dir:-}" && -d "${staging_dir}" &&
    "${staging_dir}" == "${output_parent}/.canarysting-build."* ]]; then
    rm -rf -- "${staging_dir}"
  fi
}
trap cleanup EXIT INT TERM

manifest="${staging_dir}/manifest.tsv"
checksums="${staging_dir}/SHA256SUMS"
printf 'record\tkind_or_key\tname_or_value\tpath\tsize_bytes\tsha256\n' >"${manifest}"
printf 'metadata\tformat_version\t1\n' >>"${manifest}"
printf 'metadata\ttarget_os\t%s\n' "${target_os}" >>"${manifest}"
printf 'metadata\ttarget_arch\t%s\n' "${target_arch}" >>"${manifest}"
printf 'metadata\ttarget_arm64\t%s\n' "${target_arm64}" >>"${manifest}"
printf 'metadata\tcgo_enabled\t0\n' >>"${manifest}"
printf 'metadata\tgo_version\t%s\n' "${go_version}" >>"${manifest}"
printf 'metadata\tbuilder_os\t%s\n' "${builder_os}" >>"${manifest}"
printf 'metadata\tbuilder_arch\t%s\n' "${builder_arch}" >>"${manifest}"
printf 'metadata\tsource_revision\t%s\n' "${source_revision}" >>"${manifest}"
printf 'metadata\tsource_state\t%s\n' "${source_state}" >>"${manifest}"
printf 'metadata\tsource_tree_sha256\t%s\n' "${source_tree_sha256}" >>"${manifest}"
: >"${checksums}"

for target in "${selected_targets[@]}"; do
  IFS=$'\t' read -r artifact_kind artifact_name package_path <<<"$(target_record "${target}")"
  artifact_dir="${staging_dir}/${artifact_kind}"
  artifact_path="${artifact_dir}/${artifact_name}"
  mkdir -p "${artifact_dir}"

  printf 'build: %s (%s) <- %s\n' "${artifact_name}" "${artifact_kind}" "${package_path}"
  (
    cd "${repo_root}"
    env \
      CGO_ENABLED=0 \
      GO111MODULE=on \
      GOARCH="${target_arch}" \
      GOARM64="${target_arm64}" \
      GOENV=off \
      GOFLAGS=-mod=readonly \
      GOOS="${target_os}" \
      GOPROXY=off \
      GOSUMDB=off \
      GOTOOLCHAIN=local \
      GOWORK=off \
      go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o "${artifact_path}" "${package_path}"
  ) || fail "build failed for ${target}; required modules and the pinned Go toolchain must already be present"
  chmod 0755 "${artifact_path}"

  file_description="$(file -b "${artifact_path}")"
  [[ "${file_description}" == *'ELF 64-bit'* && "${file_description}" == *'ARM aarch64'* ]] ||
    fail "${artifact_name} is not a Linux ARM64 ELF executable: ${file_description}"
  artifact_sha256="$(sha256_file "${artifact_path}")"
  artifact_size="$(wc -c <"${artifact_path}" | tr -d '[:space:]')"
  relative_path="${artifact_kind}/${artifact_name}"
  printf 'artifact\t%s\t%s\t%s\t%s\t%s\n' \
    "${artifact_kind}" "${artifact_name}" "${relative_path}" "${artifact_size}" "${artifact_sha256}" >>"${manifest}"
  printf '%s  %s\n' "${artifact_sha256}" "${relative_path}" >>"${checksums}"
done

manifest_sha256="$(sha256_file "${manifest}")"
printf '%s  manifest.tsv\n' "${manifest_sha256}" >>"${checksums}"
chmod 0644 "${manifest}" "${checksums}"

mv "${staging_dir}" "${output_dir}"
staging_dir=""
trap - EXIT INT TERM

printf 'PASS: built %d Linux/ARM64 artifact(s)\n' "${#selected_targets[@]}"
printf 'output_dir=%s\n' "${output_dir}"
printf 'source_revision=%s\n' "${source_revision}"
printf 'source_state=%s\n' "${source_state}"
printf 'source_tree_sha256=%s\n' "${source_tree_sha256}"
printf 'manifest=%s/manifest.tsv\n' "${output_dir}"
printf 'checksums=%s/SHA256SUMS\n' "${output_dir}"
