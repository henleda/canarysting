#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="falcon1"
readonly expected_hostname="spark-5343"
readonly expected_architecture="aarch64"
readonly remote_root="/var/tmp/canarysting"
readonly -a ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=12
  -o StrictHostKeyChecking=yes
)

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/copy.sh --artifact-dir DIR --run-id ID [--dry-run]
  scripts/dgx/copy.sh --verify-only --run-id ID

Copy a build.sh artifact directory to falcon1 as the explicit run stage
/var/tmp/canarysting/ID. Local and remote manifests, allowlists, file inventories,
and SHA-256 checksums must all pass. Existing stages are never overwritten.

--dry-run validates local input and reports the intended stage without SSH access.
--verify-only performs a read-only validation of an existing remote stage.
EOF
}

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

metadata_value() {
  local key="$1"
  awk -F '\t' -v key="${key}" '
    $1 == "metadata" && $2 == key { count++; value = $3 }
    END { if (count != 1) exit 1; print value }
  ' "${manifest}"
}

is_allowed_artifact() {
  case "$1/$2" in
    product/engine | product/canaryctl | product/operator | product/envoy-adapter | product/dashboard-backend | test/cookiespike | test/enforcespike | test/dgxstackspike | test/correlationspike | test/tracespike | test/attackerexecutorspike | test/attackerloopspike)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

validate_local_artifacts() {
  [[ "${artifact_dir}" == /* ]] || fail '--artifact-dir must be an absolute path'
  [[ "${artifact_dir}" != *$'\n'* && "${artifact_dir}" != *$'\t'* ]] ||
    fail '--artifact-dir must not contain tabs or newlines'
  [[ -d "${artifact_dir}" && ! -L "${artifact_dir}" ]] ||
    fail "artifact directory is missing, not a directory, or a symlink: ${artifact_dir}"
  artifact_dir="$(cd "${artifact_dir}" && pwd -P)"
  readonly artifact_dir

  manifest="${artifact_dir}/manifest.tsv"
  checksums="${artifact_dir}/SHA256SUMS"
  readonly manifest checksums
  [[ -f "${manifest}" && ! -L "${manifest}" ]] || fail 'manifest.tsv must be a regular file'
  [[ -f "${checksums}" && ! -L "${checksums}" ]] || fail 'SHA256SUMS must be a regular file'

  awk -F '\t' '
    NR == 1 {
      if ($0 != "record\tkind_or_key\tname_or_value\tpath\tsize_bytes\tsha256") exit 1
      next
    }
    $1 == "metadata" && NF == 3 { next }
    $1 == "artifact" && NF == 6 { next }
    { exit 1 }
    END { if (NR < 2) exit 1 }
  ' "${manifest}" || fail 'manifest.tsv has an unsupported schema or malformed row'

  [[ "$(metadata_value format_version)" == '1' ]] || fail 'manifest format_version must be 1'
  [[ "$(metadata_value target_os)" == 'linux' ]] || fail 'manifest target_os must be linux'
  [[ "$(metadata_value target_arch)" == 'arm64' ]] || fail 'manifest target_arch must be arm64'
  [[ "$(metadata_value target_arm64)" == 'v8.0' ]] || fail 'manifest target_arm64 must be v8.0'
  [[ "$(metadata_value cgo_enabled)" == '0' ]] || fail 'manifest cgo_enabled must be 0'
  source_revision="$(metadata_value source_revision)" || fail 'manifest must contain one source_revision'
  source_state="$(metadata_value source_state)" || fail 'manifest must contain one source_state'
  source_tree_sha256="$(metadata_value source_tree_sha256)" || fail 'manifest must contain one source_tree_sha256'
  [[ "${source_revision}" =~ ^[0-9a-f]{40,64}$ ]] || fail 'manifest source_revision is malformed'
  [[ "${source_state}" == 'clean' || "${source_state}" == 'dirty' ]] || fail 'manifest source_state is malformed'
  [[ "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'manifest source_tree_sha256 is malformed'

  artifact_count=0
  has_product=0
  has_test=0
  expected_checksums=''
  expected_files=$'SHA256SUMS\nmanifest.tsv\n'
  seen_paths=$'\n'
  declare -a validated_paths=()

  while IFS=$'\t' read -r record artifact_kind artifact_name relative_path artifact_size artifact_sha256; do
    [[ "${record}" == 'artifact' ]] || continue
    is_allowed_artifact "${artifact_kind}" "${artifact_name}" ||
      fail "manifest contains an unapproved artifact: ${artifact_kind}/${artifact_name}"
    [[ "${relative_path}" == "${artifact_kind}/${artifact_name}" ]] ||
      fail "artifact path does not match its approved kind/name: ${relative_path}"
    [[ "${artifact_size}" =~ ^[0-9]+$ ]] || fail "artifact size is malformed: ${relative_path}"
    [[ "${artifact_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail "artifact checksum is malformed: ${relative_path}"
    case "${seen_paths}" in
      *$'\n'"${relative_path}"$'\n'*) fail "duplicate artifact path: ${relative_path}" ;;
    esac
    seen_paths+="${relative_path}"$'\n'

    local_path="${artifact_dir}/${relative_path}"
    [[ -f "${local_path}" && ! -L "${local_path}" && -x "${local_path}" ]] ||
      fail "artifact must be a regular executable file: ${relative_path}"
    actual_size="$(wc -c <"${local_path}" | tr -d '[:space:]')"
    [[ "${actual_size}" == "${artifact_size}" ]] || fail "artifact size mismatch: ${relative_path}"
    actual_sha256="$(sha256_file "${local_path}")"
    [[ "${actual_sha256}" == "${artifact_sha256}" ]] || fail "artifact checksum mismatch: ${relative_path}"

    validated_paths+=("${relative_path}")
    artifact_count=$((artifact_count + 1))
    [[ "${artifact_kind}" == 'product' ]] && has_product=1
    [[ "${artifact_kind}" == 'test' ]] && has_test=1
    expected_checksums+="${artifact_sha256}  ${relative_path}"$'\n'
    expected_files+="${relative_path}"$'\n'
  done <"${manifest}"

  [[ "${artifact_count}" -gt 0 ]] || fail 'manifest contains no artifacts'
  artifact_paths=("${validated_paths[@]}")

  manifest_sha256="$(sha256_file "${manifest}")"
  expected_checksums+="${manifest_sha256}  manifest.tsv"
  actual_checksums="$(<"${checksums}")"
  [[ "${actual_checksums}" == "${expected_checksums}" ]] ||
    fail 'SHA256SUMS does not exactly match the manifest artifact inventory'

  non_regular="$(cd "${artifact_dir}" && find . -mindepth 1 ! -type f ! -type d -print | LC_ALL=C sort)"
  [[ -z "${non_regular}" ]] || fail 'artifact directory contains a symlink or unsupported filesystem entry'
  actual_files="$(cd "${artifact_dir}" && find . -mindepth 1 -type f -print | sed 's#^\./##' | LC_ALL=C sort)"
  expected_files="$(printf '%s' "${expected_files}" | LC_ALL=C sort)"
  [[ "${actual_files}" == "${expected_files}" ]] || fail 'artifact directory contains an unexpected or missing file'

  expected_dirs=''
  [[ "${has_product}" -eq 1 ]] && expected_dirs+=$'product\n'
  [[ "${has_test}" -eq 1 ]] && expected_dirs+=$'test\n'
  actual_dirs="$(cd "${artifact_dir}" && find . -mindepth 1 -type d -print | sed 's#^\./##' | LC_ALL=C sort)"
  expected_dirs="$(printf '%s' "${expected_dirs}" | LC_ALL=C sort)"
  [[ "${actual_dirs}" == "${expected_dirs}" ]] || fail 'artifact directory contains an unexpected or missing directory'
}

remote_preflight_and_create() {
  ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${has_product}" "${has_test}" <<'REMOTE'
set -euo pipefail
run_id="$1"
has_product="$2"
has_test="$3"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || { echo 'FAIL: invalid remote run ID' >&2; exit 1; }
[[ "$(hostname)" == 'spark-5343' ]] || { echo "FAIL: unexpected hostname: $(hostname)" >&2; exit 1; }
[[ "$(uname -m)" == 'aarch64' ]] || { echo "FAIL: unexpected architecture: $(uname -m)" >&2; exit 1; }
for tool in bash awk find sort sha256sum wc mv mkdir stat; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "FAIL: missing remote prerequisite: ${tool}" >&2; exit 1; }
done

root='/var/tmp/canarysting'
incoming="${root}/.incoming-${run_id}"
stage="${root}/${run_id}"
[[ ! -e "${incoming}" && ! -L "${incoming}" ]] || { echo "FAIL: incoming stage already exists: ${incoming}" >&2; exit 1; }
[[ ! -e "${stage}" && ! -L "${stage}" ]] || { echo "FAIL: run stage already exists: ${stage}" >&2; exit 1; }
if [[ -e "${root}" || -L "${root}" ]]; then
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] || {
    echo "FAIL: remote root must be an owned, writable, non-symlink directory: ${root}" >&2
    exit 1
  }
else
  [[ -w /var/tmp ]] || { echo 'FAIL: /var/tmp is not writable' >&2; exit 1; }
  umask 077
  mkdir -m 0700 "${root}"
fi
umask 077
mkdir -m 0700 "${incoming}"
[[ "${has_product}" == '1' ]] && mkdir -m 0700 "${incoming}/product"
[[ "${has_test}" == '1' ]] && mkdir -m 0700 "${incoming}/test"
printf 'remote_incoming=%s\n' "${incoming}"
REMOTE
}

remote_validate() {
  local mode="$1"
  ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" <<'REMOTE'
set -euo pipefail
run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || { echo 'FAIL: invalid remote run ID' >&2; exit 1; }
[[ "$(hostname)" == 'spark-5343' ]] || { echo "FAIL: unexpected hostname: $(hostname)" >&2; exit 1; }
[[ "$(uname -m)" == 'aarch64' ]] || { echo "FAIL: unexpected architecture: $(uname -m)" >&2; exit 1; }

root='/var/tmp/canarysting'
case "${mode}" in
  incoming) path="${root}/.incoming-${run_id}" ;;
  final) path="${root}/${run_id}" ;;
  *) echo "FAIL: unsupported verification mode: ${mode}" >&2; exit 1 ;;
esac
[[ -d "${path}" && ! -L "${path}" && -O "${path}" ]] || {
  echo "FAIL: stage must be an owned, non-symlink directory: ${path}" >&2
  exit 1
}
cd "${path}"
[[ -f manifest.tsv && ! -L manifest.tsv ]] || { echo 'FAIL: remote manifest.tsv is invalid' >&2; exit 1; }
[[ -f SHA256SUMS && ! -L SHA256SUMS ]] || { echo 'FAIL: remote SHA256SUMS is invalid' >&2; exit 1; }

awk -F '\t' '
  NR == 1 {
    if ($0 != "record\tkind_or_key\tname_or_value\tpath\tsize_bytes\tsha256") exit 1
    next
  }
  $1 == "metadata" && NF == 3 { next }
  $1 == "artifact" && NF == 6 { next }
  { exit 1 }
  END { if (NR < 2) exit 1 }
' manifest.tsv || { echo 'FAIL: remote manifest schema is invalid' >&2; exit 1; }

metadata_value() {
  awk -F '\t' -v key="$1" '
    $1 == "metadata" && $2 == key { count++; value = $3 }
    END { if (count != 1) exit 1; print value }
  ' manifest.tsv
}
[[ "$(metadata_value format_version)" == '1' ]] || { echo 'FAIL: remote format_version is invalid' >&2; exit 1; }
[[ "$(metadata_value target_os)" == 'linux' ]] || { echo 'FAIL: remote target_os is invalid' >&2; exit 1; }
[[ "$(metadata_value target_arch)" == 'arm64' ]] || { echo 'FAIL: remote target_arch is invalid' >&2; exit 1; }
[[ "$(metadata_value target_arm64)" == 'v8.0' ]] || { echo 'FAIL: remote target_arm64 is invalid' >&2; exit 1; }
[[ "$(metadata_value cgo_enabled)" == '0' ]] || { echo 'FAIL: remote cgo_enabled is invalid' >&2; exit 1; }
source_revision="$(metadata_value source_revision)" || { echo 'FAIL: remote source_revision is missing' >&2; exit 1; }
source_state="$(metadata_value source_state)" || { echo 'FAIL: remote source_state is missing' >&2; exit 1; }
source_tree_sha256="$(metadata_value source_tree_sha256)" || { echo 'FAIL: remote source_tree_sha256 is missing' >&2; exit 1; }
[[ "${source_revision}" =~ ^[0-9a-f]{40,64}$ ]] || { echo 'FAIL: remote source_revision is malformed' >&2; exit 1; }
[[ "${source_state}" == 'clean' || "${source_state}" == 'dirty' ]] || { echo 'FAIL: remote source_state is malformed' >&2; exit 1; }
[[ "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] || { echo 'FAIL: remote source_tree_sha256 is malformed' >&2; exit 1; }

expected_checksums=''
expected_files=$'SHA256SUMS\nmanifest.tsv\n'
expected_dirs=''
seen_paths=$'\n'
artifact_count=0
while IFS=$'\t' read -r record artifact_kind artifact_name relative_path artifact_size artifact_sha256; do
  [[ "${record}" == 'artifact' ]] || continue
  case "${artifact_kind}/${artifact_name}" in
    product/engine | product/canaryctl | product/operator | product/envoy-adapter | product/dashboard-backend | test/cookiespike | test/enforcespike | test/dgxstackspike | test/correlationspike | test/tracespike | test/attackerexecutorspike | test/attackerloopspike) ;;
    *) echo "FAIL: unapproved remote artifact: ${artifact_kind}/${artifact_name}" >&2; exit 1 ;;
  esac
  [[ "${relative_path}" == "${artifact_kind}/${artifact_name}" ]] || {
    echo "FAIL: unsafe remote artifact path: ${relative_path}" >&2
    exit 1
  }
  [[ "${artifact_size}" =~ ^[0-9]+$ && "${artifact_sha256}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "FAIL: malformed remote artifact metadata: ${relative_path}" >&2
    exit 1
  }
  case "${seen_paths}" in
    *$'\n'"${relative_path}"$'\n'*) echo "FAIL: duplicate remote artifact: ${relative_path}" >&2; exit 1 ;;
  esac
  seen_paths+="${relative_path}"$'\n'
  [[ -f "${relative_path}" && ! -L "${relative_path}" && -x "${relative_path}" ]] || {
    echo "FAIL: remote artifact is not a regular executable: ${relative_path}" >&2
    exit 1
  }
  [[ "$(stat -c %s "${relative_path}")" == "${artifact_size}" ]] || {
    echo "FAIL: remote artifact size mismatch: ${relative_path}" >&2
    exit 1
  }
  expected_checksums+="${artifact_sha256}  ${relative_path}"$'\n'
  expected_files+="${relative_path}"$'\n'
  case "${artifact_kind}" in
    product) [[ "${expected_dirs}" == *$'product\n'* ]] || expected_dirs+=$'product\n' ;;
    test) [[ "${expected_dirs}" == *$'test\n'* ]] || expected_dirs+=$'test\n' ;;
  esac
  artifact_count=$((artifact_count + 1))
done <manifest.tsv
[[ "${artifact_count}" -gt 0 ]] || { echo 'FAIL: remote manifest contains no artifacts' >&2; exit 1; }

manifest_sha256="$(sha256sum manifest.tsv | awk '{print $1}')"
expected_checksums+="${manifest_sha256}  manifest.tsv"
actual_checksums="$(<SHA256SUMS)"
[[ "${actual_checksums}" == "${expected_checksums}" ]] || {
  echo 'FAIL: remote SHA256SUMS does not match the manifest inventory' >&2
  exit 1
}
sha256sum -c SHA256SUMS >/dev/null

non_regular="$(find . -mindepth 1 ! -type f ! -type d -print | LC_ALL=C sort)"
[[ -z "${non_regular}" ]] || { echo 'FAIL: remote stage contains a symlink or unsupported entry' >&2; exit 1; }
actual_files="$(find . -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort)"
expected_files="$(printf '%s' "${expected_files}" | LC_ALL=C sort)"
[[ "${actual_files}" == "${expected_files}" ]] || { echo 'FAIL: remote stage contains an unexpected or missing file' >&2; exit 1; }
actual_dirs="$(find . -mindepth 1 -type d -printf '%P\n' | LC_ALL=C sort)"
expected_dirs="$(printf '%s' "${expected_dirs}" | LC_ALL=C sort)"
[[ "${actual_dirs}" == "${expected_dirs}" ]] || { echo 'FAIL: remote stage contains an unexpected or missing directory' >&2; exit 1; }

if [[ "${mode}" == 'incoming' ]]; then
  final="${root}/${run_id}"
  [[ ! -e "${final}" && ! -L "${final}" ]] || { echo "FAIL: final stage already exists: ${final}" >&2; exit 1; }
  mv "${path}" "${final}"
  printf 'remote_stage=%s\n' "${final}"
else
  printf 'remote_verified=%s\n' "${path}"
fi
printf 'remote_artifacts=%d\n' "${artifact_count}"
REMOTE
}

cleanup_incoming() {
  local status="$?"
  trap - EXIT INT TERM
  if [[ "${incoming_created:-0}" -eq 1 ]]; then
    ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" <<'REMOTE' || true
set -euo pipefail
run_id="$1"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || exit 1
root='/var/tmp/canarysting'
incoming="${root}/.incoming-${run_id}"
case "${incoming}" in
  /var/tmp/canarysting/.incoming-*) ;;
  *) exit 1 ;;
esac
if [[ -e "${incoming}" || -L "${incoming}" ]]; then
  rm -rf -- "${incoming}"
fi
rmdir "${root}" 2>/dev/null || true
REMOTE
  fi
  exit "${status}"
}

artifact_dir=''
run_id=''
dry_run=0
verify_only=0
declare -a artifact_paths=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      [[ "$#" -ge 2 ]] || fail '--artifact-dir requires a value'
      [[ -z "${artifact_dir}" ]] || fail '--artifact-dir may be specified only once'
      artifact_dir="$2"
      shift 2
      ;;
    --run-id)
      [[ "$#" -ge 2 ]] || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --verify-only)
      verify_only=1
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

[[ -n "${run_id}" ]] || fail '--run-id is required'
validate_run_id "${run_id}"
if [[ "${verify_only}" -eq 1 ]]; then
  [[ "${dry_run}" -eq 0 ]] || fail '--verify-only cannot be combined with --dry-run'
  [[ -z "${artifact_dir}" ]] || fail '--verify-only cannot be combined with --artifact-dir'
else
  [[ -n "${artifact_dir}" ]] || fail '--artifact-dir is required unless --verify-only is used'
fi

if [[ "${verify_only}" -eq 1 ]]; then
  command -v ssh >/dev/null 2>&1 || fail 'ssh is required'
  remote_validate final
  printf 'PASS: verified DGX run stage\n'
  exit 0
fi

for required_tool in awk find sort sed wc tr; do
  command -v "${required_tool}" >/dev/null 2>&1 || fail "required local tool not found: ${required_tool}"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail 'required checksum tool not found: provide existing sha256sum or shasum'
fi
validate_local_artifacts

remote_stage="${remote_root}/${run_id}"
if [[ "${dry_run}" -eq 1 ]]; then
  printf 'DRY RUN: local artifact inventory passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'remote_stage=%s\n' "${remote_stage}"
  printf 'artifacts=%d\n' "${artifact_count}"
  printf 'source_revision=%s\n' "${source_revision}"
  printf 'source_state=%s\n' "${source_state}"
  printf 'source_tree_sha256=%s\n' "${source_tree_sha256}"
  exit 0
fi

command -v ssh >/dev/null 2>&1 || fail 'ssh is required'
command -v scp >/dev/null 2>&1 || fail 'scp is required'

incoming_created=0
trap cleanup_incoming EXIT INT TERM
remote_preflight_and_create
incoming_created=1
remote_incoming="${remote_root}/.incoming-${run_id}"

scp "${ssh_options[@]}" "${manifest}" "${checksums}" "${dgx_host}:${remote_incoming}/"
for relative_path in "${artifact_paths[@]}"; do
  scp "${ssh_options[@]}" "${artifact_dir}/${relative_path}" "${dgx_host}:${remote_incoming}/${relative_path}"
done

remote_validate incoming
incoming_created=0
remote_validate final
trap - EXIT INT TERM

printf 'PASS: copied %d approved artifact(s) to the DGX\n' "${artifact_count}"
printf 'host=%s\n' "${dgx_host}"
printf 'remote_stage=%s\n' "${remote_stage}"
printf 'source_revision=%s\n' "${source_revision}"
printf 'source_state=%s\n' "${source_state}"
printf 'source_tree_sha256=%s\n' "${source_tree_sha256}"
