#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="falcon1"
readonly remote_root="/var/tmp/canarysting"
readonly retention_hours=72
readonly -a ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=12
  -o StrictHostKeyChecking=yes
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
readonly repo_root
copy_script="${script_dir}/copy.sh"
check_script="${script_dir}/check.sh"
readonly copy_script check_script

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/collect.sh --run-id ID --output-dir DIR [--dry-run]
  scripts/dgx/collect.sh --run-id ID --output-dir DIR --fixture-dir DIR

Collect the fixed M1B artifact/execution schema plus a read-only DGX state check.
The output is an atomic, mode-0700 directory outside the source repository with
a manifest and SHA-256 inventory. Existing output is never overwritten.

Before any live transfer, the remote files are bounded, type/ownership checked,
and scanned for credential-like material. Suspicious input is refused rather
than copied. No kubeconfig or Kubernetes Secret contents are read.

--fixture-dir validates an explicit local test fixture and never accesses the
DGX. --dry-run validates only local arguments and reports the live contract.
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

validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

validate_output_path() {
  [[ "${output_dir}" == /* ]] || fail '--output-dir must be an absolute path'
  [[ "${output_dir}" != *$'\n'* && "${output_dir}" != *$'\t'* ]] ||
    fail '--output-dir must not contain tabs or newlines'
  output_parent="$(dirname "${output_dir}")"
  output_name="$(basename "${output_dir}")"
  [[ "${output_name}" != '.' && "${output_name}" != '..' && -n "${output_name}" ]] ||
    fail '--output-dir must name a new directory'
  [[ -d "${output_parent}" && -w "${output_parent}" ]] ||
    fail "output parent must be an existing writable directory: ${output_parent}"
  output_parent="$(cd "${output_parent}" && pwd -P)"
  [[ -d "${output_parent}" && ! -L "${output_parent}" && -w "${output_parent}" ]] ||
    fail "resolved output parent must be a writable non-symlink directory: ${output_parent}"
  output_dir="${output_parent}/${output_name}"
  case "${output_dir}" in
    "${repo_root}"|"${repo_root}/"*) fail '--output-dir must be outside the source repository' ;;
  esac
  [[ ! -e "${output_dir}" && ! -L "${output_dir}" ]] ||
    fail "output directory already exists: ${output_dir}"
  readonly output_parent output_name output_dir
}

validate_fixture_path() {
  [[ "${fixture_dir}" == /* ]] || fail '--fixture-dir must be an absolute path'
  [[ "${fixture_dir}" != *$'\n'* && "${fixture_dir}" != *$'\t'* ]] ||
    fail '--fixture-dir must not contain tabs or newlines'
  [[ -d "${fixture_dir}" && ! -L "${fixture_dir}" ]] ||
    fail "fixture directory is missing, not a directory, or a symlink: ${fixture_dir}"
  fixture_dir="$(cd "${fixture_dir}" && pwd -P)"
  readonly fixture_dir
}

contains_prohibited_data() {
  local path="$1"
  local pattern='-----BEGIN [^-]*(PRIVATE KEY|OPENSSH PRIVATE KEY)-----|authorization:[[:space:]]*(bearer|basic)[[:space:]]+[^[:space:]]+|(^|[^[:alnum:]_])(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|client-key-data|client-certificate-data|certificate-authority-data|secret[[:space:]_-]*value)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}|^[[:space:]]*token[[:space:]]*:[[:space:]]*[^[:space:]]{4,}'
  LC_ALL=C grep -Eiq -- "${pattern}" "${path}"
}

validate_text_file() {
  local path="$1"
  local label="$2"
  local maximum_bytes="$3"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} must be a regular non-symlink file"
  local bytes
  bytes="$(wc -c <"${path}" | tr -d '[:space:]')"
  [[ "${bytes}" =~ ^[0-9]+$ && "${bytes}" -le "${maximum_bytes}" ]] ||
    fail "${label} exceeds its ${maximum_bytes}-byte limit"
  if LC_ALL=C grep -Eq $'[\001-\010\013\014\016-\037\177]' "${path}"; then
    fail "${label} contains non-text control data"
  fi
  if contains_prohibited_data "${path}"; then
    fail "${label} contains prohibited credential-like material"
  fi
}

metadata_value() {
  local manifest="$1"
  local key="$2"
  awk -F '\t' -v key="${key}" '
    $1 == "metadata" && $2 == key { count++; value = $3 }
    END { if (count != 1) exit 1; print value }
  ' "${manifest}"
}

validate_stage_metadata() {
  local source="$1"
  local manifest="${source}/manifest.tsv"
  local checksums="${source}/SHA256SUMS"
  validate_text_file "${manifest}" 'artifact manifest' 131072
  validate_text_file "${checksums}" 'artifact checksum inventory' 131072

  awk -F '\t' '
    NR == 1 {
      if ($0 != "record\tkind_or_key\tname_or_value\tpath\tsize_bytes\tsha256") exit 1
      next
    }
    $1 == "metadata" && NF == 3 { next }
    $1 == "artifact" && NF == 6 { artifacts++; next }
    { exit 1 }
    END { if (artifacts < 1) exit 1 }
  ' "${manifest}" || fail 'artifact manifest has an unsupported schema or malformed row'

  [[ "$(metadata_value "${manifest}" format_version)" == '1' ]] || fail 'artifact format_version must be 1'
  [[ "$(metadata_value "${manifest}" target_os)" == 'linux' ]] || fail 'artifact target_os must be linux'
  [[ "$(metadata_value "${manifest}" target_arch)" == 'arm64' ]] || fail 'artifact target_arch must be arm64'
  local source_revision source_state source_tree_sha256
  source_revision="$(metadata_value "${manifest}" source_revision)" || fail 'artifact source_revision is missing'
  source_state="$(metadata_value "${manifest}" source_state)" || fail 'artifact source_state is missing'
  source_tree_sha256="$(metadata_value "${manifest}" source_tree_sha256)" || fail 'artifact source_tree_sha256 is missing'
  [[ "${source_revision}" =~ ^[0-9a-f]{40,64}$ ]] || fail 'artifact source_revision is malformed'
  [[ "${source_state}" == 'clean' || "${source_state}" == 'dirty' ]] || fail 'artifact source_state is malformed'
  [[ "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact source_tree_sha256 is malformed'

  local expected_checksums=''
  local artifact_count=0
  local record artifact_kind artifact_name relative_path artifact_size artifact_sha256
  local seen_paths=$'\n'
  while IFS=$'\t' read -r record artifact_kind artifact_name relative_path artifact_size artifact_sha256; do
    [[ "${record}" == 'artifact' ]] || continue
    case "${artifact_kind}/${artifact_name}" in
      product/engine|product/canaryctl|product/operator|product/envoy-adapter|product/dashboard-backend|test/cookiespike|test/enforcespike) ;;
      *) fail "artifact manifest contains an undeclared path: ${artifact_kind}/${artifact_name}" ;;
    esac
    [[ "${relative_path}" == "${artifact_kind}/${artifact_name}" ]] ||
      fail "artifact manifest path does not match kind/name: ${relative_path}"
    [[ "${artifact_size}" =~ ^[0-9]+$ && "${artifact_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
      fail "artifact metadata is malformed: ${relative_path}"
    case "${seen_paths}" in
      *$'\n'"${relative_path}"$'\n'*) fail "artifact manifest path is duplicated: ${relative_path}" ;;
    esac
    seen_paths+="${relative_path}"$'\n'
    expected_checksums+="${artifact_sha256}  ${relative_path}"$'\n'
    artifact_count=$((artifact_count + 1))
  done <"${manifest}"
  [[ "${artifact_count}" -gt 0 ]] || fail 'artifact manifest contains no artifact rows'
  expected_checksums+="$(sha256_file "${manifest}")  manifest.tsv"
  [[ "$(<"${checksums}")" == "${expected_checksums}" ]] ||
    fail 'artifact SHA256SUMS does not exactly match the collected manifest'
}

result_value() {
  local result="$1"
  local key="$2"
  awk -F '\t' -v key="${key}" '
    NR > 1 && $1 == key { count++; value = $2 }
    END { if (count != 1) exit 1; print value }
  ' "${result}"
}

validate_execution() {
  local source="$1"
  local result="${source}/result.tsv"
  local stdout_log="${source}/stdout.log"
  local stderr_log="${source}/stderr.log"
  validate_text_file "${stdout_log}" 'execution stdout' 1048576
  validate_text_file "${stderr_log}" 'execution stderr' 1048576
  validate_text_file "${result}" 'execution result' 32768

  awk -F '\t' '
    NR == 1 { if ($0 != "key\tvalue") exit 1; next }
    NF != 2 || $1 == "" || seen[$1]++ { exit 1 }
    { count++ }
    END { if (count != 16) exit 1 }
  ' "${result}" || fail 'execution result has an unsupported schema, duplicate key, or malformed row'

  local key
  for key in format_version run_id profile artifact artifact_sha256 privilege timeout_seconds expected_outcome exit_code process_residue stdout_bytes stderr_bytes started_utc finished_utc status diagnostic; do
    result_value "${result}" "${key}" >/dev/null || fail "execution result is missing exactly one ${key}"
  done
  [[ "$(result_value "${result}" format_version)" == '1' ]] || fail 'execution format_version must be 1'
  [[ "$(result_value "${result}" run_id)" == "${run_id}" ]] || fail 'execution result belongs to a different run ID'
  [[ "$(result_value "${result}" privilege)" == 'unprivileged' ]] || fail 'generic execution evidence must be unprivileged'
  [[ "$(result_value "${result}" process_residue)" =~ ^(none|present)$ ]] || fail 'execution process_residue is malformed'
  [[ "$(result_value "${result}" status)" =~ ^(PASS|FAIL)$ ]] || fail 'execution status is malformed'
  [[ "$(result_value "${result}" artifact_sha256)" =~ ^[0-9a-f]{64}$ ]] || fail 'execution artifact checksum is malformed'
  local stdout_bytes stderr_bytes
  stdout_bytes="$(wc -c <"${stdout_log}" | tr -d '[:space:]')"
  stderr_bytes="$(wc -c <"${stderr_log}" | tr -d '[:space:]')"
  [[ "$(result_value "${result}" stdout_bytes)" == "${stdout_bytes}" ]] || fail 'execution stdout size does not match result.tsv'
  [[ "$(result_value "${result}" stderr_bytes)" == "${stderr_bytes}" ]] || fail 'execution stderr size does not match result.tsv'
}

validate_state_check() {
  local path="$1"
  validate_text_file "${path}" 'DGX state check' 524288
  local marker
  for marker in '[host]' 'hostname=spark-5343' 'architecture=aarch64' '[kubernetes]' '[cilium]' '[kernel_bpf]' '[root_cgroup_attachments]' '[security_observations]'; do
    grep -F -- "${marker}" "${path}" >/dev/null || fail "DGX state check is missing marker: ${marker}"
  done
}

validate_source_inventory() {
  local source="$1"
  local expected=$'dgx-check.txt\nexecution/result.tsv\nexecution/stderr.log\nexecution/stdout.log\nstage/SHA256SUMS\nstage/manifest.tsv'
  local actual
  actual="$(cd "${source}" && find . -mindepth 1 -type f -print | sed 's#^\./##' | LC_ALL=C sort)"
  [[ "${actual}" == "${expected}" ]] || fail 'collection source contains an unexpected or missing file'
  local non_regular
  non_regular="$(find "${source}" -mindepth 1 ! -type f ! -type d -print | LC_ALL=C sort)"
  [[ -z "${non_regular}" ]] || fail 'collection source contains a symlink or unsupported entry'
  validate_stage_metadata "${source}/stage"
  validate_execution "${source}/execution"
  validate_state_check "${source}/dgx-check.txt"

  local artifact_path artifact_sha result_sha
  artifact_path="$(result_value "${source}/execution/result.tsv" artifact)"
  result_sha="$(result_value "${source}/execution/result.tsv" artifact_sha256)"
  artifact_sha="$(awk -F '\t' -v path="${artifact_path}" '$1 == "artifact" && $4 == path { count++; sha = $6 } END { if (count != 1) exit 1; print sha }' "${source}/stage/manifest.tsv")" ||
    fail 'execution artifact is not uniquely declared by the artifact manifest'
  [[ "${result_sha}" == "${artifact_sha}" ]] || fail 'execution artifact checksum does not match the artifact manifest'
}

expiration_utc() {
  if date -u -v+"${retention_hours}"H '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
    date -u -v+"${retention_hours}"H '+%Y-%m-%dT%H:%M:%SZ'
  else
    date -u -d "+${retention_hours} hours" '+%Y-%m-%dT%H:%M:%SZ'
  fi
}

publish_collection() {
  local source="$1"
  local publish="${work_dir}/publish"
  mkdir -m 0700 "${publish}"
  cp "${source}/stage/manifest.tsv" "${publish}/artifact-manifest.tsv"
  cp "${source}/stage/SHA256SUMS" "${publish}/artifact-SHA256SUMS"
  cp "${source}/execution/result.tsv" "${publish}/execution-result.tsv"
  cp "${source}/execution/stdout.log" "${publish}/stdout.log"
  cp "${source}/execution/stderr.log" "${publish}/stderr.log"
  cp "${source}/dgx-check.txt" "${publish}/dgx-check.txt"
  chmod 0600 "${publish}"/*

  local collected_utc expires_utc manifest checksums file bytes digest total_bytes
  collected_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  expires_utc="$(expiration_utc)"
  manifest="${publish}/collection-manifest.tsv"
  checksums="${publish}/SHA256SUMS"
  total_bytes=0
  {
    printf 'record\tkey_or_path\tvalue_or_size\tsha256\n'
    printf 'metadata\tformat_version\t1\t-\n'
    printf 'metadata\trun_id\t%s\t-\n' "${run_id}"
    printf 'metadata\tsource_mode\t%s\t-\n' "${source_mode}"
    printf 'metadata\tcollected_at_utc\t%s\t-\n' "${collected_utc}"
    printf 'metadata\tdata_class\tdevelopment-validation-evidence\t-\n'
    printf 'metadata\tsensitivity\tinternal-operational\t-\n'
    printf 'metadata\tretention_profile\tephemeral-%sh\t-\n' "${retention_hours}"
    printf 'metadata\texpires_at_utc\t%s\t-\n' "${expires_utc}"
    printf 'metadata\tlegal_hold\tnot-supported-export-to-governed-case-store\t-\n'
    printf 'metadata\tresidency\tlocal-output-directory\t-\n'
    printf 'metadata\tencryption_boundary\toperator-managed-local-filesystem\t-\n'
    printf 'metadata\tmodel_use_policy\tprohibited\t-\n'
    printf 'metadata\tsynthetic\tfalse\t-\n'
    printf 'metadata\tsensitive_content_policy\trefuse-before-transfer\t-\n'
    for file in artifact-manifest.tsv artifact-SHA256SUMS execution-result.tsv stdout.log stderr.log dgx-check.txt; do
      bytes="$(wc -c <"${publish}/${file}" | tr -d '[:space:]')"
      digest="$(sha256_file "${publish}/${file}")"
      total_bytes=$((total_bytes + bytes))
      printf 'file\t%s\t%s\t%s\n' "${file}" "${bytes}" "${digest}"
    done
    printf 'metadata\testimated_payload_bytes\t%s\t-\n' "${total_bytes}"
  } >"${manifest}"
  chmod 0600 "${manifest}"

  : >"${checksums}"
  for file in artifact-manifest.tsv artifact-SHA256SUMS execution-result.tsv stdout.log stderr.log dgx-check.txt collection-manifest.tsv; do
    printf '%s  %s\n' "$(sha256_file "${publish}/${file}")" "${file}" >>"${checksums}"
  done
  chmod 0600 "${checksums}"
  (cd "${publish}" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS >/dev/null; else shasum -a 256 -c SHA256SUMS >/dev/null; fi) ||
    fail 'published collection checksum verification failed'

  mv "${publish}" "${output_dir}"
  work_dir=''
  printf 'PASS: collected bounded redacted DGX evidence\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'run_id=%s\n' "${run_id}"
  printf 'output_dir=%s\n' "${output_dir}"
  printf 'expires_at_utc=%s\n' "${expires_utc}"
  printf 'model_use_policy=prohibited\n'
}

collect_remote_source() {
  [[ -x "${copy_script}" ]] || fail "copy verifier is missing or not executable: ${copy_script}"
  [[ -x "${check_script}" ]] || fail "DGX checker is missing or not executable: ${check_script}"
  command -v ssh >/dev/null 2>&1 || fail 'ssh is required'
  command -v scp >/dev/null 2>&1 || fail 'scp is required'
  "${copy_script}" --verify-only --run-id "${run_id}"

  local source="${work_dir}/source"
  mkdir -m 0700 "${source}" "${source}/stage" "${source}/execution"
  local remote_digests="${work_dir}/remote-digests.tsv"
  ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" >"${remote_digests}" <<'REMOTE'
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "$(hostname)" == 'spark-5343' ]] || fail "unexpected hostname: $(hostname)"
[[ "$(uname -m)" == 'aarch64' ]] || fail "unexpected architecture: $(uname -m)"
for tool in awk find grep id sha256sum stat wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'artifact stage is missing or unsafe'
[[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'execution evidence is missing or unsafe'

expected=$'result.tsv\nstderr.log\nstdout.log'
actual="$(cd "${evidence}" && find . -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort)"
[[ "${actual}" == "${expected}" ]] || fail 'execution evidence contains an unexpected or missing file'
unsupported="$(find "${evidence}" -mindepth 1 ! -type f ! -type d -print -quit)"
[[ -z "${unsupported}" ]] || fail 'execution evidence contains a symlink or unsupported entry'
unowned="$(find "${evidence}" -mindepth 1 ! -user "$(id -un)" -print -quit)"
[[ -z "${unowned}" ]] || fail 'execution evidence contains an unowned entry'

pattern='-----BEGIN [^-]*(PRIVATE KEY|OPENSSH PRIVATE KEY)-----|authorization:[[:space:]]*(bearer|basic)[[:space:]]+[^[:space:]]+|(^|[^[:alnum:]_])(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|client-key-data|client-certificate-data|certificate-authority-data|secret[[:space:]_-]*value)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}|^[[:space:]]*token[[:space:]]*:[[:space:]]*[^[:space:]]{4,}'
for spec in "${stage}/manifest.tsv:131072" "${stage}/SHA256SUMS:131072" "${evidence}/stdout.log:1048576" "${evidence}/stderr.log:1048576" "${evidence}/result.tsv:32768"; do
  path="${spec%:*}"
  maximum="${spec##*:}"
  [[ -f "${path}" && ! -L "${path}" && -O "${path}" ]] || fail "declared evidence is missing or unsafe: ${path}"
  bytes="$(wc -c <"${path}" | tr -d '[:space:]')"
  [[ "${bytes}" =~ ^[0-9]+$ && "${bytes}" -le "${maximum}" ]] || fail "declared evidence exceeds its limit: ${path}"
  ! LC_ALL=C grep -Eq $'[\001-\010\013\014\016-\037\177]' "${path}" || fail "declared evidence contains non-text control data: ${path}"
  ! LC_ALL=C grep -Eiq -- "${pattern}" "${path}" || fail "declared evidence contains prohibited credential-like material: ${path}"
done

awk -F '\t' -v expected_run="${run_id}" '
  NR == 1 { if ($0 != "key\tvalue") exit 1; next }
  NF != 2 || $1 == "" || seen[$1]++ { exit 1 }
  $1 == "run_id" { run_count++; if ($2 != expected_run) exit 1 }
  END { if (run_count != 1) exit 1 }
' "${evidence}/result.tsv" || fail 'execution result schema or run identity is invalid'

for record in \
  "stage/manifest.tsv:${stage}/manifest.tsv" \
  "stage/SHA256SUMS:${stage}/SHA256SUMS" \
  "execution/stdout.log:${evidence}/stdout.log" \
  "execution/stderr.log:${evidence}/stderr.log" \
  "execution/result.tsv:${evidence}/result.tsv"; do
  relative="${record%%:*}"
  path="${record#*:}"
  printf '%s\t%s\n' "$(sha256sum "${path}" | awk '{print $1}')" "${relative}"
done
REMOTE

  scp "${ssh_options[@]}" "${dgx_host}:${remote_root}/${run_id}/manifest.tsv" "${source}/stage/manifest.tsv"
  scp "${ssh_options[@]}" "${dgx_host}:${remote_root}/${run_id}/SHA256SUMS" "${source}/stage/SHA256SUMS"
  scp "${ssh_options[@]}" "${dgx_host}:${remote_root}/execution-${run_id}/stdout.log" "${source}/execution/stdout.log"
  scp "${ssh_options[@]}" "${dgx_host}:${remote_root}/execution-${run_id}/stderr.log" "${source}/execution/stderr.log"
  scp "${ssh_options[@]}" "${dgx_host}:${remote_root}/execution-${run_id}/result.tsv" "${source}/execution/result.tsv"
  chmod 0600 "${source}/stage/manifest.tsv" "${source}/stage/SHA256SUMS" "${source}/execution/"*

  local digest relative extra
  while IFS=$'\t' read -r digest relative extra; do
    [[ "${digest}" =~ ^[0-9a-f]{64}$ && -n "${relative}" && -z "${extra:-}" ]] || fail 'remote digest inventory is malformed'
    case "${relative}" in
      stage/manifest.tsv|stage/SHA256SUMS|execution/stdout.log|execution/stderr.log|execution/result.tsv) ;;
      *) fail "remote digest inventory contains an undeclared path: ${relative}" ;;
    esac
    [[ "$(sha256_file "${source}/${relative}")" == "${digest}" ]] || fail "remote evidence changed during transfer: ${relative}"
  done <"${remote_digests}"
  [[ "$(wc -l <"${remote_digests}" | tr -d '[:space:]')" == '5' ]] || fail 'remote digest inventory must contain exactly five rows'

  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}" |
    LC_ALL=C sed $'s/\033\\[[0-9;]*m//g' >"${source}/dgx-check.txt"
  chmod 0600 "${source}/dgx-check.txt"
  validate_source_inventory "${source}"
  publish_collection "${source}"
}

run_id=''
output_dir=''
fixture_dir=''
dry_run=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ "$#" -ge 2 ]] || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || fail '--output-dir requires a value'
      [[ -z "${output_dir}" ]] || fail '--output-dir may be specified only once'
      output_dir="$2"
      shift 2
      ;;
    --fixture-dir)
      [[ "$#" -ge 2 ]] || fail '--fixture-dir requires a value'
      [[ -z "${fixture_dir}" ]] || fail '--fixture-dir may be specified only once'
      fixture_dir="$2"
      shift 2
      ;;
    --dry-run)
      [[ "${dry_run}" -eq 0 ]] || fail '--dry-run may be specified only once'
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
[[ -n "${output_dir}" ]] || fail '--output-dir is required'
validate_run_id "${run_id}"
validate_output_path
if [[ -n "${fixture_dir}" ]]; then
  [[ "${dry_run}" -eq 0 ]] || fail '--fixture-dir cannot be combined with --dry-run'
  validate_fixture_path
  source_mode='fixture'
else
  source_mode='falcon1'
fi
readonly run_id dry_run source_mode

if [[ "${dry_run}" -eq 1 ]]; then
  printf 'DRY RUN: collection contract passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'run_id=%s\n' "${run_id}"
  printf 'remote_stage=%s/%s\n' "${remote_root}" "${run_id}"
  printf 'remote_evidence=%s/execution-%s\n' "${remote_root}" "${run_id}"
  printf 'output_dir=%s\n' "${output_dir}"
  printf 'retention_hours=%s\n' "${retention_hours}"
  printf 'sensitive_content_policy=refuse-before-transfer\n'
  exit 0
fi

for required_tool in awk basename chmod cp date dirname find grep mktemp mv sed sort tr wc; do
  command -v "${required_tool}" >/dev/null 2>&1 || fail "required local tool not found: ${required_tool}"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail 'required checksum tool not found: provide existing sha256sum or shasum'
fi

umask 077
work_dir="$(mktemp -d "${output_parent}/.canarysting-collect.XXXXXX")"
cleanup_work_dir() {
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${output_parent}/.canarysting-collect."* ]]; then
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup_work_dir EXIT INT TERM

if [[ "${source_mode}" == 'fixture' ]]; then
  validate_source_inventory "${fixture_dir}"
  publish_collection "${fixture_dir}"
else
  collect_remote_source
fi

trap - EXIT INT TERM
