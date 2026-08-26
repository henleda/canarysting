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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
readonly copy_script

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/run.sh --run-id ID --profile PROFILE [--dry-run]
  scripts/dgx/run.sh --list

Execute one fixed, unprivileged profile from the checksum-verified DGX artifact
stage /var/tmp/canarysting/ID. Output and an atomic result record are written to
the distinct run-owned directory /var/tmp/canarysting/execution-ID.

--dry-run validates the requested profile and reports its exact contract without
accessing the DGX. No arbitrary command, argument, privilege, path, or timeout is
accepted.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

profile_record() {
  case "$1" in
    engine-selfcheck)
      printf 'product/engine\t15\texit-zero\tunprivileged\n'
      ;;
    engine-timeout-probe)
      printf 'product/engine\t2\ttimeout\tunprivileged\n'
      ;;
    *)
      return 1
      ;;
  esac
}

list_profiles() {
  printf 'PROFILE\tARTIFACT\tTIMEOUT_SECONDS\tEXPECTED\tPRIVILEGE\n'
  local profile record
  for profile in engine-selfcheck engine-timeout-probe; do
    record="$(profile_record "${profile}")"
    printf '%s\t%s\n' "${profile}" "${record}"
  done
}

validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

run_id=''
profile=''
dry_run=0
list_only=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ "$#" -ge 2 ]] || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --profile)
      [[ "$#" -ge 2 ]] || fail '--profile requires a value'
      [[ -z "${profile}" ]] || fail '--profile may be specified only once'
      profile="$2"
      shift 2
      ;;
    --dry-run)
      [[ "${dry_run}" -eq 0 ]] || fail '--dry-run may be specified only once'
      dry_run=1
      shift
      ;;
    --list)
      [[ "${list_only}" -eq 0 ]] || fail '--list may be specified only once'
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
  [[ -z "${run_id}" && -z "${profile}" && "${dry_run}" -eq 0 ]] ||
    fail '--list cannot be combined with execution arguments'
  list_profiles
  exit 0
fi

[[ -n "${run_id}" ]] || fail '--run-id is required'
[[ -n "${profile}" ]] || fail '--profile is required'
validate_run_id "${run_id}"
profile_data="$(profile_record "${profile}")" || {
  printf 'FAIL: unsupported profile %q; use --list for the allowlist\n' "${profile}" >&2
  exit 1
}
IFS=$'\t' read -r artifact_relative timeout_seconds expected_outcome privilege <<<"${profile_data}"
readonly run_id profile artifact_relative timeout_seconds expected_outcome privilege

remote_stage="${remote_root}/${run_id}"
remote_evidence="${remote_root}/execution-${run_id}"
readonly remote_stage remote_evidence

if [[ "${dry_run}" -eq 1 ]]; then
  printf 'DRY RUN: fixed execution profile passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'remote_stage=%s\n' "${remote_stage}"
  printf 'remote_evidence=%s\n' "${remote_evidence}"
  printf 'profile=%s\n' "${profile}"
  printf 'artifact=%s\n' "${artifact_relative}"
  printf 'timeout_seconds=%s\n' "${timeout_seconds}"
  printf 'expected_outcome=%s\n' "${expected_outcome}"
  printf 'privilege=%s\n' "${privilege}"
  exit 0
fi

[[ -x "${copy_script}" ]] || fail "copy verifier is missing or not executable: ${copy_script}"
command -v ssh >/dev/null 2>&1 || fail 'ssh is required'

"${copy_script}" --verify-only --run-id "${run_id}"

ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${profile}" <<'REMOTE'
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
profile="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'

case "${profile}" in
  engine-selfcheck)
    artifact_relative='product/engine'
    timeout_seconds=15
    expected_outcome='exit-zero'
    privilege='unprivileged'
    ;;
  engine-timeout-probe)
    artifact_relative='product/engine'
    timeout_seconds=2
    expected_outcome='timeout'
    privilege='unprivileged'
    ;;
  *)
    fail "unsupported remote profile: ${profile}"
    ;;
esac
readonly artifact_relative timeout_seconds expected_outcome privilege

[[ "$(hostname)" == 'spark-5343' ]] || fail "unexpected hostname: $(hostname)"
[[ "$(uname -m)" == 'aarch64' ]] || fail "unexpected architecture: $(uname -m)"
for tool in awk date env grep mkdir mv readlink sha256sum stat timeout; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] ||
  fail "remote root must be an owned, writable, non-symlink directory: ${root}"
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] ||
  fail "artifact stage must be an owned, non-symlink directory: ${stage}"
[[ ! -e "${evidence}" && ! -L "${evidence}" ]] ||
  fail "execution evidence already exists: ${evidence}"
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] ||
  fail 'verified stage manifest is missing or not owned'

artifact_metadata="$({
  awk -F '\t' -v path="${artifact_relative}" '
    $1 == "artifact" && $4 == path {
      count++
      size = $5
      digest = $6
    }
    END {
      if (count != 1) exit 1
      print size "\t" digest
    }
  ' "${stage}/manifest.tsv"
})" || fail "manifest must contain exactly one ${artifact_relative} artifact"
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ ]] || fail 'artifact size metadata is malformed'
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact checksum metadata is malformed'

artifact="${stage}/${artifact_relative}"
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] ||
  fail "artifact must be an owned regular executable: ${artifact_relative}"
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'artifact size changed after stage verification'
artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
[[ "${artifact_sha256}" == "${expected_sha256}" ]] || fail 'artifact checksum changed after stage verification'

umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

set +e
case "${profile}" in
  engine-selfcheck)
    (
      cd "${evidence}"
      ulimit -c 0
      exec timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" \
        env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
        "${artifact}" "-scope-boundary=dgx-harness-${run_id}" -selfcheck
    ) >"${stdout_log}" 2>"${stderr_log}"
    exit_code=$?
    ;;
  engine-timeout-probe)
    (
      cd "${evidence}"
      ulimit -c 0
      exec timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" \
        env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
        "${artifact}" "-scope-boundary=dgx-harness-${run_id}"
    ) >"${stdout_log}" 2>"${stderr_log}"
    exit_code=$?
    ;;
esac
set -e

finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stdout_bytes="$(stat -c %s "${stdout_log}")"
stderr_bytes="$(stat -c %s "${stderr_log}")"
status='PASS'
diagnostic='expected outcome observed'

if [[ "${stdout_bytes}" -gt 1048576 || "${stderr_bytes}" -gt 1048576 ]]; then
  status='FAIL'
  diagnostic='profile log exceeded 1048576 bytes'
fi

artifact_resolved="$(readlink -f "${artifact}")"
process_residue='none'
for proc_exe in /proc/[0-9]*/exe; do
  resolved="$(readlink -f "${proc_exe}" 2>/dev/null || true)"
  if [[ "${resolved}" == "${artifact_resolved}" ]]; then
    process_residue='present'
    status='FAIL'
    diagnostic='artifact process remained after bounded execution'
    break
  fi
done

case "${expected_outcome}" in
  exit-zero)
    if [[ "${exit_code}" -ne 0 ]]; then
      status='FAIL'
      diagnostic="expected exit 0, observed ${exit_code}"
    elif ! grep -F 'selfcheck verdict:' "${stdout_log}" >/dev/null; then
      status='FAIL'
      diagnostic='self-check success marker missing'
    fi
    ;;
  timeout)
    if [[ "${exit_code}" -ne 124 ]]; then
      status='FAIL'
      diagnostic="expected timeout exit 124, observed ${exit_code}"
    elif ! grep -F 'engine: ready' "${stderr_log}" >/dev/null; then
      status='FAIL'
      diagnostic='timeout probe never reached ready state'
    elif ! grep -F 'engine: shutting down' "${stderr_log}" >/dev/null; then
      status='FAIL'
      diagnostic='timeout probe did not report graceful SIGTERM shutdown'
    fi
    ;;
esac

result_tmp="${evidence}/.result.tsv.tmp"
result="${evidence}/result.tsv"
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'profile\t%s\n' "${profile}"
  printf 'artifact\t%s\n' "${artifact_relative}"
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'privilege\t%s\n' "${privilege}"
  printf 'timeout_seconds\t%s\n' "${timeout_seconds}"
  printf 'expected_outcome\t%s\n' "${expected_outcome}"
  printf 'exit_code\t%s\n' "${exit_code}"
  printf 'process_residue\t%s\n' "${process_residue}"
  printf 'stdout_bytes\t%s\n' "${stdout_bytes}"
  printf 'stderr_bytes\t%s\n' "${stderr_bytes}"
  printf 'started_utc\t%s\n' "${started_utc}"
  printf 'finished_utc\t%s\n' "${finished_utc}"
  printf 'status\t%s\n' "${status}"
  printf 'diagnostic\t%s\n' "${diagnostic}"
} >"${result_tmp}"
mv "${result_tmp}" "${result}"

printf 'remote_evidence=%s\n' "${evidence}"
printf 'profile=%s\n' "${profile}"
printf 'privilege=%s\n' "${privilege}"
printf 'timeout_seconds=%s\n' "${timeout_seconds}"
printf 'exit_code=%s\n' "${exit_code}"
printf 'process_residue=%s\n' "${process_residue}"
printf 'status=%s\n' "${status}"

[[ "${status}" == 'PASS' ]] || exit 1
REMOTE

printf 'PASS: deterministic DGX execution completed\n'
printf 'host=%s\n' "${dgx_host}"
printf 'run_id=%s\n' "${run_id}"
printf 'profile=%s\n' "${profile}"
printf 'remote_evidence=%s\n' "${remote_evidence}"
