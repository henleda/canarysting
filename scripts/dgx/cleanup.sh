#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host="falcon1"
readonly remote_root="/var/tmp/canarysting"
readonly -a ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=12
  -o StrictHostKeyChecking=yes
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
check_script="${script_dir}/check.sh"
readonly check_script

usage() {
  cat <<'EOF'
Usage:
  scripts/dgx/cleanup.sh --run-id ID [--inspect | --dry-run]

Remove only the run-owned M1B harness paths for ID on falcon1:
  /var/tmp/canarysting/.incoming-ID
  /var/tmp/canarysting/ID
  /var/tmp/canarysting/execution-ID

The command validates ownership, entry types, and the fixed filesystem schema
before deleting anything. --inspect is remote and read-only. --dry-run performs
local validation and reports the exact paths without accessing the DGX.

This generic cleanup does not remove Kubernetes resources, BPF state, containers,
images, system configuration, product deployments, or historical artifacts.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

run_id=''
mode='cleanup'

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ "$#" -ge 2 ]] || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --inspect)
      [[ "${mode}" == 'cleanup' ]] || fail '--inspect and --dry-run are mutually exclusive and may appear only once'
      mode='inspect'
      shift
      ;;
    --dry-run)
      [[ "${mode}" == 'cleanup' ]] || fail '--inspect and --dry-run are mutually exclusive and may appear only once'
      mode='dry-run'
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
readonly run_id mode

readonly incoming="${remote_root}/.incoming-${run_id}"
readonly stage="${remote_root}/${run_id}"
readonly evidence="${remote_root}/execution-${run_id}"

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: cleanup contract passed; DGX was not accessed\n'
  printf 'host=%s\n' "${dgx_host}"
  printf 'run_id=%s\n' "${run_id}"
  printf 'candidate=%s\n' "${incoming}"
  printf 'candidate=%s\n' "${stage}"
  printf 'candidate=%s\n' "${evidence}"
  printf 'excluded=Kubernetes,BPF,containers,images,system-config,product-deployments,historical-artifacts\n'
  exit 0
fi

command -v ssh >/dev/null 2>&1 || fail 'ssh is required'

ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" <<'REMOTE'
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
[[ "$(hostname)" == 'spark-5343' ]] || fail "unexpected hostname: $(hostname)"
[[ "$(uname -m)" == 'aarch64' ]] || fail "unexpected architecture: $(uname -m)"
for tool in awk find hostname id readlink rm rmdir sha256sum sort stat uname; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
incoming="${root}/.incoming-${run_id}"
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
readonly root incoming stage evidence

if [[ ! -e "${root}" && ! -L "${root}" ]]; then
  printf 'mode=%s\nrun_id=%s\nroot=absent\npostcondition=all-candidates-absent\n' "${mode}" "${run_id}"
  exit 0
fi
[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] ||
  fail "remote root must be an owned, writable, non-symlink directory: ${root}"

validate_common() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" && -O "${path}" ]] ||
    fail "candidate must be an owned, non-symlink directory: ${path}"
  local unsupported unowned
  unsupported="$(find "${path}" -mindepth 1 ! -type f ! -type d -print -quit)"
  [[ -z "${unsupported}" ]] || fail "candidate contains a symlink or unsupported entry: ${unsupported}"
  unowned="$(find "${path}" -mindepth 1 ! -user "$(id -un)" -print -quit)"
  [[ -z "${unowned}" ]] || fail "candidate contains an entry not owned by the current user: ${unowned}"
}

validate_artifact_tree() {
  local path="$1"
  local require_complete="$2"
  validate_common "${path}"
  local entry
  while IFS= read -r entry; do
    case "${entry}" in
      d:product|d:test|f:manifest.tsv|f:SHA256SUMS|f:product/engine|f:product/canaryctl|f:product/operator|f:product/envoy-adapter|f:product/dashboard-backend|f:test/cookiespike|f:test/enforcespike|f:test/dgxstackspike|f:test/correlationspike|f:test/tracespike|f:test/attackerexecutorspike|f:test/attackerloopspike)
        ;;
      *)
        fail "artifact candidate contains an undeclared entry: ${path}/${entry#*:}"
        ;;
    esac
  done < <(cd "${path}" && find . -mindepth 1 -printf '%y:%P\n' | LC_ALL=C sort)

  if [[ "${require_complete}" == 'yes' ]]; then
    [[ -f "${path}/manifest.tsv" && -f "${path}/SHA256SUMS" ]] ||
      fail "published stage lacks manifest or checksum inventory: ${path}"
    while read -r digest relative_path extra; do
      [[ "${digest}" =~ ^[0-9a-f]{64}$ && -n "${relative_path}" && -z "${extra:-}" ]] ||
        fail "stage has a malformed checksum entry: ${path}"
      case "${relative_path}" in
        manifest.tsv|product/engine|product/canaryctl|product/operator|product/envoy-adapter|product/dashboard-backend|test/cookiespike|test/enforcespike|test/dgxstackspike|test/correlationspike|test/tracespike|test/attackerexecutorspike|test/attackerloopspike)
          ;;
        *) fail "stage checksum inventory contains an undeclared path: ${relative_path}" ;;
      esac
    done <"${path}/SHA256SUMS"
    (cd "${path}" && sha256sum -c SHA256SUMS >/dev/null) ||
      fail "published stage checksum validation failed: ${path}"

    local stage_prefix resolved proc_exe
    stage_prefix="$(readlink -f "${path}")/"
    for proc_exe in /proc/[0-9]*/exe; do
      resolved="$(readlink -f "${proc_exe}" 2>/dev/null || true)"
      [[ "${resolved}" != "${stage_prefix}"* ]] ||
        fail "a process is still executing from the published stage: ${resolved}"
    done
  fi
}

validate_evidence() {
  local path="$1"
  validate_common "${path}"
  local entry
  while IFS= read -r entry; do
    case "${entry}" in
      f:stdout.log|f:stderr.log|f:observations.ndjson|f:result.tsv|f:.result.tsv.tmp) ;;
      *) fail "evidence candidate contains an undeclared entry: ${path}/${entry#*:}" ;;
    esac
  done < <(cd "${path}" && find . -mindepth 1 -printf '%y:%P\n' | LC_ALL=C sort)

  if [[ -f "${path}/result.tsv" ]]; then
    awk -F '\t' -v expected="${run_id}" '
      NR == 1 { if ($0 != "key\tvalue") exit 1; next }
      NF != 2 || $1 == "" { exit 1 }
      $1 == "run_id" { count++; if ($2 != expected) exit 1 }
      END { if (count != 1) exit 1 }
    ' "${path}/result.tsv" || fail "evidence result does not belong to run ${run_id}"
  elif [[ ! -e "${stage}" && ! -L "${stage}" ]]; then
    fail 'partial execution evidence without its matching stage requires manual inspection'
  fi
}

incoming_state='absent'
stage_state='absent'
evidence_state='absent'
if [[ -e "${incoming}" || -L "${incoming}" ]]; then
  validate_artifact_tree "${incoming}" no
  incoming_state='validated'
fi
if [[ -e "${stage}" || -L "${stage}" ]]; then
  validate_artifact_tree "${stage}" yes
  stage_state='validated'
fi
if [[ -e "${evidence}" || -L "${evidence}" ]]; then
  validate_evidence "${evidence}"
  evidence_state='validated'
fi

printf 'mode=%s\nrun_id=%s\nincoming=%s\nstage=%s\nevidence=%s\n' \
  "${mode}" "${run_id}" "${incoming_state}" "${stage_state}" "${evidence_state}"

if [[ "${mode}" == 'inspect' ]]; then
  printf 'mutation=none\n'
  exit 0
fi

removed=0
for path in "${evidence}" "${stage}" "${incoming}"; do
  if [[ -e "${path}" || -L "${path}" ]]; then
    rm -rf --one-file-system -- "${path}"
    [[ ! -e "${path}" && ! -L "${path}" ]] || fail "candidate remains after cleanup: ${path}"
    printf 'removed=%s\n' "${path}"
    removed=$((removed + 1))
  fi
done
if [[ -d "${root}" && ! -L "${root}" ]] && [[ -z "$(find "${root}" -mindepth 1 -print -quit)" ]]; then
  rmdir "${root}"
fi
printf 'removed_count=%d\npostcondition=all-candidates-absent\n' "${removed}"
REMOTE

if [[ "${mode}" == 'cleanup' ]]; then
  [[ -x "${check_script}" ]] || fail "post-cleanup checker is missing or not executable: ${check_script}"
  printf 'post_cleanup_check=begin\n'
  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
  printf 'post_cleanup_check=PASS\n'
fi
