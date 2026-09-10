#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly -a ssh_options=(-o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
check_script="${script_dir}/check.sh"
cleanup_script="${script_dir}/cleanup.sh"
preflight_script="${script_dir}/preflight-proof.sh"
remote_script="${script_dir}/attackerscenariospike_remote.sh"
readonly copy_script check_script cleanup_script preflight_script remote_script

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/attackerscenariospike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2C.5 five-step scenario twice against a dedicated run-labeled
Kubernetes fixture. The fixture uses an already-present pinned image, a
checksum-verified read-only proof binary, one ClusterIP Service, no Secret or
service-account token, and passive/no-Sting preconditions. Raw fixture logs and
the dynamically allocated address are removed before bounded evidence is
published. Namespace cleanup is exact and idempotent.
USAGE
}

fail() { printf 'attackerscenariospike: %s\n' "$*" >&2; exit 1; }
validate_run_id() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,42}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-44 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
}

run_id=''
mode='run'
while (($#)); do
  case "$1" in
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may be specified only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run|--inspect|--cleanup)
      [[ "${mode}" == 'run' ]] || fail 'choose at most one mode'
      mode="${1#--}"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
validate_run_id "${run_id}"
readonly run_id mode

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: reproducible attacker scenario contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/attackerscenariospike\n' "${dgx_host}" "${run_id}"
  printf 'journey=enumeration,http-probe,disposable-credential,canary-discovery,canary-touch\n'
  printf 'mutation=run-labeled-namespace,pod,clusterip-service\n'
  printf 'image=pinned-already-present\nsecret_reads=false\nmodel_execution=false\nsting_posture=absent-or-passive\ncleanup=exact-idempotent\n'
  exit 0
fi

for required in ssh "${remote_script}" "${cleanup_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -r "${required}" ]] || fail "required file is missing: ${required}"
  else
    command -v "${required}" >/dev/null 2>&1 || fail "required tool is missing: ${required}"
  fi
done

if [[ "${mode}" == 'cleanup' ]]; then
  ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" cleanup <"${remote_script}"
  exec "${cleanup_script}" --run-id "${run_id}"
fi

for required in "${copy_script}" "${check_script}" "${preflight_script}"; do
  [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
done
if [[ -n "${CANARYSTING_DGX_PREFLIGHT_PROOF:-}" ]]; then
  "${preflight_script}" --verify --run-id "${run_id}" --proof-file "${CANARYSTING_DGX_PREFLIGHT_PROOF}"
else
  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
fi
"${copy_script}" --verify-only --run-id "${run_id}"

ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" <"${remote_script}"

printf 'post_attacker_scenario_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_attacker_scenario_check=PASS\n'
