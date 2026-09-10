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
ssh_control_script="${script_dir}/ssh-control.sh"
readonly copy_script check_script cleanup_script preflight_script remote_script ssh_control_script
# shellcheck source=scripts/dgx/ssh-control.sh
source "${ssh_control_script}"

transport_root=''
transport_owned=0

directory_mode() {
  local path="$1" observed_mode=''
  if observed_mode="$(/usr/bin/stat -f '%Lp' "${path}" 2>/dev/null)"; then
    :
  elif observed_mode="$(/usr/bin/stat -c '%a' "${path}" 2>/dev/null)"; then
    :
  else
    return 1
  fi
  [[ "${observed_mode}" =~ ^0?700$ ]] || return 1
  printf '700\n'
}

# Every remote operation after bootstrap is forced through one reviewed control
# connection. If that connection is lost, ProxyCommand=/usr/bin/false makes the
# operation fail closed instead of resolving a different route mid-profile.
ssh() {
  "${CANARYSTING_DGX_REAL_SSH}" \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o ConnectionAttempts=1 \
    -o StrictHostKeyChecking=yes \
    -o ControlMaster=no \
    -o "ControlPath=${CANARYSTING_DGX_SSH_CONTROL_PATH}" \
    -o ProxyCommand=/usr/bin/false \
    -o ClearAllForwardings=yes \
    -o ForwardAgent=no \
    -o ForwardX11=no \
    -o GSSAPIDelegateCredentials=no \
    -o Tunnel=no \
    -o PermitLocalCommand=no \
    -o RequestTTY=no \
    -o ForkAfterAuthentication=no \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=3 \
    "$@"
}

validate_inherited_transport() {
  local control_path="${CANARYSTING_DGX_SSH_CONTROL_PATH:-}" control_root observed_mode=''
  [[ "${CANARYSTING_DGX_REAL_SSH:-}" == '/usr/bin/ssh' ]] || {
    printf 'attackerscenariospike: inherited transport does not use the fixed OpenSSH client\n' >&2
    return 1
  }
  [[ "${control_path}" =~ ^/(private/)?tmp/canarysting-dgx-(pr|batch)\.[A-Za-z0-9]+/ssh-control$ ]] || {
    printf 'attackerscenariospike: inherited control path is outside a bounded PR/batch root\n' >&2
    return 1
  }
  control_root="${control_path%/ssh-control}"
  [[ -d "${control_root}" ]] || {
    printf 'attackerscenariospike: inherited control root is unavailable\n' >&2
    return 1
  }
  [[ ! -L "${control_root}" ]] || {
    printf 'attackerscenariospike: inherited control root is a symlink\n' >&2
    return 1
  }
  [[ -O "${control_root}" ]] || {
    printf 'attackerscenariospike: inherited control root is not owned by this user\n' >&2
    return 1
  }
  observed_mode="$(directory_mode "${control_root}")" || {
    printf 'attackerscenariospike: inherited control-root mode could not be inspected\n' >&2
    return 1
  }
  [[ "${observed_mode}" == '700' ]] || {
    printf 'attackerscenariospike: inherited control root is not mode 0700\n' >&2
    return 1
  }
  [[ -S "${control_path}" && ! -L "${control_path}" && -O "${control_path}" ]] || {
    printf 'attackerscenariospike: inherited control socket is unavailable or unsafe\n' >&2
    return 1
  }
  dgx_run_ssh_control_operation "${control_path}" check 5 || {
    printf 'attackerscenariospike: inherited control master did not pass its bounded liveness check\n' >&2
    return 1
  }
}

initialize_transport() {
  [[ -x /usr/bin/ssh && -x /usr/bin/false ]] || fail 'fixed OpenSSH client paths are unavailable'
  if [[ -n "${CANARYSTING_DGX_SSH_CONTROL_PATH:-}" ]]; then
    validate_inherited_transport || fail 'inherited DGX transport is unavailable or outside its private coordinator root'
    transport_owned=0
  else
    transport_root="$(mktemp -d '/tmp/canarysting-dgx-scenario.XXXXXX')"
    [[ "${transport_root}" == /tmp/canarysting-dgx-scenario.* && -d "${transport_root}" && ! -L "${transport_root}" && -O "${transport_root}" ]] ||
      fail 'standalone DGX transport root is unsafe'
    chmod 0700 "${transport_root}"
    CANARYSTING_DGX_REAL_SSH='/usr/bin/ssh'
    CANARYSTING_DGX_SSH_CONTROL_PATH="${transport_root}/ssh-control"
    CANARYSTING_DGX_SSH_MASTER_PID=''
    transport_owned=1
    dgx_open_ssh_control "${CANARYSTING_DGX_SSH_CONTROL_PATH}" ||
      fail 'unable to establish bounded standalone DGX transport after three pre-mutation attempts'
  fi
  readonly CANARYSTING_DGX_REAL_SSH CANARYSTING_DGX_SSH_CONTROL_PATH
  export CANARYSTING_DGX_REAL_SSH CANARYSTING_DGX_SSH_CONTROL_PATH
  export -f ssh
}

cleanup_transport() {
  local status=$? cleanup_failed=0
  trap - EXIT HUP INT TERM
  if ((transport_owned)); then
    if [[ -n "${CANARYSTING_DGX_SSH_MASTER_PID:-}" ]]; then
      dgx_close_ssh_control "${CANARYSTING_DGX_SSH_CONTROL_PATH}" || cleanup_failed=1
    elif [[ -n "${CANARYSTING_DGX_SSH_CONTROL_PATH:-}" ]]; then
      dgx_remove_ssh_control_socket "${CANARYSTING_DGX_SSH_CONTROL_PATH}" || cleanup_failed=1
    fi
    if ((cleanup_failed == 0)) && [[ -n "${transport_root}" && "${transport_root}" == /tmp/canarysting-dgx-scenario.* && -d "${transport_root}" && ! -L "${transport_root}" ]]; then
      rmdir "${transport_root}" || cleanup_failed=1
    fi
    if ((cleanup_failed)); then
      printf 'attackerscenariospike: retaining unverified standalone transport root %s\n' "${transport_root:-unknown}" >&2
      ((status != 0)) || status=1
    fi
  fi
  exit "${status}"
}

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
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] ||
    fail 'run ID must be 1-48 lowercase alphanumeric/hyphen characters and begin/end alphanumeric'
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

for required in "${remote_script}" "${cleanup_script}" "${ssh_control_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -r "${required}" ]] || fail "required file is missing: ${required}"
  fi
done

trap cleanup_transport EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
initialize_transport

remote_wall_seconds_for_mode() {
  case "$1" in
    run) printf '720\n' ;;
    inspect) printf '180\n' ;;
    cleanup) printf '360\n' ;;
    *) return 2 ;;
  esac
}

run_remote() {
  local requested_mode="$1" remote_wall_seconds
  remote_wall_seconds="$(remote_wall_seconds_for_mode "${requested_mode}")" || return 2
  ssh "${ssh_options[@]}" "${dgx_host}" \
    timeout --foreground --signal=TERM --kill-after=5s "${remote_wall_seconds}s" \
    bash -s -- "${run_id}" "${requested_mode}" <"${remote_script}"
}

if [[ "${mode}" == 'cleanup' ]]; then
  run_remote cleanup
  "${cleanup_script}" --run-id "${run_id}"
  exit 0
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

run_remote "${mode}"

printf 'post_attacker_scenario_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_attacker_scenario_check=PASS\n'
