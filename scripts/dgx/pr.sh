#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fail() {
  printf 'dgx-pr: %s\n' "$*" >&2
  exit 1
}

# The NVIDIA Sync ProxyCommand used by the pinned DGX alias is intentionally
# paid once per coordinator run. Every child harness inherits these functions,
# so SSH and SCP share one host-key-verified connection instead of repeatedly
# exposing the run to independent proxy handshakes.
ssh() {
  "${CANARYSTING_DGX_REAL_SSH}" \
    -o ControlMaster=auto \
    -o ControlPersist=1200 \
    -o "ControlPath=${CANARYSTING_DGX_SSH_CONTROL_PATH}" \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=3 \
    "$@"
}

scp() {
  "${CANARYSTING_DGX_REAL_SCP}" \
    -o ControlMaster=auto \
    -o ControlPersist=1200 \
    -o "ControlPath=${CANARYSTING_DGX_SSH_CONTROL_PATH}" \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=3 \
    "$@"
}

close_ssh_control() {
  "${CANARYSTING_DGX_REAL_SSH}" \
    -o "ControlPath=${CANARYSTING_DGX_SSH_CONTROL_PATH}" \
    -O exit falcon1 >/dev/null 2>&1 || true
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/pr.sh --profile PROFILE --run-id ID [--dry-run]

Profiles: preflight, attacker-check, attacker-executor, attacker-loop, cookie, enforcement,
kernel-full, stack, correlation, trace.

The coordinator performs one DGX preflight before artifact-backed scenarios.
The attacker-check profile instead runs only its fixed passive inspection and
prints a minimized CI-safe summary; it performs no general BPF capability
probe, artifact build, or transfer. Mutable scenario state remains isolated by
run ID and receives exact cleanup. Unsupported Kubernetes or live-Qwen profiles
fail closed.
USAGE
}

profile=''
run_id=''
dry_run=0
while (($#)); do
  case "$1" in
    --profile)
      (($# >= 2)) || fail '--profile requires a value'
      profile="$2"
      shift 2
      ;;
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      run_id="$2"
      shift 2
      ;;
    --dry-run)
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

[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'
read_only_check=''
preflight_count=1
target_count=0
scenario_count=0
case "${profile}" in
  preflight) targets=(); scenarios=() ;;
  attacker-check) targets=(); scenarios=(); read_only_check='attackercheck'; preflight_count=0 ;;
  attacker-executor) targets=(attackerexecutorspike); scenarios=(attackerexecutorspike); target_count=1; scenario_count=1 ;;
  attacker-loop) targets=(attackerloopspike); scenarios=(attackerloopspike); target_count=1; scenario_count=1 ;;
  cookie) targets=(cookiespike); scenarios=(cookiespike); target_count=1; scenario_count=1 ;;
  enforcement) targets=(enforcespike); scenarios=(enforcespike); target_count=1; scenario_count=1 ;;
  kernel-full) targets=(cookiespike enforcespike); scenarios=(cookiespike enforcespike); target_count=2; scenario_count=2 ;;
  stack) targets=(dgxstackspike); scenarios=(dgxstackspike); target_count=1; scenario_count=1 ;;
  correlation) targets=(correlationspike); scenarios=(correlationspike); target_count=1; scenario_count=1 ;;
  trace) targets=(tracespike); scenarios=(tracespike); target_count=1; scenario_count=1 ;;
  dgx-kubernetes|dgx-attacker-smoke|campaign)
    fail "profile ${profile} is not implemented by the bounded DGX harness; refusing to substitute weaker coverage"
    ;;
  *) fail 'profile must be preflight, attacker-check, attacker-executor, attacker-loop, cookie, enforcement, kernel-full, stack, correlation, or trace' ;;
esac

printf 'profile=%s\nrun_id=%s\npreflight_count=%s\nread_only_check_count=%s\nartifact_build_count=%s\nartifact_transfer_count=%s\n' \
  "${profile}" "${run_id}" "${preflight_count}" "$(( ${#read_only_check} > 0 ? 1 : 0 ))" "$(( target_count > 0 ? 1 : 0 ))" "$(( target_count > 0 ? 1 : 0 ))"
if ((dry_run)); then
  if [[ -n "${read_only_check}" ]]; then
    "${script_dir}/${read_only_check}.sh" --dry-run
  fi
  if ((scenario_count > 0)); then
    for scenario in "${scenarios[@]}"; do
      "${script_dir}/${scenario}.sh" --run-id "${run_id}" --dry-run
    done
  fi
  printf 'DRY RUN: DGX was not accessed\n'
  exit 0
fi

if [[ -n "${read_only_check}" ]]; then
  "${script_dir}/${read_only_check}.sh" --summary
  printf 'PASS: passive DGX inspection profile completed\n'
  exit 0
fi

work_root="$(mktemp -d "/tmp/canarysting-dgx-pr.XXXXXX")"
[[ "${work_root}" == /tmp/canarysting-dgx-pr.* ]] || fail 'unsafe temporary work root'
[[ -x /usr/bin/ssh && -x /usr/bin/scp ]] || fail 'fixed OpenSSH client paths are unavailable'
artifact_dir="${work_root}/artifacts"
proof_file="${work_root}/preflight.proof"
CANARYSTING_DGX_REAL_SSH='/usr/bin/ssh'
CANARYSTING_DGX_REAL_SCP='/usr/bin/scp'
CANARYSTING_DGX_SSH_CONTROL_PATH="${work_root}/ssh-%C"
readonly CANARYSTING_DGX_REAL_SSH CANARYSTING_DGX_REAL_SCP CANARYSTING_DGX_SSH_CONTROL_PATH
export CANARYSTING_DGX_REAL_SSH CANARYSTING_DGX_REAL_SCP CANARYSTING_DGX_SSH_CONTROL_PATH
export -f ssh scp
cleanup_required=0
should_run_generic_cleanup() {
  local selected_profile="$1" scenario_cleanup_failed="$2"
  [[ "${selected_profile}" != 'attacker-loop' || "${scenario_cleanup_failed}" -eq 0 ]]
}
cleanup() {
  local status=$? scenario_cleanup_failed=0
  trap - EXIT INT TERM
  if ((cleanup_required)); then
    for ((index=scenario_count-1; index>=0; index--)); do
      if ! CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
        "${script_dir}/${scenarios[index]}.sh" --run-id "${run_id}" --cleanup; then
        status=1
        scenario_cleanup_failed=1
      fi
    done
    if should_run_generic_cleanup "${profile}" "${scenario_cleanup_failed}"; then
      CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
        "${script_dir}/cleanup.sh" --run-id "${run_id}" || status=1
    else
      printf 'dgx-pr: preserving attacker-loop stage after scenario-specific cleanup failure\n' >&2
    fi
  fi
  close_ssh_control
  if [[ -d "${work_root}" && ! -L "${work_root}" && "${work_root}" == /tmp/canarysting-dgx-pr.* ]]; then
    rm -rf -- "${work_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

"${script_dir}/preflight-proof.sh" --create --run-id "${run_id}" --proof-file "${proof_file}"
if ((target_count == 0)); then
  printf 'PASS: preflight-only profile completed\n'
  exit 0
fi
build_args=(--output-dir "${artifact_dir}")
for target in "${targets[@]}"; do
  build_args+=(--target "${target}")
done
"${script_dir}/build.sh" "${build_args[@]}"
"${script_dir}/copy.sh" --artifact-dir "${artifact_dir}" --run-id "${run_id}"
cleanup_required=1

for scenario in "${scenarios[@]}"; do
  CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
    "${script_dir}/${scenario}.sh" --run-id "${run_id}"
  CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
    "${script_dir}/${scenario}.sh" --run-id "${run_id}" --inspect
done
printf 'PASS: selected DGX PR profile completed; cleanup follows\n'
