#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
# shellcheck source=scripts/dgx/ssh-control.sh
source "${script_dir}/ssh-control.sh"

fail() {
  printf 'dgx-pr-batch: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/pr-batch.sh --profiles "PROFILE ..." --run-prefix ID [--dry-run]

Runs a bounded, space-separated profile list with distinct run IDs while all
selected coordinators reuse one batch-scoped falcon1 SSH connection.
USAGE
}

profiles=''
run_prefix=''
dry_run=0
while (($#)); do
  case "$1" in
    --profiles)
      (($# >= 2)) || fail '--profiles requires a value'
      profiles="$2"
      shift 2
      ;;
    --run-prefix)
      (($# >= 2)) || fail '--run-prefix requires a value'
      run_prefix="$2"
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

[[ "${run_prefix}" =~ ^[a-z0-9]([a-z0-9-]{0,43}[a-z0-9])?$ ]] || fail 'invalid run prefix'
[[ "${profiles}" != *$'\n'* && "${profiles}" != *$'\r'* ]] || fail 'profile list must occupy one line'
selected_profiles=()
read -r -a selected_profiles <<<"${profiles}"
(( ${#selected_profiles[@]} > 0 && ${#selected_profiles[@]} <= 10 )) || fail 'profile count must be between one and ten'

seen_profiles=' '
for profile in "${selected_profiles[@]}"; do
  case "${profile}" in
    preflight|attacker-check|attacker-executor|attacker-loop|cookie|enforcement|kernel-full|stack|correlation|trace) ;;
    *) fail "unsupported profile in batch: ${profile}" ;;
  esac
  case "${seen_profiles}" in
    *" ${profile} "*) fail "duplicate profile in batch: ${profile}" ;;
  esac
  seen_profiles="${seen_profiles}${profile} "
done

printf 'batch_profile_count=%s\nrun_prefix=%s\n' "${#selected_profiles[@]}" "${run_prefix}"
if ((dry_run)); then
  for index in "${!selected_profiles[@]}"; do
    run_id="${run_prefix}-$((index + 1))"
    "${script_dir}/pr.sh" --profile "${selected_profiles[index]}" --run-id "${run_id}" --dry-run
  done
  printf 'DRY RUN: DGX batch transport was not created\n'
  exit 0
fi

transport_root=''
CANARYSTING_DGX_BATCH_CONTROL_PATH=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "${CANARYSTING_DGX_BATCH_CONTROL_PATH}" ]]; then
    /usr/bin/ssh -o "ControlPath=${CANARYSTING_DGX_BATCH_CONTROL_PATH}" -O exit falcon1 >/dev/null 2>&1 || true
  fi
  if [[ -n "${transport_root}" && -d "${transport_root}" && ! -L "${transport_root}" && "${transport_root}" =~ ^/tmp/canarysting-dgx-batch\.[A-Za-z0-9]+$ ]]; then
    rm -rf -- "${transport_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

[[ -x /usr/bin/ssh && -x /usr/bin/false ]] || fail 'fixed OpenSSH client paths are unavailable'
CANARYSTING_DGX_REAL_SSH='/usr/bin/ssh'
transport_root="$(mktemp -d "/tmp/canarysting-dgx-batch.XXXXXX")"
[[ "${transport_root}" =~ ^/tmp/canarysting-dgx-batch\.[A-Za-z0-9]+$ && -d "${transport_root}" && ! -L "${transport_root}" && -O "${transport_root}" ]] || \
  fail 'unsafe DGX batch transport root'
chmod 0700 "${transport_root}"
CANARYSTING_DGX_BATCH_CONTROL_PATH="${transport_root}/ssh-%C"
readonly transport_root CANARYSTING_DGX_BATCH_CONTROL_PATH CANARYSTING_DGX_REAL_SSH
export CANARYSTING_DGX_BATCH_CONTROL_PATH CANARYSTING_DGX_REAL_SSH

dgx_open_ssh_control "${CANARYSTING_DGX_BATCH_CONTROL_PATH}" || \
  fail 'unable to establish bounded DGX batch transport after three pre-mutation attempts'

for index in "${!selected_profiles[@]}"; do
  run_id="${run_prefix}-$((index + 1))"
  "${script_dir}/pr.sh" --profile "${selected_profiles[index]}" --run-id "${run_id}"
done
printf 'PASS: selected DGX PR profile batch completed\n'
