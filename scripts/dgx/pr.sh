#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir

fail() {
  printf 'dgx-pr: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/pr.sh --profile PROFILE --run-id ID [--dry-run]

Profiles: preflight, cookie, enforcement, kernel-full, stack, correlation, trace.

The coordinator performs one read-only DGX preflight, one compatible local
artifact build, and one transfer. Mutable state remains isolated by run ID.
Every selected scenario still performs stage verification, after-state checks,
and exact cleanup. Unsupported Kubernetes or live-Qwen profiles fail closed.
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
case "${profile}" in
  preflight) targets=(); scenarios=() ;;
  cookie) targets=(cookiespike); scenarios=(cookiespike) ;;
  enforcement) targets=(enforcespike); scenarios=(enforcespike) ;;
  kernel-full) targets=(cookiespike enforcespike); scenarios=(cookiespike enforcespike) ;;
  stack) targets=(dgxstackspike); scenarios=(dgxstackspike) ;;
  correlation) targets=(correlationspike); scenarios=(correlationspike) ;;
  trace) targets=(tracespike); scenarios=(tracespike) ;;
  dgx-kubernetes|dgx-attacker-smoke|campaign)
    fail "profile ${profile} is not implemented by the bounded DGX harness; refusing to substitute weaker coverage"
    ;;
  *) fail 'profile must be preflight, cookie, enforcement, kernel-full, stack, correlation, or trace' ;;
esac

printf 'profile=%s\nrun_id=%s\npreflight_count=1\nartifact_build_count=%s\nartifact_transfer_count=%s\n' \
  "${profile}" "${run_id}" "$(( ${#targets[@]} > 0 ? 1 : 0 ))" "$(( ${#targets[@]} > 0 ? 1 : 0 ))"
if ((dry_run)); then
  for scenario in "${scenarios[@]}"; do
    "${script_dir}/${scenario}.sh" --run-id "${run_id}" --dry-run
  done
  printf 'DRY RUN: DGX was not accessed\n'
  exit 0
fi

work_root="$(mktemp -d "/tmp/canarysting-dgx-pr.XXXXXX")"
[[ "${work_root}" == /tmp/canarysting-dgx-pr.* ]] || fail 'unsafe temporary work root'
artifact_dir="${work_root}/artifacts"
proof_file="${work_root}/preflight.proof"
cleanup_required=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ((cleanup_required)); then
    for ((index=${#scenarios[@]}-1; index>=0; index--)); do
      CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
        "${script_dir}/${scenarios[index]}.sh" --run-id "${run_id}" --cleanup || status=1
    done
    CANARYSTING_DGX_PREFLIGHT_PROOF="${proof_file}" \
      "${script_dir}/cleanup.sh" --run-id "${run_id}" || status=1
  fi
  if [[ -d "${work_root}" && ! -L "${work_root}" && "${work_root}" == /tmp/canarysting-dgx-pr.* ]]; then
    rm -rf -- "${work_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

"${script_dir}/preflight-proof.sh" --create --run-id "${run_id}" --proof-file "${proof_file}"
if ((${#targets[@]} == 0)); then
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
