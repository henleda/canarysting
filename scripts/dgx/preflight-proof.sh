#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly max_age_seconds=1800
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
readonly repo_root

fail() {
  printf 'preflight-proof: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/preflight-proof.sh --create --run-id ID --proof-file ABSOLUTE_PATH
  scripts/dgx/preflight-proof.sh --verify --run-id ID --proof-file ABSOLUTE_PATH

Create or verify a short-lived, run-bound proof that the workflow already ran
the fixed read-only DGX preflight. Scenario scripts accept this proof only to
avoid repeating that same inspection; their own before/after safety assertions,
stage verification, cleanup, and emergency cleanup remain mandatory.
USAGE
}

mode=''
run_id=''
proof_file=''
while (($#)); do
  case "$1" in
    --create|--verify)
      [[ -z "${mode}" ]] || fail 'choose exactly one mode'
      mode="${1#--}"
      shift
      ;;
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      run_id="$2"
      shift 2
      ;;
    --proof-file)
      (($# >= 2)) || fail '--proof-file requires a value'
      proof_file="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ "${mode}" == 'create' || "${mode}" == 'verify' ]] || fail 'a mode is required'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'
[[ "${proof_file}" == /* && "${proof_file}" != *$'\n'* && "${proof_file}" != *$'\t'* ]] ||
  fail 'proof file must be an absolute path without control separators'
proof_parent="$(dirname "${proof_file}")"
proof_name="$(basename "${proof_file}")"
[[ -d "${proof_parent}" && ! -L "${proof_parent}" && -O "${proof_parent}" ]] ||
  fail 'proof parent must be an owned, non-symlink directory'
proof_parent="$(cd "${proof_parent}" && pwd -P)"
proof_file="${proof_parent}/${proof_name}"
readonly proof_parent proof_file
source_revision="$(git -C "${repo_root}" rev-parse --verify HEAD)"
readonly source_revision

file_mode() {
  if [[ "$(uname -s)" == 'Darwin' ]]; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

if [[ "${mode}" == 'create' ]]; then
  [[ ! -e "${proof_file}" && ! -L "${proof_file}" ]] || fail 'proof file already exists'
  CANARYSTING_DGX_HOST="${dgx_host}" "${script_dir}/check.sh"
  temporary="$(mktemp "${proof_parent}/.canarysting-preflight.XXXXXX")"
  trap 'rm -f -- "${temporary}"' EXIT INT TERM
  chmod 0600 "${temporary}"
  printf 'proof_version\t1\nrun_id\t%s\nhost\t%s\nsource_revision\t%s\ncreated_epoch\t%s\n' \
    "${run_id}" "${dgx_host}" "${source_revision}" "$(date +%s)" >"${temporary}"
  mv "${temporary}" "${proof_file}"
  trap - EXIT INT TERM
  printf 'PASS: one DGX workflow preflight recorded for %s\n' "${run_id}"
  exit 0
fi

[[ -f "${proof_file}" && ! -L "${proof_file}" && -O "${proof_file}" ]] ||
  fail 'proof must be an owned, non-symlink regular file'
[[ "$(file_mode "${proof_file}")" == '600' ]] || fail 'proof mode must be 0600'
awk -F '\t' '
  NR == 1 { good = ($1 == "proof_version" && $2 == "1" && NF == 2) }
  NR == 2 { good = good && ($1 == "run_id" && NF == 2) }
  NR == 3 { good = good && ($1 == "host" && NF == 2) }
  NR == 4 { good = good && ($1 == "source_revision" && NF == 2) }
  NR == 5 { good = good && ($1 == "created_epoch" && NF == 2) }
  END { exit !(NR == 5 && good) }
' "${proof_file}" || fail 'proof has an unexpected or malformed schema'
proof_run_id="$(awk -F '\t' 'NR == 2 { print $2 }' "${proof_file}")"
proof_host="$(awk -F '\t' 'NR == 3 { print $2 }' "${proof_file}")"
proof_revision="$(awk -F '\t' 'NR == 4 { print $2 }' "${proof_file}")"
created_epoch="$(awk -F '\t' 'NR == 5 { print $2 }' "${proof_file}")"
[[ "${proof_run_id}" == "${run_id}" && "${proof_host}" == "${dgx_host}" &&
  "${proof_revision}" == "${source_revision}" ]] ||
  fail 'proof is incompatible with this run, host, or revision'
[[ "${created_epoch}" =~ ^[0-9]+$ ]] || fail 'proof timestamp is malformed'
age=$(( $(date +%s) - created_epoch ))
((age >= 0 && age <= max_age_seconds)) || fail 'proof is expired or from the future'
printf 'PASS: reused compatible DGX workflow preflight for %s\n' "${run_id}"
