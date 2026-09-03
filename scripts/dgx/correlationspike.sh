#!/usr/bin/env bash
set -euo pipefail

readonly dgx_host='falcon1'
readonly expected_hostname='spark-5343'
readonly expected_architecture='aarch64'
readonly remote_root='/var/tmp/canarysting'
readonly -a ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=12
  -o StrictHostKeyChecking=yes
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
copy_script="${script_dir}/copy.sh"
check_script="${script_dir}/check.sh"
cleanup_script="${script_dir}/cleanup.sh"
preflight_script="${script_dir}/preflight-proof.sh"
readonly copy_script check_script cleanup_script preflight_script

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/correlationspike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2B.3 unprivileged DGX known-flow correlation proof. The artifact
creates two transient loopback TCP connections, reads one SO_COOKIE, minimizes
all identifiers before correlation, and emits only eight fixed proof statements.
It changes no Kubernetes, Cilium, BPF, service, firewall, or system state.
USAGE
}

fail() {
  printf 'correlationspike: %s\n' "$*" >&2
  exit 1
}

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
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${run_id}" ]] || fail '--run-id is required'
validate_run_id "${run_id}"
readonly run_id mode

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: correlation proof contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/correlationspike\n' "${dgx_host}" "${run_id}"
  printf 'mutation=run-owned-stage,evidence,transient-loopback-sockets\n'
  printf 'privilege=unprivileged\nraw_identifiers_emitted=false\ncleanup=exact-run\n'
  exit 0
fi

if [[ "${mode}" == 'cleanup' ]]; then
  exec "${cleanup_script}" --run-id "${run_id}"
fi

for required in ssh "${copy_script}" "${check_script}"; do
  if [[ "${required}" == */* ]]; then
    [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
  else
    command -v "${required}" >/dev/null 2>&1 || fail "required tool is missing: ${required}"
  fi
done

if [[ -n "${CANARYSTING_DGX_PREFLIGHT_PROOF:-}" ]]; then
  "${preflight_script}" --verify --run-id "${run_id}" --proof-file "${CANARYSTING_DGX_PREFLIGHT_PROOF}"
else
  CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
fi
"${copy_script}" --verify-only --run-id "${run_id}"

ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" "${mode}" <<'REMOTE'
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' ]] || fail 'invalid remote mode'
[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || fail 'unexpected proof host'
for tool in awk chmod date env find grep hostname mkdir mv readlink sha256sum sort stat timeout tr uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
artifact_relative='test/correlationspike'
artifact="${stage}/${artifact_relative}"
readonly root stage evidence artifact_relative artifact

[[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'run stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'manifest is unsafe'
artifact_metadata="$(awk -F '\t' -v wanted="${artifact_relative}" '
  $1 == "artifact" && $4 == wanted { count++; size=$5; digest=$6 }
  END { if (count != 1) exit 1; print size "\t" digest }
' "${stage}/manifest.tsv")" || fail 'manifest must contain exactly one correlation proof artifact'
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ && "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] || fail 'proof artifact is unsafe'
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'proof artifact size changed'
[[ "$(sha256sum "${artifact}" | awk '{print $1}')" == "${expected_sha256}" ]] || fail 'proof artifact checksum changed'

validate_published_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'published evidence is unsafe'
  [[ "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence mode must be 0700'
  actual_entries="$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | sort)"
  expected_entries=$'f:result.tsv\nf:stderr.log\nf:stdout.log'
  [[ "${actual_entries}" == "${expected_entries}" ]] || fail 'published evidence inventory is not exact'
  for file in result.tsv stderr.log stdout.log; do
    [[ -f "${evidence}/${file}" && ! -L "${evidence}/${file}" && -O "${evidence}/${file}" ]] || fail "unsafe evidence file: ${file}"
    [[ "$(stat -c %a "${evidence}/${file}")" == '600' ]] || fail "evidence file mode must be 0600: ${file}"
    [[ "$(stat -c %s "${evidence}/${file}")" -le 1048576 ]] || fail "evidence file exceeds 1 MiB: ${file}"
  done
  awk -F '\t' -v run="${run_id}" '
    NR == 1 { good=($0 == "key\tvalue"); next }
    NF != 2 || seen[$1]++ { exit 1 }
    $1 == "run_id" { good=good && ($2 == run) }
    $1 == "profile" { good=good && ($2 == "correlation-known-flow") }
    $1 == "proof_line_count" { good=good && ($2 == "8") }
    $1 == "raw_identifiers_emitted" { good=good && ($2 == "false") }
    $1 == "privilege" { good=good && ($2 == "unprivileged") }
    $1 == "status" { good=good && ($2 == "PASS") }
    END { exit !good }
  ' "${evidence}/result.tsv" || fail 'result schema or proof fields are invalid'
  awk '
    NR == 1 { good=($0 == "PROOF live_loopback=PASS flows=2 raw_addresses_emitted=false") }
    NR == 2 { good=good && ($0 == "PROOF socket_cookie=EXACT sole_sting_l7_kernel_join=true") }
    NR == 3 { good=good && ($0 == "PROOF translated_tuple=STRONG hops=1 tuples_retained=true control_retained=true") }
    NR == 4 { good=good && ($0 == "PROOF tuple_time=WEAK window_version=1") }
    NR == 5 { good=good && ($0 == "PROOF otel_trace=STRONG trace_boundary=false") }
    NR == 6 { good=good && ($0 == "PROOF missing_time=PASS rejected_contextual_join=true") }
    NR == 7 { good=good && ($0 == "PROOF ambiguity=PASS candidates=2 chosen=false") }
    NR == 8 { good=good && ($0 == "PROOF bounds=PASS candidate_limit=256 translation_hops=4 translation_paths=16") }
    NR > 8 { exit 1 }
    END { exit !(good && NR == 8) }
  ' "${evidence}/stdout.log" || fail 'fixed proof output is incomplete or contains extra data'
  stdout_sha256="$(awk -F '\t' '$1 == "stdout_sha256" {print $2}' "${evidence}/result.tsv")"
  stderr_sha256="$(awk -F '\t' '$1 == "stderr_sha256" {print $2}' "${evidence}/result.tsv")"
  [[ "${stdout_sha256}" =~ ^[0-9a-f]{64}$ && "${stderr_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'evidence checksums are malformed'
  [[ "$(sha256sum "${evidence}/stdout.log" | awk '{print $1}')" == "${stdout_sha256}" ]] || fail 'stdout checksum mismatch'
  [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "${stderr_sha256}" ]] || fail 'stderr checksum mismatch'
  [[ ! -s "${evidence}/stderr.log" ]] || fail 'proof emitted unexpected stderr'
  grep -F 'PROOF live_loopback=PASS' "${evidence}/stdout.log"
}

if [[ "${mode}" == 'inspect' ]]; then
  validate_published_evidence
  printf 'PASS: correlation known-flow evidence inspection passed\n'
  exit 0
fi

[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'published evidence already exists'
umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pseudonym_key="$(printf '%s\0%s\0m2b3-correlation' "${run_id}" "${expected_sha256}" | sha256sum | awk '{print $1}')"

set +e
(
  cd "${evidence}"
  ulimit -c 0
  ulimit -f 1024
  exec timeout --signal=TERM --kill-after=2s 20s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" \
      -run-id "${run_id}" \
      -scenario-id "m2b3-known-flow-${run_id}" \
      -pseudonym-key-sha256 "${pseudonym_key}" \
      -selfcheck
) >"${stdout_log}" 2>"${stderr_log}"
exit_code=$?
set -e

finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
expires_epoch="$(( $(date -u +%s) + 86400 ))"
expires_utc="$(date -u -d "@${expires_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
proof_line_count="$(wc -l <"${stdout_log}" | tr -d '[:space:]')"
status='FAIL'
[[ "${exit_code}" -eq 0 && "${proof_line_count}" == '8' ]] && status='PASS'
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'profile\tcorrelation-known-flow\n'
  printf 'artifact_sha256\t%s\n' "${expected_sha256}"
  printf 'proof_line_count\t%s\n' "${proof_line_count}"
  printf 'raw_identifiers_emitted\tfalse\n'
  printf 'privilege\tunprivileged\n'
  printf 'started_utc\t%s\n' "${started_utc}"
  printf 'finished_utc\t%s\n' "${finished_utc}"
  printf 'expires_utc\t%s\n' "${expires_utc}"
  printf 'stdout_sha256\t%s\n' "${stdout_sha256}"
  printf 'stderr_sha256\t%s\n' "${stderr_sha256}"
  printf 'exit_code\t%s\n' "${exit_code}"
  printf 'status\t%s\n' "${status}"
} >"${evidence}/.result.tsv.tmp"
mv "${evidence}/.result.tsv.tmp" "${evidence}/result.tsv"
chmod 0600 "${evidence}/stdout.log" "${evidence}/stderr.log" "${evidence}/result.tsv"
[[ "${status}" == 'PASS' ]] || fail "proof artifact failed with exit ${exit_code}"

validate_published_evidence
printf 'PASS: DGX correlation known-flow proof completed\n'
printf 'evidence=%s\n' "${evidence}"
REMOTE

printf 'post_correlation_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_correlation_check=PASS\n'
