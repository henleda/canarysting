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
  scripts/dgx/tracespike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2B.4/M2B.5 unprivileged DGX trace proof. The artifact uses only
minimized synthetic records to prove passive partial traces, ambiguity,
evidence citations, lifecycle, exact-scope invalidation, hard bounds, the
read-only operator projection, and separate M2D.1 ground-truth ingestion. It emits only ten fixed proof statements and
changes no Kubernetes, Cilium, BPF, service, firewall, socket, or system state.
USAGE
}

fail() {
  printf 'tracespike: %s\n' "$*" >&2
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
  printf 'DRY RUN: trace proof contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/tracespike\n' "${dgx_host}" "${run_id}"
  printf 'mutation=run-owned-stage,evidence\n'
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
artifact_relative='test/tracespike'
artifact="${stage}/${artifact_relative}"
readonly root stage evidence artifact_relative artifact

[[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'run stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'manifest is unsafe'
artifact_metadata="$(awk -F '\t' -v wanted="${artifact_relative}" '
  $1 == "artifact" && $4 == wanted { count++; size=$5; digest=$6 }
  END { if (count != 1) exit 1; print size "\t" digest }
' "${stage}/manifest.tsv")" || fail 'manifest must contain exactly one trace proof artifact'
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ && "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] || fail 'proof artifact is unsafe'
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'proof artifact size changed'
[[ "$(sha256sum "${artifact}" | awk '{print $1}')" == "${expected_sha256}" ]] || fail 'proof artifact checksum changed'

manifest_value() {
  awk -F '\t' -v wanted="$1" '
    $1 == "metadata" && $2 == wanted { count++; value=$3 }
    END { if (count != 1) exit 1; print value }
  ' "${stage}/manifest.tsv"
}
source_revision="$(manifest_value source_revision)" || fail 'manifest source revision is missing or duplicated'
source_state="$(manifest_value source_state)" || fail 'manifest source state is missing or duplicated'
source_tree_sha256="$(manifest_value source_tree_sha256)" || fail 'manifest source-tree checksum is missing or duplicated'
[[ "${source_revision}" =~ ^[0-9a-f]{40}$ ]] || fail 'manifest source revision is malformed'
[[ "${source_state}" == 'clean' || "${source_state}" == 'dirty' ]] || fail 'manifest source state is malformed'
[[ "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'manifest source-tree checksum is malformed'
scenario_id='m2b5-operator-conflict'
readonly source_revision source_state source_tree_sha256 scenario_id

validate_trace_result_schema() {
  local result_file="$1"
  local wanted_run="$2"
  local wanted_revision="$3"
  local wanted_state="$4"
  local wanted_tree="$5"
  local wanted_artifact="$6"
  awk -F '\t' \
    -v run="${wanted_run}" \
    -v revision="${wanted_revision}" \
    -v source_state="${wanted_state}" \
    -v source_tree="${wanted_tree}" \
    -v artifact="${wanted_artifact}" '
    BEGIN { good=1 }
    NR == 1 { good=good && ($0 == "key\tvalue"); next }
    {
      if (NF != 2 || seen[$1]++) { good=0; next }
      if (NR == 2) good=good && ($1 == "format_version" && $2 == "1")
      else if (NR == 3) good=good && ($1 == "run_id" && $2 == run)
      else if (NR == 4) good=good && ($1 == "scenario_id" && $2 == "m2b5-operator-conflict")
      else if (NR == 5) good=good && ($1 == "profile" && $2 == "trace-construction")
      else if (NR == 6) good=good && ($1 == "source_revision" && $2 == revision && length($2) == 40 && $2 !~ /[^0-9a-f]/)
      else if (NR == 7) good=good && ($1 == "source_state" && $2 == source_state && ($2 == "clean" || $2 == "dirty"))
      else if (NR == 8) good=good && ($1 == "source_tree_sha256" && $2 == source_tree && length($2) == 64 && $2 !~ /[^0-9a-f]/)
      else if (NR == 9) good=good && ($1 == "artifact_sha256" && $2 == artifact && length($2) == 64 && $2 !~ /[^0-9a-f]/)
      else if (NR == 10) good=good && ($1 == "proof_line_count" && $2 == "10")
      else if (NR == 11) good=good && ($1 == "raw_identifiers_emitted" && $2 == "false")
      else if (NR == 12) good=good && ($1 == "privilege" && $2 == "unprivileged")
      else if (NR == 13) good=good && ($1 == "started_utc" && $2 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/)
      else if (NR == 14) good=good && ($1 == "finished_utc" && $2 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/)
      else if (NR == 15) good=good && ($1 == "expires_utc" && $2 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/)
      else if (NR == 16) good=good && ($1 == "stdout_sha256" && length($2) == 64 && $2 !~ /[^0-9a-f]/)
      else if (NR == 17) good=good && ($1 == "stderr_sha256" && length($2) == 64 && $2 !~ /[^0-9a-f]/)
      else if (NR == 18) good=good && ($1 == "exit_code" && $2 == "0")
      else if (NR == 19) good=good && ($1 == "status" && $2 == "PASS")
      else good=0
    }
    END { exit !(good && NR == 19) }
  ' "${result_file}"
}

validate_fixed_trace_output() {
  awk '
    NR == 1 { good=($0 == "PROOF passive_partial=PASS canary_touch_required=false") }
    NR == 2 { good=good && ($0 == "PROOF deterministic_id=PASS input_order_independent=true") }
    NR == 3 { good=good && ($0 == "PROOF ambiguity=PASS candidates=2 chosen=false") }
    NR == 4 { good=good && ($0 == "PROOF join_citations=PASS all_links_evidence_backed=true") }
    NR == 5 { good=good && ($0 == "PROOF broken_raw=PASS availability=INTEGRITY_MISMATCH") }
    NR == 6 { good=good && ($0 == "PROOF lifecycle=PASS held_visible=true expired_hidden=true") }
    NR == 7 { good=good && ($0 == "PROOF invalidation=PASS exact_scope=true") }
    NR == 8 { good=good && ($0 == "PROOF bounds=PASS truncation=false") }
    NR == 9 { good=good && ($0 == "PROOF operator_projection=PASS scenario_id=m2b5-operator-conflict explanation_present=true raw_reference_metadata_present=true raw_availability=INTEGRITY_MISMATCH status=CONFLICTED missing=2 conflicts=3") }
    NR == 10 { good=good && ($0 == "PROOF ground_truth_ingest=PASS declared_only=true assisted=1 unassisted=1 unmatched_steps=1") }
    NR > 10 { good=0 }
    END { exit !(good && NR == 10) }
  ' "$1"
}

result_value() {
  local result_file="$1"
  local wanted="$2"
  awk -F '\t' -v wanted="${wanted}" '
    $1 == wanted { count++; value=$2 }
    END { if (count != 1) exit 1; print value }
  ' "${result_file}"
}

validate_trace_result_timestamps() {
  local result_file="$1"
  local started_utc finished_utc expires_utc
  local started_epoch finished_epoch expires_epoch now_epoch
  started_utc="$(result_value "${result_file}" started_utc)" || return 1
  finished_utc="$(result_value "${result_file}" finished_utc)" || return 1
  expires_utc="$(result_value "${result_file}" expires_utc)" || return 1
  started_epoch="$(date -u -d "${started_utc}" +%s)" || return 1
  finished_epoch="$(date -u -d "${finished_utc}" +%s)" || return 1
  expires_epoch="$(date -u -d "${expires_utc}" +%s)" || return 1
  now_epoch="$(date -u +%s)" || return 1
  ((started_epoch <= finished_epoch)) || return 1
  ((finished_epoch - started_epoch <= 30)) || return 1
  ((expires_epoch - finished_epoch == 86400)) || return 1
  ((now_epoch < expires_epoch)) || return 1
}

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
  validate_trace_result_schema \
    "${evidence}/result.tsv" "${run_id}" "${source_revision}" \
    "${source_state}" "${source_tree_sha256}" "${expected_sha256}" ||
    fail 'result schema, lineage, or proof fields are invalid'
  validate_trace_result_timestamps "${evidence}/result.tsv" ||
    fail 'result timestamps or 24-hour expiry are invalid'
  validate_fixed_trace_output "${evidence}/stdout.log" || fail 'fixed proof output is incomplete or contains extra data'
  stdout_sha256="$(result_value "${evidence}/result.tsv" stdout_sha256)" || fail 'stdout checksum is missing or duplicated'
  stderr_sha256="$(result_value "${evidence}/result.tsv" stderr_sha256)" || fail 'stderr checksum is missing or duplicated'
  [[ "${stdout_sha256}" =~ ^[0-9a-f]{64}$ && "${stderr_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'evidence checksums are malformed'
  [[ "$(sha256sum "${evidence}/stdout.log" | awk '{print $1}')" == "${stdout_sha256}" ]] || fail 'stdout checksum mismatch'
  [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "${stderr_sha256}" ]] || fail 'stderr checksum mismatch'
  [[ ! -s "${evidence}/stderr.log" ]] || fail 'proof emitted unexpected stderr'
  grep -Fqx 'PROOF passive_partial=PASS canary_touch_required=false' "${evidence}/stdout.log" ||
    fail 'passive partial-trace proof marker is missing'
  grep -Fqx 'PROOF ground_truth_ingest=PASS declared_only=true assisted=1 unassisted=1 unmatched_steps=1' "${evidence}/stdout.log" ||
    fail 'separate declared ground-truth proof marker is missing'
}

if [[ "${mode}" == 'inspect' ]]; then
  validate_published_evidence
  printf 'PASS: trace construction evidence inspection passed\n'
  exit 0
fi

[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'published evidence already exists'
umask 077
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
started_epoch="$(date -u +%s)"
started_utc="$(date -u -d "@${started_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
set +e
(
  cd "${evidence}"
  ulimit -c 0
  ulimit -f 1024
  exec timeout --signal=TERM --kill-after=2s 20s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" \
      -run-id "${run_id}" \
      -scenario-id "${scenario_id}" \
      -selfcheck
) >"${stdout_log}" 2>"${stderr_log}"
exit_code=$?
set -e

finished_epoch="$(date -u +%s)"
finished_utc="$(date -u -d "@${finished_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
expires_epoch="$((finished_epoch + 86400))"
expires_utc="$(date -u -d "@${expires_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
proof_line_count="$(wc -l <"${stdout_log}" | tr -d '[:space:]')"
status='FAIL'
if [[ "${exit_code}" -eq 0 && ! -s "${stderr_log}" ]] && validate_fixed_trace_output "${stdout_log}"; then
  status='PASS'
fi
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'scenario_id\t%s\n' "${scenario_id}"
  printf 'profile\ttrace-construction\n'
  printf 'source_revision\t%s\n' "${source_revision}"
  printf 'source_state\t%s\n' "${source_state}"
  printf 'source_tree_sha256\t%s\n' "${source_tree_sha256}"
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
printf 'PASS: DGX trace construction proof completed\n'
printf 'evidence=%s\n' "${evidence}"
REMOTE

printf 'post_trace_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_trace_check=PASS\n'
