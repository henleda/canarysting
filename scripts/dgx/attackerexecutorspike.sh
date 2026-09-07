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
readonly copy_script check_script cleanup_script preflight_script

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/attackerexecutorspike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2C.3 unprivileged bounded-executor proof against one transient
in-process loopback fixture. The proof emits eight fixed statements and owns
only its verified run stage, three bounded evidence files, and process-lifetime
loopback socket. It changes no Kubernetes, Cilium, BPF, service, firewall,
container, package, source, or system state and executes no model.
USAGE
}

fail() { printf 'attackerexecutorspike: %s\n' "$*" >&2; exit 1; }
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
  printf 'DRY RUN: bounded attacker executor proof contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/attackerexecutorspike\n' "${dgx_host}" "${run_id}"
  printf 'mutation=run-owned-stage,evidence,transient-loopback-socket\n'
  printf 'privilege=unprivileged\nmodel_execution=false\nraw_identifiers_emitted=false\ncleanup=exact-run\n'
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
for tool in awk chmod date env find hostname mkdir mv sha256sum sort stat timeout tr uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
artifact_relative='test/attackerexecutorspike'
artifact="${stage}/${artifact_relative}"
scenario_id='m2c3-bounded-executor'
readonly root stage evidence artifact_relative artifact scenario_id

[[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'run stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'manifest is unsafe'
artifact_metadata="$(awk -F '\t' -v wanted="${artifact_relative}" '
  $1 == "artifact" && $4 == wanted { count++; size=$5; digest=$6 }
  END { if (count != 1) exit 1; print size "\t" digest }
' "${stage}/manifest.tsv")" || fail 'manifest must contain exactly one bounded-executor proof artifact'
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
readonly source_revision source_state source_tree_sha256

result_value() {
  local result_file="$1"
  local wanted="$2"
  awk -F '\t' -v wanted="${wanted}" '$1 == wanted { count++; value=$2 } END { if (count != 1) exit 1; print value }' "${result_file}"
}

validate_fixed_output() {
  awk '
    NR == 1 { good=($0 == "PROOF catalog=PASS tools=7 arbitrary_tools=false") }
    NR == 2 { good=good && ($0 == "PROOF audit_order=PASS intent_before_resolve_and_dial=true failures_terminal=true") }
    NR == 3 { good=good && ($0 == "PROOF allowlist=PASS http_dns_tcp=loopback_only exact_target=true ambient_proxy=false") }
    NR == 4 { good=good && ($0 == "PROOF structured_tools=PASS enumeration=true follow_link=true fixture_credential=true inspect_response=true") }
    NR == 5 { good=good && ($0 == "PROOF redirect_rebinding=PASS redirects_followed=false dns_set_change_denied=true") }
    NR == 6 { good=good && ($0 == "PROOF bounds=PASS action_time_rate_concurrency_request_response_memory=true cancellation=audited") }
    NR == 7 { good=good && ($0 == "PROOF denied=PASS shell_kubernetes_docker_filesystem_control_plane=false audited=true") }
    NR == 8 { good=good && ($0 == "PROOF cleanup=PASS listener_closed=true persistent_state=false") }
    NR > 8 { good=0 }
    END { exit !(good && NR == 8) }
  ' "$1"
}

validate_result_schema() {
  awk -F '\t' -v run="${run_id}" -v revision="${source_revision}" -v state="${source_state}" -v tree="${source_tree_sha256}" -v artifact="${expected_sha256}" '
    BEGIN { good=1 }
    NR == 1 { good=good && ($0 == "key\tvalue"); next }
    { if (NF != 2 || seen[$1]++) { good=0; next } }
    NR == 2 { good=good && ($1 == "format_version" && $2 == "1"); next }
    NR == 3 { good=good && ($1 == "run_id" && $2 == run); next }
    NR == 4 { good=good && ($1 == "scenario_id" && $2 == "m2c3-bounded-executor"); next }
    NR == 5 { good=good && ($1 == "profile" && $2 == "attacker-bounded-executor"); next }
    NR == 6 { good=good && ($1 == "source_revision" && $2 == revision); next }
    NR == 7 { good=good && ($1 == "source_state" && $2 == state); next }
    NR == 8 { good=good && ($1 == "source_tree_sha256" && $2 == tree); next }
    NR == 9 { good=good && ($1 == "artifact_sha256" && $2 == artifact); next }
    NR == 10 { good=good && ($1 == "proof_line_count" && $2 == "8"); next }
    NR == 11 { good=good && ($1 == "raw_identifiers_emitted" && $2 == "false"); next }
    NR == 12 { good=good && ($1 == "model_execution" && $2 == "false"); next }
    NR == 13 { good=good && ($1 == "privilege" && $2 == "unprivileged"); next }
    NR == 14 { good=good && ($1 == "started_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 15 { good=good && ($1 == "finished_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 16 { good=good && ($1 == "expires_utc" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/); next }
    NR == 17 { good=good && ($1 == "stdout_sha256" && length($2) == 64 && $2 !~ /[^0-9a-f]/); next }
    NR == 18 { good=good && ($1 == "stderr_sha256" && length($2) == 64 && $2 !~ /[^0-9a-f]/); next }
    NR == 19 { good=good && ($1 == "exit_code" && $2 == "0"); next }
    NR == 20 { good=good && ($1 == "status" && $2 == "PASS"); next }
    { good=0 }
    END { exit !(good && NR == 20) }
  ' "$1"
}

validate_timestamps() {
  local started finished expires now
  started="$(date -u -d "$(result_value "$1" started_utc)" +%s)" || return 1
  finished="$(date -u -d "$(result_value "$1" finished_utc)" +%s)" || return 1
  expires="$(date -u -d "$(result_value "$1" expires_utc)" +%s)" || return 1
  now="$(date -u +%s)" || return 1
  ((started <= finished && finished - started <= 30 && expires - finished == 86400 && now < expires))
}

validate_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" && "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence is unsafe'
  [[ "$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | sort)" == $'f:result.tsv\nf:stderr.log\nf:stdout.log' ]] || fail 'published evidence inventory is not exact'
  for file in result.tsv stderr.log stdout.log; do
    [[ -f "${evidence}/${file}" && ! -L "${evidence}/${file}" && -O "${evidence}/${file}" ]] || fail "unsafe evidence file: ${file}"
    [[ "$(stat -c %a "${evidence}/${file}")" == '600' && "$(stat -c %s "${evidence}/${file}")" -le 1048576 ]] || fail "evidence file mode or size is unsafe: ${file}"
  done
  validate_result_schema "${evidence}/result.tsv" || fail 'result schema, lineage, or proof fields are invalid'
  validate_timestamps "${evidence}/result.tsv" || fail 'result timestamps or 24-hour expiry are invalid'
  validate_fixed_output "${evidence}/stdout.log" || fail 'fixed proof output is incomplete or contains extra data'
  [[ ! -s "${evidence}/stderr.log" ]] || fail 'proof emitted unexpected stderr'
  [[ "$(sha256sum "${evidence}/stdout.log" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" stdout_sha256)" ]] || fail 'stdout checksum mismatch'
  [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" stderr_sha256)" ]] || fail 'stderr checksum mismatch'
}

if [[ "${mode}" == 'inspect' ]]; then
  validate_evidence
  printf 'PASS: bounded attacker executor evidence inspection passed\n'
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
    "${artifact}" -run-id "${run_id}" -scenario-id "${scenario_id}" -selfcheck
) >"${stdout_log}" 2>"${stderr_log}"
exit_code=$?
set -e
finished_epoch="$(date -u +%s)"
finished_utc="$(date -u -d "@${finished_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
expires_utc="$(date -u -d "@$((finished_epoch + 86400))" +%Y-%m-%dT%H:%M:%SZ)"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"
proof_line_count="$(wc -l <"${stdout_log}" | tr -d '[:space:]')"
status='FAIL'
if [[ "${exit_code}" -eq 0 && ! -s "${stderr_log}" ]] && validate_fixed_output "${stdout_log}"; then status='PASS'; fi
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\nrun_id\t%s\nscenario_id\t%s\nprofile\tattacker-bounded-executor\n' "${run_id}" "${scenario_id}"
  printf 'source_revision\t%s\nsource_state\t%s\nsource_tree_sha256\t%s\nartifact_sha256\t%s\n' "${source_revision}" "${source_state}" "${source_tree_sha256}" "${expected_sha256}"
  printf 'proof_line_count\t%s\nraw_identifiers_emitted\tfalse\nmodel_execution\tfalse\nprivilege\tunprivileged\n' "${proof_line_count}"
  printf 'started_utc\t%s\nfinished_utc\t%s\nexpires_utc\t%s\nstdout_sha256\t%s\nstderr_sha256\t%s\nexit_code\t%s\nstatus\t%s\n' \
    "${started_utc}" "${finished_utc}" "${expires_utc}" "${stdout_sha256}" "${stderr_sha256}" "${exit_code}" "${status}"
} >"${evidence}/.result.tsv.tmp"
mv "${evidence}/.result.tsv.tmp" "${evidence}/result.tsv"
chmod 0600 "${evidence}/stdout.log" "${evidence}/stderr.log" "${evidence}/result.tsv"
[[ "${status}" == 'PASS' ]] || fail "proof artifact failed with exit ${exit_code}"
validate_evidence
printf 'PASS: DGX bounded attacker executor proof completed\n'
printf 'evidence=%s\n' "${evidence}"
REMOTE

printf 'post_attacker_executor_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_attacker_executor_check=PASS\n'
