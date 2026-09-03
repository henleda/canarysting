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
  scripts/dgx/dgxstackspike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run the fixed M2B.2 read-only DGX source-capture and normalization proof.
The profile reads bounded CanarySting, engine, kernel/eBPF, Envoy, Kubernetes,
Cilium, and Hubble inventory only. Raw captures are hashed and deleted before
evidence publication; only synthetic schema-v3 observations and proof metadata
remain until exact cleanup.
USAGE
}

fail() {
  printf 'dgxstackspike: %s\n' "$*" >&2
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
  printf 'DRY RUN: DGX-stack proof contract passed; DGX was not accessed\n'
  printf 'host=%s\nrun_id=%s\nartifact=test/dgxstackspike\n' "${dgx_host}" "${run_id}"
  printf 'sources=canarysting,canarysting-engine,kernel-ebpf,envoy,kubernetes,cilium,hubble\n'
  printf 'source_access=read-only\nraw_capture=ephemeral-hash-then-delete\nsynthetic=true\n'
  exit 0
fi

if [[ "${mode}" == 'cleanup' ]]; then
  command -v ssh >/dev/null 2>&1 || fail 'ssh is required'
  [[ -x "${cleanup_script}" ]] || fail "required executable is missing: ${cleanup_script}"
  ssh "${ssh_options[@]}" "${dgx_host}" bash -s -- "${run_id}" <<'REMOTE_CLEANUP'
set -euo pipefail
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
run_id="$1"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || fail 'unexpected cleanup host'
for tool in find id rm rmdir sort stat; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote cleanup prerequisite: ${tool}"
done
root='/var/tmp/canarysting'
working="${root}/.dgxstack-${run_id}"
if [[ -e "${working}" || -L "${working}" ]]; then
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'remote root is unsafe'
  [[ -d "${working}" && ! -L "${working}" && -O "${working}" ]] || fail 'partial workspace is unsafe'
  unsupported="$(find "${working}" -mindepth 1 ! -type f ! -type d -print -quit)"
  unowned="$(find "${working}" -mindepth 1 ! -user "$(id -un)" -print -quit)"
  [[ -z "${unsupported}" && -z "${unowned}" ]] || fail 'partial workspace contains unsafe entries'
  while IFS= read -r entry; do
    case "${entry}" in
      d:captures|f:capture.tsv|f:observations.ndjson|f:stderr.log|f:result.tsv|f:.result.tsv.tmp|f:captures/canarysting|f:captures/canarysting-engine|f:captures/kernel-ebpf|f:captures/envoy|f:captures/kubernetes|f:captures/cilium|f:captures/hubble) ;;
      *) fail "partial workspace contains an undeclared entry: ${entry}" ;;
    esac
  done < <(cd "${working}" && find . -mindepth 1 -printf '%y:%P\n' | sort)
  rm -f -- \
    "${working}/captures/canarysting" "${working}/captures/canarysting-engine" \
    "${working}/captures/kernel-ebpf" "${working}/captures/envoy" \
    "${working}/captures/kubernetes" "${working}/captures/cilium" "${working}/captures/hubble"
  [[ ! -d "${working}/captures" ]] || rmdir "${working}/captures"
  rm -f -- "${working}/capture.tsv" "${working}/observations.ndjson" "${working}/stderr.log" \
    "${working}/result.tsv" "${working}/.result.tsv.tmp"
  rmdir "${working}"
  printf 'partial_workspace_removed=%s\n' "${working}"
else
  printf 'partial_workspace=absent\n'
fi
REMOTE_CLEANUP
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

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' ]] || fail 'invalid remote mode'
[[ "$(hostname)" == 'spark-5343' ]] || fail "unexpected hostname: $(hostname)"
[[ "$(uname -m)" == 'aarch64' ]] || fail "unexpected architecture: $(uname -m)"
for tool in awk date env find grep id mkdir mv readlink rm rmdir sed sha256sum sort stat sudo timeout tr wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
working="${root}/.dgxstack-${run_id}"
artifact_relative='test/dgxstackspike'
artifact="${stage}/${artifact_relative}"
readonly root stage evidence working artifact_relative artifact

[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'artifact stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'stage manifest is unsafe'

artifact_metadata="$({
  awk -F '\t' -v path="${artifact_relative}" '
    $1 == "artifact" && $4 == path { count++; size=$5; digest=$6 }
    END { if (count != 1) exit 1; print size "\t" digest }
  ' "${stage}/manifest.tsv"
})" || fail 'manifest must contain exactly one DGX-stack proof artifact'
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ && "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] || fail 'proof artifact is unsafe'
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'proof artifact size changed'
artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
[[ "${artifact_sha256}" == "${expected_sha256}" ]] || fail 'proof artifact checksum changed'

validate_published_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'published evidence is unsafe'
  [[ "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence mode must be 0700'
  actual_entries="$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | sort)"
  expected_entries=$'f:observations.ndjson\nf:result.tsv\nf:stderr.log'
  [[ "${actual_entries}" == "${expected_entries}" ]] || fail 'published evidence inventory is not exact'
  for file in observations.ndjson result.tsv stderr.log; do
    [[ -f "${evidence}/${file}" && ! -L "${evidence}/${file}" && -O "${evidence}/${file}" ]] || fail "unsafe evidence file: ${file}"
    [[ "$(stat -c %a "${evidence}/${file}")" == '600' ]] || fail "evidence file mode must be 0600: ${file}"
    [[ "$(stat -c %s "${evidence}/${file}")" -le 1048576 ]] || fail "evidence file exceeds 1 MiB: ${file}"
  done
  awk -F '\t' -v run="${run_id}" '
    NR == 1 { good=($0 == "key\tvalue"); next }
    NF != 2 || seen[$1]++ { exit 1 }
    $1 == "run_id" { good=good && ($2 == run) }
    $1 == "status" { good=good && ($2 == "PASS") }
    $1 == "source_count" { good=good && ($2 == "7") }
    $1 == "observation_count" { good=good && ($2 == "7") }
    $1 == "synthetic" { good=good && ($2 == "true") }
    $1 == "raw_payload_retained" { good=good && ($2 == "false") }
    $1 == "raw_capture_removed" { good=good && ($2 == "PASS") }
    END { exit !good }
  ' "${evidence}/result.tsv" || fail 'result schema or proof fields are invalid'
  [[ "$(wc -l <"${evidence}/observations.ndjson" | tr -d '[:space:]')" == '7' ]] || fail 'expected exactly seven observations'
  for source in canarysting canarysting-engine kernel-ebpf envoy kubernetes cilium hubble; do
    source_count="$(grep -F -c "\"system\":\"${source}\"" "${evidence}/observations.ndjson" || true)"
    [[ "${source_count}" == '1' ]] || fail "source observation missing or duplicated: ${source}"
  done
  observation_sha256="$(awk -F '\t' '$1 == "observations_sha256" {print $2}' "${evidence}/result.tsv")"
  stderr_sha256="$(awk -F '\t' '$1 == "stderr_sha256" {print $2}' "${evidence}/result.tsv")"
  [[ "${observation_sha256}" =~ ^[0-9a-f]{64}$ && "${stderr_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'evidence checksums are malformed'
  [[ "$(sha256sum "${evidence}/observations.ndjson" | awk '{print $1}')" == "${observation_sha256}" ]] || fail 'observation checksum mismatch'
  [[ "$(sha256sum "${evidence}/stderr.log" | awk '{print $1}')" == "${stderr_sha256}" ]] || fail 'stderr checksum mismatch'
  grep -F 'PROOF sources=7 records=7' "${evidence}/stderr.log" >/dev/null || fail 'proof summary is missing'
  grep -F 'synthetic=true raw_payload_retained=false' "${evidence}/stderr.log" >/dev/null || fail 'privacy summary is missing'
  grep -F 'PROOF sources=7 records=7' "${evidence}/stderr.log"
  [[ ! -e "${evidence}/captures" && ! -e "${evidence}/capture.tsv" ]] || fail 'raw capture material remains published'
}

if [[ "${mode}" == 'inspect' ]]; then
  [[ ! -e "${working}" && ! -L "${working}" ]] || fail 'partial proof workspace requires cleanup before inspection'
  validate_published_evidence
  printf 'PASS: DGX-stack evidence inspection passed\n'
  exit 0
fi

[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'published evidence already exists'
[[ ! -e "${working}" && ! -L "${working}" ]] || fail 'partial proof workspace already exists'
umask 077
mkdir -m 0700 "${working}"
mkdir -m 0700 "${working}/captures"

cleanup_partial() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -d "${working}/captures" && ! -L "${working}/captures" && -O "${working}/captures" ]]; then
    find "${working}/captures" -mindepth 1 -maxdepth 1 -type f -user "$(id -un)" -exec rm -f -- {} + || status=1
    rmdir "${working}/captures" 2>/dev/null || status=1
  fi
  if [[ -d "${working}" && ! -L "${working}" && -O "${working}" ]]; then
    rm -f -- "${working}/capture.tsv" "${working}/observations.ndjson" "${working}/stderr.log" "${working}/result.tsv" "${working}/.result.tsv.tmp" || status=1
    rmdir "${working}" 2>/dev/null || status=1
  fi
  exit "${status}"
}
trap cleanup_partial EXIT INT TERM

captures="${working}/captures"
capture_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly captures capture_time

(
  ulimit -c 0
  ulimit -f 2048
  sudo -n k3s kubectl get all -A -l app.kubernetes.io/part-of=canarysting \
    -o custom-columns=KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid --no-headers 2>&1
) >"${captures}/canarysting"
[[ -s "${captures}/canarysting" ]] || printf 'canarysting_resources=none\n' >"${captures}/canarysting"

(
  ulimit -c 0
  ulimit -f 2048
  found=0
  for proc_dir in /proc/[0-9]*; do
    comm="$(sed -n '1p' "${proc_dir}/comm" 2>/dev/null || true)"
    case "${comm}" in
      engine|envoy-adapter|dashboard-backend)
        printf 'process=%s\n' "${comm}"
        found=1
        ;;
    esac
  done
  [[ "${found}" -eq 1 ]] || printf 'engine_processes=none\n'
) >"${captures}/canarysting-engine"

(
  ulimit -c 0
  ulimit -f 2048
  sudo -n timeout 30s bpftool -j prog show
) >"${captures}/kernel-ebpf" 2>&1

(
  ulimit -c 0
  ulimit -f 2048
  sudo -n k3s kubectl -n kube-system get pods -l k8s-app=cilium-envoy \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,IMAGE:.spec.containers[0].image' --no-headers
) >"${captures}/envoy" 2>&1

(
  ulimit -c 0
  ulimit -f 2048
  sudo -n k3s kubectl get nodes \
    -o 'custom-columns=NAME:.metadata.name,UID:.metadata.uid,READY:.status.conditions[-1].status,ARCH:.status.nodeInfo.architecture,KUBELET:.status.nodeInfo.kubeletVersion' --no-headers
) >"${captures}/kubernetes" 2>&1

(
  ulimit -c 0
  ulimit -f 2048
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E timeout 30s cilium status --wait=false
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E timeout 30s cilium version
) >"${captures}/cilium" 2>&1

(
  ulimit -c 0
  ulimit -f 2048
  set +e
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E timeout 30s cilium hubble status
  hubble_status=$?
  set -e
  printf 'hubble_status_exit=%s\n' "${hubble_status}"
) >"${captures}/hubble" 2>&1

capture_manifest="${working}/capture.tsv"
printf 'kind\tinstance\tevent_key\tsource_timestamp\tobserved_at\tingested_at\traw_reference_sha256\tcontent_sha256\n' >"${capture_manifest}"
for source in canarysting canarysting-engine kernel-ebpf envoy kubernetes cilium hubble; do
  capture_file="${captures}/${source}"
  [[ -f "${capture_file}" && ! -L "${capture_file}" && -O "${capture_file}" ]] || fail "unsafe source capture: ${source}"
  [[ -s "${capture_file}" ]] || printf 'source_report=empty\n' >"${capture_file}"
  capture_bytes="$(stat -c %s "${capture_file}")"
  [[ "${capture_bytes}" -gt 0 && "${capture_bytes}" -le 1048576 ]] || fail "source capture size is unsafe: ${source}"
  content_sha256="$(sha256sum "${capture_file}" | awk '{print $1}')"
  reference_sha256="$(printf '%s\0%s\0%s' "${run_id}" "${source}" "${content_sha256}" | sha256sum | awk '{print $1}')"
  printf '%s\tdgx-spark\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${source}" "${reference_sha256}" "${capture_time}" "${capture_time}" "${capture_time}" \
    "${reference_sha256}" "${content_sha256}" >>"${capture_manifest}"
done

pseudonym_key="$(printf '%s\0%s\0m2b2-pseudonym' "${run_id}" "${artifact_sha256}" | sha256sum | awk '{print $1}')"
set +e
(
  cd "${working}"
  ulimit -c 0
  ulimit -f 2048
  exec timeout --signal=TERM --kill-after=2s 20s \
    env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
    "${artifact}" \
      -capture-manifest "${capture_manifest}" \
      -run-id "${run_id}" \
      -scenario-id "m2b2-dgx-stack-${run_id}" \
      -pseudonym-key-sha256 "${pseudonym_key}"
) >"${working}/observations.ndjson" 2>"${working}/stderr.log"
exit_code=$?
set -e
[[ "${exit_code}" -eq 0 ]] || fail "proof artifact failed with exit ${exit_code}"
[[ "$(wc -l <"${working}/observations.ndjson" | tr -d '[:space:]')" == '7' ]] || fail 'proof did not emit seven observations'
[[ "$(stat -c %s "${working}/observations.ndjson")" -le 1048576 ]] || fail 'normalized observation evidence exceeded 1 MiB'
[[ "$(stat -c %s "${working}/stderr.log")" -le 1048576 ]] || fail 'proof stderr exceeded 1 MiB'

find "${captures}" -mindepth 1 -maxdepth 1 -type f -user "$(id -un)" -exec rm -f -- {} +
rmdir "${captures}"
rm -f -- "${capture_manifest}"
[[ ! -e "${captures}" && ! -e "${capture_manifest}" ]] || fail 'raw capture cleanup failed'

observations_sha256="$(sha256sum "${working}/observations.ndjson" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${working}/stderr.log" | awk '{print $1}')"
completed_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
expires_epoch="$(( $(date -u +%s) + 86400 ))"
expires_time="$(date -u -d "@${expires_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'profile\tdgx-stack-normalization\n'
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'source_count\t7\n'
  printf 'observation_count\t7\n'
  printf 'synthetic\ttrue\n'
  printf 'raw_payload_retained\tfalse\n'
  printf 'raw_capture_removed\tPASS\n'
  printf 'capture_started_utc\t%s\n' "${capture_time}"
  printf 'completed_utc\t%s\n' "${completed_time}"
  printf 'expires_utc\t%s\n' "${expires_time}"
  printf 'observations_sha256\t%s\n' "${observations_sha256}"
  printf 'stderr_sha256\t%s\n' "${stderr_sha256}"
  printf 'status\tPASS\n'
} >"${working}/.result.tsv.tmp"
mv "${working}/.result.tsv.tmp" "${working}/result.tsv"
chmod 0600 "${working}/observations.ndjson" "${working}/stderr.log" "${working}/result.tsv"
mv "${working}" "${evidence}"
trap - EXIT INT TERM

validate_published_evidence
printf 'PASS: DGX-stack source capture and normalization completed\n'
printf 'evidence=%s\n' "${evidence}"
REMOTE

printf 'post_capture_check=begin\n'
CANARYSTING_DGX_HOST="${dgx_host}" "${check_script}"
printf 'post_capture_check=PASS\n'
