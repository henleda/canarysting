#!/usr/bin/env bash
set -euo pipefail

readonly remote_alias='falcon1'
readonly remote_root='/var/tmp/canarysting'
readonly remote_evidence_root='/run/user/1000/canarysting'
readonly cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
readonly snapshot_root='/var/tmp/canarysting-privileged'
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly check_script="${script_dir}/check.sh"
readonly copy_script="${script_dir}/copy.sh"
readonly cleanup_script="${script_dir}/cleanup.sh"

usage() {
  cat <<'USAGE'
Usage:
  scripts/dgx/enforcespike.sh --run-id ID [--dry-run | --inspect | --cleanup]

Run one fixed precise-enforcement proof from the checksum-verified
/var/tmp/canarysting/ID/test/enforcespike artifact. The proof attaches sockops,
cgroup_skb/egress, and sock_release only to the exact run-owned child cgroup,
observes target and control traffic before enforcement, programs only the target
socket cookie, proves control/map-miss fail-open behavior, releases the target,
and proves restored connectivity. It never changes Cilium or Kubernetes state.

--inspect validates fixed evidence and runtime absence without mutation.
--cleanup removes only exact run-owned evidence, cgroup/snapshot residue, and the
verified artifact stage; it is idempotent. --dry-run never accesses the DGX.

No arbitrary command, path, cgroup, timeout, target, attach scope, or privilege is
accepted.
USAGE
}

fail() {
  printf 'enforcespike: %s\n' "$*" >&2
  exit 1
}

run_id=''
mode='run'
while (($#)); do
  case "$1" in
    --run-id)
      (($# >= 2)) || fail '--run-id requires a value'
      [[ -z "${run_id}" ]] || fail '--run-id may appear only once'
      run_id="$2"
      shift 2
      ;;
    --dry-run)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='dry-run'
      shift
      ;;
    --inspect)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='inspect'
      shift
      ;;
    --cleanup)
      [[ "${mode}" == 'run' ]] || fail 'modes are mutually exclusive and may appear only once'
      mode='cleanup'
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
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'

readonly stage="${remote_root}/${run_id}"
readonly evidence="${remote_evidence_root}/enforcespike-${run_id}"
readonly cgroup="${cgroup_parent}/${run_id}"
readonly snapshot="${snapshot_root}/enforcespike-${run_id}"

if [[ "${mode}" == 'dry-run' ]]; then
  printf 'DRY RUN: precise-enforcement proof contract passed; DGX was not accessed\n'
  printf 'run_id=%s\nstage=%s\nevidence=%s\ncgroup=%s\nsnapshot=%s\n' \
    "${run_id}" "${stage}" "${evidence}" "${cgroup}" "${snapshot}"
  printf 'attach_scope=run-owned-child-cgroup\nmutation=run-scoped-cgroup-bpf-snapshot-evidence-and-expiry-units\ncleanup=exact-run-idempotent\n'
  exit 0
fi

command -v ssh >/dev/null 2>&1 || fail 'required command is missing: ssh'
for required in "${check_script}" "${copy_script}" "${cleanup_script}"; do
  [[ -x "${required}" ]] || fail "required executable is missing: ${required}"
done

if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${check_script}"
  printf 'pre_mutation_check=PASS\n'
fi
if [[ "${mode}" == 'run' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${copy_script}" --verify-only --run-id "${run_id}"
fi

ssh -T "${remote_alias}" bash -s -- "${mode}" "${run_id}" <<'REMOTE'
set -euo pipefail

mode="$1"
run_id="$2"
stage_root='/var/tmp/canarysting'
root='/run/user/1000/canarysting'
stage="${stage_root}/${run_id}"
evidence="${root}/enforcespike-${run_id}"
evidence_quarantine="${root}/.cleanup-enforcespike-${run_id}"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot="${snapshot_root}/enforcespike-${run_id}"
artifact_relative='test/enforcespike'
artifact="${stage}/${artifact_relative}"
expiry_unit="canarysting-enforcespike-expire-${run_id}"
readonly mode run_id stage_root root stage evidence evidence_quarantine cgroup_parent cgroup snapshot_root snapshot artifact_relative artifact expiry_unit

fail() {
  printf 'enforcespike(remote): %s\n' "$*" >&2
  exit 1
}

[[ "$(hostname -s)" == 'spark-5343' ]] || fail 'unexpected remote host'
[[ "$(uname -m)" == 'aarch64' ]] || fail 'unexpected remote architecture'
[[ "$(id -u)" == '1000' && -d /run/user/1000 && ! -L /run/user/1000 && -O /run/user/1000 &&
  "$(stat -fc %T /run/user/1000)" == 'tmpfs' ]] || fail 'expected user-owned runtime tmpfs is unavailable'
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || fail 'cgroup v2 unified hierarchy is required'
sudo -n true >/dev/null || fail 'non-interactive sudo is required'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid mode'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid run ID'

named_bpf_state() {
  local programs maps links state
  programs="$(sudo -n bpftool prog show 2>/dev/null)" || return 1
  maps="$(sudo -n bpftool map show 2>/dev/null)" || return 1
  links="$(sudo -n bpftool link show 2>/dev/null)" || return 1
  state="$(printf '%s\n%s\n%s\n' "${programs}" "${maps}" "${links}" |
    grep -E 'canary_sockops|enforce_(egress|release)|flow_cookies|verdict_map' || true)"
  [[ -z "${state}" ]] && printf 'none' || printf 'present'
}

bpf_ids() {
  local kind inventory
  for kind in prog map link; do
    inventory="$(sudo -n bpftool "${kind}" show 2>/dev/null)" || return 1
    awk -v kind="${kind}" '/^[0-9]+:/ { id=$1; sub(/:$/, "", id); print kind ":" id }' <<<"${inventory}"
  done | LC_ALL=C sort
}

bounded_capture() {
  local destination="$1" state_file="$2"
  local capture_status=0 count_status=0 discarded=''
  dd bs=1048576 count=1 iflag=fullblock status=none >"${destination}" || capture_status=$?
  discarded="$(wc -c | awk '{ print $1 }')" || count_status=$?
  if [[ "${capture_status}" -ne 0 || "${count_status}" -ne 0 || ! "${discarded}" =~ ^[0-9]+$ ]]; then
    printf 'error\n' >"${state_file}"
    return 1
  fi
  if [[ "${discarded}" == '0' ]]; then
    printf 'complete\n' >"${state_file}"
  else
    printf 'truncated\n' >"${state_file}"
  fi
}

assert_platform_healthy() {
  local ready desired output
  sudo -n systemctl is-active --quiet k3s || return 1
  output="$(sudo -n k3s kubectl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" || return 1
  [[ "${output}" == 'True' ]] || return 1
  output="$(sudo -n k3s kubectl -n kube-system get daemonset cilium -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  output="$(sudo -n k3s kubectl -n kube-system get daemonset cilium-envoy -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  output="$(sudo -n k3s kubectl -n kube-system get deployment cilium-operator -o jsonpath='{.status.readyReplicas} {.status.replicas}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml sudo -n -E cilium status --wait=false >/dev/null || return 1
}

validate_stage() {
  [[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'verified artifact stage is missing or unsafe'
  [[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" ]] || fail 'stage manifest is missing or unsafe'
  [[ -f "${stage}/SHA256SUMS" && ! -L "${stage}/SHA256SUMS" ]] || fail 'stage checksum inventory is missing or unsafe'
  [[ -f "${artifact}" && ! -L "${artifact}" && -x "${artifact}" ]] || fail 'enforcespike artifact is missing or unsafe'
  local artifact_metadata actual_artifact_size actual_artifact_sha256
  artifact_metadata="$({
    awk -F '\t' -v p="${artifact_relative}" '
      $1 == "artifact" && $4 == p {
        count++
        size = $5
        digest = $6
      }
      END {
        if (count != 1) exit 1
        print size "\t" digest
      }
    ' "${stage}/manifest.tsv"
  })" || fail 'stage manifest does not name exactly one enforcespike artifact'
  IFS=$'\t' read -r artifact_size artifact_sha256 <<<"${artifact_metadata}"
  [[ "${artifact_size}" =~ ^[0-9]+$ ]] || fail 'artifact size metadata is malformed'
  [[ "${artifact_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact checksum metadata is malformed'
  (cd "${stage}" && sha256sum -c SHA256SUMS >/dev/null) || fail 'stage checksum verification failed'
  actual_artifact_size="$(stat -c %s "${artifact}")"
  actual_artifact_sha256="$(sha256sum "${artifact}" | awk '{print $1}')"
  [[ "${actual_artifact_size}" == "${artifact_size}" ]] || fail 'artifact size changed after stage verification'
  [[ "${actual_artifact_sha256}" == "${artifact_sha256}" ]] || fail 'artifact checksum changed after stage verification'
}

validate_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" ]] || fail 'evidence directory is missing or unsafe'
  [[ "$(stat -c %a "${evidence}")" == '700' ]] || fail 'evidence directory mode must be 0700'
  local files
  files="$(find "${evidence}" -mindepth 1 -maxdepth 1 -printf '%y:%f\n' | LC_ALL=C sort)"
  [[ "${files}" == $'f:result.tsv\nf:stderr.log\nf:stdout.log' ]] || fail 'evidence inventory is not exact'
  local f
  for f in result.tsv stderr.log stdout.log; do
    [[ ! -L "${evidence}/${f}" && "$(stat -c %a "${evidence}/${f}")" == '600' ]] || fail "unsafe evidence file: ${f}"
    [[ "$(stat -c %s "${evidence}/${f}")" -le 1048576 ]] || fail "oversized evidence file: ${f}"
  done
  awk -F '\t' -v run="${run_id}" -v artifact="${artifact_sha256}" '
    BEGIN {
      expected["format_version"]="1"; expected["run_id"]=run; expected["status"]="PASS"
      expected["artifact_sha256"]=artifact; expected["attach_scope"]="run-owned-child-cgroup"
      expected["runtime_cleanup"]="PASS"; expected["stdout_capture"]="complete"; expected["stderr_capture"]="complete"
      expected["retention"]="run-through-cleanup-with-24-hour-maximum"
      expected["expiration_cleanup"]="scheduled-systemd-transient-timer"
      expected["legal_hold"]="unsupported"; expected["deletion"]="exact-run-cleanup-or-scheduled-expiry"
      expected["residency"]="DGX-host-filesystem"; expected["encryption_boundary"]="operator-managed-host"
      expected["model_use"]="prohibited"; expected["derivation_lineage"]="artifact-checksum-plus-synthetic-proof"
      expected["estimated_storage_impact"]="less-than-3MiB"
    }
    NF != 2 || !($1 in expected) && $1 !~ /^(stdout_bytes|stderr_bytes|stdout_sha256|stderr_sha256|root_attachments_before_sha256|root_attachments_after_sha256|bpf_inventory_before_sha256|bpf_inventory_after_sha256|created_at_utc|completed_at_utc|expires_at_utc)$/ { exit 1 }
    { seen[$1]++; value[$1]=$2 }
    END {
      for (key in expected) if (seen[key] != 1 || value[key] != expected[key]) exit 1
      if (seen["stdout_bytes"] != 1 || value["stdout_bytes"] !~ /^[0-9]+$/ || value["stdout_bytes"] > 1048576) exit 1
      if (seen["stderr_bytes"] != 1 || value["stderr_bytes"] !~ /^[0-9]+$/ || value["stderr_bytes"] > 1048576) exit 1
      for (key in seen) {
        if (key ~ /sha256$/ && value[key] !~ /^[0-9a-f]{64}$/) exit 1
        if (seen[key] != 1) exit 1
      }
      if (seen["created_at_utc"] != 1 || value["created_at_utc"] !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/) exit 1
      if (seen["completed_at_utc"] != 1 || value["completed_at_utc"] !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/) exit 1
      if (seen["expires_at_utc"] != 1 || value["expires_at_utc"] !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/) exit 1
      if (value["root_attachments_before_sha256"] != value["root_attachments_after_sha256"]) exit 1
      if (value["bpf_inventory_before_sha256"] != value["bpf_inventory_after_sha256"]) exit 1
      if (length(seen) != 28) exit 1
    }
  ' "${evidence}/result.tsv" || fail 'evidence result schema is invalid or inconsistent'
  local created_at completed_at expires_at created_epoch completed_epoch expires_epoch now_epoch
  local expected_bytes expected_sha actual_bytes actual_sha observe_line target_cookie control_cookie
  created_at="$(awk -F '\t' '$1 == "created_at_utc" { print $2 }' "${evidence}/result.tsv")"
  completed_at="$(awk -F '\t' '$1 == "completed_at_utc" { print $2 }' "${evidence}/result.tsv")"
  expires_at="$(awk -F '\t' '$1 == "expires_at_utc" { print $2 }' "${evidence}/result.tsv")"
  created_epoch="$(date -u -d "${created_at}" +%s)" || fail 'evidence creation timestamp is invalid'
  completed_epoch="$(date -u -d "${completed_at}" +%s)" || fail 'evidence completion timestamp is invalid'
  expires_epoch="$(date -u -d "${expires_at}" +%s)" || fail 'evidence expiration is invalid'
  [[ "${completed_epoch}" -ge "${created_epoch}" && $((expires_epoch - completed_epoch)) -eq 86400 ]] || fail 'evidence timestamp ordering or lifetime is invalid'
  now_epoch="$(date -u +%s)"
  [[ "${expires_epoch}" -gt "${now_epoch}" ]] || fail 'evidence expired; exact cleanup is required'
  for f in stdout stderr; do
    expected_bytes="$(awk -F '\t' -v key="${f}_bytes" '$1 == key { print $2 }' "${evidence}/result.tsv")"
    expected_sha="$(awk -F '\t' -v key="${f}_sha256" '$1 == key { print $2 }' "${evidence}/result.tsv")"
    actual_bytes="$(stat -c %s "${evidence}/${f}.log")"
    actual_sha="$(sha256sum "${evidence}/${f}.log" | awk '{print $1}')"
    [[ "${actual_bytes}" == "${expected_bytes}" && "${actual_sha}" == "${expected_sha}" ]] || fail "${f} evidence does not match result metadata"
  done
  [[ "$(grep -Fxc 'PROOF missing_attribution=PASS cookie=0 action=refused' "${evidence}/stdout.log")" == '1' ]] || fail 'missing or duplicate unattributable-flow proof'
  [[ "$(grep -Ec '^PROOF shared_destination=PASS listener=127\.0\.0\.1:[1-9][0-9]* distinct_cookies=PASS$' "${evidence}/stdout.log")" == '1' ]] || fail 'shared-destination proof is malformed'
  observe_line="$(grep -E '^PROOF observe_before_enforce=PASS target_cookie=[1-9][0-9]* control_cookie=[1-9][0-9]*$' "${evidence}/stdout.log")" || fail 'observe-before-enforce proof is missing'
  [[ "$(grep -Ec '^PROOF observe_before_enforce=PASS target_cookie=[1-9][0-9]* control_cookie=[1-9][0-9]*$' "${evidence}/stdout.log")" == '1' ]] || fail 'observe-before-enforce proof is duplicated'
  target_cookie="$(sed -E 's/.*target_cookie=([0-9]+).*/\1/' <<<"${observe_line}")"
  control_cookie="$(sed -E 's/.*control_cookie=([0-9]+).*/\1/' <<<"${observe_line}")"
  [[ "${target_cookie}" != "${control_cookie}" ]] || fail 'target/control cookies are not distinct'
  [[ "$(grep -Fxc "PROOF canary_touch=PASS source=explicit-proof-fixture target_cookie=${target_cookie} baseline_trigger=none" "${evidence}/stdout.log")" == '1' ]] || fail 'canary-touch proof is inconsistent'
  [[ "$(grep -Fxc "PROOF target_programmed=PASS cookie=${target_cookie} action=jail control_map_entry=absent" "${evidence}/stdout.log")" == '1' ]] || fail 'programmed-target proof is inconsistent'
  [[ "$(grep -Ec "^PROOF target_only_enforcement=PASS target_cookie=${target_cookie} dropped_pkts=[1-9][0-9]* dropped_bytes=[1-9][0-9]*$" "${evidence}/stdout.log")" == '1' ]] || fail 'target-only enforcement proof is inconsistent'
  [[ "$(grep -Fxc "PROOF bystander_fail_open=PASS control_cookie=${control_cookie} verdict_map=MISS round_trip=PASS" "${evidence}/stdout.log")" == '1' ]] || fail 'bystander proof is inconsistent'
  [[ "$(grep -Fxc 'PROOF cilium_active_window_ack=PASS enforcement=programmed traffic=exercised' "${evidence}/stdout.log")" == '1' ]] || fail 'active-window acknowledgement is missing'
  [[ "$(grep -Fxc "PROOF release_restore=PASS target_cookie=${target_cookie} same_connection=PASS retransmit=PASS" "${evidence}/stdout.log")" == '1' ]] || fail 'release proof is inconsistent'
  [[ "$(grep -Fxc "PROOF attach_scope_observed=PASS child=${cgroup} parent=absent root=absent programs=sockops,enforce,release" "${evidence}/stdout.log")" == '1' ]] || fail 'attachment-scope proof is inconsistent'
  [[ "$(grep -Fxc 'PROOF cilium_active_window=PASS node=spark-5343 attachments=live enforcement=programmed traffic=exercised' "${evidence}/stdout.log")" == '1' ]] || fail 'active-window Cilium proof is inconsistent'
  [[ "$(grep -Fxc 'PROOF runtime_cleanup=PASS cgroup=absent snapshot=absent' "${evidence}/stdout.log")" == '1' ]] || fail 'runtime cleanup proof is inconsistent'
  [[ "$(grep -Fxc 'RESULT PASS proof=precise-cookie-enforcement' "${evidence}/stdout.log")" == '1' ]] || fail 'explicit proof result is missing or duplicated'
  ! grep -Eq '^(FAIL:|RESULT FAIL)' "${evidence}/stdout.log" || fail 'failure marker appears in successful evidence'
}

validate_cleanup_evidence() {
  local evidence_dir="$1" entry name type owner
  [[ -d "${evidence_dir}" && ! -L "${evidence_dir}" && -O "${evidence_dir}" ]] || fail 'cleanup evidence directory is missing or unsafe'
  evidence_dir="$(cd -P -- "${evidence_dir}" && pwd -P)" || fail 'could not physically resolve cleanup evidence'
  while IFS= read -r entry; do
    name="${entry##*/}"
    case "${name}" in result.tsv|stderr.log|stdout.log|.stdout.capture|.stderr.capture|.result.tsv.tmp) ;; *) fail 'cleanup evidence has an unexpected entry' ;; esac
    type="$(stat -c %F "${entry}")"
    owner="$(stat -c %u "${entry}")"
    [[ "${type}" == 'regular file' && "${owner}" == "$(id -u)" ]] || fail 'cleanup evidence entry is unsafe'
  done < <(find "${evidence_dir}" -mindepth 1 -maxdepth 1 -print)
}

cleanup_evidence() {
  local evidence_name="enforcespike-${run_id}"
  local quarantine_name=".cleanup-${evidence_name}"
  [[ "${evidence}" == "${root}/${evidence_name}" && "${evidence_name}" != */* ]] || fail 'cleanup evidence is outside the fixed run scope'
  [[ "${evidence_quarantine}" == "${root}/${quarantine_name}" && "${quarantine_name}" != */* ]] || fail 'cleanup quarantine is outside the fixed run scope'
  if [[ ! -e "${root}" && ! -L "${root}" ]]; then
    printf 'absent'
    return
  fi
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" ]] || fail 'cleanup root is missing or unsafe'

  (
    cd -P -- "${root}" || fail 'could not enter cleanup root'
    [[ "$(pwd -P)" == "${root}" && ! -L "${root}" && . -ef "${root}" ]] || fail 'cleanup root is not physically anchored'
    local removed='no'
    while [[ -e "${evidence_name}" || -L "${evidence_name}" || -e "${quarantine_name}" || -L "${quarantine_name}" ]]; do
      local evidence_identity evidence_links
      if [[ -e "${evidence_name}" || -L "${evidence_name}" ]]; then
        [[ ! -e "${quarantine_name}" && ! -L "${quarantine_name}" ]] || fail 'live evidence and quarantine both exist'
        [[ -d "${evidence_name}" && ! -L "${evidence_name}" && -O "${evidence_name}" ]] || fail 'live evidence directory is unsafe'
        exec 8<"${evidence_name}" || fail 'could not open exact evidence directory'
        [[ -d /dev/fd/8/. ]] || fail 'opened evidence is not a directory'
        evidence_identity="$(stat -Lc %d:%i /dev/fd/8)" || fail 'could not identify opened evidence directory'
        validate_cleanup_evidence /dev/fd/8/.
        mv -T -- "${evidence_name}" "${quarantine_name}" || fail 'could not quarantine exact evidence'
      else
        [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" && -O "${quarantine_name}" ]] || fail 'quarantined evidence is unsafe'
        exec 8<"${quarantine_name}" || fail 'could not open exact evidence quarantine'
        evidence_identity="$(stat -Lc %d:%i /dev/fd/8)" || fail 'could not identify opened evidence quarantine'
      fi
      [[ "$(stat -Lc %d:%i "${quarantine_name}")" == "${evidence_identity}" ]] || fail 'quarantined evidence is not the validated directory inode'
      (
        cd -P -- /dev/fd/8/. || fail 'could not enter validated evidence directory'
        [[ "$(stat -Lc %d:%i .)" == "${evidence_identity}" ]] || fail 'cleanup left the validated evidence directory'
        validate_cleanup_evidence .
        for file in .stdout.capture .stderr.capture .result.tsv.tmp result.tsv stderr.log stdout.log; do
          if [[ -e "${file}" || -L "${file}" ]]; then
            rm -- "${file}" || fail "could not remove allowlisted evidence file: ${file}"
          fi
        done
      ) || fail 'anchored evidence-file cleanup failed'
      [[ "$(stat -Lc %d:%i "${quarantine_name}")" == "${evidence_identity}" ]] || fail 'quarantined evidence changed after cleanup'
      rmdir -- "${quarantine_name}" || fail 'could not remove empty evidence quarantine'
      evidence_links="$(stat -Lc %h /dev/fd/8)" || fail 'could not verify evidence unlink'
      [[ "${evidence_links}" == '0' ]] || fail 'validated evidence directory remains linked after cleanup'
      exec 8<&-
      removed='yes'
    done
    [[ "${removed}" == 'yes' ]] && printf 'removed' || printf 'absent'
  )
  local remaining
  remaining="$(find "${root}" -mindepth 1 -maxdepth 1 -print -quit)" || fail 'could not inspect cleanup root after evidence deletion'
  if [[ -z "${remaining}" ]]; then
    rmdir -- "${root}" || fail 'could not remove empty evidence root'
  fi
}

expiry_timer_active() {
  local load_state
  load_state="$(sudo -n systemctl show --property=LoadState --value "${expiry_unit}.timer" 2>/dev/null)" || return 1
  [[ "${load_state}" == 'loaded' ]] || return 1
  sudo -n systemctl is-active --quiet "${expiry_unit}.timer"
}

cancel_expiry_timer() {
  local unit load_state active_state attempt
  for unit in "${expiry_unit}.timer" "${expiry_unit}.service"; do
    load_state="$(sudo -n systemctl show --property=LoadState --value "${unit}" 2>/dev/null)" || return 1
    if [[ "${load_state}" == 'loaded' ]]; then
      sudo -n systemctl stop "${unit}" || return 1
      active_state="$(sudo -n systemctl show --property=ActiveState --value "${unit}" 2>/dev/null)" || return 1
      if [[ "${active_state}" == 'failed' ]]; then
        sudo -n systemctl reset-failed "${unit}" >/dev/null 2>&1 || return 1
      elif [[ "${active_state}" != 'inactive' ]]; then
        return 1
      fi
    elif [[ "${load_state}" != 'not-found' ]]; then
      return 1
    fi
  done
  for attempt in $(seq 1 100); do
    local all_unloaded='yes'
    for unit in "${expiry_unit}.timer" "${expiry_unit}.service"; do
      load_state="$(sudo -n systemctl show --property=LoadState --value "${unit}" 2>/dev/null)" || return 1
      if [[ "${load_state}" != 'not-found' ]]; then
        [[ "${load_state}" == 'loaded' ]] || return 1
        active_state="$(sudo -n systemctl show --property=ActiveState --value "${unit}" 2>/dev/null)" || return 1
        [[ "${active_state}" == 'inactive' ]] || return 1
        all_unloaded='no'
      fi
    done
    [[ "${all_unloaded}" == 'yes' ]] && return 0
    sleep 0.05
  done
  return 1
}

schedule_expiry_cleanup() {
  local evidence_name="enforcespike-${run_id}"
  local quarantine_name=".cleanup-${evidence_name}"
  local owner_uid expiry_cleanup_program
  owner_uid="$(id -u)"
  read -r -d '' expiry_cleanup_program <<'EXPIRY' || true
set -euo pipefail
root="$1"
evidence_name="$2"
quarantine_name="$3"
owner_uid="$4"
fail() { printf 'enforcespike(expiry): %s\n' "$*" >&2; exit 1; }
validate_dir() {
  local dir="$1" entry name type owner
  [[ -d "${dir}" && ! -L "${dir}" ]] || fail 'evidence directory is missing or unsafe'
  dir="$(cd -P -- "${dir}" && pwd -P)" || fail 'could not resolve evidence directory'
  [[ "$(stat -c %u "${dir}")" == "${owner_uid}" ]] || fail 'evidence directory owner changed'
  while IFS= read -r entry; do
    name="${entry##*/}"
    case "${name}" in result.tsv|stderr.log|stdout.log|.stdout.capture|.stderr.capture|.result.tsv.tmp) ;; *) fail 'evidence contains an unexpected entry' ;; esac
    type="$(stat -c %F "${entry}")"
    owner="$(stat -c %u "${entry}")"
    [[ "${type}" == 'regular file' && "${owner}" == "${owner_uid}" ]] || fail 'evidence entry is unsafe'
  done < <(find "${dir}" -mindepth 1 -maxdepth 1 -print)
}
[[ "${root}" == '/run/user/1000/canarysting' && "${evidence_name}" =~ ^enforcespike-[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ &&
  "${quarantine_name}" == ".cleanup-${evidence_name}" && "${owner_uid}" =~ ^[0-9]+$ ]] || fail 'unsafe expiry scope'
[[ -d "${root}" && ! -L "${root}" && "$(stat -c %u "${root}")" == "${owner_uid}" ]] || fail 'evidence root is unsafe'
cd -P -- "${root}" || fail 'could not enter evidence root'
[[ "$(pwd -P)" == "${root}" && . -ef "${root}" ]] || fail 'evidence root is not physically anchored'
if [[ -e "${evidence_name}" || -L "${evidence_name}" || -e "${quarantine_name}" || -L "${quarantine_name}" ]]; then
  if [[ -e "${evidence_name}" || -L "${evidence_name}" ]]; then
    [[ ! -e "${quarantine_name}" && ! -L "${quarantine_name}" ]] || fail 'live evidence and quarantine both exist'
    [[ -d "${evidence_name}" && ! -L "${evidence_name}" ]] || fail 'live evidence is unsafe'
    exec 9<"${evidence_name}" || fail 'could not open evidence directory'
    identity="$(stat -Lc %d:%i /proc/self/fd/9)" || fail 'could not identify evidence directory'
    validate_dir /proc/self/fd/9/.
    mv -T -- "${evidence_name}" "${quarantine_name}" || fail 'could not quarantine evidence'
  else
    [[ -d "${quarantine_name}" && ! -L "${quarantine_name}" ]] || fail 'evidence quarantine is unsafe'
    exec 9<"${quarantine_name}" || fail 'could not open evidence quarantine'
    identity="$(stat -Lc %d:%i /proc/self/fd/9)" || fail 'could not identify evidence quarantine'
  fi
  [[ "$(stat -Lc %d:%i "${quarantine_name}")" == "${identity}" ]] ||
    fail 'quarantined evidence is not the validated directory inode'
  (
    cd -P -- /proc/self/fd/9/. || fail 'could not enter validated evidence directory'
    [[ "$(stat -Lc %d:%i .)" == "${identity}" ]] || fail 'expiry left the validated evidence directory'
    validate_dir .
    rm -f -- .stdout.capture .stderr.capture .result.tsv.tmp result.tsv stderr.log stdout.log
  )
  [[ "$(stat -Lc %d:%i "${quarantine_name}")" == "${identity}" ]] || fail 'evidence quarantine changed before unlink'
  rmdir -- "${quarantine_name}" || fail 'could not remove evidence quarantine'
  [[ "$(stat -Lc %h /proc/self/fd/9)" == '0' ]] || fail 'validated evidence directory remains linked after expiry'
  exec 9<&-
fi
remaining="$(find "${root}" -mindepth 1 -maxdepth 1 -print -quit)" || fail 'could not inspect evidence root after expiry'
if [[ -z "${remaining}" ]]; then
  cd -P -- /run/user/1000
  rmdir -- "${root}" || fail 'could not remove empty evidence root'
fi
EXPIRY
  sudo -n systemd-run --quiet --collect --expand-environment=no --unit="${expiry_unit}" --on-active=23h55m \
    --timer-property=AccuracySec=1s --property=Type=oneshot --property=Restart=on-failure \
    --property=RestartSec=5m --property=StartLimitIntervalSec=0 --property="User=$(id -un)" \
    /usr/bin/bash -c "${expiry_cleanup_program}" _ "${root}" "${evidence_name}" "${quarantine_name}" "${owner_uid}" || return 1
  expiry_timer_active
}

cleanup_runtime_residue() {
  if sudo -n test -e "${cgroup}"; then
    [[ "$(sudo -n awk 'NF { n++ } END { print n+0 }' "${cgroup}/cgroup.procs")" == '0' ]] || fail 'run-owned cgroup contains a process'
    sudo -n rmdir "${cgroup}"
  fi
  if sudo -n test -e "${snapshot}"; then
    sudo -n test -d "${snapshot}" || fail 'snapshot residue is not a directory'
    sudo -n test ! -L "${snapshot}" || fail 'snapshot residue is a symlink'
    snapshot_inventory="$(sudo -n find "${snapshot}" -mindepth 1 -maxdepth 1 -printf '%y:%f\n' | LC_ALL=C sort)"
    while IFS= read -r snapshot_entry; do
      [[ -z "${snapshot_entry}" ]] && continue
      case "${snapshot_entry}" in
        f:.enforcement-active|f:.enforcespike.tmp|f:.health-checked|f:.health-checked.tmp|f:enforcespike) ;;
        *) fail 'snapshot inventory is unsafe' ;;
      esac
    done <<<"${snapshot_inventory}"
    for proc_exe in /proc/[0-9]*/exe; do
      [[ "$(sudo -n readlink "${proc_exe}" 2>/dev/null || true)" != "${snapshot}/enforcespike" ]] || fail 'privileged snapshot is still executing'
    done
    sudo -n rm -f "${snapshot}/.enforcement-active" "${snapshot}/.health-checked" \
      "${snapshot}/.health-checked.tmp" "${snapshot}/.enforcespike.tmp" "${snapshot}/enforcespike"
    sudo -n rmdir "${snapshot}"
  fi
  if sudo -n test -d "${cgroup_parent}"; then sudo -n rmdir "${cgroup_parent}" 2>/dev/null || true; fi
  if sudo -n test -d "${snapshot_root}"; then sudo -n rmdir "${snapshot_root}" 2>/dev/null || true; fi
}

if [[ "${mode}" == 'inspect' ]]; then
  [[ ! -e "${evidence_quarantine}" && ! -L "${evidence_quarantine}" ]] || fail 'interrupted evidence quarantine remains; run cleanup'
  validate_stage
  readonly artifact_size artifact_sha256
  validate_evidence
  bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state'
  [[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state remains'
  sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup remains'
  sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot remains'
  expiry_timer_active || fail 'automatic evidence-expiration timer is not active'
  printf 'mode=inspect\nrun_id=%s\nevidence=PASS\nruntime_residue=none\n' "${run_id}"
  exit 0
fi

if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_runtime_residue
  bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state after cleanup'
  [[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state remains after cleanup'
  cancel_expiry_timer || fail 'could not cancel automatic evidence-expiration timer'
  evidence_state="$(cleanup_evidence)" || fail 'anchored evidence cleanup failed'
  printf 'mode=cleanup\nrun_id=%s\nevidence=%s\nruntime_residue=none\n' "${run_id}" "${evidence_state}"
  exit 0
fi

validate_stage
readonly artifact_size artifact_sha256
if [[ -e "${root}" || -L "${root}" ]]; then
  [[ -d "${root}" && ! -L "${root}" && -O "${root}" && "$(stat -c %a "${root}")" == '700' ]] || fail 'evidence root is unsafe'
else
  mkdir -m 0700 "${root}"
fi
[[ ! -e "${evidence}" && ! -L "${evidence}" && ! -e "${evidence_quarantine}" && ! -L "${evidence_quarantine}" ]] || fail 'proof evidence or interrupted quarantine already exists'
expiry_load_state="$(sudo -n systemctl show --property=LoadState --value "${expiry_unit}.timer" 2>/dev/null)" || fail 'could not inspect proof expiration timer'
[[ "${expiry_load_state}" == 'not-found' ]] || fail 'proof expiration timer already exists or has unexpected state'
sudo -n test ! -e "${cgroup}" || fail 'run-owned cgroup already exists'
sudo -n test ! -e "${snapshot}" || fail 'privileged snapshot already exists'
bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state before proof'
[[ "${bpf_state}" == 'none' ]] || fail 'named CanarySting BPF state exists before proof'
assert_platform_healthy || fail 'K3s node or Cilium is unhealthy before proof'

root_before="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_before="$(bpf_ids)"
bpf_before_sha="$(printf '%s\n' "${bpf_before}" | sha256sum | awk '{print $1}')"
created_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
schedule_expiry_cleanup || fail 'could not schedule automatic evidence expiration'
mkdir -m 0700 "${evidence}"
stdout_log="${evidence}/stdout.log"
stderr_log="${evidence}/stderr.log"
stdout_capture_state_file="${evidence}/.stdout.capture"
stderr_capture_state_file="${evidence}/.stderr.capture"

set +e
exec 3> >(bounded_capture "${stdout_log}" "${stdout_capture_state_file}")
stdout_capture_pid=$!
exec 4> >(bounded_capture "${stderr_log}" "${stderr_capture_state_file}")
stderr_capture_pid=$!
sudo -n bash -s -- "${artifact}" "${artifact_size}" "${artifact_sha256}" "${run_id}" >&3 2>&4 <<'PROOF'
set -euo pipefail
artifact="$1"
expected_size="$2"
expected_sha="$3"
run_id="$4"
cgroup_parent='/sys/fs/cgroup/canarysting-dgx'
cgroup="${cgroup_parent}/${run_id}"
snapshot_root='/var/tmp/canarysting-privileged'
snapshot="${snapshot_root}/enforcespike-${run_id}"
snapshot_artifact="${snapshot}/enforcespike"
health_ready="${snapshot}/.enforcement-active"
health_ack="${snapshot}/.health-checked"
readonly artifact expected_size expected_sha run_id cgroup_parent cgroup snapshot_root snapshot snapshot_artifact health_ready health_ack

proof_fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
platform_healthy() {
  local ready desired output
  systemctl is-active --quiet k3s || return 1
  output="$(k3s kubectl get node spark-5343 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" || return 1
  [[ "${output}" == 'True' ]] || return 1
  output="$(k3s kubectl -n kube-system get daemonset cilium -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  output="$(k3s kubectl -n kube-system get daemonset cilium-envoy -o jsonpath='{.status.numberReady} {.status.desiredNumberScheduled}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  output="$(k3s kubectl -n kube-system get deployment cilium-operator -o jsonpath='{.status.readyReplicas} {.status.replicas}')" || return 1
  read -r ready desired <<<"${output}" || return 1
  [[ "${desired}" =~ ^[1-9][0-9]*$ && "${ready}" == "${desired}" ]] || return 1
  KUBECONFIG=/etc/rancher/k3s/k3s.yaml cilium status --wait=false >/dev/null || return 1
}
cleanup() {
  local failed=0
  if [[ -d "${cgroup}" && ! -L "${cgroup}" ]]; then
    if [[ -z "$(awk 'NF { print; exit }' "${cgroup}/cgroup.procs")" ]]; then rmdir "${cgroup}" || failed=1; else failed=1; fi
  fi
  if [[ -d "${snapshot}" && ! -L "${snapshot}" ]]; then
    rm -f "${health_ready}" "${health_ack}" "${health_ack}.tmp" "${snapshot_artifact}" || failed=1
    rmdir "${snapshot}" || failed=1
  fi
  [[ ! -e "${cgroup}" && ! -L "${cgroup}" && ! -e "${snapshot}" && ! -L "${snapshot}" ]] || failed=1
  rmdir "${cgroup_parent}" 2>/dev/null || true
  rmdir "${snapshot_root}" 2>/dev/null || true
  if [[ "${failed}" -eq 0 ]]; then printf 'PROOF runtime_cleanup=PASS cgroup=absent snapshot=absent\n'; else printf 'FAIL: runtime cleanup incomplete\n' >&2; fi
  return "${failed}"
}
trap cleanup EXIT INT TERM

[[ "$(id -u)" == '0' ]] || proof_fail 'helper is not root'
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || proof_fail 'invalid run ID'
[[ "$(stat -fc %T /sys/fs/cgroup)" == 'cgroup2fs' ]] || proof_fail 'cgroup v2 is required'
[[ "$(stat -c %u:%a /var/tmp)" == '0:1777' ]] || proof_fail '/var/tmp must be root-owned mode 1777'
[[ ! -e "${snapshot}" && ! -L "${snapshot}" && ! -e "${cgroup}" && ! -L "${cgroup}" ]] || proof_fail 'run-owned runtime state already exists'

if [[ -e "${snapshot_root}" || -L "${snapshot_root}" ]]; then
  [[ -d "${snapshot_root}" && ! -L "${snapshot_root}" && -O "${snapshot_root}" && "$(stat -c %a "${snapshot_root}")" == '700' ]] || proof_fail 'unsafe snapshot root'
else
  mkdir -m 0700 "${snapshot_root}"
fi
mkdir -m 0700 "${snapshot}"
exec 5<"${artifact}" || proof_fail 'could not open staged artifact'
[[ "$(stat -Lc %F:%s /proc/self/fd/5)" == "regular file:${expected_size}" ]] || proof_fail 'staged artifact descriptor changed'
tmp="${snapshot}/.enforcespike.tmp"
cp --reflink=never --sparse=never /proc/self/fd/5 "${tmp}"
chmod 0500 "${tmp}"
[[ "$(stat -c %s "${tmp}")" == "${expected_size}" ]] || proof_fail 'snapshot size mismatch'
[[ "$(sha256sum "${tmp}" | awk '{print $1}')" == "${expected_sha}" ]] || proof_fail 'snapshot checksum mismatch'
mv -T "${tmp}" "${snapshot_artifact}"
printf 'PROOF privileged_artifact=PASS sha256=%s\n' "${expected_sha}"

if [[ -e "${cgroup_parent}" || -L "${cgroup_parent}" ]]; then
  [[ -d "${cgroup_parent}" && ! -L "${cgroup_parent}" && -O "${cgroup_parent}" ]] || proof_fail 'unsafe cgroup parent'
else
  mkdir "${cgroup_parent}"
fi
mkdir "${cgroup}"
(
  printf '%s\n' "${BASHPID}" >"${cgroup}/cgroup.procs"
  exec timeout --signal=TERM --kill-after=3s 15s "${snapshot_artifact}" -cgroup "${cgroup}" -proof
) &
proof_pid=$!
attach='FAIL'
cilium_window='FAIL'
for _ in $(seq 1 500); do
  child="$(bpftool cgroup show "${cgroup}" 2>/dev/null)" || proof_fail 'could not inventory child cgroup attachments'
  if grep -q 'canary_sockops' <<<"${child}" && grep -q 'enforce_egress' <<<"${child}" && grep -q 'enforce_release' <<<"${child}"; then
    parent="$(bpftool cgroup show "${cgroup_parent}" 2>/dev/null)" || proof_fail 'could not inventory parent cgroup attachments'
    root="$(bpftool cgroup show /sys/fs/cgroup 2>/dev/null)" || proof_fail 'could not inventory root cgroup attachments'
    if ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${parent}" && ! grep -Eq 'canary_sockops|enforce_(egress|release)' <<<"${root}"; then
      attach='PASS'
      if [[ -f "${health_ready}" && ! -L "${health_ready}" && "$(stat -c %a "${health_ready}")" == '600' &&
        "$(<"${health_ready}")" == 'enforcement-active' ]] && platform_healthy; then
        child_after_health="$(bpftool cgroup show "${cgroup}" 2>/dev/null)" || proof_fail 'could not recheck child attachments after Cilium health'
        if grep -q 'canary_sockops' <<<"${child_after_health}" && grep -q 'enforce_egress' <<<"${child_after_health}" && grep -q 'enforce_release' <<<"${child_after_health}"; then
          health_ack_tmp="${health_ack}.tmp"
          (umask 077; printf 'cilium-health-pass\n' >"${health_ack_tmp}") || proof_fail 'could not create health acknowledgement'
          mv -T -- "${health_ack_tmp}" "${health_ack}" || proof_fail 'could not publish health acknowledgement'
          cilium_window='PASS'
          break
        fi
      fi
    fi
  fi
  kill -0 "${proof_pid}" 2>/dev/null || break
  sleep 0.02
done
wait "${proof_pid}"
proof_status=$?
printf 'PROOF attach_scope_observed=%s child=%s parent=absent root=absent programs=sockops,enforce,release\n' "${attach}" "${cgroup}"
printf 'PROOF cilium_active_window=%s node=spark-5343 attachments=live enforcement=programmed traffic=exercised\n' "${cilium_window}"
[[ "${proof_status}" -eq 0 ]] || proof_fail "proof exited ${proof_status}"
[[ "${attach}" == 'PASS' ]] || proof_fail 'exact child attachment scope was not observed'
[[ "${cilium_window}" == 'PASS' ]] || proof_fail 'K3s node and Cilium health were not proven during live attachment'
PROOF
proof_exit=$?
exec 3>&-
exec 4>&-
stdout_capture_exit=0
stderr_capture_exit=0
wait "${stdout_capture_pid}" || stdout_capture_exit=$?
wait "${stderr_capture_pid}" || stderr_capture_exit=$?
set -e
chmod 0600 "${stdout_log}" "${stderr_log}"

stdout_capture='missing'
stderr_capture='missing'
[[ ! -f "${stdout_capture_state_file}" ]] || IFS= read -r stdout_capture <"${stdout_capture_state_file}"
[[ ! -f "${stderr_capture_state_file}" ]] || IFS= read -r stderr_capture <"${stderr_capture_state_file}"
rm -f -- "${stdout_capture_state_file}" "${stderr_capture_state_file}"
stdout_bytes="$(stat -c %s "${stdout_log}")"
stderr_bytes="$(stat -c %s "${stderr_log}")"
stdout_sha256="$(sha256sum "${stdout_log}" | awk '{print $1}')"
stderr_sha256="$(sha256sum "${stderr_log}" | awk '{print $1}')"

root_after="$(sudo -n bpftool cgroup show /sys/fs/cgroup 2>/dev/null | sha256sum | awk '{print $1}')"
bpf_after="$(bpf_ids)"
bpf_after_sha="$(printf '%s\n' "${bpf_after}" | sha256sum | awk '{print $1}')"
completed_epoch="$(date -u +%s)"
completed_at_utc="$(date -u -d "@${completed_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
expires_at_utc="$(date -u -d "@$((completed_epoch + 86400))" +%Y-%m-%dT%H:%M:%SZ)"
assert_platform_healthy || fail 'K3s node or Cilium is unhealthy after proof'
runtime_cleanup='FAIL'
bpf_state="$(named_bpf_state)" || fail 'could not inventory named CanarySting BPF state after proof'
if [[ "${proof_exit}" -eq 0 && "${root_before}" == "${root_after}" && "${bpf_before}" == "${bpf_after}" && "${bpf_state}" == 'none' ]] &&
   sudo -n test ! -e "${cgroup}" && sudo -n test ! -e "${snapshot}"; then
  runtime_cleanup='PASS'
fi

status='FAIL'
if [[ "${runtime_cleanup}" == 'PASS' && "${stdout_capture_exit}" -eq 0 && "${stderr_capture_exit}" -eq 0 &&
  "${stdout_capture}" == 'complete' && "${stderr_capture}" == 'complete' &&
  "${stdout_bytes}" -le 1048576 && "${stderr_bytes}" -le 1048576 ]] &&
  grep -Fxq 'RESULT PASS proof=precise-cookie-enforcement' "${evidence}/stdout.log"; then
  status='PASS'
fi
{
  printf 'format_version\t1\n'
  printf 'run_id\t%s\n' "${run_id}"
  printf 'status\t%s\n' "${status}"
  printf 'artifact_sha256\t%s\n' "${artifact_sha256}"
  printf 'attach_scope\trun-owned-child-cgroup\n'
  printf 'runtime_cleanup\t%s\n' "${runtime_cleanup}"
  printf 'stdout_capture\t%s\n' "${stdout_capture}"
  printf 'stderr_capture\t%s\n' "${stderr_capture}"
  printf 'stdout_bytes\t%s\n' "${stdout_bytes}"
  printf 'stderr_bytes\t%s\n' "${stderr_bytes}"
  printf 'stdout_sha256\t%s\n' "${stdout_sha256}"
  printf 'stderr_sha256\t%s\n' "${stderr_sha256}"
  printf 'root_attachments_before_sha256\t%s\n' "${root_before}"
  printf 'root_attachments_after_sha256\t%s\n' "${root_after}"
  printf 'bpf_inventory_before_sha256\t%s\n' "${bpf_before_sha}"
  printf 'bpf_inventory_after_sha256\t%s\n' "${bpf_after_sha}"
  printf 'created_at_utc\t%s\n' "${created_at_utc}"
  printf 'completed_at_utc\t%s\n' "${completed_at_utc}"
  printf 'expires_at_utc\t%s\n' "${expires_at_utc}"
  printf 'retention\trun-through-cleanup-with-24-hour-maximum\n'
  printf 'expiration_cleanup\tscheduled-systemd-transient-timer\n'
  printf 'legal_hold\tunsupported\n'
  printf 'deletion\texact-run-cleanup-or-scheduled-expiry\n'
  printf 'residency\tDGX-host-filesystem\n'
  printf 'encryption_boundary\toperator-managed-host\n'
  printf 'model_use\tprohibited\n'
  printf 'derivation_lineage\tartifact-checksum-plus-synthetic-proof\n'
  printf 'estimated_storage_impact\tless-than-3MiB\n'
} >"${evidence}/result.tsv"
chmod 0600 "${evidence}/result.tsv"

[[ "${status}" == 'PASS' ]] || fail "proof failed; inspect ${evidence}"
validate_evidence
printf 'mode=run\nrun_id=%s\nstatus=PASS\nevidence=%s\nruntime_residue=none\n' "${run_id}" "${evidence}"
REMOTE

if [[ "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${cleanup_script}" --run-id "${run_id}"
fi
if [[ "${mode}" == 'run' || "${mode}" == 'cleanup' ]]; then
  CANARYSTING_DGX_HOST="${remote_alias}" "${check_script}"
  printf 'post_mutation_check=PASS\n'
fi
