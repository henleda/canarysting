#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly subject="${script_dir}/enforcespike.sh"

fail() {
  printf 'enforcespike_test: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "expected failure: ${label}"
  fi
}

[[ -f "${subject}" ]] || fail 'subject script is missing'
bash -n "${subject}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${tmp_dir}"' EXIT

awk '/^ssh -T .*<<.REMOTE.$/ { capture=1; next } capture && /^REMOTE$/ { exit } capture { print }' \
  "${subject}" >"${tmp_dir}/remote.sh"
[[ -s "${tmp_dir}/remote.sh" ]] || fail 'could not extract remote program'
bash -n "${tmp_dir}/remote.sh"

awk '/^sudo -n bash -s .*<<.PROOF.$/ { capture=1; next } capture && /^PROOF$/ { exit } capture { print }' \
  "${subject}" >"${tmp_dir}/proof.sh"
[[ -s "${tmp_dir}/proof.sh" ]] || fail 'could not extract privileged proof program'
bash -n "${tmp_dir}/proof.sh"

named_bpf_definition="$(awk '
  /^named_bpf_state\(\) \{$/ { capture=1 }
  capture { print }
  capture && /^}$/ { exit }
' "${subject}")"
[[ -n "${named_bpf_definition}" ]] || fail 'named BPF inventory function is missing'
if bash -c 'set -o pipefail; sudo() { return 1; }; source /dev/stdin; named_bpf_state' <<<"${named_bpf_definition}" >/dev/null 2>&1; then
  fail 'named BPF inventory reports none when bpftool fails'
fi

cleanup_validation_definition="$(awk '
  /^validate_cleanup_evidence\(\) \{$/ { capture=1 }
  capture { print }
  capture && /^}$/ { exit }
' "${subject}")"
cleanup_definition="$(awk '
  /^cleanup_evidence\(\) \{$/ { capture=1 }
  capture { print }
  capture && /^}$/ { exit }
' "${subject}")"
[[ -n "${cleanup_validation_definition}" && -n "${cleanup_definition}" ]] || fail 'anchored evidence cleanup functions are missing'
cleanup_prelude='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''stat() { case "$1:$2" in -c:%F) [[ -f "$3" && ! -L "$3" ]] && printf "regular file\n" || return 1 ;; -c:%u) id -u ;; -Lc:%d:%i) if [[ "$3" == /dev/fd/8 ]]; then if [[ -e "${quarantine_name}" ]]; then command stat -f %d:%i "${quarantine_name}"; else command stat -f %d:%i "${evidence_name}"; fi; else command stat -f %d:%i "$3"; fi ;; -Lc:%h) if [[ "$3" == /dev/fd/8 && ! -e "${quarantine_name}" ]]; then printf "0\n"; else command stat -f %l "$3"; fi ;; *) command stat "$@" ;; esac; }'$'\n''cd() { if [[ "${@: -1}" == /dev/fd/8/. ]]; then if [[ -e "${quarantine_name}" ]]; then builtin cd -P -- "${quarantine_name}"; else builtin cd -P -- "${evidence_name}"; fi; else builtin cd "$@"; fi; }'
cleanup_suffix=$'\n'"${cleanup_validation_definition}"$'\n'"${cleanup_definition}"$'\n''run_id="$1"; root="$2"; evidence="${root}/enforcespike-${run_id}"; evidence_quarantine="${root}/.cleanup-enforcespike-${run_id}"; cleanup_evidence'
normal_mv='mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'
cleanup_runner="${cleanup_prelude}"$'\n'"${normal_mv}${cleanup_suffix}"
cleanup_shell="$(command -v zsh || command -v bash)"

cleanup_root="${tmp_dir}/cleanup-root"
mkdir -m 700 "${cleanup_root}"
cleanup_root="$(cd -P "${cleanup_root}" && pwd -P)"
cleanup_run_id='m1d-oversized-test'
mkdir -m 700 "${cleanup_root}/enforcespike-${cleanup_run_id}"
head -c 1048577 /dev/zero >"${cleanup_root}/enforcespike-${cleanup_run_id}/stdout.log"
cleanup_state="$("${cleanup_shell}" -c "${cleanup_runner}" -- "${cleanup_run_id}" "${cleanup_root}")" || fail 'anchored cleanup rejected oversized failed-run evidence'
[[ "${cleanup_state}" == 'removed' ]] || fail 'anchored cleanup did not report removal'
[[ ! -e "${cleanup_root}/enforcespike-${cleanup_run_id}" ]] || fail 'anchored cleanup left oversized evidence'
mkdir -m 700 "${cleanup_root}"

cdpath_external="${tmp_dir}/cdpath-external"
mkdir -m 700 "${cdpath_external}"
cdpath_run_id='m1d-cdpath-test'
cdpath_name=".cleanup-enforcespike-${cdpath_run_id}"
mkdir -m 700 "${cleanup_root}/${cdpath_name}" "${cdpath_external}/${cdpath_name}"
printf 'owned evidence\n' >"${cleanup_root}/${cdpath_name}/stderr.log"
printf 'external sentinel\n' >"${cdpath_external}/${cdpath_name}/stderr.log"
CDPATH="${cdpath_external}" "${cleanup_shell}" -c "${cleanup_runner}" -- "${cdpath_run_id}" "${cleanup_root}" >/dev/null || fail 'anchored cleanup honored inherited CDPATH'
[[ "$(<"${cdpath_external}/${cdpath_name}/stderr.log")" == 'external sentinel' ]] || fail 'CDPATH cleanup changed external evidence'

dry_output="$(bash "${subject}" --run-id m1d-test-20260826-01 --dry-run)"
grep -Fq 'DGX was not accessed' <<<"${dry_output}" || fail 'dry-run did not declare no access'
grep -Fq 'attach_scope=run-owned-child-cgroup' <<<"${dry_output}" || fail 'dry-run attach scope is missing'
grep -Fq 'mutation=run-scoped-cgroup-bpf-snapshot-evidence-and-expiry-units' <<<"${dry_output}" || fail 'dry-run mutation boundary is incomplete'
grep -Fq '/sys/fs/cgroup/canarysting-dgx/m1d-test-20260826-01' <<<"${dry_output}" || fail 'dry-run cgroup is not exact'

expect_failure 'missing run ID' bash "${subject}" --dry-run
expect_failure 'unsafe traversal run ID' bash "${subject}" --run-id '../escape' --dry-run
expect_failure 'uppercase run ID' bash "${subject}" --run-id 'M1D' --dry-run
expect_failure 'overlong run ID' bash "${subject}" --run-id 'm1d-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' --dry-run
expect_failure 'duplicate run ID' bash "${subject}" --run-id one --run-id two --dry-run
expect_failure 'duplicate mode' bash "${subject}" --run-id m1d-test --dry-run --inspect
expect_failure 'arbitrary cgroup' bash "${subject}" --run-id m1d-test --cgroup /sys/fs/cgroup --dry-run
expect_failure 'arbitrary target' bash "${subject}" --run-id m1d-test --target 127.0.0.1:1 --dry-run
expect_failure 'arbitrary command' bash "${subject}" --run-id m1d-test --command id --dry-run
expect_failure 'arbitrary timeout' bash "${subject}" --run-id m1d-test --timeout 999 --dry-run

grep -Fq "artifact_relative='test/enforcespike'" "${subject}" || fail 'artifact is not fixed'
grep -Fq 'digest = $6' "${subject}" || fail 'expected artifact checksum is not captured from the manifest'
grep -Fq 'readonly artifact_size artifact_sha256' "${subject}" || fail 'manifest-captured artifact identity is not frozen before privileged use'
if grep -Eq '^artifact_sha256="\$\(sha256sum "\$\{artifact\}"' "${subject}"; then
  fail 'expected artifact checksum is derived from the mutable executable'
fi
[[ "$(grep -Fc 'CANARYSTING_DGX_HOST="${remote_alias}"' "${subject}")" -eq 4 ]] || fail 'check/copy/cleanup host is not pinned to the proof host'
grep -Fq "cgroup_parent='/sys/fs/cgroup/canarysting-dgx'" "${subject}" || fail 'cgroup parent is not fixed'
grep -Fq 'exec timeout --signal=TERM --kill-after=3s 15s' "${subject}" || fail 'timeout is not fixed'
bounded_capture_definition="$(awk '/^bounded_capture\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${subject}")"
[[ -n "${bounded_capture_definition}" ]] || fail 'bounded capture function is missing'
capture_file="${tmp_dir}/bounded.log"
capture_state="${tmp_dir}/bounded.state"
head -c 1048577 /dev/zero | bash -c "${bounded_capture_definition}"$'\n''bounded_capture "$1" "$2"' -- "${capture_file}" "${capture_state}"
[[ "$(stat -f %z "${capture_file}" 2>/dev/null || stat -c %s "${capture_file}")" == '1048576' ]] || fail 'bounded capture did not enforce the 1 MiB limit'
[[ "$(<"${capture_state}")" == 'truncated' ]] || fail 'bounded capture did not report discarded output'
if grep -Fq 'ulimit -f ' "${subject}"; then fail 'evidence cap still depends on an inherited file-size limit'; fi
grep -Fq 'command -v ssh' "${subject}" || fail 'SSH prerequisite is not resolved through PATH'
grep -Fq "grep -q 'enforce_egress'" "${subject}" || fail 'live observer does not match the real egress program name'
grep -Fq "grep -q 'enforce_release'" "${subject}" || fail 'live observer does not match the real release program name'
grep -Fq 'control_map_entry=absent' cmd/enforcespike/main.go || fail 'binary does not report control map-miss proof'
grep -Fq 'PROOF shared_destination=PASS' cmd/enforcespike/main.go || fail 'binary does not prove a shared target/control destination'
grep -Fq 'PROOF cilium_active_window=PASS' "${subject}" || fail 'harness does not require active-window Cilium health'
grep -Fq '.enforcement-active' cmd/enforcespike/main.go || fail 'binary does not hold an enforcement-active health handshake'
assert_health_definition="$(awk '/^assert_platform_healthy\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${subject}")"
platform_health_definition="$(awk '/^platform_healthy\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${subject}")"
health_failure_stubs='systemctl() { return 0; }'$'\n''k3s() { printf "True"; return 42; }'$'\n''cilium() { return 0; }'$'\n''sudo() { [[ "$1" != "-n" ]] || shift; "$@"; }'
expect_failure 'outer node health producer failure' bash -c "${health_failure_stubs}"$'\n'"${assert_health_definition}"$'\n''assert_platform_healthy'
expect_failure 'active-window node health producer failure' bash -c "${health_failure_stubs}"$'\n'"${platform_health_definition}"$'\n''platform_healthy'
grep -Fq 'scheduled-systemd-transient-timer' "${subject}" || fail 'evidence has no scheduled expiration cleanup'
grep -Fq -- '--on-active=23h55m' "${subject}" || fail 'expiration cleanup is not scheduled before the 24-hour deadline'
grep -Fq -- '--expand-environment=no' "${subject}" || fail 'systemd is allowed to rewrite expiry-script shell variables'
grep -Fq -- '--property=Restart=on-failure' "${subject}" || fail 'expiration cleanup has no retry after failure'
schedule_line="$(grep -n 'schedule_expiry_cleanup || fail' "${subject}" | head -1 | cut -d: -f1)"
evidence_line="$(grep -n 'mkdir -m 0700 "${evidence}"' "${subject}" | head -1 | cut -d: -f1)"
[[ "${schedule_line}" -lt "${evidence_line}" ]] || fail 'expiration cleanup is scheduled after evidence creation'
grep -Fq 'mv -T -- "${evidence_name}" "${quarantine_name}"' "${subject}" || fail 'cleanup does not quarantine exact evidence before deletion'
grep -Fq 'quarantined evidence is not the validated directory inode' "${subject}" || fail 'cleanup does not bind validation to the quarantined inode'
grep -Fq 'cd -P -- /dev/fd/8/.' "${subject}" || fail 'manual cleanup does not delete through the validated directory descriptor'
grep -Fq 'validated evidence directory remains linked after cleanup' "${subject}" || fail 'manual cleanup does not verify unlink of the validated inode'
grep -Fq 'cd -P -- /proc/self/fd/9/.' "${subject}" || fail 'expiry cleanup does not delete through the validated directory descriptor'
grep -Fq 'validated evidence directory remains linked after expiry' "${subject}" || fail 'expiry cleanup does not verify unlink of the validated inode'
grep -Fq 'mv -T -- "${health_ack_tmp}" "${health_ack}"' "${subject}" || fail 'health acknowledgement is not published atomically'
grep -Fq 'completed_epoch + 86400' "${subject}" || fail 'expiration is not derived from the captured completion time'
cancel_definition="$(awk '/^cancel_expiry_timer\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${subject}")"
expect_failure 'systemd timer query failure' bash -c 'sudo() { return 42; }'$'\n'"${cancel_definition}"$'\n''expiry_unit=test-unit; cancel_expiry_timer'
grep -Fq 'stdout_sha256' "${subject}" || fail 'inspection does not bind result metadata to stdout evidence'
grep -Fq 'validate_stage' "${subject}" || fail 'inspection does not bind evidence to a verified stage'
if grep -Eq 'bpftool (prog|map|link|cgroup) show.*\|\| true' "${script_dir}/check.sh"; then fail 'supporting DGX check masks BPF inventory failure'; fi
grep -Fq 'source=explicit-proof-fixture' cmd/enforcespike/main.go || fail 'binary does not identify the explicit proof trigger'
grep -Fq 'baseline_trigger=none' cmd/enforcespike/main.go || fail 'binary does not exclude baseline triggering'

printf 'enforcespike_test: PASS\n'
