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

awk '/^  sudo -n bash -s .*<<.PROOF.$/ { capture=1; next } capture && /^PROOF$/ { exit } capture { print }' \
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
cleanup_runner='fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }'$'\n''stat() { case "$1:$2" in -c:%F) [[ -f "$3" && ! -L "$3" ]] && printf "regular file\n" || return 1 ;; -c:%u) id -u ;; *) command stat "$@" ;; esac; }'$'\n''mv() { if [[ "$1" == "-T" && "$2" == "--" ]]; then command mv -- "$3" "$4"; else command mv "$@"; fi; }'$'\n'"${cleanup_validation_definition}"$'\n'"${cleanup_definition}"$'\n''run_id="$1"; root="$2"; evidence="${root}/enforcespike-${run_id}"; evidence_quarantine="${root}/.cleanup-enforcespike-${run_id}"; cleanup_evidence'

cleanup_root="${tmp_dir}/cleanup-root"
mkdir -m 700 "${cleanup_root}"
cleanup_root="$(cd -P "${cleanup_root}" && pwd -P)"
cleanup_run_id='m1d-oversized-test'
mkdir -m 700 "${cleanup_root}/enforcespike-${cleanup_run_id}"
head -c 1048577 /dev/zero >"${cleanup_root}/enforcespike-${cleanup_run_id}/stdout.log"
cleanup_state="$(bash -c "${cleanup_runner}" -- "${cleanup_run_id}" "${cleanup_root}")" || fail 'anchored cleanup rejected oversized failed-run evidence'
[[ "${cleanup_state}" == 'removed' ]] || fail 'anchored cleanup did not report removal'
[[ ! -e "${cleanup_root}/enforcespike-${cleanup_run_id}" ]] || fail 'anchored cleanup left oversized evidence'

leaf_target="${tmp_dir}/leaf-target"
mkdir -m 700 "${leaf_target}"
printf 'external sentinel\n' >"${leaf_target}/stdout.log"
leaf_run_id='m1d-leaf-test'
ln -s "${leaf_target}" "${cleanup_root}/enforcespike-${leaf_run_id}"
expect_failure 'evidence leaf symlink' bash -c "${cleanup_runner}" -- "${leaf_run_id}" "${cleanup_root}"
[[ "$(<"${leaf_target}/stdout.log")" == 'external sentinel' ]] || fail 'leaf-symlink refusal changed external evidence'
rm "${cleanup_root}/enforcespike-${leaf_run_id}"

cdpath_external="${tmp_dir}/cdpath-external"
mkdir -m 700 "${cdpath_external}"
cdpath_run_id='m1d-cdpath-test'
cdpath_name=".cleanup-enforcespike-${cdpath_run_id}"
mkdir -m 700 "${cleanup_root}/${cdpath_name}" "${cdpath_external}/${cdpath_name}"
printf 'owned evidence\n' >"${cleanup_root}/${cdpath_name}/stderr.log"
printf 'external sentinel\n' >"${cdpath_external}/${cdpath_name}/stderr.log"
CDPATH="${cdpath_external}" bash -c "${cleanup_runner}" -- "${cdpath_run_id}" "${cleanup_root}" >/dev/null || fail 'anchored cleanup honored inherited CDPATH'
[[ "$(<"${cdpath_external}/${cdpath_name}/stderr.log")" == 'external sentinel' ]] || fail 'CDPATH cleanup changed external evidence'

dry_output="$(bash "${subject}" --run-id m1d-test-20260826-01 --dry-run)"
grep -Fq 'DGX was not accessed' <<<"${dry_output}" || fail 'dry-run did not declare no access'
grep -Fq 'attach_scope=run-owned-child-cgroup' <<<"${dry_output}" || fail 'dry-run attach scope is missing'
grep -Fq 'mutation=cgroup-and-transient-bpf-only' <<<"${dry_output}" || fail 'dry-run mutation boundary is missing'
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
grep -Fq 'ulimit -f 1024' "${subject}" || fail 'evidence output is not capped at 1 MiB'
if grep -Fq 'ulimit -f 2048' "${subject}"; then fail 'evidence output still permits 2 MiB'; fi
grep -Fq 'command -v ssh' "${subject}" || fail 'SSH prerequisite is not resolved through PATH'
grep -Fq "grep -q 'enforce_egress'" "${subject}" || fail 'live observer does not match the real egress program name'
grep -Fq "grep -q 'enforce_release'" "${subject}" || fail 'live observer does not match the real release program name'
grep -Fq 'control_map_entry=absent' cmd/enforcespike/main.go || fail 'binary does not report control map-miss proof'
grep -Fq 'PROOF shared_destination=PASS' cmd/enforcespike/main.go || fail 'binary does not prove a shared target/control destination'
grep -Fq 'PROOF cilium_active_window=PASS' "${subject}" || fail 'harness does not require active-window Cilium health'
grep -Fq 'expires_at_utc' "${subject}" || fail 'evidence has no enforceable expiration'
grep -Fq 'mv -T -- "${evidence_name}" "${quarantine_name}"' "${subject}" || fail 'cleanup does not quarantine exact evidence before deletion'
grep -Fq 'cd -P -- "./${quarantine_name}"' "${subject}" || fail 'cleanup is not anchored inside the evidence quarantine'
grep -Fq 'source=explicit-proof-fixture' cmd/enforcespike/main.go || fail 'binary does not identify the explicit proof trigger'
grep -Fq 'baseline_trigger=none' cmd/enforcespike/main.go || fail 'binary does not exclude baseline triggering'

printf 'enforcespike_test: PASS\n'
