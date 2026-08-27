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
grep -Fq "cgroup_parent='/sys/fs/cgroup/canarysting-dgx'" "${subject}" || fail 'cgroup parent is not fixed'
grep -Fq 'exec timeout --signal=TERM --kill-after=3s 15s' "${subject}" || fail 'timeout is not fixed'
grep -Fq 'command -v ssh' "${subject}" || fail 'SSH prerequisite is not resolved through PATH'
grep -Fq "grep -q 'enforce_egress'" "${subject}" || fail 'live observer does not match the real egress program name'
grep -Fq "grep -q 'enforce_release'" "${subject}" || fail 'live observer does not match the real release program name'
grep -Fq 'control_map_entry=absent' cmd/enforcespike/main.go || fail 'binary does not report control map-miss proof'
grep -Fq 'source=explicit-proof-fixture' cmd/enforcespike/main.go || fail 'binary does not identify the explicit proof trigger'
grep -Fq 'baseline_trigger=none' cmd/enforcespike/main.go || fail 'binary does not exclude baseline triggering'

printf 'enforcespike_test: PASS\n'
