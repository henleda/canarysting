#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/attackerscenariospike.sh"
remote_script="${script_dir}/attackerscenariospike_remote.sh"
readonly proof_script remote_script

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  local name="$1" expected="$2" output
  shift 2
  if output="$("$@" 2>&1)"; then fail "${name} unexpectedly succeeded"; fi
  [[ "${output}" == *"${expected}"* ]] || fail "${name} did not report ${expected}: ${output}"
}

[[ -x "${proof_script}" && -r "${remote_script}" ]] || fail 'scenario proof scripts are missing'
bash -n "${proof_script}" "${remote_script}" || fail 'scenario proof has invalid Bash syntax'

output="$(${proof_script} --run-id m2c5-contract --dry-run)"
[[ "${output}" == *'DGX was not accessed'* ]] || fail 'dry run accessed or omitted the DGX boundary'
[[ "${output}" == *'artifact=test/attackerscenariospike'* ]] || fail 'dry run omitted the fixed artifact'
[[ "${output}" == *'journey=enumeration,http-probe,disposable-credential,canary-discovery,canary-touch'* ]] || fail 'dry run omitted the five-step journey'
[[ "${output}" == *'mutation=run-labeled-namespace,pod,clusterip-service'* ]] || fail 'dry run omitted exact mutations'
[[ "${output}" == *'secret_reads=false'* && "${output}" == *'model_execution=false'* ]] || fail 'dry run omitted authority boundaries'
[[ "${output}" == *'cleanup=exact-idempotent'* ]] || fail 'dry run omitted cleanup posture'

expect_failure missing_run_id '--run-id is required' "${proof_script}" --dry-run
expect_failure invalid_run_id 'run ID must be' "${proof_script}" --run-id '../escape' --dry-run
expect_failure long_run_id 'run ID must be' "${proof_script}" --run-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2c5-modes --dry-run --inspect
expect_failure arbitrary_target 'unknown argument: --target' "${proof_script}" --run-id m2c5-target --target 10.0.0.1 --dry-run
expect_failure arbitrary_namespace 'unknown argument: --namespace' "${proof_script}" --run-id m2c5-namespace --namespace default --dry-run
expect_failure arbitrary_command 'unknown argument: --command' "${proof_script}" --run-id m2c5-command --command id --dry-run

for marker in \
  'imagePullPolicy: Never' \
  'automountServiceAccountToken: false' \
  'readOnlyRootFilesystem: true' \
  'allowPrivilegeEscalation: false' \
  'drop: [ALL]' \
  'type: ClusterIP' \
  'hostPath:' \
  'path: ${artifact}' \
  'cmp -s "${working}/proof-1.log" "${working}/proof-2.log"' \
  "fail 'unable to inventory CanarySting Kubernetes runtime state'" \
  "fail 'unable to inventory eBPF program state'" \
  'namespace_uid\t%s' \
  'cleanup_namespace yes' \
  'raw_fixture_log_retained\tfalse' \
  'sting_posture\tnot-deployed'; do
  grep -F "${marker}" "${remote_script}" >/dev/null || fail "scenario safety marker missing: ${marker}"
done
[[ "$(grep -c '^validate_passive_posture$' "${remote_script}")" == '2' ]] ||
  fail 'scenario must prove passive posture before and after the fixture'

if grep -E 'kubectl.*get.*secrets?|kctl.*get.*secrets?' "${remote_script}" >/dev/null; then
  fail 'scenario fixture reads Kubernetes Secrets'
fi
if grep -E 'type:[[:space:]]*(NodePort|LoadBalancer)|hostNetwork:[[:space:]]*true|imagePullPolicy:[[:space:]]*(Always|IfNotPresent)' "${remote_script}" >/dev/null; then
  fail 'scenario fixture exposes or downloads its target'
fi
if grep -E '(^|[[:space:]])(curl|wget|docker|nerdctl)([[:space:]]|$)' "${remote_script}" >/dev/null; then
  fail 'scenario proof bypasses its checksum-built executor or pulls runtime state'
fi
if grep -E '(^|[^0-9])(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' "${proof_script}" "${remote_script}" >/dev/null; then
  fail 'scenario harness hardcodes a private address instead of resolving the Service per run'
fi
if grep -F -- '-v namespace=' "${remote_script}" >/dev/null; then
  fail 'result validator uses the GNU awk reserved namespace identifier'
fi
grep -F "' \"\${path}\" || return 1" "${remote_script}" >/dev/null ||
  fail 'result-schema parser failure is not propagated by the validator'

inventory_definition="$(awk '/^validate_namespace_inventory\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${inventory_definition}" ]] || fail 'namespace inventory validator is not independently testable'
inventory_program=$'set -euo pipefail\n''fail() { printf "%s\n" "$*" >&2; return 1; }'$'\n'"${inventory_definition}"$'\n''run_id=m2c5-fixture fixture_name=initial-fixture namespace=cs-m2c5-fixture'$'\n''kctl() {
  case "$*" in
    *"get all,configmap,serviceaccount,networkpolicy,role,rolebinding -o name"*) printf "%s\n" "$INVENTORY" ;;
    *"get pod/initial-fixture -o jsonpath="*run-id*) printf "%s" "$run_id" ;;
    *"get pod/initial-fixture -o jsonpath="*fixture*) printf "%s" "$fixture_name" ;;
    *"get service/initial-fixture -o jsonpath="*run-id*) printf "%s" "$run_id" ;;
    *"get service/initial-fixture -o jsonpath="*fixture*) printf "%s" "$fixture_name" ;;
    *"get pod/initial-fixture"*|*"get service/initial-fixture"*) return 0 ;;
    *) return 1 ;;
  esac
}
validate_namespace_inventory yes'
INVENTORY=$'configmap/kube-root-ca.crt\npod/initial-fixture\nservice/initial-fixture\nserviceaccount/default' bash -c "${inventory_program}" ||
  fail 'namespace inventory validator rejected its exact fixture'
if INVENTORY=$'configmap/foreign\npod/initial-fixture\nservice/initial-fixture\nserviceaccount/default' bash -c "${inventory_program}" >/dev/null 2>&1; then
  fail 'namespace inventory validator accepted a foreign resource'
fi

passive_definition="$(awk '/^validate_passive_posture\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${passive_definition}" ]] || fail 'passive-posture validator is not independently testable'
passive_program=$'set -euo pipefail\n''fail() { printf "%s\n" "$*" >&2; return 1; }'$'\n'"${passive_definition}"$'\n''kctl() {
  [[ "${KCTL_FAIL:-0}" == 0 ]] || return 1
  printf "%s" "${K8S_OUTPUT:-}"
}
ps() {
  [[ "${PS_FAIL:-0}" == 0 ]] || return 1
  printf "%s" "${PS_OUTPUT:-}"
}
sudo() {
  [[ "$*" == "-n bpftool prog show" ]] || return 1
  [[ "${BPF_FAIL:-0}" == 0 ]] || return 1
  printf "%s" "${BPF_OUTPUT:-}"
}
validate_passive_posture'
bash -c "${passive_program}" || fail 'passive-posture validator rejected an empty safe baseline'
for unsafe in kctl ps runtime bpf; do
  case "${unsafe}" in
    kctl) environment=(KCTL_FAIL=1) ;;
    ps) environment=(PS_FAIL=1) ;;
    runtime) environment=(PS_OUTPUT=engine) ;;
    bpf) environment=(BPF_OUTPUT='1: sock_ops name canary_sockops') ;;
  esac
  if env "${environment[@]}" bash -c "${passive_program}" >/dev/null 2>&1; then
    fail "passive-posture validator accepted unsafe ${unsafe} state"
  fi
done

printf 'PASS: DGX reproducible attacker scenario harness contract\n'
