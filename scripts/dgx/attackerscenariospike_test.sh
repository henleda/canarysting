#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
proof_script="${script_dir}/attackerscenariospike.sh"
remote_script="${script_dir}/attackerscenariospike_remote.sh"
enforce_script="${script_dir}/enforcespike.sh"
readonly proof_script remote_script enforce_script

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
valid_run_id_48='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
invalid_run_id_49='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
"${proof_script}" --run-id "${valid_run_id_48}" --dry-run >/dev/null
expect_failure long_run_id 'run ID must be' "${proof_script}" --run-id "${invalid_run_id_49}" --dry-run
expect_failure duplicate_mode 'choose at most one mode' "${proof_script}" --run-id m2c5-modes --dry-run --inspect
expect_failure arbitrary_target 'unknown argument: --target' "${proof_script}" --run-id m2c5-target --target 10.0.0.1 --dry-run
expect_failure arbitrary_namespace 'unknown argument: --namespace' "${proof_script}" --run-id m2c5-namespace --namespace default --dry-run
expect_failure arbitrary_command 'unknown argument: --command' "${proof_script}" --run-id m2c5-command --command id --dry-run
expect_failure spoofed_inherited_transport 'inherited DGX transport is unavailable' env \
  CANARYSTING_DGX_REAL_SSH=/usr/bin/ssh CANARYSTING_DGX_SSH_CONTROL_PATH=/tmp/unreviewed/ssh-control \
  "${proof_script}" --run-id m2c5-transport --inspect

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
  "fail 'unable to inventory CanarySting Cilium policy state'" \
  "fail 'unable to inventory eBPF program state'" \
  'namespace_uid\t%s' \
  'delete --raw "/api/v1/namespaces/${namespace}" -f -' \
  '"preconditions":{"uid":"${expected_uid}"}' \
  'response_posture_lease=acquired' \
  'scenario_recovery_state=preserved' \
  'cleanup_namespace yes' \
  'raw_fixture_log_retained\tfalse' \
  'sting_posture\tnot-deployed'; do
  grep -F "${marker}" "${remote_script}" >/dev/null || fail "scenario safety marker missing: ${marker}"
done
[[ "$(grep -Ec '^ *validate_passive_posture (no|yes)$' "${remote_script}")" -ge 4 ]] ||
  fail 'scenario must repeatedly prove passive posture while its exclusive lease is held'
grep -Fq "[[ \"\$(id -u)\" == '1000' ]]" "${remote_script}" ||
  fail 'scenario does not require the shared DGX runtime UID'
grep -Fq "posture_lock_root='/run/user/1000'" "${remote_script}" ||
  fail 'scenario posture lease root differs from the enforcement contract'
grep -Fq 'posture_lock_file="${posture_lock_root}/canarysting-response-posture.lock"' "${remote_script}" ||
  fail 'scenario posture lease filename differs from the enforcement contract'
grep -Fq "posture_lock='/run/user/1000/canarysting-response-posture.lock'" "${enforce_script}" ||
  fail 'enforcement posture lease path differs from the scenario contract'

namespace_cleanup_line="$(grep -nF "cleanup_namespace yes || fail 'namespace cleanup failed; preserving the recovery workspace and artifact stage'" "${remote_script}" | cut -d: -f1)"
cleanup_disable_line="$(grep -nE '^cleanup_required=0$' "${remote_script}" | cut -d: -f1)"
final_posture_line="$(grep -nF "validate_posture_lease || fail 'response-posture lease was lost before final passive check'" "${remote_script}" | cut -d: -f1)"
evidence_validation_line="$(grep -nF 'validate_evidence' "${remote_script}" | tail -1 | cut -d: -f1)"
recovery_clear_line="$(grep -nF "recovery_path=''" "${remote_script}" | cut -d: -f1)"
if [[ ! "${namespace_cleanup_line}" =~ ^[0-9]+$ || ! "${cleanup_disable_line}" =~ ^[0-9]+$ ||
  ! "${final_posture_line}" =~ ^[0-9]+$ || ! "${evidence_validation_line}" =~ ^[0-9]+$ ||
  ! "${recovery_clear_line}" =~ ^[0-9]+$ ]] ||
  ((namespace_cleanup_line >= cleanup_disable_line || cleanup_disable_line >= final_posture_line ||
    final_posture_line >= evidence_validation_line || evidence_validation_line >= recovery_clear_line)); then
  fail 'late finalization failures are not guaranteed to preserve recovery evidence'
fi

for marker in \
  'source "${ssh_control_script}"' \
  "CANARYSTING_DGX_REAL_SSH='/usr/bin/ssh'" \
  '-o ProxyCommand=/usr/bin/false' \
  '-o ControlMaster=no' \
  'dgx_open_ssh_control "${CANARYSTING_DGX_SSH_CONTROL_PATH}"' \
  '^/(private/)?tmp/canarysting-dgx-(pr|batch)' \
  "trap cleanup_transport EXIT"; do
  grep -F -- "${marker}" "${proof_script}" >/dev/null || fail "standalone transport marker missing: ${marker}"
done
open_line="$(grep -nF 'initialize_transport' "${proof_script}" | tail -1 | cut -d: -f1)"
remote_line="$(grep -nF 'ssh "${ssh_options[@]}" "${dgx_host}" bash -s' "${proof_script}" | head -1 | cut -d: -f1)"
[[ "${open_line}" =~ ^[0-9]+$ && "${remote_line}" =~ ^[0-9]+$ && "${open_line}" -lt "${remote_line}" ]] ||
  fail 'standalone transport is not initialized before remote access'
directory_mode_definition="$(awk '/^directory_mode\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${proof_script}")"
mode_test_root="$(mktemp -d)"
chmod 0700 "${mode_test_root}"
[[ "$(bash -c 'readonly mode=inspect'$'\n'"${directory_mode_definition}"$'\n''directory_mode "$1"' -- "${mode_test_root}")" == '700' ]] ||
  fail 'transport directory validation collides with the readonly execution mode or omits its normalized value'
rmdir "${mode_test_root}"

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
validation_error_definition="$(awk '/^validation_error\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
namespace_observed_definition="$(awk '/^namespace_uid_observed\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${inventory_definition}" && -n "${validation_error_definition}" && -n "${namespace_observed_definition}" ]] || fail 'namespace validators are not independently testable'
inventory_program=$'set -euo pipefail\n'"${validation_error_definition}"$'\n'"${namespace_observed_definition}"$'\n'"${inventory_definition}"$'\n''run_id=m2c5-fixture fixture_name=initial-fixture namespace=cs-m2c5-fixture'$'\n''kctl() {
  case "$*" in
    "get namespace cs-m2c5-fixture --ignore-not-found -o jsonpath={.metadata.uid}") printf "%s" "11111111-1111-1111-1111-111111111111" ;;
    "api-resources --namespaced=true --verbs=list -o name") printf "%s\n" pods services configmaps serviceaccounts secrets endpointslices.discovery.k8s.io ciliumendpoints.cilium.io pods.metrics.k8s.io ;;
    "-n cs-m2c5-fixture get pods --ignore-not-found -o name") printf "%s\n" pod/initial-fixture ;;
    "-n cs-m2c5-fixture get services --ignore-not-found -o name") printf "%s\n" service/initial-fixture ;;
    "-n cs-m2c5-fixture get configmaps --ignore-not-found -o name") printf "%s\n" configmap/kube-root-ca.crt ;;
    "-n cs-m2c5-fixture get serviceaccounts --ignore-not-found -o name") printf "%s\n" serviceaccount/default ;;
    "-n cs-m2c5-fixture get secrets --ignore-not-found -o name") printf "%s" "${SECRET_INVENTORY:-}" ;;
    "-n cs-m2c5-fixture get endpointslices.discovery.k8s.io --ignore-not-found -o name") printf "%s" endpointslice.discovery.k8s.io/initial-fixture-abc ;;
    "-n cs-m2c5-fixture get ciliumendpoints.cilium.io --ignore-not-found -o name") printf "%s" ciliumendpoint.cilium.io/initial-fixture ;;
    "-n cs-m2c5-fixture get pods.metrics.k8s.io --ignore-not-found -o name") printf "%s" podmetrics.metrics.k8s.io/initial-fixture ;;
    "-n cs-m2c5-fixture get endpointslice.discovery.k8s.io/initial-fixture-abc -o jsonpath={.metadata.ownerReferences[0].uid}") printf "%s" "${ENDPOINTSLICE_OWNER_UID:-33333333-3333-3333-3333-333333333333}" ;;
    *"get endpointslice.discovery.k8s.io/initial-fixture-abc -o jsonpath="*service-name*) printf "%s" "${ENDPOINTSLICE_SERVICE_NAME:-initial-fixture}" ;;
    "-n cs-m2c5-fixture get ciliumendpoint.cilium.io/initial-fixture -o jsonpath={.metadata.ownerReferences[0].uid}") printf "%s" "22222222-2222-2222-2222-222222222222" ;;
    "-n cs-m2c5-fixture get pod/initial-fixture --ignore-not-found -o name") printf "%s" pod/initial-fixture ;;
    "-n cs-m2c5-fixture get service/initial-fixture --ignore-not-found -o name") printf "%s" service/initial-fixture ;;
    "-n cs-m2c5-fixture get pod/initial-fixture -o jsonpath={.metadata.uid}") printf "%s" "22222222-2222-2222-2222-222222222222" ;;
    "-n cs-m2c5-fixture get service/initial-fixture -o jsonpath={.metadata.uid}") printf "%s" "33333333-3333-3333-3333-333333333333" ;;
    *"get pod/initial-fixture -o jsonpath="*run-id*) printf "%s" "$run_id" ;;
    *"get pod/initial-fixture -o jsonpath="*fixture*) printf "%s" "$fixture_name" ;;
    *"get service/initial-fixture -o jsonpath="*run-id*) printf "%s" "$run_id" ;;
    *"get service/initial-fixture -o jsonpath="*fixture*) printf "%s" "$fixture_name" ;;
    *) return 1 ;;
  esac
}
validate_namespace_inventory yes'
SECRET_INVENTORY='' bash -c "${inventory_program}" ||
  fail 'namespace inventory validator rejected its exact fixture'
if SECRET_INVENTORY='secret/foreign' bash -c "${inventory_program}" >/dev/null 2>&1; then
  fail 'namespace inventory validator accepted a foreign Secret name'
fi
if ENDPOINTSLICE_OWNER_UID='44444444-4444-4444-4444-444444444444' bash -c "${inventory_program}" >/dev/null 2>&1; then
  fail 'namespace inventory validator accepted a foreign EndpointSlice owner'
fi
if ENDPOINTSLICE_SERVICE_NAME='foreign-service' bash -c "${inventory_program}" >/dev/null 2>&1; then
  fail 'namespace inventory validator accepted a foreign EndpointSlice service label'
fi
grep -F 'api-resources --namespaced=true --verbs=list -o name' "${remote_script}" >/dev/null ||
  fail 'namespace inventory does not dynamically cover every listable namespaced kind'

namespace_state_program=$'set -euo pipefail\n'"${validation_error_definition}"$'\n'"${namespace_observed_definition}"$'\n''namespace=cs-m2c5-fixture
kctl() {
  case "${NAMESPACE_STATE}" in
    absent) return 0 ;;
    present) printf "%s" "11111111-1111-1111-1111-111111111111" ;;
    error) return 1 ;;
  esac
}
namespace_uid_observed'
[[ -z "$(NAMESPACE_STATE=absent bash -c "${namespace_state_program}")" ]] || fail 'NotFound did not map to confirmed namespace absence'
[[ "$(NAMESPACE_STATE=present bash -c "${namespace_state_program}")" == '11111111-1111-1111-1111-111111111111' ]] || fail 'present namespace UID was not observed'
if NAMESPACE_STATE=error bash -c "${namespace_state_program}" >/dev/null 2>&1; then
  fail 'Kubernetes API failure was treated as namespace absence'
fi

cleanup_definition="$(awk '/^cleanup_namespace\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${cleanup_definition}" ]] || fail 'namespace cleanup is not independently testable'
uid_mismatch_program=$'set -euo pipefail\n'"${validation_error_definition}"$'\n'"${cleanup_definition}"$'\n''namespace=cs-m2c5-fixture
namespace_uid_observed() { printf "%s" "11111111-1111-1111-1111-111111111111"; }
owned_namespace_uid() { printf "%s" "22222222-2222-2222-2222-222222222222"; }
validate_namespace_identity() { return 0; }
validate_namespace_inventory() { return 0; }
kctl() { printf "delete-called\n" >>"$DELETE_LOG"; }
cleanup_namespace no'
delete_log="$(mktemp)"
if DELETE_LOG="${delete_log}" bash -c "${uid_mismatch_program}" >/dev/null 2>&1; then
  fail 'namespace cleanup accepted a replacement namespace UID'
fi
[[ ! -s "${delete_log}" ]] || fail 'namespace cleanup issued a delete after UID mismatch'
rm -f "${delete_log}"

acquire_lease_definition="$(awk '/^acquire_posture_lease\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
validate_lease_definition="$(awk '/^validate_posture_lease\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
release_lease_definition="$(awk '/^release_posture_lease\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${acquire_lease_definition}" && -n "${validate_lease_definition}" && -n "${release_lease_definition}" ]] ||
  fail 'response-posture lease is not independently testable'
lease_program=$'set -euo pipefail\n'"${validation_error_definition}"$'\n'"${acquire_lease_definition}"$'\n'"${validate_lease_definition}"$'\n'"${release_lease_definition}"$'\n''posture_lease_acquired=0
posture_lock_root="$LEASE_ROOT"
posture_lock_file="${posture_lock_root}/canarysting-response-posture.lock"
stat() {
  case "$*" in
    *"%a"*) printf "600\n" ;;
    *"%d:%i"*) printf "1:2\n" ;;
    *) return 1 ;;
  esac
}
flock() { [[ "${LOCK_BUSY:-0}" == 0 ]]; }
acquire_posture_lease
release_posture_lease'
lease_root="$(mktemp -d)"
LEASE_ROOT="${lease_root}" LOCK_BUSY=0 bash -c "${lease_program}" >/dev/null || fail 'response-posture lease rejected an exclusive acquisition'
if LEASE_ROOT="${lease_root}" LOCK_BUSY=1 bash -c "${lease_program}" >/dev/null 2>&1; then
  fail 'response-posture lease accepted a simulated concurrent holder'
fi
rm -f "${lease_root}/canarysting-response-posture.lock"
rmdir "${lease_root}"

passive_definition="$(awk '/^validate_passive_posture\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { exit }' "${remote_script}")"
[[ -n "${passive_definition}" ]] || fail 'passive-posture validator is not independently testable'
passive_program=$'set -euo pipefail\n''fail() { printf "%s\n" "$*" >&2; return 1; }'$'\n'"${passive_definition}"$'\n''namespace=cs-m2c5-fixture fixture_name=initial-fixture
kctl() {
  [[ "${KCTL_FAIL:-0}" == 0 ]] || return 1
  case "$*" in
    "get all,networkpolicy -A -l app.kubernetes.io/part-of=canarysting "*) printf "%s" "${K8S_OUTPUT:-}" ;;
    "get cnp,ccnp -A -l app.kubernetes.io/part-of=canarysting "*)
      [[ "${CILIUM_FAIL:-0}" == 0 ]] || return 1
      printf "%s" "${CILIUM_OUTPUT:-}"
      ;;
    *) return 1 ;;
  esac
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
fixture_passive_program="${passive_program%validate_passive_posture}"$'validate_passive_posture yes'
K8S_OUTPUT=$'cs-m2c5-fixture\tPod/initial-fixture\ncs-m2c5-fixture\tService/initial-fixture' \
  bash -c "${fixture_passive_program}" || fail 'passive-posture validator rejected only its owned fixture during execution'
for unsafe in kctl cilium-api cilium-policy ps runtime bpf; do
  case "${unsafe}" in
    kctl) environment=(KCTL_FAIL=1) ;;
    cilium-api) environment=(CILIUM_FAIL=1) ;;
    cilium-policy) environment=(CILIUM_OUTPUT=$'\tCiliumClusterwideNetworkPolicy/canarysting-deny') ;;
    ps) environment=(PS_FAIL=1) ;;
    runtime) environment=(PS_OUTPUT=engine) ;;
    bpf) environment=(BPF_OUTPUT='1: sock_ops name canary_sockops') ;;
  esac
  if env "${environment[@]}" bash -c "${passive_program}" >/dev/null 2>&1; then
    fail "passive-posture validator accepted unsafe ${unsafe} state"
  fi
done

printf 'PASS: DGX reproducible attacker scenario harness contract\n'
