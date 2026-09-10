#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

run_id="$1"
mode="$2"
[[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,42}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
[[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || fail 'unexpected scenario host'
for tool in awk bpftool cmp date env find grep hostname id mkdir mv ps rm rmdir sha256sum sort stat sudo timeout tr uname wc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing remote prerequisite: ${tool}"
done

kctl() { sudo -n k3s kubectl "$@"; }

root='/var/tmp/canarysting'
stage="${root}/${run_id}"
evidence="${root}/execution-${run_id}"
working="${root}/.attackerscenario-${run_id}"
namespace="cs-m2c5-${run_id}"
artifact_relative='test/attackerscenariospike'
artifact="${stage}/${artifact_relative}"
scenario_id='m2c5-initial-journey'
fixture_name='initial-fixture'
image='docker.io/rancher/mirrored-pause@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4'
readonly root stage evidence working namespace artifact_relative artifact scenario_id fixture_name image

namespace_label() {
  kctl get namespace "${namespace}" -o "jsonpath={.metadata.labels.canarysting\\.dev/$1}"
}

validate_namespace_identity() {
  [[ "$(namespace_label run-id)" == "${run_id}" ]] || fail 'namespace run label does not match'
  [[ "$(namespace_label fixture)" == "${fixture_name}" ]] || fail 'namespace fixture label does not match'
  local uid
  uid="$(kctl get namespace "${namespace}" -o jsonpath='{.metadata.uid}')"
  [[ "${uid}" =~ ^[0-9a-f-]{36}$ ]] || fail 'namespace UID is malformed'
  if [[ -f "${working}/namespace.uid" ]]; then
    [[ "$(<"${working}/namespace.uid")" == "${uid}" ]] || fail 'namespace UID changed after acquisition'
  fi
}

validate_namespace_inventory() {
  local require_fixture="$1" entry actual has_pod=0 has_service=0
  actual="$(kctl -n "${namespace}" get all,configmap,serviceaccount,networkpolicy,role,rolebinding -o name | LC_ALL=C sort -u)"
  while IFS= read -r entry; do
    [[ -z "${entry}" ]] && continue
    case "${entry}" in
      configmap/kube-root-ca.crt|serviceaccount/default) ;;
      pod/${fixture_name}) has_pod=1 ;;
      service/${fixture_name}) has_service=1 ;;
      *) fail "namespace contains an undeclared resource: ${entry}" ;;
    esac
  done <<<"${actual}"
  if [[ "${require_fixture}" == 'yes' ]]; then
    ((has_pod == 1 && has_service == 1)) || fail 'namespace fixture inventory is incomplete'
  fi
  for resource in pod/${fixture_name} service/${fixture_name}; do
    if kctl -n "${namespace}" get "${resource}" >/dev/null 2>&1; then
      [[ "$(kctl -n "${namespace}" get "${resource}" -o 'jsonpath={.metadata.labels.canarysting\.dev/run-id}')" == "${run_id}" ]] ||
        fail "resource run label does not match: ${resource}"
      [[ "$(kctl -n "${namespace}" get "${resource}" -o 'jsonpath={.metadata.labels.canarysting\.dev/fixture}')" == "${fixture_name}" ]] ||
        fail "resource fixture label does not match: ${resource}"
    fi
  done
}

cleanup_namespace() {
  local require_fixture="$1"
  if ! kctl get namespace "${namespace}" >/dev/null 2>&1; then
    printf 'scenario_namespace=absent\n'
    return 0
  fi
  validate_namespace_identity
  validate_namespace_inventory "${require_fixture}"
  kctl delete namespace "${namespace}" --wait=true --timeout=90s >/dev/null
  ! kctl get namespace "${namespace}" >/dev/null 2>&1 || fail 'scenario namespace remained after deletion'
  printf 'scenario_namespace_removed=%s\n' "${namespace}"
}

cleanup_working() {
  local entry
  if [[ ! -e "${working}" && ! -L "${working}" ]]; then
    printf 'scenario_workspace=absent\n'
    return 0
  fi
  [[ -d "${working}" && ! -L "${working}" && -O "${working}" ]] || fail 'partial scenario workspace is unsafe'
  while IFS= read -r entry; do
    case "${entry}" in
      f:namespace.uid|f:corpus-1.json|f:corpus-2.json|f:proof-1.log|f:proof-2.log|f:fixture.log|f:result.tsv|f:.result.tsv.tmp) ;;
      *) fail "partial scenario workspace contains an undeclared entry: ${entry}" ;;
    esac
  done < <(cd "${working}" && find . -mindepth 1 -printf '%y:%P\n' | LC_ALL=C sort)
  find "${working}" -mindepth 1 -maxdepth 1 -type f -user "$(id -un)" -exec rm -f -- {} +
  rmdir "${working}"
  printf 'scenario_workspace_removed=%s\n' "${working}"
}

validate_passive_posture() {
  local canarysting_resources host_processes bpf_programs
  canarysting_resources="$(kctl get all,networkpolicy -A -l app.kubernetes.io/part-of=canarysting -o name)" ||
    fail 'unable to inventory CanarySting Kubernetes runtime state'
  [[ -z "${canarysting_resources}" ]] ||
    fail 'CanarySting Kubernetes runtime is present; passive posture is not proven'
  host_processes="$(ps -eo comm=)" || fail 'unable to inventory host process state'
  if grep -Eq '^[[:space:]]*(engine|envoy-adapter|canarysting[^[:space:]]*)[[:space:]]*$' <<<"${host_processes}"; then
    fail 'CanarySting host runtime is present; passive posture is not proven'
  fi
  bpf_programs="$(sudo -n bpftool prog show)" || fail 'unable to inventory eBPF program state'
  [[ -z "$(grep -Ei 'canary_sockops|enforce_(egress|release)' <<<"${bpf_programs}" || true)" ]] ||
    fail 'CanarySting eBPF response program is present; passive posture is not proven'
}

if [[ "${mode}" == 'cleanup' ]]; then
  cleanup_namespace no
  cleanup_working
  printf 'PASS: reproducible attacker scenario cleanup completed\n'
  exit 0
fi

[[ -d "${root}" && ! -L "${root}" && -O "${root}" && -w "${root}" ]] || fail 'remote root is unsafe'
[[ -d "${stage}" && ! -L "${stage}" && -O "${stage}" ]] || fail 'run stage is unsafe'
[[ -f "${stage}/manifest.tsv" && ! -L "${stage}/manifest.tsv" && -O "${stage}/manifest.tsv" ]] || fail 'manifest is unsafe'
artifact_metadata="$(awk -F '\t' -v wanted="${artifact_relative}" '
  $1 == "artifact" && $4 == wanted { count++; size=$5; digest=$6 }
  END { if (count != 1) exit 1; print size "\t" digest }
' "${stage}/manifest.tsv")" || fail 'manifest must contain exactly one attacker-scenario artifact'
IFS=$'\t' read -r expected_size expected_sha256 <<<"${artifact_metadata}"
[[ "${expected_size}" =~ ^[0-9]+$ && "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact metadata is malformed'
[[ -f "${artifact}" && ! -L "${artifact}" && -O "${artifact}" && -x "${artifact}" ]] || fail 'scenario artifact is unsafe'
[[ "$(stat -c %s "${artifact}")" == "${expected_size}" ]] || fail 'scenario artifact size changed'
[[ "$(sha256sum "${artifact}" | awk '{print $1}')" == "${expected_sha256}" ]] || fail 'scenario artifact checksum changed'

manifest_value() {
  awk -F '\t' -v wanted="$1" '$1 == "metadata" && $2 == wanted { count++; value=$3 } END { if (count != 1) exit 1; print value }' "${stage}/manifest.tsv"
}
source_revision="$(manifest_value source_revision)" || fail 'source revision is missing or duplicated'
source_state="$(manifest_value source_state)" || fail 'source state is missing or duplicated'
source_tree_sha256="$(manifest_value source_tree_sha256)" || fail 'source-tree checksum is missing or duplicated'
[[ "${source_revision}" =~ ^[0-9a-f]{40}$ && ( "${source_state}" == 'clean' || "${source_state}" == 'dirty' ) && "${source_tree_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'source identity is malformed'
readonly expected_sha256 source_revision source_state source_tree_sha256

result_value() {
  awk -F '\t' -v wanted="$2" '$1 == wanted { count++; value=$2 } END { if (count != 1) exit 1; print value }' "$1"
}

validate_proof() {
  awk '
    NR == 1 { good=($0 ~ /^PROOF scenario=PASS id=m2c5-initial-journey version=1 scenario_sha256=[0-9a-f]{64}$/) }
    NR == 2 { good=good && ($0 ~ /^PROOF journey=PASS steps=5 intents=5 actions=5 semantic_sha256=[0-9a-f]{64}$/) }
    NR == 3 { good=good && ($0 == "PROOF isolation=PASS synthetic=true model_use=DISABLED address_retained=false credential_retained=false") }
    NR == 4 { good=good && ($0 == "PROOF safety=PASS model_execution=false kubernetes_authority=false shell_authority=false") }
    NR > 4 { good=0 }
    END { exit !(good && NR == 4) }
  ' "$1"
}

validate_corpus() {
  local path="$1" child_run="$2" service_ip="$3"
  [[ -f "${path}" && ! -L "${path}" && -O "${path}" && "$(stat -c %a "${path}")" == '600' ]] || return 1
  [[ "$(stat -c %s "${path}")" -gt 0 && "$(stat -c %s "${path}")" -le 1048576 ]] || return 1
  [[ "$(grep -F -c '"scenario_id": "m2c5-initial-journey"' "${path}")" -ge 1 ]] || return 1
  [[ "$(grep -F -c "\"run_id\": \"${child_run}\"" "${path}")" -ge 1 ]] || return 1
  [[ "$(grep -F -c '"status": "SUCCEEDED"' "${path}")" == '5' ]] || return 1
  [[ "$(grep -F -c '"record_kind": "ATTACKER_INTENT"' "${path}")" == '5' ]] || return 1
  [[ "$(grep -F -c '"record_kind": "ATTACKER_ACTION"' "${path}")" == '5' ]] || return 1
  ! grep -Fq 'fixture-secret' "${path}" || return 1
  ! grep -Fq 'Authorization' "${path}" || return 1
  if [[ -n "${service_ip}" ]] && grep -Fq "${service_ip}" "${path}"; then return 1; fi
}

validate_result() {
  local path="$1"
  awk -F '\t' -v run="${run_id}" -v expected_namespace="${namespace}" -v revision="${source_revision}" -v state="${source_state}" -v tree="${source_tree_sha256}" -v artifact="${expected_sha256}" '
    NR == 1 { good=($0 == "key\tvalue"); next }
    NF != 2 || seen[$1]++ { exit 1 }
    {
      known=1
      if ($1 == "format_version") good=good && ($2 == "1")
      else if ($1 == "run_id") good=good && ($2 == run)
      else if ($1 == "scenario_id") good=good && ($2 == "m2c5-initial-journey")
      else if ($1 == "scenario_version") good=good && ($2 == "1")
      else if ($1 == "profile") good=good && ($2 == "attacker-scenarios")
      else if ($1 == "namespace") good=good && ($2 == expected_namespace)
      else if ($1 == "namespace_uid") good=good && ($2 ~ /^[0-9a-f-]{36}$/)
      else if ($1 == "source_revision") good=good && ($2 == revision)
      else if ($1 == "source_state") good=good && ($2 == state)
      else if ($1 == "source_tree_sha256") good=good && ($2 == tree)
      else if ($1 == "artifact_sha256") good=good && ($2 == artifact)
      else if ($1 == "repeat_count") good=good && ($2 == "2")
      else if ($1 == "step_count") good=good && ($2 == "5")
      else if ($1 == "intent_count") good=good && ($2 == "10")
      else if ($1 == "action_count") good=good && ($2 == "10")
      else if ($1 == "fixture_event_count") good=good && ($2 == "12")
      else if ($1 == "semantic_stability") good=good && ($2 == "PASS")
      else if ($1 == "namespace_cleanup") good=good && ($2 == "PASS")
      else if ($1 == "sting_posture") good=good && ($2 == "not-deployed")
      else if ($1 == "secret_reads") good=good && ($2 == "false")
      else if ($1 == "model_execution") good=good && ($2 == "false")
      else if ($1 == "raw_fixture_log_retained") good=good && ($2 == "false")
      else if ($1 ~ /^(scenario_sha256|semantic_sha256|corpus_1_sha256|corpus_2_sha256|fixture_log_sha256|proof_sha256)$/) good=good && ($2 ~ /^[0-9a-f]{64}$/)
      else if ($1 ~ /^(started_utc|finished_utc|expires_utc)$/) good=good && ($2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/)
      else if ($1 == "status") good=good && ($2 == "PASS")
      else known=0
      good=good && known
    }
    END { exit !(good && NR == 33) }
  ' "${path}" || return 1
  local started finished expires now
  started="$(date -u -d "$(result_value "${path}" started_utc)" +%s)" || return 1
  finished="$(date -u -d "$(result_value "${path}" finished_utc)" +%s)" || return 1
  expires="$(date -u -d "$(result_value "${path}" expires_utc)" +%s)" || return 1
  now="$(date -u +%s)" || return 1
  ((started <= finished && finished - started <= 120 && expires - finished == 86400 && now < expires))
}

validate_evidence() {
  [[ -d "${evidence}" && ! -L "${evidence}" && -O "${evidence}" && "$(stat -c %a "${evidence}")" == '700' ]] || fail 'published evidence is unsafe'
  [[ "$(cd "${evidence}" && find . -mindepth 1 -maxdepth 1 -printf '%y:%P\n' | LC_ALL=C sort)" == $'f:corpus-1.json\nf:corpus-2.json\nf:proof.log\nf:result.tsv' ]] ||
    fail 'published evidence inventory is not exact'
  for file in corpus-1.json corpus-2.json proof.log result.tsv; do
    [[ -f "${evidence}/${file}" && ! -L "${evidence}/${file}" && -O "${evidence}/${file}" && "$(stat -c %a "${evidence}/${file}")" == '600' ]] ||
      fail "published evidence file is unsafe: ${file}"
    [[ "$(stat -c %s "${evidence}/${file}")" -le 1048576 ]] || fail "published evidence file is oversized: ${file}"
  done
  validate_proof "${evidence}/proof.log" || fail 'stable semantic proof is invalid'
  validate_corpus "${evidence}/corpus-1.json" "${run_id}-one" '' || fail 'first corpus is invalid'
  validate_corpus "${evidence}/corpus-2.json" "${run_id}-two" '' || fail 'second corpus is invalid'
  validate_result "${evidence}/result.tsv" || fail 'result schema or lifecycle is invalid'
  [[ "$(sha256sum "${evidence}/corpus-1.json" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" corpus_1_sha256)" ]] || fail 'first corpus checksum mismatch'
  [[ "$(sha256sum "${evidence}/corpus-2.json" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" corpus_2_sha256)" ]] || fail 'second corpus checksum mismatch'
  [[ "$(sha256sum "${evidence}/proof.log" | awk '{print $1}')" == "$(result_value "${evidence}/result.tsv" proof_sha256)" ]] || fail 'proof checksum mismatch'
  [[ ! -e "${working}" && ! -L "${working}" ]] || fail 'partial workspace remains after publication'
  ! kctl get namespace "${namespace}" >/dev/null 2>&1 || fail 'scenario namespace remains after publication'
}

if [[ "${mode}" == 'inspect' ]]; then
  validate_evidence
  printf 'PASS: reproducible attacker scenario evidence inspection passed\n'
  exit 0
fi

[[ ! -e "${evidence}" && ! -L "${evidence}" ]] || fail 'published evidence already exists'
[[ ! -e "${working}" && ! -L "${working}" ]] || fail 'partial scenario workspace already exists'
! kctl get namespace "${namespace}" >/dev/null 2>&1 || fail 'scenario namespace already exists'

# A canary touch is permitted only while the lab has no deployed CanarySting
# response path. Baseline/Kubernetes state can still observe the harmless flow.
validate_passive_posture

umask 077
mkdir -m 0700 "${working}"
cleanup_required=1
cleanup_on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if ((cleanup_required)); then
    cleanup_namespace no || status=1
    cleanup_working || status=1
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

started_epoch="$(date -u +%s)"
started_utc="$(date -u -d "@${started_epoch}" +%Y-%m-%dT%H:%M:%SZ)"

kctl create -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    app.kubernetes.io/part-of: canarysting
    canarysting.dev/run-id: ${run_id}
    canarysting.dev/fixture: ${fixture_name}
YAML
validate_namespace_identity
kctl get namespace "${namespace}" -o jsonpath='{.metadata.uid}' >"${working}/namespace.uid"
chmod 0600 "${working}/namespace.uid"

kctl -n "${namespace}" create -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${fixture_name}
  labels:
    app.kubernetes.io/name: canaryattacker-fixture
    app.kubernetes.io/part-of: canarysting
    canarysting.dev/run-id: ${run_id}
    canarysting.dev/fixture: ${fixture_name}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 5
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: fixture
      image: ${image}
      imagePullPolicy: Never
      command: [/fixture/attackerscenariospike, serve]
      ports:
        - name: http
          containerPort: 18080
          protocol: TCP
      readinessProbe:
        httpGet:
          path: /ready
          port: http
        periodSeconds: 1
        timeoutSeconds: 1
        failureThreshold: 30
      resources:
        requests:
          cpu: 10m
          memory: 8Mi
        limits:
          cpu: 100m
          memory: 32Mi
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: fixture-artifact
          mountPath: /fixture/attackerscenariospike
          readOnly: true
  volumes:
    - name: fixture-artifact
      hostPath:
        path: ${artifact}
        type: File
---
apiVersion: v1
kind: Service
metadata:
  name: ${fixture_name}
  labels:
    app.kubernetes.io/name: canaryattacker-fixture
    app.kubernetes.io/part-of: canarysting
    canarysting.dev/run-id: ${run_id}
    canarysting.dev/fixture: ${fixture_name}
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: canaryattacker-fixture
    canarysting.dev/run-id: ${run_id}
    canarysting.dev/fixture: ${fixture_name}
  ports:
    - name: http
      port: 18080
      targetPort: http
      protocol: TCP
YAML

validate_namespace_identity
validate_namespace_inventory yes
kctl -n "${namespace}" wait --for=condition=Ready "pod/${fixture_name}" --timeout=60s >/dev/null
service_ip="$(kctl -n "${namespace}" get "service/${fixture_name}" -o jsonpath='{.spec.clusterIP}')"
[[ "${service_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'fixture Service did not receive one IPv4 ClusterIP'

for iteration in 1 2; do
  child='one'
  [[ "${iteration}" == '1' ]] || child='two'
  (
    cd "${working}"
    ulimit -c 0
    ulimit -f 1024
    exec timeout --signal=TERM --kill-after=2s 25s \
      env -i LANG=C PATH=/usr/bin:/bin TZ=UTC \
      "${artifact}" run -run-id "${run_id}-${child}" -target-address "${service_ip}"
  ) >"${working}/corpus-${iteration}.json" 2>"${working}/proof-${iteration}.log"
  chmod 0600 "${working}/corpus-${iteration}.json" "${working}/proof-${iteration}.log"
  validate_proof "${working}/proof-${iteration}.log" || fail "run ${iteration} semantic proof is invalid"
  validate_corpus "${working}/corpus-${iteration}.json" "${run_id}-${child}" "${service_ip}" || fail "run ${iteration} corpus is invalid"
done
cmp -s "${working}/proof-1.log" "${working}/proof-2.log" || fail 'repeated runs changed scenario, intent, or action semantics'

kctl -n "${namespace}" logs "pod/${fixture_name}" >"${working}/fixture.log"
chmod 0600 "${working}/fixture.log"
expected_events=$'EVENT enumeration-root\nEVENT enumeration-catalog\nEVENT http-probe\nEVENT credential-accepted\nEVENT canary-discovered\nEVENT canary-touched\nEVENT enumeration-root\nEVENT enumeration-catalog\nEVENT http-probe\nEVENT credential-accepted\nEVENT canary-discovered\nEVENT canary-touched'
[[ "$(<"${working}/fixture.log")" == "${expected_events}" ]] || fail 'fixture request sequence is not exact and reproducible'
fixture_log_sha256="$(sha256sum "${working}/fixture.log" | awk '{print $1}')"
rm -f -- "${working}/fixture.log"

scenario_sha256="$(awk -F 'scenario_sha256=' 'NR == 1 {print $2}' "${working}/proof-1.log")"
semantic_sha256="$(awk -F 'semantic_sha256=' 'NR == 2 {print $2}' "${working}/proof-1.log")"
[[ "${scenario_sha256}" =~ ^[0-9a-f]{64}$ && "${semantic_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'semantic digests are malformed'
corpus_1_sha256="$(sha256sum "${working}/corpus-1.json" | awk '{print $1}')"
corpus_2_sha256="$(sha256sum "${working}/corpus-2.json" | awk '{print $1}')"
[[ "${corpus_1_sha256}" != "${corpus_2_sha256}" ]] || fail 'distinct run identities did not produce distinct content-bound corpora'

validate_namespace_identity
validate_namespace_inventory yes
namespace_uid="$(<"${working}/namespace.uid")"
[[ "${namespace_uid}" =~ ^[0-9a-f-]{36}$ ]] || fail 'captured namespace UID is malformed'
cleanup_namespace yes
validate_passive_posture

finished_epoch="$(date -u +%s)"
finished_utc="$(date -u -d "@${finished_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
expires_utc="$(date -u -d "@$((finished_epoch + 86400))" +%Y-%m-%dT%H:%M:%SZ)"
mv "${working}/proof-1.log" "${working}/proof.log"
rm -f -- "${working}/proof-2.log" "${working}/namespace.uid"
proof_sha256="$(sha256sum "${working}/proof.log" | awk '{print $1}')"
{
  printf 'key\tvalue\n'
  printf 'format_version\t1\nrun_id\t%s\nscenario_id\t%s\nscenario_version\t1\nprofile\tattacker-scenarios\n' "${run_id}" "${scenario_id}"
  printf 'namespace\t%s\nnamespace_uid\t%s\n' "${namespace}" "${namespace_uid}"
  printf 'source_revision\t%s\nsource_state\t%s\nsource_tree_sha256\t%s\nartifact_sha256\t%s\n' "${source_revision}" "${source_state}" "${source_tree_sha256}" "${expected_sha256}"
  printf 'repeat_count\t2\nstep_count\t5\nintent_count\t10\naction_count\t10\nfixture_event_count\t12\n'
  printf 'semantic_stability\tPASS\nnamespace_cleanup\tPASS\nsting_posture\tnot-deployed\nsecret_reads\tfalse\nmodel_execution\tfalse\nraw_fixture_log_retained\tfalse\n'
  printf 'scenario_sha256\t%s\nsemantic_sha256\t%s\ncorpus_1_sha256\t%s\ncorpus_2_sha256\t%s\nfixture_log_sha256\t%s\n' \
    "${scenario_sha256}" "${semantic_sha256}" "${corpus_1_sha256}" "${corpus_2_sha256}" "${fixture_log_sha256}"
  printf 'proof_sha256\t%s\nstarted_utc\t%s\nfinished_utc\t%s\nexpires_utc\t%s\nstatus\tPASS\n' \
    "${proof_sha256}" "${started_utc}" "${finished_utc}" "${expires_utc}"
} >"${working}/.result.tsv.tmp"
mv "${working}/.result.tsv.tmp" "${working}/result.tsv"
chmod 0600 "${working}/corpus-1.json" "${working}/corpus-2.json" "${working}/proof.log" "${working}/result.tsv"
mv "${working}" "${evidence}"
cleanup_required=0
validate_evidence
trap - EXIT INT TERM
printf 'PASS: reproducible attacker scenario proof completed\n'
printf 'evidence=%s\n' "${evidence}"
