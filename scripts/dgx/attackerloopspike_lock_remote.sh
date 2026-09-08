#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
proof_pid=''
terminate_proof_group() {
  local attempt
  trap - HUP INT TERM
  if [[ -n "${proof_pid}" ]] && kill -0 -- "-${proof_pid}" 2>/dev/null; then
    kill -TERM -- "-${proof_pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 250; attempt++)); do
      kill -0 -- "-${proof_pid}" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 -- "-${proof_pid}" 2>/dev/null; then
      kill -KILL -- "-${proof_pid}" 2>/dev/null || true
    fi
  fi
  if [[ -n "${proof_pid}" ]]; then
    wait "${proof_pid}" 2>/dev/null || true
    proof_pid=''
  fi
  exit 130
}

[[ "$(hostname)" == 'spark-5343' && "$(uname -m)" == 'aarch64' ]] || exit 70
for tool in bash cat chmod flock hostname id kill setsid sleep stat uname; do
  command -v "${tool}" >/dev/null 2>&1 || exit 71
done
lock_root="/run/user/$(id -u)"
[[ -d "${lock_root}" && ! -L "${lock_root}" && -O "${lock_root}" && -w "${lock_root}" ]] || exit 72
lock_file="${lock_root}/canarysting-ollama-qwen.lock"
[[ ! -L "${lock_file}" ]] || exit 73
exec 9>>"${lock_file}"
[[ -f "${lock_file}" && ! -L "${lock_file}" && -O "${lock_file}" ]] || exit 74
chmod 0600 "${lock_file}"
if ! flock -n 9; then
  printf 'model_lock=busy\n'
  exit 75
fi
printf 'model_lock=acquired\n'

supervise_proof() {
  local action='' run_id='' mode='' expected_model='' expected_model_id='' program_bytes='' extra=''
  local proof_program='' proof_status attempt
  if ! IFS=$'\t' read -r action run_id mode expected_model expected_model_id program_bytes extra; then
    return 0
  fi
  [[ "${action}" == 'execute' && -z "${extra}" ]] || fail 'invalid proof-supervisor request'
  [[ "${run_id}" =~ ^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$ ]] || fail 'invalid remote run ID'
  [[ "${mode}" == 'run' || "${mode}" == 'inspect' || "${mode}" == 'cleanup' ]] || fail 'invalid remote mode'
  [[ "${expected_model}" == 'qwen3-coder:30b-a3b-q8_0' && "${expected_model_id}" == '7b438a19895a' ]] ||
    fail 'unexpected model identity'
  [[ "${program_bytes}" =~ ^[0-9]+$ && "${program_bytes}" -ge 1 && "${program_bytes}" -le 32768 ]] ||
    fail 'invalid proof program size'

  IFS= read -r -N "${program_bytes}" proof_program || fail 'proof program was truncated'
  [[ "${#proof_program}" -eq "${program_bytes}" ]] || fail 'proof program size changed'
  trap terminate_proof_group HUP INT TERM
  setsid bash -c "${proof_program}" -- "${run_id}" "${mode}" "${expected_model}" "${expected_model_id}" &
  proof_pid=$!
  set +e
  wait "${proof_pid}"
  proof_status=$?
  set -e
  if kill -0 -- "-${proof_pid}" 2>/dev/null; then
    kill -TERM -- "-${proof_pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 250; attempt++)); do
      kill -0 -- "-${proof_pid}" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 -- "-${proof_pid}" 2>/dev/null; then
      kill -KILL -- "-${proof_pid}" 2>/dev/null || true
    fi
    proof_status=76
  fi
  proof_pid=''
  trap - HUP INT TERM
  printf 'remote_proof_status=%s\n' "${proof_status}"

  # Keep this flock-owning process alive while the caller independently proves
  # the model is unloaded and retires the recovery marker.
  cat >/dev/null
  return "${proof_status}"
}

supervise_proof
