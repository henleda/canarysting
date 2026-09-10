#!/usr/bin/env bash

# Runs a multiplex control operation with a separate wall-clock watchdog. The
# OpenSSH ConnectTimeout does not bound a wedged local mux exchange, so the
# coordinator must own, terminate, and reap the control client itself.
dgx_run_ssh_control_operation() {
  local control_path="$1"
  local operation="$2"
  local timeout_seconds="$3"
  local command_pid=''
  local watchdog_pid=''
  local status=0

  case "${operation}" in
    check|exit) ;;
    *) return 2 ;;
  esac
  [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]] && ((timeout_seconds <= 10)) || return 2

  "${CANARYSTING_DGX_REAL_SSH}" \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o ConnectionAttempts=1 \
    -o StrictHostKeyChecking=yes \
    -o ProxyCommand=/usr/bin/false \
    -o ClearAllForwardings=yes \
    -o ForwardAgent=no \
    -o ForwardX11=no \
    -o GSSAPIDelegateCredentials=no \
    -o Tunnel=no \
    -o PermitLocalCommand=no \
    -o RequestTTY=no \
    -o ForkAfterAuthentication=no \
    -o "ControlPath=${control_path}" \
    -O "${operation}" falcon1 >/dev/null 2>&1 &
  command_pid=$!
  (
    sleep "${timeout_seconds}"
    kill -TERM "${command_pid}" 2>/dev/null || exit 0
    sleep 1
    kill -KILL "${command_pid}" 2>/dev/null || true
  ) &
  watchdog_pid=$!

  if wait "${command_pid}"; then
    status=0
  else
    status=$?
  fi
  kill -KILL "${watchdog_pid}" 2>/dev/null || true
  wait "${watchdog_pid}" 2>/dev/null || true
  return "${status}"
}

dgx_wait_before_ssh_retry() {
  sleep "$1"
}

dgx_remove_ssh_control_socket() {
  local control_path="$1"
  local control_root=''
  local root_mode=''

  [[ "${control_path}" == */ssh-control ]] || return 2
  control_root="${control_path%/ssh-control}"
  [[ -n "${control_root}" && "${control_root}" != '/' ]] || return 2
  [[ -d "${control_root}" && ! -L "${control_root}" && -O "${control_root}" ]] || return 2
  if root_mode="$(/usr/bin/stat -f '%Lp' "${control_root}" 2>/dev/null)"; then
    :
  elif root_mode="$(/usr/bin/stat -c '%a' "${control_root}" 2>/dev/null)"; then
    :
  else
    return 2
  fi
  [[ "${root_mode}" =~ ^0?700$ ]] || return 2
  if [[ -e "${control_path}" || -L "${control_path}" ]]; then
    [[ -S "${control_path}" && ! -L "${control_path}" && -O "${control_path}" ]] || return 1
    rm -f -- "${control_path}" || return 1
  fi
  [[ ! -e "${control_path}" && ! -L "${control_path}" ]]
}

dgx_terminate_ssh_master() {
  local master_pid="${CANARYSTING_DGX_SSH_MASTER_PID:-}"
  local watchdog_pid=''
  local wait_status=0

  [[ "${master_pid}" =~ ^[1-9][0-9]*$ ]] || return 2
  kill -TERM "${master_pid}" 2>/dev/null || true
  (
    sleep 1
    kill -KILL "${master_pid}" 2>/dev/null || true
  ) &
  watchdog_pid=$!
  if wait "${master_pid}" 2>/dev/null; then
    wait_status=0
  else
    wait_status=$?
  fi
  kill -KILL "${watchdog_pid}" 2>/dev/null || true
  wait "${watchdog_pid}" 2>/dev/null || true
  [[ "${wait_status}" -ne 127 ]] || return 1
  CANARYSTING_DGX_SSH_MASTER_PID=''
  return 0
}

dgx_close_ssh_control() {
  local control_path="$1"
  local operation_status=0

  if dgx_run_ssh_control_operation "${control_path}" exit 5; then
    :
  else
    operation_status=$?
  fi
  dgx_terminate_ssh_master || return 1
  dgx_remove_ssh_control_socket "${control_path}" || return 1
  return "${operation_status}"
}

# Opens one bounded, host-key-verified control connection before its DGX
# profile can mutate remote state. Failed attempts cannot have transferred or
# executed that profile, so retry is safe; after success, the profile reuses
# only this connection. Forwarding and credential delegation from the current
# network's SSH configuration are explicitly suppressed.
dgx_open_ssh_control() {
  local control_path="$1"
  local attempt=1
  local deadline=0
  local max_attempts=3

  CANARYSTING_DGX_SSH_MASTER_PID=''
  dgx_remove_ssh_control_socket "${control_path}" || return 1
  while ((attempt <= max_attempts)); do
    "${CANARYSTING_DGX_REAL_SSH}" \
    -o BatchMode=yes \
    -o ConnectTimeout=20 \
    -o ConnectionAttempts=1 \
    -o StrictHostKeyChecking=yes \
    -o ClearAllForwardings=yes \
    -o ForwardAgent=no \
    -o ForwardX11=no \
    -o GSSAPIDelegateCredentials=no \
    -o Tunnel=no \
    -o PermitLocalCommand=no \
    -o RequestTTY=no \
    -o ForkAfterAuthentication=no \
    -o ControlMaster=yes \
    -o ControlPersist=no \
    -o "ControlPath=${control_path}" \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=3 \
    -n -N falcon1 &
    CANARYSTING_DGX_SSH_MASTER_PID=$!
    deadline=$((SECONDS + 20))
    while ((SECONDS < deadline)); do
      if ! kill -0 "${CANARYSTING_DGX_SSH_MASTER_PID}" 2>/dev/null; then
        break
      fi
      if dgx_run_ssh_control_operation "${control_path}" check 5 &&
        kill -0 "${CANARYSTING_DGX_SSH_MASTER_PID}" 2>/dev/null; then
        return 0
      fi
      sleep 1
    done
    dgx_terminate_ssh_master || return 1
    dgx_remove_ssh_control_socket "${control_path}" || return 1
    if ((attempt < max_attempts)); then
      printf 'dgx-ssh: bootstrap attempt %d/%d failed before remote mutation; retrying\n' \
        "${attempt}" "${max_attempts}" >&2
      dgx_wait_before_ssh_retry "$((attempt * 2))"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}
