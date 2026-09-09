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
  kill -TERM "${watchdog_pid}" 2>/dev/null || true
  wait "${watchdog_pid}" 2>/dev/null || true
  return "${status}"
}

dgx_wait_before_ssh_retry() {
  sleep "$1"
}

# Opens one bounded, host-key-verified control connection before any DGX
# profile can mutate remote state. Failed attempts cannot have transferred or
# executed a profile, so retry is safe; after success, the batch reuses only
# this connection. Forwarding and credential delegation from the current
# network's SSH configuration are explicitly suppressed.
dgx_open_ssh_control() {
  local control_path="$1"
  local attempt=1
  local max_attempts=3

  while ((attempt <= max_attempts)); do
    if "${CANARYSTING_DGX_REAL_SSH}" \
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
      -o ControlMaster=yes \
      -o ControlPersist=1200 \
      -o "ControlPath=${control_path}" \
      -o ServerAliveInterval=5 \
      -o ServerAliveCountMax=3 \
      -N -f falcon1; then
      if dgx_run_ssh_control_operation "${control_path}" check 5; then
        return 0
      fi
      dgx_run_ssh_control_operation "${control_path}" exit 5 || true
    else
      dgx_run_ssh_control_operation "${control_path}" exit 5 || true
    fi
    if ((attempt < max_attempts)); then
      printf 'dgx-ssh: bootstrap attempt %d/%d failed before remote mutation; retrying\n' \
        "${attempt}" "${max_attempts}" >&2
      dgx_wait_before_ssh_retry "$((attempt * 2))"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}
