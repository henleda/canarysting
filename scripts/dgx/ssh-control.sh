#!/usr/bin/env bash

# Opens one bounded, host-key-verified control connection before any DGX
# profile can mutate remote state. Failed attempts cannot have transferred or
# executed a profile, so retry is safe; after success, the batch reuses only
# this connection.
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
      -o ControlMaster=yes \
      -o ControlPersist=1200 \
      -o "ControlPath=${control_path}" \
      -o ServerAliveInterval=5 \
      -o ServerAliveCountMax=3 \
      -N -f falcon1; then
      if "${CANARYSTING_DGX_REAL_SSH}" \
        -o "ControlPath=${control_path}" \
        -O check falcon1 >/dev/null 2>&1; then
        return 0
      fi
      "${CANARYSTING_DGX_REAL_SSH}" \
        -o "ControlPath=${control_path}" \
        -O exit falcon1 >/dev/null 2>&1 || true
    else
      "${CANARYSTING_DGX_REAL_SSH}" \
        -o "ControlPath=${control_path}" \
        -O exit falcon1 >/dev/null 2>&1 || true
    fi
    if ((attempt < max_attempts)); then
      printf 'dgx-ssh: bootstrap attempt %d/%d failed before remote mutation; retrying\n' \
        "${attempt}" "${max_attempts}" >&2
      sleep "$((attempt * 2))"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}
