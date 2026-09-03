//go:build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func socketCookie(connection *net.TCPConn) (uint64, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, fmt.Errorf("SO_COOKIE: %w", socketErr)
	}
	return cookie, nil
}
