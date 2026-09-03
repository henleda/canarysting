//go:build !linux

package main

import (
	"fmt"
	"net"
)

func socketCookie(*net.TCPConn) (uint64, error) {
	return 0, fmt.Errorf("SO_COOKIE proof requires Linux")
}
