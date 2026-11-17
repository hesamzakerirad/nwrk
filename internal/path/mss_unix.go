//go:build !windows

package path

import (
	"net"
	"syscall"
)

// segmentSize reads TCP_MAXSEG from the connection.
func segmentSize(c net.Conn) (int, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var mss int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		mss, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpMaxSeg)
	}); err != nil || serr != nil {
		return 0, false
	}
	return mss, true
}
