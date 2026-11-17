//go:build !windows

package path

import (
	"syscall"
)

// ttlControl returns a dialer control function that sets the IP TTL (or the
// IPv6 hop limit) on the socket before it connects.
func ttlControl(ttl int, v6 bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if v6 {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
				return
			}
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
		if err != nil {
			return err
		}
		return serr
	}
}
