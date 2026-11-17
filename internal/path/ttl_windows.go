//go:build windows

package path

import (
	"syscall"
)

const (
	ipTTL           = 4  // IP_TTL
	ipv6UnicastHops = 4  // IPV6_UNICAST_HOPS
	ipprotoIP       = 0  // IPPROTO_IP
	ipprotoIPv6     = 41 // IPPROTO_IPV6
)

// ttlControl returns a dialer control function that sets the IP TTL (or the
// IPv6 hop limit) on the socket before it connects.
func ttlControl(ttl int, v6 bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if v6 {
				serr = syscall.SetsockoptInt(syscall.Handle(fd), ipprotoIPv6, ipv6UnicastHops, ttl)
				return
			}
			serr = syscall.SetsockoptInt(syscall.Handle(fd), ipprotoIP, ipTTL, ttl)
		})
		if err != nil {
			return err
		}
		return serr
	}
}
