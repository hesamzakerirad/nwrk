//go:build windows

package platform

import (
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dnsSource           = "adapter configuration (GetAdaptersAddresses)"
	resolvConfPathValue = ""
)

func joinPort(ip netip.Addr, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func systemResolvers() ([]string, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	size := uint32(15000)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}

	var out []string
	seen := map[string]bool{}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for ds := aa.FirstDnsServerAddress; ds != nil; ds = ds.Next {
			sa, err := ds.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			var ip netip.Addr
			switch a := sa.(type) {
			case *syscall.SockaddrInet4:
				ip = netip.AddrFrom4(a.Addr)
			case *syscall.SockaddrInet6:
				ip = netip.AddrFrom16(a.Addr)
			default:
				continue
			}
			// Windows lists the site-local placeholders fec0:0:0:ffff::1
			// to ::3 for adapters without IPv6 DNS; they answer nothing.
			if ip.Is6() && ip.As16()[0] == 0xfe && ip.As16()[1]&0xc0 == 0xc0 {
				continue
			}
			s := joinPort(ip, 53)
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}
