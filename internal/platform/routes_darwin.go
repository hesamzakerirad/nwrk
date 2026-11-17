//go:build darwin

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

func routes() ([]Route, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names[i.Index] = i.Name
		}
	}
	var out []Route
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dst, gw := rm.Addrs[syscall.RTAX_DST], rm.Addrs[syscall.RTAX_GATEWAY]
		if dst == nil {
			continue
		}
		r := Route{Interface: names[rm.Index]}
		var da netip.Addr
		switch a := dst.(type) {
		case *route.Inet4Addr:
			da, r.Family = netip.AddrFrom4(a.IP), "ipv4"
		case *route.Inet6Addr:
			da, r.Family = netip.AddrFrom16(a.IP), "ipv6"
		default:
			continue
		}
		bits := prefixBits(rm.Addrs[syscall.RTAX_NETMASK], da.Is4())
		switch g := gw.(type) {
		case *route.Inet4Addr:
			r.Gateway = netip.AddrFrom4(g.IP).String()
		case *route.Inet6Addr:
			r.Gateway = netip.AddrFrom16(g.IP).String()
		}
		r.Default = da.IsUnspecified() && bits == 0
		if r.Default {
			r.Destination = "default"
		} else {
			r.Destination = fmt.Sprintf("%s/%d", da, bits)
		}
		out = append(out, r)
	}
	return out, nil
}

func prefixBits(mask route.Addr, v4 bool) int {
	switch m := mask.(type) {
	case *route.Inet4Addr:
		ones, _ := net.IPMask(m.IP[:]).Size()
		return ones
	case *route.Inet6Addr:
		ones, _ := net.IPMask(m.IP[:]).Size()
		return ones
	}
	if v4 {
		return 32
	}
	return 128
}
