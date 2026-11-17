package path

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// MTUResult is what nw path mtu can establish without privileges: the MTU of
// the interface the connection uses, and the maximum segment size the
// connection negotiated. It is a hint about the path, not a discovery of it.
type MTUResult struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Family  string `json:"family"`
	// InterfaceMTU is the MTU of the local interface carrying the connection.
	InterfaceMTU int `json:"interface_mtu"`
	// MSS is the maximum segment size of the connection, when the platform
	// reports it.
	MSS int `json:"mss,omitempty"`
	// ImpliedPathMTU is MSS plus the IP and TCP headers: the largest packet
	// the connection is willing to send.
	ImpliedPathMTU int `json:"implied_path_mtu,omitempty"`
	// Reduced is true when the implied MTU is clearly below the interface MTU.
	Reduced bool   `json:"reduced"`
	Note    string `json:"note"`
}

// MTU opens one TCP connection to addr:port and reports the interface MTU
// and the negotiated segment size.
func MTU(ctx context.Context, target string, addr netip.Addr, port int, timeout time.Duration) (*MTUResult, error) {
	addr = addr.Unmap()
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(c, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res := &MTUResult{Target: target, Address: addr.String(), Port: port, Family: "ipv4"}
	hdr := 40 // IPv4 (20) + TCP (20)
	if addr.Is6() {
		res.Family, hdr = "ipv6", 60
	}
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		res.InterfaceMTU = interfaceMTU(la.IP)
	}
	if mss, ok := segmentSize(conn); ok && mss > 0 {
		res.MSS = mss
		res.ImpliedPathMTU = mss + hdr
	}
	// Timestamps and other options take a few bytes per segment, so only a
	// clear gap counts as a reduction.
	if res.ImpliedPathMTU > 0 && res.InterfaceMTU > 0 && res.ImpliedPathMTU+40 < res.InterfaceMTU {
		res.Reduced = true
	}
	res.Note = mtuNote(res)
	return res, nil
}

func interfaceMTU(ip net.IP) int {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, ok := a.(*net.IPNet); ok && p.IP.Equal(ip) {
				return i.MTU
			}
		}
	}
	return 0
}

func mtuNote(r *MTUResult) string {
	base := "This is a hint, not a discovery: it reports the local interface MTU and the segment size the connection negotiated, with no probing of the path. Finding the exact path MTU needs packets with the Don't Fragment bit and ICMP feedback, which nw does not do."
	switch {
	case r.MSS == 0:
		return "This platform does not report the segment size of a connection. " + base
	case r.Reduced:
		return fmt.Sprintf("The connection uses packets of at most %d bytes while the interface allows %d. Tunnels, VPNs, PPPoE, or a device that clamps the segment size on the path or at the other end each produce this. ", r.ImpliedPathMTU, r.InterfaceMTU) + base
	}
	return "The negotiated segment size is consistent with the interface MTU. " + base
}
