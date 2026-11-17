package path

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// tcpPinger measures how long a TCP connection takes to open. It needs no
// privileges and works through most filters that drop ICMP.
type tcpPinger struct{ port int }

// NewTCPPinger returns a pinger that times TCP connects to port.
func NewTCPPinger(port int) Pinger { return &tcpPinger{port: port} }

func (p *tcpPinger) Name() string { return MethodTCP }
func (p *tcpPinger) Close() error { return nil }

func (p *tcpPinger) Ping(ctx context.Context, addr netip.Addr, _ int, timeout time.Duration) (time.Duration, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(c, "tcp", netip.AddrPortFrom(addr.Unmap(), uint16(p.port)).String())
	d := time.Since(start)
	if err != nil {
		// A refusal still shows the host is up and the path works.
		if isRefused(err) {
			return d, nil
		}
		return 0, err
	}
	_ = conn.Close()
	return d, nil
}

// icmpPinger sends ICMP echo requests over an unprivileged datagram socket
// where the system allows it, else over a raw socket.
type icmpPinger struct {
	conn *icmp.PacketConn
	v6   bool
	udp  bool
	id   int
}

// NewICMPPinger opens an ICMP socket for addr. It returns an error wrapping
// ErrPrivilege, with what would allow it, when the system refuses.
func NewICMPPinger(addr netip.Addr) (Pinger, error) {
	v6 := addr.Unmap().Is6()
	udpNet, rawNet, listen := "udp4", "ip4:icmp", "0.0.0.0"
	if v6 {
		udpNet, rawNet, listen = "udp6", "ip6:ipv6-icmp", "::"
	}
	// Datagram ICMP needs no privilege on macOS and on Linux when the
	// group is allowed by net.ipv4.ping_group_range. Windows has no such
	// socket, so it goes straight to the raw one.
	conn, err := icmp.ListenPacket(udpNet, listen)
	udp := true
	if err != nil {
		conn, err = icmp.ListenPacket(rawNet, listen)
		udp = false
	}
	if err != nil {
		return nil, fmt.Errorf("ICMP echo is %w: %v (on Linux, allow your group in net.ipv4.ping_group_range or run with CAP_NET_RAW; on macOS and Windows an administrator may be needed for raw sockets)", ErrPrivilege, err)
	}
	return &icmpPinger{conn: conn, v6: v6, udp: udp, id: os.Getpid() & 0xffff}, nil
}

func (p *icmpPinger) Name() string { return MethodICMP }
func (p *icmpPinger) Close() error { return p.conn.Close() }

func (p *icmpPinger) Ping(ctx context.Context, addr netip.Addr, seq int, timeout time.Duration) (time.Duration, error) {
	typ := icmp.Type(ipv4.ICMPTypeEcho)
	proto := 1
	if p.v6 {
		typ, proto = ipv6.ICMPTypeEchoRequest, 58
	}
	wire, err := (&icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: p.id, Seq: seq, Data: []byte("nw path ping")}}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	var dst net.Addr = &net.IPAddr{IP: addr.Unmap().AsSlice()}
	if p.udp {
		dst = &net.UDPAddr{IP: addr.Unmap().AsSlice()}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = p.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = p.conn.SetDeadline(time.Now()) })
	defer stop()

	start := time.Now()
	if _, err := p.conn.WriteTo(wire, dst); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		reply := msg.Type == ipv4.ICMPTypeEchoReply || msg.Type == ipv6.ICMPTypeEchoReply
		if echo, ok := msg.Body.(*icmp.Echo); reply && ok && echo.Seq == seq {
			return time.Since(start), nil
		}
	}
}
