package path

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// tcpProber connects with a limited TTL. It needs no privileges, but it can
// only tell whether the destination answered at a given TTL: the routers
// that drop the probe on the way are not visible to an unprivileged socket.
type tcpProber struct {
	addr netip.Addr
	port int
}

// NewTCPProber returns a prober that opens TCP connections with a limited
// TTL to addr:port.
func NewTCPProber(addr netip.Addr, port int) Prober {
	return &tcpProber{addr: addr.Unmap(), port: port}
}

func (p *tcpProber) Name() string      { return MethodTCP }
func (p *tcpProber) SeesRouters() bool { return false }
func (p *tcpProber) Close() error      { return nil }

func (p *tcpProber) Probe(ctx context.Context, ttl int, timeout time.Duration) (ProbeReply, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{Control: ttlControl(ttl, p.addr.Is6())}
	start := time.Now()
	conn, err := d.DialContext(c, "tcp", netip.AddrPortFrom(p.addr, uint16(p.port)).String())
	rtt := time.Since(start)
	if err != nil {
		// A refusal means the host answered, so the destination was reached.
		if isRefused(err) {
			return ProbeReply{RTT: rtt, Reached: true}, nil
		}
		return ProbeReply{}, err
	}
	_ = conn.Close()
	return ProbeReply{RTT: rtt, Reached: true}, nil
}

// icmpProber sends echo requests with a limited TTL over a raw socket and
// reads the Time Exceeded messages that routers send back. It needs
// privileges: root or CAP_NET_RAW on Linux and macOS.
type icmpProber struct {
	conn *icmp.PacketConn
	addr netip.Addr
	v6   bool
	id   int
	seq  int
}

// NewICMPProber opens a raw ICMP socket for addr. It returns an error
// wrapping ErrPrivilege when the system refuses, and ErrUnsupported on
// Windows, where the raw socket cannot read router replies reliably.
func NewICMPProber(addr netip.Addr) (Prober, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("listing routers with ICMP is %w on Windows: use the TCP method", ErrUnsupported)
	}
	addr = addr.Unmap()
	network, listen := "ip4:icmp", "0.0.0.0"
	if addr.Is6() {
		network, listen = "ip6:ipv6-icmp", "::"
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return nil, fmt.Errorf("listing routers with ICMP is %w: %v (run with administrator privileges: root or CAP_NET_RAW)", ErrPrivilege, err)
	}
	return &icmpProber{conn: conn, addr: addr, v6: addr.Is6(), id: os.Getpid() & 0xffff}, nil
}

func (p *icmpProber) Name() string      { return MethodICMP }
func (p *icmpProber) SeesRouters() bool { return true }
func (p *icmpProber) Close() error      { return p.conn.Close() }

func (p *icmpProber) setTTL(ttl int) error {
	if p.v6 {
		return ipv6.NewPacketConn(p.conn).SetHopLimit(ttl)
	}
	return ipv4.NewPacketConn(p.conn).SetTTL(ttl)
}

func (p *icmpProber) Probe(ctx context.Context, ttl int, timeout time.Duration) (ProbeReply, error) {
	if err := p.setTTL(ttl); err != nil {
		return ProbeReply{}, err
	}
	p.seq++
	typ, proto := icmp.Type(ipv4.ICMPTypeEcho), 1
	if p.v6 {
		typ, proto = ipv6.ICMPTypeEchoRequest, 58
	}
	wire, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: p.id, Seq: p.seq, Data: []byte("nw path trace")}}).Marshal(nil)
	if err != nil {
		return ProbeReply{}, err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = p.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = p.conn.SetDeadline(time.Now()) })
	defer stop()

	start := time.Now()
	if _, err := p.conn.WriteTo(wire, &net.IPAddr{IP: p.addr.AsSlice()}); err != nil {
		return ProbeReply{}, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return ProbeReply{}, err
		}
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		fromAddr := netip.Addr{}
		if ip, ok := from.(*net.IPAddr); ok {
			fromAddr, _ = netip.AddrFromSlice(ip.IP)
		}
		rtt := time.Since(start)
		switch body := msg.Body.(type) {
		case *icmp.Echo:
			if (msg.Type == ipv4.ICMPTypeEchoReply || msg.Type == ipv6.ICMPTypeEchoReply) && body.ID == p.id && body.Seq == p.seq {
				return ProbeReply{From: fromAddr, RTT: rtt, Reached: true}, nil
			}
		case *icmp.TimeExceeded:
			if matches(body.Data, p.id, p.seq, p.v6) {
				return ProbeReply{From: fromAddr, RTT: rtt}, nil
			}
		case *icmp.DstUnreach:
			if matches(body.Data, p.id, p.seq, p.v6) {
				return ProbeReply{From: fromAddr, RTT: rtt, Reached: true}, nil
			}
		}
	}
}

// matches checks that the original packet quoted inside an ICMP error is
// our echo request.
func matches(quoted []byte, id, seq int, v6 bool) bool {
	hdr := 20
	if v6 {
		hdr = 40
	} else if len(quoted) > 0 {
		hdr = int(quoted[0]&0x0f) * 4
	}
	if len(quoted) < hdr+8 {
		return false
	}
	icmpHdr := quoted[hdr:]
	return int(icmpHdr[4])<<8|int(icmpHdr[5]) == id && int(icmpHdr[6])<<8|int(icmpHdr[7]) == seq
}
