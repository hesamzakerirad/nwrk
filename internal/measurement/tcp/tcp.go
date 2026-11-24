// Package tcp measures whether a TCP connection to one address succeeds.
package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/errclass"
)

// Version is the implementation version recorded in every measurement.
const Version = "1"

// Result is the structured result of a TCP measurement.
type Result struct {
	Address   string  `json:"address"`
	Family    string  `json:"family"`
	ConnectMS float64 `json:"connect_ms"`
}

// Details describes the result in plain lines for the human report.
func (r *Result) Details() []string {
	return []string{fmt.Sprintf("connected to %s (%s) in %.1f ms", r.Address, r.Family, r.ConnectMS)}
}

// Dialer opens connections. *net.Dialer implements it; tests substitute
// their own.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Family names the IP family of a as "ipv4" or "ipv6".
func Family(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// Connect opens and closes a TCP connection to addr. host is the name the
// address was resolved from, kept for the record; it may be empty.
// A nil dialer means a default one. ctx carries the deadline.
func Connect(ctx context.Context, host string, addr netip.AddrPort, d Dialer) *domain.Measurement {
	if d == nil {
		d = &net.Dialer{}
	}
	ip := addr.Addr().Unmap()
	m := domain.Begin(domain.TypeTCP, Version, domain.Target{
		Host: host, IP: ip.String(), Port: int(addr.Port()), Family: Family(ip),
	})
	address := netip.AddrPortFrom(ip, addr.Port()).String()
	m.Params = map[string]any{"address": address}

	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", address)
	elapsed := time.Since(start)
	if err != nil {
		code := errclass.TCP(err)
		return m.Fail(code, message(code, address), nil)
	}
	_ = conn.Close()
	return m.Succeed(&Result{Address: address, Family: Family(ip), ConnectMS: domain.Millis(elapsed)})
}

func message(code domain.ErrorCode, address string) string {
	switch code {
	case domain.TCPRefused:
		return "connection to " + address + " was refused"
	case domain.TCPTimeout:
		return "no answer from " + address + " before the deadline"
	case domain.TCPUnreachable:
		return "no route to " + address
	case domain.TCPReset:
		return "connection to " + address + " was reset"
	}
	return "could not connect to " + address
}
