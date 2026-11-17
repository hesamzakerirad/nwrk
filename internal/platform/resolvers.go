// Package platform holds the operating system specific parts of nw behind
// narrow interfaces.
package platform

import (
	"io"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// SystemResolvers returns the DNS servers the operating system is
// configured to use, as host:port, in the order it would try them.
// An empty result with a nil error means none are configured.
func SystemResolvers() ([]string, error) { return systemResolvers() }

// ParseResolvConf extracts the name servers from resolv.conf text.
func ParseResolvConf(r io.Reader) ([]string, error) {
	cfg, err := dns.ClientConfigFromReader(r)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range cfg.Servers {
		a, err := netip.ParseAddr(stripZone(s))
		if err != nil {
			continue
		}
		out = append(out, net.JoinHostPort(a.String(), cfg.Port))
	}
	return out, nil
}

// stripZone drops an IPv6 zone such as %en0, which link-local servers carry.
func stripZone(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			return s[:i]
		}
	}
	return s
}
