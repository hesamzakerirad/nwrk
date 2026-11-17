package platform

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
)

// ErrUnsupported is returned, wrapped, when an inspection is not available
// on this operating system. Every such limit is listed in
// docs/platform-support.md.
var ErrUnsupported = errors.ErrUnsupported

// Address is one address of an interface.
type Address struct {
	CIDR   string `json:"cidr"`
	Family string `json:"family"` // "ipv4" or "ipv6"
	// Kind is "global", "private", "link-local" or "loopback".
	Kind string `json:"kind"`
}

// Interface is one network interface.
type Interface struct {
	Name         string    `json:"name"`
	Index        int       `json:"index"`
	MTU          int       `json:"mtu"`
	Up           bool      `json:"up"`
	Loopback     bool      `json:"loopback"`
	PointToPoint bool      `json:"point_to_point"`
	Addresses    []Address `json:"addresses"`
}

// Usable reports whether the interface can carry traffic off this machine:
// it is up, is not loopback, and has an address that is not link-local.
func (i Interface) Usable() bool {
	if !i.Up || i.Loopback {
		return false
	}
	for _, a := range i.Addresses {
		if a.Kind == "global" || a.Kind == "private" {
			return true
		}
	}
	return false
}

// Route is one entry of the routing table.
type Route struct {
	Destination string `json:"destination"` // CIDR, or "default"
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	Family      string `json:"family"`
	Default     bool   `json:"default"`
}

// DNSConfig is the resolver configuration of the operating system.
type DNSConfig struct {
	Servers       []string `json:"servers"`
	SearchDomains []string `json:"search_domains,omitempty"`
	// Source says where the configuration was read from.
	Source string `json:"source"`
}

// ProxySetting is one proxy that applications on this machine may use.
// Credentials are never kept.
type ProxySetting struct {
	// Source is an environment variable name, or the settings store.
	Source string `json:"source"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
	// NoProxy is the exclusion list, for NO_PROXY.
	NoProxy string `json:"no_proxy,omitempty"`
}

// Interfaces lists the network interfaces. It uses the operating system
// API, so it works the same everywhere.
func Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, i := range ifs {
		ni := Interface{
			Name:         i.Name,
			Index:        i.Index,
			MTU:          i.MTU,
			Up:           i.Flags&net.FlagUp != 0,
			Loopback:     i.Flags&net.FlagLoopback != 0,
			PointToPoint: i.Flags&net.FlagPointToPoint != 0,
			Addresses:    []Address{},
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				ni.Addresses = append(ni.Addresses, describeAddr(p))
			}
		}
		out = append(out, ni)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	return out, nil
}

func describeAddr(p netip.Prefix) Address {
	a := p.Addr().Unmap()
	fam := "ipv4"
	if a.Is6() {
		fam = "ipv6"
	}
	return Address{CIDR: netip.PrefixFrom(a, p.Bits()).String(), Family: fam, Kind: AddrKind(a)}
}

// AddrKind classifies an address as "global", "private", "link-local" or
// "loopback".
func AddrKind(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "link-local"
	case a.IsPrivate(), isCGNAT(a):
		return "private"
	}
	return "global"
}

// isCGNAT reports the shared address space 100.64.0.0/10 (RFC 6598), which
// carrier-grade NAT uses. It is not globally routable.
func isCGNAT(a netip.Addr) bool {
	return a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// Routes returns the routing table. See docs/platform-support.md for where
// it is not available.
func Routes() ([]Route, error) { return routes() }

// DNS returns the operating system's resolver configuration.
func DNS() (DNSConfig, error) { return dnsConfig() }

// Proxies returns the proxies applications may use, from the environment
// and, where the platform has one, the system settings.
func Proxies() []ProxySetting {
	out := ProxiesFromEnv(os.Getenv)
	return append(out, systemProxies()...)
}

// proxyVars are the environment variables the common tools honor.
var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// ProxiesFromEnv reads proxy settings from environment variables, in either
// case. Credentials in the values are dropped.
func ProxiesFromEnv(getenv func(string) string) []ProxySetting {
	var out []ProxySetting
	for _, name := range proxyVars {
		v := getenv(name)
		if v == "" {
			v = getenv(strings.ToLower(name))
		}
		if v == "" {
			continue
		}
		if name == "NO_PROXY" {
			out = append(out, ProxySetting{Source: name, NoProxy: v})
			continue
		}
		scheme, host := splitProxy(v)
		out = append(out, ProxySetting{Source: name, Scheme: scheme, Host: host})
	}
	return out
}

// splitProxy returns the scheme and host:port of a proxy value, without any
// user name or password.
func splitProxy(v string) (scheme, host string) {
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return "", "(unparsable)"
	}
	return u.Scheme, u.Host
}
