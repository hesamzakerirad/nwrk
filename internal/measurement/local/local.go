// Package local inspects this machine's own network setup: interfaces, a
// default route, configured resolvers and proxies. It is the "local" layer
// of nw doctor.
//
// Results record counts and kinds, not addresses, so a report can be
// shared without exposing the private addresses of the network.
package local

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/errclass"
	"github.com/hesamzakerirad/nwrk/internal/platform"
)

// Version is the implementation version recorded in every measurement.
const Version = "1"

// Checks are the names recorded in params.check.
const (
	CheckInterfaces = "interfaces"
	CheckRoute      = "route"
	CheckResolvers  = "resolvers"
	CheckProxy      = "proxy"
)

// Inspector reads the operating system. platform.System is the real one;
// tests supply their own.
type Inspector interface {
	Interfaces() ([]platform.Interface, error)
	DNS() (platform.DNSConfig, error)
	Proxies() []platform.ProxySetting
}

// System inspects the running operating system.
type System struct{}

func (System) Interfaces() ([]platform.Interface, error) { return platform.Interfaces() }
func (System) DNS() (platform.DNSConfig, error)          { return platform.DNS() }
func (System) Proxies() []platform.ProxySetting          { return platform.Proxies() }

var redacted = []string{"interface.addresses", "interface.names", "route.local_address", "resolver.addresses"}

func begin(check string) *domain.Measurement {
	m := domain.Begin(domain.TypeLocal, Version, domain.Target{})
	m.Scope = domain.ScopeLocal
	m.Params = map[string]any{"check": check}
	m.Redacted = redacted
	return m
}

// InterfacesResult summarizes the interfaces without their addresses.
type InterfacesResult struct {
	Total      int      `json:"total"`
	Up         int      `json:"up"`
	Usable     int      `json:"usable"`
	Families   []string `json:"families"`
	GlobalIPv6 bool     `json:"global_ipv6"`
}

// Details describes the result in plain lines for the human report.
func (r *InterfacesResult) Details() []string {
	return []string{
		fmt.Sprintf("%d interfaces, %d up, %d able to reach beyond this machine", r.Total, r.Up, r.Usable),
		"address families: " + orNone(r.Families),
	}
}

// Interfaces checks that at least one interface can carry traffic off this
// machine: up, not loopback, with a non-link-local address.
func Interfaces(ins Inspector) *domain.Measurement {
	m := begin(CheckInterfaces)
	ifs, err := ins.Interfaces()
	if err != nil {
		m.Status = domain.StatusInconclusive
		m.Note = "the interfaces could not be read: " + err.Error()
		return m.Finish()
	}
	res := &InterfacesResult{Total: len(ifs), Families: []string{}}
	fams := map[string]bool{}
	for _, i := range ifs {
		if i.Up {
			res.Up++
		}
		if !i.Usable() {
			continue
		}
		res.Usable++
		for _, a := range i.Addresses {
			if a.Kind == "global" || a.Kind == "private" {
				fams[a.Family] = true
				if a.Family == "ipv6" && a.Kind == "global" {
					res.GlobalIPv6 = true
				}
			}
		}
	}
	for f := range fams {
		res.Families = append(res.Families, f)
	}
	sort.Strings(res.Families)
	if res.Usable == 0 {
		return m.Fail(domain.LocalNoInterface, "no network interface is up with an address that can reach beyond this machine", res)
	}
	return m.Succeed(res)
}

// RouteState is whether a route exists for one IP family.
type RouteState struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// RouteResult says whether a default route exists for each family.
type RouteResult struct {
	IPv4 RouteState `json:"ipv4"`
	IPv6 RouteState `json:"ipv6"`
}

// Details describes the result in plain lines for the human report.
func (r *RouteResult) Details() []string {
	state := func(s RouteState) string {
		if s.Available {
			return "route found"
		}
		return "no route"
	}
	return []string{"IPv4: " + state(r.IPv4), "IPv6: " + state(r.IPv6)}
}

// Probe addresses. Connecting a UDP socket asks the operating system which
// route it would use and sends no packet, so these are never contacted.
const (
	ProbeIPv4 = "1.1.1.1:53"
	ProbeIPv6 = "[2606:4700:4700::1111]:53"
)

// Dial opens a connection; *net.Dialer implements it.
type Dial func(ctx context.Context, network, address string) (net.Conn, error)

// Route checks whether the operating system has a route to the internet,
// for IPv4 and IPv6, without sending anything.
func Route(ctx context.Context, dial Dial) *domain.Measurement {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	m := begin(CheckRoute)
	res := &RouteResult{}
	var unreachable, other int
	probe := func(addr string, st *RouteState) {
		c, err := dial(ctx, "udp", addr)
		if err == nil {
			_ = c.Close()
			st.Available = true
			return
		}
		st.Error = err.Error()
		if errclass.Unreachable(err) {
			unreachable++
		} else {
			other++
		}
	}
	probe(ProbeIPv4, &res.IPv4)
	probe(ProbeIPv6, &res.IPv6)
	switch {
	case res.IPv4.Available || res.IPv6.Available:
		return m.Succeed(res)
	case unreachable > 0:
		return m.Fail(domain.LocalNoRoute, "the operating system has no route to the internet for IPv4 or IPv6", res)
	}
	m.Status = domain.StatusInconclusive
	m.Note = "the route lookup failed for a reason other than a missing route: " + res.IPv4.Error
	m.Result = res
	return m.Finish()
}

// ResolversResult summarizes the configured resolvers without their
// addresses.
type ResolversResult struct {
	Count  int            `json:"count"`
	Kinds  map[string]int `json:"kinds"`
	Source string         `json:"source"`
}

// Details describes the result in plain lines for the human report.
func (r *ResolversResult) Details() []string {
	var parts []string
	for _, k := range []string{"private", "global", "loopback", "link-local"} {
		if n := r.Kinds[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return []string{fmt.Sprintf("%d configured (%s), from %s", r.Count, orNone(parts), r.Source)}
}

// Resolvers checks that the operating system has at least one DNS server
// configured.
func Resolvers(ins Inspector) *domain.Measurement {
	m := begin(CheckResolvers)
	cfg, err := ins.DNS()
	if err != nil {
		m.Status = domain.StatusInconclusive
		m.Note = "the resolver configuration could not be read: " + err.Error()
		return m.Finish()
	}
	res := &ResolversResult{Count: len(cfg.Servers), Kinds: map[string]int{}, Source: cfg.Source}
	for _, s := range cfg.Servers {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			host = s
		}
		if a, err := netip.ParseAddr(host); err == nil {
			res.Kinds[platform.AddrKind(a.Unmap())]++
		}
	}
	if res.Count == 0 {
		return m.Fail(domain.LocalNoResolver, "the operating system has no DNS server configured", res)
	}
	return m.Succeed(res)
}

// ProxyResult lists the proxies applications may use. nw itself ignores
// them and measures the direct path.
type ProxyResult struct {
	Detected bool                    `json:"detected"`
	Settings []platform.ProxySetting `json:"settings"`
}

// Details describes the result in plain lines for the human report.
func (r *ProxyResult) Details() []string {
	if !r.Detected {
		return []string{"no proxy configured in the environment or system settings"}
	}
	var out []string
	for _, s := range r.Settings {
		switch {
		case s.NoProxy != "":
			out = append(out, s.Source+" exclusions: "+s.NoProxy)
		default:
			out = append(out, strings.TrimSpace(s.Source+": "+s.Scheme+" "+s.Host))
		}
	}
	return out
}

// Proxy records proxy settings. It always succeeds: a proxy is context, not
// a fault. Credentials in proxy URLs are never kept.
func Proxy(ins Inspector) *domain.Measurement {
	m := begin(CheckProxy)
	m.Redacted = []string{"proxy.credentials"}
	settings := ins.Proxies()
	if settings == nil {
		settings = []platform.ProxySetting{}
	}
	return m.Succeed(&ProxyResult{Detected: len(settings) > 0, Settings: settings})
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}
