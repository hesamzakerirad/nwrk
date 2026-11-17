package local

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/internal/platform"
)

type fake struct {
	ifs     []platform.Interface
	ifsErr  error
	dns     platform.DNSConfig
	dnsErr  error
	proxies []platform.ProxySetting
}

func (f fake) Interfaces() ([]platform.Interface, error) { return f.ifs, f.ifsErr }
func (f fake) DNS() (platform.DNSConfig, error)          { return f.dns, f.dnsErr }
func (f fake) Proxies() []platform.ProxySetting          { return f.proxies }

func iface(name string, up, loop bool, kinds ...string) platform.Interface {
	i := platform.Interface{Name: name, Up: up, Loopback: loop}
	for _, k := range kinds {
		fam := "ipv4"
		if k == "global6" {
			k, fam = "global", "ipv6"
		}
		i.Addresses = append(i.Addresses, platform.Address{CIDR: "x", Family: fam, Kind: k})
	}
	return i
}

func TestInterfaces(t *testing.T) {
	lo := iface("lo", true, true, "loopback")
	cases := []struct {
		name   string
		ifs    []platform.Interface
		status domain.Status
		code   domain.ErrorCode
		v6     bool
	}{
		{"wifi up", []platform.Interface{lo, iface("en0", true, false, "private")}, domain.StatusSuccess, "", false},
		{"global ipv6", []platform.Interface{lo, iface("en0", true, false, "private", "global6")}, domain.StatusSuccess, "", true},
		{"only loopback", []platform.Interface{lo}, domain.StatusFailure, domain.LocalNoInterface, false},
		{"interface down", []platform.Interface{lo, iface("en0", false, false, "private")}, domain.StatusFailure, domain.LocalNoInterface, false},
		{"link-local only", []platform.Interface{lo, iface("en0", true, false, "link-local")}, domain.StatusFailure, domain.LocalNoInterface, false},
		{"none at all", nil, domain.StatusFailure, domain.LocalNoInterface, false},
	}
	for _, c := range cases {
		m := Interfaces(fake{ifs: c.ifs})
		if m.Status != c.status || (c.code != "" && m.Error.Code != c.code) {
			t.Errorf("%s: %s %v", c.name, m.Status, m.Error)
		}
		if m.Scope != domain.ScopeLocal || m.Type != domain.TypeLocal || m.Params["check"] != CheckInterfaces {
			t.Errorf("%s: %+v", c.name, m)
		}
		if res := m.Result.(*InterfacesResult); res.GlobalIPv6 != c.v6 {
			t.Errorf("%s: %+v", c.name, res)
		}
	}
	m := Interfaces(fake{ifsErr: errors.New("boom")})
	if m.Status != domain.StatusInconclusive || m.Note == "" {
		t.Fatalf("an unreadable setup is inconclusive, not a failure: %+v", m)
	}
}

func TestResultsDoNotExposeAddresses(t *testing.T) {
	ins := fake{
		ifs: []platform.Interface{{Name: "en0-private-name", Up: true, Addresses: []platform.Address{{CIDR: "192.168.77.5/24", Family: "ipv4", Kind: "private"}}}},
		dns: platform.DNSConfig{Servers: []string{"192.168.77.1:53"}, Source: "test"},
	}
	for _, m := range []*domain.Measurement{Interfaces(ins), Resolvers(ins)} {
		b := strings.Join(m.Result.(domain.Detailer).Details(), " ")
		for _, secret := range []string{"192.168.77", "en0-private-name"} {
			if strings.Contains(b, secret) {
				t.Errorf("%v leaks %q", m.Params, secret)
			}
		}
		if len(m.Redacted) == 0 {
			t.Error("redaction metadata missing")
		}
	}
}

func errDial(err error) Dial {
	return func(context.Context, string, string) (net.Conn, error) { return nil, err }
}

type okDial struct{}

func (okDial) dial(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

func TestRoute(t *testing.T) {
	noRoute := fixtures.NoRouteError()
	m := Route(context.Background(), okDial{}.dial)
	if m.Status != domain.StatusSuccess || !m.Result.(*RouteResult).IPv4.Available || !m.Result.(*RouteResult).IPv6.Available {
		t.Fatalf("%+v", m)
	}
	m = Route(context.Background(), errDial(noRoute))
	if m.Status != domain.StatusFailure || m.Error.Code != domain.LocalNoRoute {
		t.Fatalf("no route in either family is a failure: %+v", m)
	}
	// IPv4 works, IPv6 has no route: success, with the difference recorded.
	calls := 0
	partial := func(ctx context.Context, n, a string) (net.Conn, error) {
		calls++
		if strings.HasPrefix(a, "[") {
			return nil, noRoute
		}
		return okDial{}.dial(ctx, n, a)
	}
	m = Route(context.Background(), partial)
	res := m.Result.(*RouteResult)
	if m.Status != domain.StatusSuccess || !res.IPv4.Available || res.IPv6.Available || calls != 2 {
		t.Fatalf("%+v calls=%d", res, calls)
	}
	m = Route(context.Background(), errDial(errors.New("permission denied")))
	if m.Status != domain.StatusInconclusive {
		t.Fatalf("an unrelated error proves nothing: %+v", m)
	}
}

func TestRouteSendsNoPackets(t *testing.T) {
	// A UDP "connection" only selects a route; this must hold for the real
	// dialer too, which is why the probe addresses are never contacted.
	m := Route(context.Background(), nil)
	if m.Status == domain.StatusInconclusive {
		t.Skip("route lookup is not permitted here")
	}
	if m.Params["check"] != CheckRoute {
		t.Fatal(m.Params)
	}
}

func TestResolvers(t *testing.T) {
	m := Resolvers(fake{dns: platform.DNSConfig{Servers: []string{"192.168.1.1:53", "8.8.8.8:53", "[fd00::1]:53"}, Source: "/etc/resolv.conf"}})
	res := m.Result.(*ResolversResult)
	if m.Status != domain.StatusSuccess || res.Count != 3 || res.Kinds["private"] != 2 || res.Kinds["global"] != 1 {
		t.Fatalf("%+v", res)
	}
	m = Resolvers(fake{dns: platform.DNSConfig{Servers: []string{}, Source: "x"}})
	if m.Status != domain.StatusFailure || m.Error.Code != domain.LocalNoResolver {
		t.Fatalf("%+v", m)
	}
	if m := Resolvers(fake{dnsErr: errors.New("x")}); m.Status != domain.StatusInconclusive {
		t.Fatalf("%+v", m)
	}
}

func TestProxy(t *testing.T) {
	m := Proxy(fake{})
	if m.Status != domain.StatusSuccess || m.Result.(*ProxyResult).Detected {
		t.Fatalf("%+v", m)
	}
	m = Proxy(fake{proxies: []platform.ProxySetting{{Source: "HTTPS_PROXY", Scheme: "http", Host: "proxy.test:3128"}}})
	if !m.Result.(*ProxyResult).Detected || m.Status != domain.StatusSuccess {
		t.Fatalf("a proxy is context, never a failure: %+v", m)
	}
	if got := strings.Join(m.Result.(domain.Detailer).Details(), " "); !strings.Contains(got, "proxy.test:3128") {
		t.Fatal(got)
	}
}
