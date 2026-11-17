package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func resolver(t *testing.T, transport, addr string) target.Resolver {
	t.Helper()
	r, err := target.ParseResolver(map[string]string{"udp": "", "tcp": "tcp://"}[transport] + addr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func lookup(t *testing.T, srv *fixtures.DNSServer, transport, name string) *domain.Measurement {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return Lookup(ctx, name, resolver(t, transport, srv.Addr))
}

func server(t *testing.T) *fixtures.DNSServer {
	return fixtures.NewDNS(t, map[string]fixtures.DNSRule{
		"ok.test":        {A: []string{"192.0.2.10"}, AAAA: []string{"2001:db8::10"}},
		"v4only.test":    {A: []string{"192.0.2.11"}},
		"cname.test":     {A: []string{"192.0.2.12"}, CNAME: "target.test"},
		"empty.test":     {Behavior: fixtures.DNSEmpty},
		"nx.test":        {Behavior: fixtures.DNSNXDomain},
		"servfail.test":  {Behavior: fixtures.DNSServFail},
		"refused.test":   {Behavior: fixtures.DNSRefused},
		"silent.test":    {Behavior: fixtures.DNSSilent},
		"truncated.test": {Behavior: fixtures.DNSTruncate, A: []string{"192.0.2.13"}},
	})
}

func TestLookupSuccess(t *testing.T) {
	srv := server(t)
	m := lookup(t, srv, "udp", "ok.test")
	if m.Status != domain.StatusSuccess || m.Error != nil {
		t.Fatalf("status %s, error %v", m.Status, m.Error)
	}
	res := m.Result.(*Result)
	if len(res.A) != 1 || res.A[0] != "192.0.2.10" || len(res.AAAA) != 1 || res.AAAA[0] != "2001:db8::10" {
		t.Fatalf("result %+v", res)
	}
	if m.Resolver == nil || m.Resolver.Kind != "udp" || m.Resolver.Address != srv.Addr {
		t.Fatalf("resolver %+v", m.Resolver)
	}
	if m.DurationMS <= 0 || m.Type != domain.TypeDNS || m.Version != Version {
		t.Fatalf("metadata %+v", m)
	}
	if got := len(Addresses(m)); got != 2 {
		t.Fatalf("Addresses = %d", got)
	}
}

func TestLookupOverTCP(t *testing.T) {
	srv := server(t)
	m := lookup(t, srv, "tcp", "ok.test")
	if m.Status != domain.StatusSuccess || m.Resolver.Kind != "tcp" {
		t.Fatalf("%+v", m)
	}
}

func TestMissingAAAAIsNotAFailure(t *testing.T) {
	m := lookup(t, server(t), "udp", "v4only.test")
	if m.Status != domain.StatusSuccess {
		t.Fatalf("status %s: %v", m.Status, m.Error)
	}
	res := m.Result.(*Result)
	if len(res.AAAA) != 0 {
		t.Fatalf("AAAA = %v", res.AAAA)
	}
	var aaaa QueryResult
	for _, q := range res.Queries {
		if q.Type == "AAAA" {
			aaaa = q
		}
	}
	if aaaa.Error == nil || aaaa.Error.Code != domain.DNSNoAnswer {
		t.Fatalf("the per-type result must keep the evidence: %+v", aaaa)
	}
}

func TestCNAMEChainIsRecorded(t *testing.T) {
	m := lookup(t, server(t), "udp", "cname.test")
	res := m.Result.(*Result)
	if m.Status != domain.StatusSuccess || res.Queries[0].CNAMEs[0] != "target.test" {
		t.Fatalf("%+v", res)
	}
}

func TestFailures(t *testing.T) {
	srv := server(t)
	cases := []struct {
		name  string
		code  domain.ErrorCode
		rcode string
	}{
		{"nx.test", domain.DNSNXDomain, "NXDOMAIN"},
		{"unknown.test", domain.DNSNXDomain, "NXDOMAIN"},
		{"empty.test", domain.DNSNoAnswer, "NOERROR"},
		{"servfail.test", domain.DNSServFail, "SERVFAIL"},
		{"refused.test", domain.DNSRefused, "REFUSED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := lookup(t, srv, "udp", c.name)
			if m.Status != domain.StatusFailure || m.Error == nil || m.Error.Code != c.code {
				t.Fatalf("status %s error %v; want %s", m.Status, m.Error, c.code)
			}
			if got := m.Result.(*Result).Queries[0].RCode; got != c.rcode {
				t.Fatalf("rcode %q; want %q", got, c.rcode)
			}
			if Addresses(m) != nil {
				t.Fatal("a failed lookup must yield no addresses")
			}
		})
	}
}

func TestNoResponseTimesOut(t *testing.T) {
	srv := server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	m := Lookup(ctx, "silent.test", resolver(t, "udp", srv.Addr))
	if m.Error == nil || m.Error.Code != domain.DNSTimeout {
		t.Fatalf("want dns.timeout, got %v", m.Error)
	}
	if m.DurationMS > 1500 {
		t.Fatalf("took %v ms despite the deadline", m.DurationMS)
	}
}

func TestSilentResolverTimesOut(t *testing.T) {
	addr := fixtures.SilentUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	m := Lookup(ctx, "example.test", resolver(t, "udp", addr))
	if m.Error == nil || m.Error.Code != domain.DNSTimeout {
		t.Fatalf("want dns.timeout, got %v", m.Error)
	}
}

func TestUnreachableResolverIsTransportError(t *testing.T) {
	// Nothing listens on this TCP port, so the connection is refused.
	addr := fixtures.ClosedPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := Lookup(ctx, "example.test", resolver(t, "tcp", addr))
	if m.Error == nil || m.Error.Code != domain.DNSTransport {
		t.Fatalf("want dns.transport, got %v", m.Error)
	}
}

func TestTruncatedUDPFallsBackToTCP(t *testing.T) {
	m := lookup(t, server(t), "udp", "truncated.test")
	if m.Status != domain.StatusSuccess {
		t.Fatalf("status %s: %v", m.Status, m.Error)
	}
	if !m.Result.(*Result).Queries[0].TCPFallback {
		t.Fatal("the TCP fallback must be recorded")
	}
}

func TestCancellationStopsTheLookup(t *testing.T) {
	addr := fixtures.SilentUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	m := Lookup(ctx, "example.test", resolver(t, "udp", addr))
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation was not honored")
	}
	if m.Status != domain.StatusFailure {
		t.Fatalf("status %s", m.Status)
	}
}

func TestSystemUsesTheOSResolver(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	lookupIP = func(_ context.Context, network, name string) ([]netip.Addr, error) {
		switch name {
		case "ok.test":
			if network == "ip4" {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		case "slow.test":
			return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	ctx := context.Background()

	m := System(ctx, "ok.test")
	if m.Status != domain.StatusSuccess || m.Resolver.Kind != "system" {
		t.Fatalf("%+v", m)
	}
	m = System(ctx, "slow.test")
	if m.Error == nil || m.Error.Code != domain.DNSTimeout {
		t.Fatalf("%v", m.Error)
	}
	m = System(ctx, "nx.test")
	if m.Error == nil || m.Error.Code != domain.DNSNoAnswer || !strings.Contains(m.Error.Message, "response code") {
		t.Fatalf("the OS API cannot tell NXDOMAIN apart and must say so: %v", m.Error)
	}
}

func TestPriorityPrefersTransportOverEmpty(t *testing.T) {
	m := domain.Begin(domain.TypeDNS, Version, domain.Target{})
	got := finish(m, []QueryResult{
		{Type: "A", Error: &domain.Error{Code: domain.DNSNXDomain}},
		{Type: "AAAA", Error: &domain.Error{Code: domain.DNSTimeout}},
	})
	if got.Error.Code != domain.DNSTimeout {
		t.Fatalf("got %v", got.Error)
	}
	if got.Result == nil {
		t.Fatal("partial evidence must be kept on failure")
	}
}
