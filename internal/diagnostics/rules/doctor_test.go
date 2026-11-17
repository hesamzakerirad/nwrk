package rules

import (
	"context"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/local"
	"github.com/hesamzakerirad/nwrk/internal/platform"
)

type osFake struct {
	ifs     []platform.Interface
	servers []string
	proxies []platform.ProxySetting
}

func (f osFake) Interfaces() ([]platform.Interface, error) { return f.ifs, nil }
func (f osFake) DNS() (platform.DNSConfig, error) {
	return platform.DNSConfig{Servers: f.servers, Source: "t"}, nil
}
func (f osFake) Proxies() []platform.ProxySetting { return f.proxies }

var upIface = []platform.Interface{{Name: "en0", Up: true, Addresses: []platform.Address{{Family: "ipv4", Kind: "private"}}}}

func healthyLocal(o osFake) []*domain.Measurement {
	if o.ifs == nil {
		o.ifs = upIface
	}
	if o.servers == nil {
		o.servers = []string{"192.168.1.1:53"}
	}
	ok := func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	return []*domain.Measurement{local.Interfaces(o), local.Route(context.Background(), ok), local.Resolvers(o), local.Proxy(o)}
}

func scopedM(m *domain.Measurement, s domain.Scope) *domain.Measurement { m.Scope = s; return m }

func sysDNS(host string, scope domain.Scope, ok bool) *domain.Measurement {
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: host})
	m.Resolver = &domain.ResolverInfo{Kind: "system"}
	if !ok {
		return scopedM(m.Fail(domain.DNSTimeout, "t", &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}), scope)
	}
	return scopedM(m.Succeed(&dns.Result{A: []string{"192.0.2.1"}, AAAA: []string{}, Queries: []dns.QueryResult{}}), scope)
}

func otherDNS(host string, scope domain.Scope, ok bool, chosen bool, ip string) *domain.Measurement {
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: host})
	m.Resolver = &domain.ResolverInfo{Kind: "udp", Address: "9.9.9.9:53"}
	m.Params = map[string]any{"chosen": chosen}
	if !ok {
		return scopedM(m.Fail(domain.DNSTimeout, "t", &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}), scope)
	}
	return scopedM(m.Succeed(&dns.Result{A: []string{ip}, AAAA: []string{}, Queries: []dns.QueryResult{}}), scope)
}

func reach(host string, scope domain.Scope, ok bool) *domain.Measurement {
	m := domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: host, URL: "https://" + host + "/"})
	m.Params = map[string]any{}
	if !ok {
		return scopedM(m.Fail(domain.HTTPTimeout, "t", nil), scope)
	}
	return scopedM(m.Succeed(&mhttp.Result{Method: "GET", StatusCode: 204, Hops: []mhttp.Hop{}, Headers: map[string]string{}}), scope)
}

func skippedReach(host string, scope domain.Scope) *domain.Measurement {
	m := domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: host})
	return scopedM(m.Skip("no route"), scope)
}

func doctorReport(ms ...*domain.Measurement) *domain.Report {
	r := domain.NewReport("doctor", "region ir", "test")
	for _, m := range ms {
		if m.EndedAt.IsZero() {
			m.Finish()
		}
		r.Add(m)
	}
	return r
}

func cat(parts ...[]*domain.Measurement) []*domain.Measurement {
	var out []*domain.Measurement
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func one(ms ...*domain.Measurement) []*domain.Measurement { return ms }

func TestDoctorRules(t *testing.T) {
	const intl, dom = domain.ScopeInternational, domain.ScopeDomestic
	noRoute := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	}
	cases := []struct {
		name     string
		ms       []*domain.Measurement
		want     []string
		wantNot  []string
		severity map[string]domain.Severity
	}{
		{"healthy: nothing fires", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true), reach("a.test", intl, true), reach("d.test", dom, true))),
			nil, []string{"LOCAL_NO_ACTIVE_INTERFACE", "LOCAL_NO_DEFAULT_ROUTE", "LOCAL_NO_RESOLVER_CONFIGURED", "SYSTEM_RESOLVER_FAILING", "INTERNATIONAL_UNREACHABLE", "DOMESTIC_UNREACHABLE", "REFERENCE_RESOLVER_FAILING", "RESOLVER_ANSWER_DIFFERENCE", "PROXY_CONFIGURED", "UNCLASSIFIED_FAILURE"}, nil},

		{"interface: only loopback", cat(healthyLocal(osFake{ifs: []platform.Interface{{Name: "lo", Up: true, Loopback: true}}})),
			[]string{"LOCAL_NO_ACTIVE_INTERFACE"}, []string{"LOCAL_NO_DEFAULT_ROUTE"}, map[string]domain.Severity{"LOCAL_NO_ACTIVE_INTERFACE": domain.SeverityError}},

		{"route: none", one(local.Interfaces(osFake{ifs: upIface}), local.Route(context.Background(), noRoute), local.Resolvers(osFake{servers: []string{"x:53"}}), local.Proxy(osFake{})),
			[]string{"LOCAL_NO_DEFAULT_ROUTE"}, []string{"LOCAL_NO_ACTIVE_INTERFACE"}, map[string]domain.Severity{"LOCAL_NO_DEFAULT_ROUTE": domain.SeverityError}},

		{"resolver: none configured", cat(healthyLocal(osFake{servers: []string{}})),
			[]string{"LOCAL_NO_RESOLVER_CONFIGURED"}, nil, map[string]domain.Severity{"LOCAL_NO_RESOLVER_CONFIGURED": domain.SeverityWarning}},

		{"system dns: all fail", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, false), sysDNS("b.test", intl, false))),
			[]string{"SYSTEM_RESOLVER_FAILING"}, nil, map[string]domain.Severity{"SYSTEM_RESOLVER_FAILING": domain.SeverityError}},
		{"system dns: one name fails", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, false), sysDNS("b.test", intl, true))),
			[]string{"SYSTEM_RESOLVER_FAILING"}, nil, map[string]domain.Severity{"SYSTEM_RESOLVER_FAILING": domain.SeverityWarning}},
		{"system dns: all fine", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true))),
			nil, []string{"SYSTEM_RESOLVER_FAILING"}, nil},

		{"intl: all unreachable, domestic fine", cat(healthyLocal(osFake{}), one(reach("a.test", intl, false), reach("d.test", dom, true))),
			[]string{"INTERNATIONAL_UNREACHABLE"}, []string{"DOMESTIC_UNREACHABLE"}, map[string]domain.Severity{"INTERNATIONAL_UNREACHABLE": domain.SeverityError}},
		{"intl: one of two unreachable", cat(healthyLocal(osFake{}), one(reach("a.test", intl, false), reach("b.test", intl, true))),
			[]string{"INTERNATIONAL_UNREACHABLE"}, nil, map[string]domain.Severity{"INTERNATIONAL_UNREACHABLE": domain.SeverityWarning}},
		{"intl: skipped is not unreachable", cat(healthyLocal(osFake{}), one(skippedReach("a.test", intl))),
			nil, []string{"INTERNATIONAL_UNREACHABLE"}, nil},
		{"intl: both scopes down", cat(healthyLocal(osFake{}), one(reach("a.test", intl, false), reach("d.test", dom, false))),
			[]string{"INTERNATIONAL_UNREACHABLE", "DOMESTIC_UNREACHABLE"}, nil, nil},
		{"domestic: unreachable only", cat(healthyLocal(osFake{}), one(reach("a.test", intl, true), reach("d.test", dom, false))),
			[]string{"DOMESTIC_UNREACHABLE"}, []string{"INTERNATIONAL_UNREACHABLE"}, nil},

		{"compared resolver: preset one fails is info", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true), otherDNS("a.test", intl, false, false, ""))),
			[]string{"REFERENCE_RESOLVER_FAILING"}, nil, map[string]domain.Severity{"REFERENCE_RESOLVER_FAILING": domain.SeverityInfo}},
		{"compared resolver: chosen one fails is a warning", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true), otherDNS("a.test", intl, false, true, ""))),
			[]string{"REFERENCE_RESOLVER_FAILING"}, nil, map[string]domain.Severity{"REFERENCE_RESOLVER_FAILING": domain.SeverityWarning}},
		{"compared resolver: answers", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true), otherDNS("a.test", intl, true, true, "192.0.2.1"))),
			nil, []string{"REFERENCE_RESOLVER_FAILING", "RESOLVER_ANSWER_DIFFERENCE"}, nil},

		{"difference: disjoint answers", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, true), otherDNS("a.test", intl, true, true, "198.51.100.7"))),
			[]string{"RESOLVER_ANSWER_DIFFERENCE"}, nil, map[string]domain.Severity{"RESOLVER_ANSWER_DIFFERENCE": domain.SeverityInfo}},
		{"difference: failing system resolver is not a difference", cat(healthyLocal(osFake{}), one(sysDNS("a.test", intl, false), otherDNS("a.test", intl, true, true, "198.51.100.7"))),
			nil, []string{"RESOLVER_ANSWER_DIFFERENCE"}, nil},

		{"proxy: configured", cat(healthyLocal(osFake{proxies: []platform.ProxySetting{{Source: "HTTPS_PROXY", Host: "p:1"}}})),
			[]string{"PROXY_CONFIGURED"}, nil, map[string]domain.Severity{"PROXY_CONFIGURED": domain.SeverityInfo}},
		{"proxy: none", cat(healthyLocal(osFake{})), nil, []string{"PROXY_CONFIGURED"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := doctorReport(c.ms...)
			engine.Evaluate(Doctor(), rep)
			got := codesOf(rep)
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Errorf("want %s, got %v", w, got)
				}
			}
			for _, w := range c.wantNot {
				if slices.Contains(got, w) {
					t.Errorf("%s must not fire, got %v", w, got)
				}
			}
			for code, sev := range c.severity {
				for _, f := range rep.Findings {
					if f.Code == code && f.Severity != sev {
						t.Errorf("%s severity %s, want %s", code, f.Severity, sev)
					}
				}
			}
			checkInvariants(t, rep)
		})
	}
}

func TestDoctorRuleMetadata(t *testing.T) {
	if len(Doctor()) != 9 {
		t.Fatalf("expected nine doctor rules, got %d", len(Doctor()))
	}
	seen := map[string]bool{}
	for _, r := range append(All(), Doctor()...) {
		if r.ID == "" || r.Version < 1 || r.Title == "" || r.Description == "" || len(r.Caveats) == 0 || len(r.Requires) == 0 || r.Evaluate == nil {
			t.Errorf("rule %q is incomplete", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
	}
	for _, c := range LocalFindingCodes {
		if !seen[c] {
			t.Errorf("LocalFindingCodes names an unknown rule %s", c)
		}
	}
}

func TestDNSMeasurementWithoutResolverInfoDoesNotPanic(t *testing.T) {
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: "a.test"})
	rep := doctorReport(cat(healthyLocal(osFake{}), one(m.Fail(domain.DNSTimeout, "t", nil)))...)
	engine.Evaluate(Doctor(), rep)
	if !slices.Contains(codesOf(rep), "UNCLASSIFIED_FAILURE") {
		t.Fatalf("an unexplained failure must still be reported: %v", codesOf(rep))
	}
}
