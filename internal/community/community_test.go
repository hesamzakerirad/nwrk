package community

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hesamzakerirad/nwrk/contracts"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	nwhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	nwtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// secrets are values that an engine result can hold and that must never reach
// the document.
const (
	secretIPv4     = "203.0.113.77"
	secretIPv6     = "2001:db8::77"
	secretResolver = "198.51.100.53"
	secretURL      = "https://secret.example/private?token=abc"
	secretHeader   = "X-Secret-Header-Value"
	secretCert     = "CN=Secret Subject"
)

// fakeEngine returns scripted results. A target missing from the maps gets a
// full success.
type fakeEngine struct {
	mu       sync.Mutex
	dnsErr   map[string]*domain.Error // by host, both families
	noAAAA   map[string]bool
	tcpErr   map[string]*domain.Error
	tlsErr   map[string]*domain.Error
	httpErr  map[string]*domain.Error
	status   int
	calls    []string
	inflight atomic.Int32
	peak     atomic.Int32
	delay    time.Duration
}

func (f *fakeEngine) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeEngine) wait(ctx context.Context) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
		}
	}
}

func (f *fakeEngine) DNS(ctx context.Context, host string) *domain.Measurement {
	f.record("dns " + host)
	f.wait(ctx)
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: host})
	res := &dns.Result{A: []string{secretIPv4}, AAAA: []string{secretIPv6}}
	q := func(t string, answers []string) dns.QueryResult {
		return dns.QueryResult{Type: t, Answers: answers, DurationMS: 12.4, CNAMEs: []string{"cname." + secretURL}}
	}
	a, aaaa := q("A", []string{secretIPv4, "203.0.113.78"}), q("AAAA", []string{secretIPv6})
	if f.noAAAA[host] {
		aaaa = q("AAAA", nil)
		aaaa.Error = &domain.Error{Code: domain.DNSNoAnswer, Message: "no AAAA for " + secretIPv6}
	}
	if e := f.dnsErr[host]; e != nil {
		a.Answers, a.Error = nil, e
		aaaa.Answers, aaaa.Error = nil, e
	}
	res.Queries = []dns.QueryResult{a, aaaa}
	return m.Succeed(res)
}

func (f *fakeEngine) TCP(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement {
	f.record("tcp " + host)
	m := domain.Begin(domain.TypeTCP, "1", domain.Target{Host: host, IP: addr.Addr().String()})
	if e := f.tcpErr[host]; e != nil {
		return m.Fail(e.Code, e.Message, nil)
	}
	return m.Succeed(&tcp.Result{Address: addr.String(), ConnectMS: 3})
}

func (f *fakeEngine) TLS(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement {
	f.record("tls " + host)
	m := domain.Begin(domain.TypeTLS, "1", domain.Target{Host: host})
	res := &nwtls.Result{ServerName: host, Certificates: []nwtls.Certificate{{Subject: secretCert, Issuer: secretCert}}, Chain: nwtls.Chain{Error: secretCert}}
	if e := f.tlsErr[host]; e != nil {
		return m.Fail(e.Code, e.Message, res)
	}
	return m.Succeed(res)
}

func (f *fakeEngine) HTTP(ctx context.Context, ep contracts.Endpoint, addr netip.AddrPort) (*domain.Measurement, int) {
	f.record("http " + ep.Hostname)
	m := domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: ep.Hostname, URL: secretURL})
	res := &nwhttp.Result{
		FinalURL: secretURL, StatusCode: f.status,
		Headers: map[string]string{"server": secretHeader},
		Hops:    []nwhttp.Hop{{URL: secretURL, StatusCode: f.status}},
	}
	if e := f.httpErr[ep.Hostname]; e != nil {
		return m.Fail(e.Code, e.Message, res), 0
	}
	return m.Succeed(res), f.status
}

func fakeRunner(e Engine, routes Routes) *Runner {
	return &Runner{Engine: e, Routes: func(context.Context) Routes { return routes }}
}

func profile(t *testing.T, id string) *contracts.Profile {
	t.Helper()
	ps, err := contracts.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	var found *contracts.Profile
	for _, p := range ps {
		if p.ID == id {
			found = p
		}
	}
	if found == nil {
		t.Fatalf("profile %s not found", id)
	}
	return found
}

func validate(t *testing.T, c *contracts.Contribution) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := contracts.Profiles()
	if _, err := contracts.ValidateContribution(raw, ps); err != nil {
		t.Fatalf("document is not valid: %v\n%s", err, raw)
	}
	return raw
}

func TestFullSuccessMatchesTheContract(t *testing.T) {
	p := profile(t, "ir-dev-v1")
	c, err := fakeRunner(&fakeEngine{status: 200}, Routes{IPv4: true, IPv6: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, c)
	if len(c.Results) != len(p.Endpoints) {
		t.Fatalf("%d results for %d endpoints", len(c.Results), len(p.Endpoints))
	}
	if c.Profile.ID != "ir-dev-v1" || c.Client.Name != "nwrk" {
		t.Fatalf("%+v", c)
	}
}

func TestSanitizerLeaksNothing(t *testing.T) {
	// Every failure shape, with addresses and URLs in the engine messages.
	leaky := func(code domain.ErrorCode) *domain.Error {
		return &domain.Error{Code: code, Message: "failed for " + secretIPv4 + " via " + secretResolver + " at " + secretURL + " " + secretCert}
	}
	p := profile(t, "ir-core-v1")
	engines := map[string]*fakeEngine{
		"success": {status: 451},
		"dns":     {dnsErr: map[string]*domain.Error{}},
		"tcp":     {tcpErr: map[string]*domain.Error{}},
		"tls":     {tlsErr: map[string]*domain.Error{}},
		"http":    {httpErr: map[string]*domain.Error{}, status: 200},
		"local":   {tcpErr: map[string]*domain.Error{}},
	}
	for _, ep := range p.Endpoints {
		engines["dns"].dnsErr[ep.Hostname] = leaky(domain.DNSTransport)
		engines["tcp"].tcpErr[ep.Hostname] = leaky(domain.TCPRefused)
		engines["tls"].tlsErr[ep.Hostname] = leaky(domain.TLSCertUntrusted)
		engines["http"].httpErr[ep.Hostname] = leaky(domain.HTTPReset)
		engines["local"].tcpErr[ep.Hostname] = leaky(domain.LocalNoRoute) // not a contract code
	}
	ip := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f]*:[0-9a-f:]+:[0-9a-f]+`)
	for name, e := range engines {
		t.Run(name, func(t *testing.T) {
			c, err := fakeRunner(e, Routes{IPv4: true, IPv6: true}).Run(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			raw := string(validate(t, c))
			for _, s := range []string{secretIPv4, secretIPv6, secretResolver, "secret.example", secretHeader, "Secret Subject", "token=abc", "cname."} {
				if strings.Contains(raw, s) {
					t.Fatalf("document holds %q:\n%s", s, raw)
				}
			}
			// Nothing that looks like an address, except in the version text.
			scrub := strings.ReplaceAll(raw, `"version":"`, "")
			if m := ip.FindString(strings.ReplaceAll(scrub, "community-contribution.v1", "")); m != "" && strings.Count(m, ".") == 3 && !strings.Contains(m, "0.0.0") {
				t.Fatalf("document holds an address-like value %q:\n%s", m, raw)
			}
		})
	}
}

func TestUnknownErrorCodesBecomeTheGenericCode(t *testing.T) {
	cases := map[string]struct {
		layer string
		in    domain.ErrorCode
		want  string
	}{
		"local code in tcp": {"tcp", domain.LocalNoRoute, "tcp.error"},
		"empty":             {"http", "", "http.error"},
		"dns keeps dns":     {"dns", domain.DNSTimeout, "dns.timeout"},
		"tcp code in dns":   {"dns", domain.TCPRefused, "dns.error"},
		"tcp code in tls":   {"tls", domain.TCPRefused, "tcp.refused"},
	}
	for name, c := range cases {
		if got := errorCode(c.layer, &domain.Error{Code: c.in}); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	if got := errorCode("tls", nil); got != "tls.error" {
		t.Error(got)
	}
}

func TestFailureStopsLaterLayersOfThatFamily(t *testing.T) {
	p := profile(t, "ir-dev-v1")
	host := p.Endpoints[0].Hostname
	e := &fakeEngine{status: 200, tcpErr: map[string]*domain.Error{host: {Code: domain.TCPTimeout}}}
	c, err := fakeRunner(e, Routes{IPv4: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, c)
	for _, call := range e.calls {
		if call == "tls "+host || call == "http "+host {
			t.Fatalf("ran %q after a TCP failure", call)
		}
	}
	for _, r := range c.Results {
		if r.TargetID == p.Endpoints[0].TargetID {
			last := r.Measurements[len(r.Measurements)-1]
			if last.Layer != "tcp" || last.Error != "tcp.timeout" {
				t.Fatalf("%+v", r.Measurements)
			}
		}
	}
}

func TestDNSFailureIsRecordedAndNothingElseRuns(t *testing.T) {
	p := profile(t, "ir-dev-v1")
	host := p.Endpoints[1].Hostname
	e := &fakeEngine{status: 200, dnsErr: map[string]*domain.Error{host: {Code: domain.DNSTimeout}}}
	c, err := fakeRunner(e, Routes{IPv4: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, c)
	for _, call := range e.calls {
		if call == "tcp "+host {
			t.Fatal("TCP ran after a DNS failure")
		}
	}
}

func TestNoIPv6RouteLeavesOutIPv6(t *testing.T) {
	p := profile(t, "ir-core-v1")
	e := &fakeEngine{status: 200}
	c, err := fakeRunner(e, Routes{IPv4: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, c)
	for _, r := range c.Results {
		for _, m := range r.Measurements {
			if m.Family == "ipv6" {
				t.Fatalf("IPv6 measured without a route: %+v", m)
			}
		}
	}
}

func TestIPv6OnlyForFamiliesTheEndpointServes(t *testing.T) {
	p := profile(t, "ir-core-v1")
	c, err := fakeRunner(&fakeEngine{status: 200}, Routes{IPv4: true, IPv6: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Results {
		ep, _ := p.Endpoint(r.TargetID)
		for _, m := range r.Measurements {
			ok := false
			for _, f := range ep.Families {
				ok = ok || f == m.Family
			}
			if !ok {
				t.Fatalf("%s measured on %s, which it does not serve", r.TargetID, m.Family)
			}
		}
	}
}

func TestMissingAAAAOnAServingEndpointIsADNSFailureOnlyForThatFamily(t *testing.T) {
	p := profile(t, "ir-core-v1")
	var dual *contracts.Endpoint
	for i := range p.Endpoints {
		if len(p.Endpoints[i].Families) == 2 {
			dual = &p.Endpoints[i]
			break
		}
	}
	if dual == nil {
		t.Skip("no dual-stack endpoint in the profile")
	}
	e := &fakeEngine{status: 200, noAAAA: map[string]bool{dual.Hostname: true}}
	c, err := fakeRunner(e, Routes{IPv4: true, IPv6: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, c)
}

func TestNoRouteAtAll(t *testing.T) {
	_, err := fakeRunner(&fakeEngine{}, Routes{}).Run(context.Background(), profile(t, "ir-dev-v1"))
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("%v", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	p := profile(t, "ir-dev-v1")
	e := &fakeEngine{status: 200, delay: 20 * time.Millisecond}
	if _, err := fakeRunner(e, Routes{IPv4: true}).Run(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := int(e.peak.Load()); got > p.Limits.Concurrency || got < 2 {
		t.Fatalf("peak concurrency %d, limit %d", got, p.Limits.Concurrency)
	}
}

func TestBudgetEndsTheRunWithoutFakeFailures(t *testing.T) {
	p := *profile(t, "ir-dev-v1")
	p.Limits.TotalBudgetMS = 60
	e := &fakeEngine{status: 200, delay: 40 * time.Millisecond}
	start := time.Now()
	c, err := fakeRunner(e, Routes{IPv4: true}).Run(context.Background(), &p)
	if time.Since(start) > 2*time.Second {
		t.Fatal("run ignored the budget")
	}
	if err == nil {
		validate(t, c)
		for _, r := range c.Results {
			for _, m := range r.Measurements {
				if m.Outcome == "failure" {
					t.Fatalf("a budget stop was recorded as a failure: %+v", m)
				}
			}
		}
	}
}

func TestCancellationReturnsTheContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &fakeEngine{status: 200, delay: 50 * time.Millisecond}
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	_, err := fakeRunner(e, Routes{IPv4: true}).Run(ctx, profile(t, "ir-dev-v1"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestDurationAndAnswerCountAreBounded(t *testing.T) {
	m := dnsMeasurement("ipv4", dns.QueryResult{Type: "A", Answers: make([]string, 200), DurationMS: 999999})
	if m.DurationMS != maxDurationMS || m.AnswerCount != maxAnswerCount {
		t.Fatalf("%+v", m)
	}
	if millis(-5) != 0 {
		t.Fatal("negative duration")
	}
}

func TestHTTPStatusCodesAreKeptAsResponses(t *testing.T) {
	for _, code := range []int{200, 403, 451, 503} {
		meas := domain.Begin(domain.TypeHTTP, "1", domain.Target{}).Succeed(&nwhttp.Result{StatusCode: code})
		m := httpMeasurement("ipv4", code, meas)
		if m.Outcome != "response_received" || m.StatusCode != code {
			t.Fatalf("%d: %+v", code, m)
		}
	}
}

func TestClientVersionMatchesTheContract(t *testing.T) {
	cases := map[string]string{"1.2.3": "1.2.3", "v1.2.3": "1.2.3", "0.5.0-rc.1": "0.5.0-rc.1", "dev": "0.0.0-dev", "": "0.0.0-dev", "1.2": "0.0.0-dev", "1.2.3+abc": "0.0.0-dev"}
	for in, want := range cases {
		if got := clientVersion(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
