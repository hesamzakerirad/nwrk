package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	apptest "github.com/hesamzakerirad/nwrk/internal/app/test"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	"github.com/hesamzakerirad/nwrk/internal/measurement/local"
	"github.com/hesamzakerirad/nwrk/internal/platform"
	"github.com/hesamzakerirad/nwrk/internal/regions"
	"github.com/hesamzakerirad/nwrk/internal/target"
	"github.com/hesamzakerirad/nwrk/schema"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// fakeOS is a machine whose network setup is exactly what a test says.
type fakeOS struct {
	ifs     []platform.Interface
	servers []string
	proxies []platform.ProxySetting
}

func (f fakeOS) Interfaces() ([]platform.Interface, error) { return f.ifs, nil }
func (f fakeOS) DNS() (platform.DNSConfig, error) {
	return platform.DNSConfig{Servers: f.servers, Source: "test"}, nil
}
func (f fakeOS) Proxies() []platform.ProxySetting { return f.proxies }

func healthyOS() fakeOS {
	return fakeOS{
		ifs:     []platform.Interface{{Name: "en0", Up: true, Addresses: []platform.Address{{CIDR: "x", Family: "ipv4", Kind: "private"}}}},
		servers: []string{"192.168.1.1:53"},
	}
}

func routeOK(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

func noRoute(context.Context, string, string) (net.Conn, error) {
	return nil, fixtures.NoRouteError()
}

// world is a set of local servers standing in for reference targets.
type world struct {
	t    *testing.T
	dns  map[string]bool // names the fake system resolver answers
	opts Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, dns: map[string]bool{}}
	w.opts = Options{
		Test: apptest.Options{
			Timeout:     500 * time.Millisecond,
			ToolVersion: "test",
			SystemDNS: func(_ context.Context, name string) *domain.Measurement {
				m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
				m.Resolver = &domain.ResolverInfo{Kind: "system"}
				res := &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}
				if !w.dns[name] {
					return m.Fail(domain.DNSTimeout, "no response", res)
				}
				res.A = []string{"127.0.0.1"}
				return m.Succeed(res)
			},
		},
		Inspector: healthyOS(),
		Dial:      routeOK,
	}
	return w
}

// target adds a reference target served by addr under a made-up name.
func (w *world) target(scope domain.Scope, name, addr string) regions.Target {
	_, port, _ := net.SplitHostPort(addr)
	w.dns[name] = true
	return regions.Target{URL: fmt.Sprintf("http://%s:%s/ok", name, port), Name: name, Scope: scope, Reason: "test fixture target"}
}

func (w *world) run(targets ...regions.Target) *domain.Report {
	w.t.Helper()
	w.opts.Region = "ir"
	w.opts.Preset = regions.Preset{Name: "ir", Targets: targets}
	rep := Run(context.Background(), w.opts)
	b, err := json.Marshal(rep)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		w.t.Fatalf("doctor report does not match schema v1: %v\n%s", err, b)
	}
	for _, m := range rep.Measurements {
		if m.Status == domain.StatusFailure && !covered(rep, m.ID) {
			w.t.Errorf("failed measurement %s has no finding", m.ID)
		}
	}
	return rep
}

func covered(rep *domain.Report, id string) bool {
	for _, f := range rep.Findings {
		if slices.Contains(f.MeasurementIDs, id) {
			return true
		}
	}
	return false
}

func codes(rep *domain.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

func status(rep *domain.Report, s domain.Scope) string {
	for _, sc := range rep.Summary.Scopes {
		if sc.Scope == s {
			return sc.Status
		}
	}
	return ""
}

func okServer(t *testing.T) string { return fixtures.HTTPServer(t, nil).Listener.Addr().String() }

// blackhole accepts connections and never answers, like a path that drops
// traffic after the connection is made.
func blackhole(t *testing.T) string { return fixtures.MuteServer(t) }

func TestHealthy(t *testing.T) {
	w := newWorld(t)
	srv := okServer(t)
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", srv), w.target(domain.ScopeDomestic, "dom1.test", srv))
	if rep.Summary.Verdict != domain.VerdictHealthy || rep.Actionable() || rep.Summary.Outcome != "ok" {
		t.Fatalf("%v %v", rep.Summary, codes(rep))
	}
	if status(rep, domain.ScopeLocal) != "ok" || status(rep, domain.ScopeDomestic) != "reachable" || status(rep, domain.ScopeInternational) != "reachable" {
		t.Fatalf("%+v", rep.Summary.Scopes)
	}
	if rep.Run.Region != "ir" || rep.Run.Command != "doctor" {
		t.Fatalf("%+v", rep.Run)
	}
}

// Exit criterion (a): no default route names the local layer.
func TestNoDefaultRouteIsLocal(t *testing.T) {
	w := newWorld(t)
	w.opts.Dial = noRoute
	srv := okServer(t)
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", srv), w.target(domain.ScopeDomestic, "dom1.test", srv))
	if rep.Summary.Verdict != domain.VerdictLocal || !slices.Contains(codes(rep), "LOCAL_NO_DEFAULT_ROUTE") || !rep.Actionable() {
		t.Fatalf("verdict %s findings %v", rep.Summary.Verdict, codes(rep))
	}
	for _, m := range rep.Measurements {
		if m.Type == domain.TypeHTTP && (m.Status != domain.StatusSkipped || m.Note == "") {
			t.Errorf("targets must be skipped with a reason: %+v", m)
		}
	}
	if status(rep, domain.ScopeLocal) != "problem" {
		t.Fatalf("%+v", rep.Summary.Scopes)
	}
}

func TestNoInterfaceIsLocal(t *testing.T) {
	w := newWorld(t)
	w.opts.Inspector = fakeOS{ifs: []platform.Interface{{Name: "lo", Up: true, Loopback: true}}, servers: []string{"x:53"}}
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", okServer(t)))
	if rep.Summary.Verdict != domain.VerdictLocal || !slices.Contains(codes(rep), "LOCAL_NO_ACTIVE_INTERFACE") {
		t.Fatalf("%s %v", rep.Summary.Verdict, codes(rep))
	}
}

// Exit criterion (b): system DNS failing while another resolver works names
// the local layer, and the targets are still reached through the other
// resolver so the network is not blamed.
func TestSystemDNSFailingIsLocal(t *testing.T) {
	w := newWorld(t)
	srv := okServer(t)
	intl, dom := w.target(domain.ScopeInternational, "intl1.test", srv), w.target(domain.ScopeDomestic, "dom1.test", srv)
	w.dns = map[string]bool{} // the system resolver answers nothing
	rv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{
		"intl1.test": {A: []string{"127.0.0.1"}}, "dom1.test": {A: []string{"127.0.0.1"}},
	})
	r1, _ := target.ParseResolver(rv.Addr)
	r2, _ := target.ParseResolver("tcp://" + rv.Addr)
	w.opts.Test.Resolvers = []target.Resolver{r1, r2}
	rep := w.run(intl, dom)

	if rep.Summary.Verdict != domain.VerdictLocal || !slices.Contains(codes(rep), "SYSTEM_RESOLVER_FAILING") {
		t.Fatalf("verdict %s findings %v", rep.Summary.Verdict, codes(rep))
	}
	if status(rep, domain.ScopeInternational) != "reachable" || status(rep, domain.ScopeDomestic) != "reachable" {
		t.Fatalf("the targets must still be reached through the working resolver: %+v", rep.Summary.Scopes)
	}
	var f domain.Finding
	for _, x := range rep.Findings {
		if x.Code == "SYSTEM_RESOLVER_FAILING" {
			f = x
		}
	}
	if f.Severity != domain.SeverityError {
		t.Fatalf("every system lookup failed: %+v", f)
	}
	var h domain.Hypothesis
	for _, x := range rep.Hypotheses {
		if slices.Contains(x.FindingIDs, f.ID) {
			h = x
		}
	}
	if h.Confidence != domain.ConfidenceHigh || !strings.Contains(h.Summary, "configured on this machine") {
		t.Fatalf("two resolvers working while the system one fails: %+v", h)
	}
	for _, m := range rep.Measurements {
		if m.Type == domain.TypeHTTP && m.Params["addresses_from"] != "a compared resolver" {
			t.Errorf("addresses must come from the compared resolver: %v", m.Params)
		}
	}
}

// Exit criterion (c): domestic reachable while international is blackholed
// names the international layer.
func TestDomesticReachableInternationalBlackholed(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 400 * time.Millisecond
	good, bad := okServer(t), blackhole(t)
	rep := w.run(
		w.target(domain.ScopeInternational, "intl1.test", bad), w.target(domain.ScopeInternational, "intl2.test", bad),
		w.target(domain.ScopeDomestic, "dom1.test", good), w.target(domain.ScopeDomestic, "dom2.test", good),
	)
	if rep.Summary.Verdict != domain.VerdictInternational || !slices.Contains(codes(rep), "INTERNATIONAL_UNREACHABLE") || slices.Contains(codes(rep), "DOMESTIC_UNREACHABLE") {
		t.Fatalf("verdict %s findings %v", rep.Summary.Verdict, codes(rep))
	}
	if status(rep, domain.ScopeLocal) != "ok" || status(rep, domain.ScopeDomestic) != "reachable" || status(rep, domain.ScopeInternational) != "unreachable" {
		t.Fatalf("%+v", rep.Summary.Scopes)
	}
	var f domain.Finding
	for _, x := range rep.Findings {
		if x.Code == "INTERNATIONAL_UNREACHABLE" {
			f = x
		}
	}
	if f.Severity != domain.SeverityError || f.Layer != "reachability" {
		t.Fatalf("%+v", f)
	}
	var h domain.Hypothesis
	for _, x := range rep.Hypotheses {
		if slices.Contains(x.FindingIDs, f.ID) {
			h = x
		}
	}
	var cites bool
	for _, e := range h.Supporting {
		cites = cites || strings.Contains(e.Text, "domestic reference targets answered")
	}
	if !cites {
		t.Fatalf("the hypothesis must cite the working domestic targets: %+v", h)
	}
}

func TestInternationalReachableDomesticBlackholed(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 400 * time.Millisecond
	good, bad := okServer(t), blackhole(t)
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", good), w.target(domain.ScopeDomestic, "dom1.test", bad))
	if rep.Summary.Verdict != domain.VerdictDomestic || !slices.Contains(codes(rep), "DOMESTIC_UNREACHABLE") {
		t.Fatalf("verdict %s findings %v", rep.Summary.Verdict, codes(rep))
	}
}

func TestNothingAnswersIsUpstream(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 400 * time.Millisecond
	bad := blackhole(t)
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", bad), w.target(domain.ScopeDomestic, "dom1.test", bad))
	if rep.Summary.Verdict != domain.VerdictUpstream {
		t.Fatalf("%s %v", rep.Summary.Verdict, codes(rep))
	}
	if status(rep, domain.ScopeLocal) != "ok" {
		t.Fatalf("local checks passed, so the problem is beyond this machine: %+v", rep.Summary.Scopes)
	}
}

func TestWithoutDomesticAnchorsTheFailureCannotBePlaced(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 400 * time.Millisecond
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", blackhole(t)))
	if rep.Summary.Verdict != domain.VerdictUpstream {
		t.Fatalf("%s", rep.Summary.Verdict)
	}
	for _, sc := range rep.Summary.Scopes {
		if sc.Scope == domain.ScopeDomestic {
			t.Fatal("a region without domestic anchors has no domestic scope")
		}
	}
	var missing bool
	for _, h := range rep.Hypotheses {
		for _, e := range h.Missing {
			missing = missing || strings.Contains(e.Text, "--region")
		}
	}
	if !missing {
		t.Fatal("the report must say that a region with anchors is needed to place the failure")
	}
}

func TestPartialReachability(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 400 * time.Millisecond
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", okServer(t)), w.target(domain.ScopeInternational, "intl2.test", blackhole(t)))
	if rep.Summary.Verdict != domain.VerdictPartial || status(rep, domain.ScopeInternational) != "partial" {
		t.Fatalf("%s %+v", rep.Summary.Verdict, rep.Summary.Scopes)
	}
	for _, f := range rep.Findings {
		if f.Code == "INTERNATIONAL_UNREACHABLE" && f.Severity != domain.SeverityWarning {
			t.Fatalf("one failing target among several is a warning: %+v", f)
		}
	}
}

func TestComparedResolversAndDifferences(t *testing.T) {
	w := newWorld(t)
	srv := okServer(t)
	intl := w.target(domain.ScopeInternational, "intl1.test", srv)
	rv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"intl1.test": {A: []string{"192.0.2.99"}}})
	dead := fixtures.SilentUDP(t)
	r1, _ := target.ParseResolver(rv.Addr)
	r2, _ := target.ParseResolver(dead)
	w.opts.Test.Resolvers = []target.Resolver{r1, r2}
	w.opts.ChosenResolvers = true
	rep := w.run(intl)
	got := codes(rep)
	if !slices.Contains(got, "RESOLVER_ANSWER_DIFFERENCE") || !slices.Contains(got, "REFERENCE_RESOLVER_FAILING") {
		t.Fatalf("%v", got)
	}
	for _, f := range rep.Findings {
		switch f.Code {
		case "RESOLVER_ANSWER_DIFFERENCE":
			if f.Severity != domain.SeverityInfo {
				t.Errorf("differences are observations: %+v", f)
			}
		case "REFERENCE_RESOLVER_FAILING":
			if f.Severity != domain.SeverityWarning {
				t.Errorf("a resolver the user chose that fails is a warning: %+v", f)
			}
		}
	}
	if rep.Summary.Verdict != domain.VerdictHealthy {
		t.Fatalf("a difference between resolvers must not change the verdict: %s", rep.Summary.Verdict)
	}
}

func TestPresetResolverFailureIsInformational(t *testing.T) {
	w := newWorld(t)
	intl := w.target(domain.ScopeInternational, "intl1.test", okServer(t))
	r, _ := target.ParseResolver(fixtures.SilentUDP(t))
	w.opts.Test.Resolvers = []target.Resolver{r}
	w.opts.ChosenResolvers = false
	rep := w.run(intl)
	if rep.Actionable() || rep.Summary.Verdict != domain.VerdictHealthy {
		t.Fatalf("a public resolver that does not answer is not the user's problem: %v", codes(rep))
	}
}

func TestProxyIsReportedAndIgnored(t *testing.T) {
	w := newWorld(t)
	w.opts.Inspector = fakeOS{ifs: healthyOS().ifs, servers: healthyOS().servers,
		proxies: []platform.ProxySetting{{Source: "HTTPS_PROXY", Scheme: "http", Host: "proxy.test:3128"}}}
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", okServer(t)))
	if !slices.Contains(codes(rep), "PROXY_CONFIGURED") || rep.Actionable() {
		t.Fatalf("%v", codes(rep))
	}
}

func TestReportKeepsLocalAddressesOut(t *testing.T) {
	w := newWorld(t)
	w.opts.Inspector = fakeOS{
		ifs:     []platform.Interface{{Name: "secret-iface", Up: true, Addresses: []platform.Address{{CIDR: "10.77.8.9/24", Family: "ipv4", Kind: "private"}}}},
		servers: []string{"10.77.8.1:53"},
	}
	rep := w.run(w.target(domain.ScopeInternational, "intl1.test", okServer(t)))
	b, _ := json.Marshal(rep)
	for _, secret := range []string{"10.77.8", "secret-iface"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the doctor report exposes %q", secret)
		}
	}
}

func TestCancellation(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 30 * time.Second
	w.opts.Region = "ir"
	w.opts.Preset = regions.Preset{Name: "ir", Targets: []regions.Target{w.target(domain.ScopeInternational, "intl1.test", blackhole(t))}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	Run(ctx, w.opts)
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancellation was not honored")
	}
}

var _ = local.Version
