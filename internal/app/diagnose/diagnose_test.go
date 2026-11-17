package diagnose

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"go.uber.org/goleak"

	apptest "github.com/hesamzakerirad/nwrk/internal/app/test"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	"github.com/hesamzakerirad/nwrk/internal/target"
	"github.com/hesamzakerirad/nwrk/schema"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type env struct {
	opts apptest.Options
	pki  *fixtures.PKI
}

// newEnv makes example.test and v6.test resolve to loopback, through both a
// fake system resolver and a chosen fixture resolver, so nothing leaves the
// machine.
func newEnv(t *testing.T, addrs ...string) *env {
	t.Helper()
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1"}
	}
	rule := fixtures.DNSRule{}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip.To4() != nil {
			rule.A = append(rule.A, a)
		} else {
			rule.AAAA = append(rule.AAAA, a)
		}
	}
	srv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"example.test": rule})
	rv, err := target.ParseResolver(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	pki := fixtures.NewPKI(t)
	return &env{pki: pki, opts: apptest.Options{
		Timeout:     3 * time.Second,
		Resolvers:   []target.Resolver{rv},
		ToolVersion: "test",
		RootCAs:     pki.Pool,
		SystemDNS: func(_ context.Context, name string) *domain.Measurement {
			m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
			m.Resolver = &domain.ResolverInfo{Kind: "system"}
			if name != "example.test" {
				return m.Fail(domain.DNSNoAnswer, "no records", &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}})
			}
			res := &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip.To4() != nil {
					res.A = append(res.A, a)
				} else {
					res.AAAA = append(res.AAAA, a)
				}
			}
			return m.Succeed(res)
		},
	}}
}

func (e *env) run(t *testing.T, targetArg string, p Profile) *domain.Report {
	t.Helper()
	tg, err := ParseTarget(targetArg)
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), tg, Options{Test: e.opts, Profile: p})
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		t.Fatalf("report does not match schema v1: %v\n%s", err, b)
	}
	for _, f := range rep.Findings {
		if len(f.MeasurementIDs) == 0 {
			t.Errorf("finding %s has no evidence", f.ID)
		}
	}
	return rep
}

func codes(rep *domain.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

func layer(rep *domain.Report, name string) string {
	for _, l := range rep.Summary.Layers {
		if l.Layer == name {
			return l.Status
		}
	}
	return ""
}

func port(addr string) string { _, p, _ := net.SplitHostPort(addr); return p }

func skippedWithReason(rep *domain.Report, t domain.Type) bool {
	found := false
	for _, m := range rep.Measurements {
		if m.Type == t {
			if m.Status != domain.StatusSkipped || m.Note == "" {
				return false
			}
			found = true
		}
	}
	return found
}

func TestHealthyTarget(t *testing.T) {
	e := newEnv(t)
	cert := e.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	rep := e.run(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/ok", Standard)
	if rep.Actionable() || len(rep.Findings) != 0 {
		t.Fatalf("a healthy target must have no findings: %v", codes(rep))
	}
	for _, l := range []string{"dns", "tcp", "tls", "http"} {
		if layer(rep, l) != "success" {
			t.Errorf("layer %s is %s", l, layer(rep, l))
		}
	}
	if rep.Summary.Outcome != "ok" || rep.Run.Profile != "standard" || rep.Run.Command != "diagnose" {
		t.Fatalf("%+v %+v", rep.Summary, rep.Run)
	}
}

func TestTCPRefusedSkipsTheLayersAboveWithReasons(t *testing.T) {
	e := newEnv(t)
	rep := e.run(t, "example.test:"+port(fixtures.ClosedPort(t)), Standard)
	if !slices.Contains(codes(rep), "TCP_CONNECTION_REFUSED") || !rep.Actionable() {
		t.Fatalf("%v", codes(rep))
	}
	if layer(rep, "tcp") != "failure" || layer(rep, "tls") != "skipped" || layer(rep, "http") != "skipped" {
		t.Fatalf("%+v", rep.Summary)
	}
	if !skippedWithReason(rep, domain.TypeTLS) || !skippedWithReason(rep, domain.TypeHTTP) {
		t.Fatal("skipped layers must say why")
	}
}

func TestExpiredCertificate(t *testing.T) {
	e := newEnv(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{e.pki.Expired("example.test")}})
	rep := e.run(t, "example.test:"+port(addr), Standard)
	if !slices.Contains(codes(rep), "TLS_CERTIFICATE_INVALID") || slices.Contains(codes(rep), "TLS_HANDSHAKE_FAILURE_AFTER_TCP") {
		t.Fatalf("%v", codes(rep))
	}
	if layer(rep, "tls") != "failure" || layer(rep, "http") != "skipped" || !skippedWithReason(rep, domain.TypeHTTP) {
		t.Fatalf("%+v", rep.Summary)
	}
}

func TestSilentTLSServer(t *testing.T) {
	e := newEnv(t)
	e.opts.Timeout = 400 * time.Millisecond
	rep := e.run(t, "example.test:"+port(fixtures.MuteServer(t)), Standard)
	if !slices.Contains(codes(rep), "TLS_HANDSHAKE_FAILURE_AFTER_TCP") {
		t.Fatalf("%v", codes(rep))
	}
	if layer(rep, "tcp") != "success" || layer(rep, "tls") != "failure" {
		t.Fatalf("%+v", rep.Summary)
	}
}

func TestHTTPErrorStatus(t *testing.T) {
	e := newEnv(t)
	cert := e.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	p := port(srv.Listener.Addr().String())

	rep := e.run(t, "https://example.test:"+p+"/status/503", Standard)
	if !slices.Contains(codes(rep), "HTTP_ERROR_RESPONSE") || !rep.Actionable() {
		t.Fatalf("a 503 is actionable: %v", codes(rep))
	}
	rep = e.run(t, "https://example.test:"+p+"/status/404", Standard)
	if !slices.Contains(codes(rep), "HTTP_ERROR_RESPONSE") || rep.Actionable() || rep.Summary.Outcome != "ok" {
		t.Fatalf("a 404 is informational and not actionable: %v", codes(rep))
	}
}

func TestHTTPRequestFailure(t *testing.T) {
	e := newEnv(t)
	cert := e.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	rep := e.run(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/loop-a", Standard)
	if !slices.Contains(codes(rep), "HTTP_REQUEST_FAILURE") {
		t.Fatalf("%v", codes(rep))
	}
}

func TestPlainHTTPTarget(t *testing.T) {
	e := newEnv(t)
	srv := fixtures.HTTPServer(t, nil)
	rep := e.run(t, "http://example.test:"+port(srv.Listener.Addr().String())+"/ok", Standard)
	if rep.Actionable() {
		t.Fatalf("%v", codes(rep))
	}
	if layer(rep, "tls") != "skipped" || !skippedWithReason(rep, domain.TypeTLS) || layer(rep, "http") != "success" {
		t.Fatalf("%+v", rep.Summary)
	}
}

func TestDNSFailureSkipsEverythingAfter(t *testing.T) {
	e := newEnv(t)
	rep := e.run(t, "gone.test", Standard)
	if !slices.Contains(codes(rep), "DNS_RESOLUTION_FAILURE") || rep.Summary.Outcome != "problem" {
		t.Fatalf("%v", codes(rep))
	}
	for _, ty := range []domain.Type{domain.TypeTCP, domain.TypeTLS, domain.TypeHTTP} {
		if !skippedWithReason(rep, ty) {
			t.Errorf("%s must be skipped with a reason", ty)
		}
	}
}

func TestPlaceholderAnswer(t *testing.T) {
	e := newEnv(t, "0.0.0.0")
	rep := e.run(t, "example.test", Standard)
	if !slices.Contains(codes(rep), "NO_USABLE_ADDRESS") {
		t.Fatalf("%v", codes(rep))
	}
	if !skippedWithReason(rep, domain.TypeTCP) {
		t.Fatal("TCP must be skipped with a reason")
	}
}

func TestIPFamilyDifference(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	ln.Close()
	e := newEnv(t, "127.0.0.1", "::1")
	cert := e.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert) // listens on IPv4 only
	rep := e.run(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/ok", Standard)
	if !slices.Contains(codes(rep), "IP_FAMILY_BEHAVIOR_DIFFERENCE") {
		t.Fatalf("%v", codes(rep))
	}
	var v4HTTP, v6HTTP *domain.Measurement
	for i, m := range rep.Measurements {
		if m.Type == domain.TypeHTTP && m.Target.Family == "ipv4" {
			v4HTTP = &rep.Measurements[i]
		}
		if m.Type == domain.TypeHTTP && m.Target.Family == "ipv6" {
			v6HTTP = &rep.Measurements[i]
		}
	}
	if v4HTTP == nil || v4HTTP.Status != domain.StatusSuccess || v6HTTP == nil || v6HTTP.Status != domain.StatusSkipped || v6HTTP.Note == "" {
		t.Fatalf("IPv4 must be tested and IPv6 skipped with a reason: %+v %+v", v4HTTP, v6HTTP)
	}
}

func TestProfiles(t *testing.T) {
	e := newEnv(t)
	cert := e.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	target := "https://example.test:" + port(srv.Listener.Addr().String()) + "/ok"

	quick := e.run(t, target, Quick)
	if layer(quick, "tls") != "not_run" || layer(quick, "http") != "not_run" || layer(quick, "tcp") != "success" {
		t.Fatalf("quick must stop after TCP: %+v", quick.Summary)
	}
	deep := e.run(t, target, Deep)
	if deep.Run.Profile != "deep" || layer(deep, "http") != "success" {
		t.Fatalf("%+v", deep.Summary)
	}
	if _, err := ParseProfile("thorough"); err == nil {
		t.Fatal("unknown profiles must be rejected")
	}
}

func TestIPLiteralNeedsNoDNS(t *testing.T) {
	e := newEnv(t)
	cert := e.pki.Valid("127.0.0.1")
	srv := fixtures.HTTPServer(t, &cert)
	rep := e.run(t, "https://127.0.0.1:"+port(srv.Listener.Addr().String())+"/ok", Standard)
	if rep.Actionable() || layer(rep, "dns") != "skipped" || layer(rep, "http") != "success" {
		t.Fatalf("%v %+v", codes(rep), rep.Summary)
	}
}

func TestCancellation(t *testing.T) {
	e := newEnv(t)
	e.opts.Timeout = 30 * time.Second
	addr := fixtures.MuteServer(t)
	tg, _ := ParseTarget("example.test:" + port(addr))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	Run(ctx, tg, Options{Test: e.opts, Profile: Standard})
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancellation was not honored")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  int
		tls   bool
		url   string
		valid bool
	}{
		{"example.com", "example.com", 443, true, "https://example.com/", true},
		{"example.com:8443", "example.com", 8443, true, "https://example.com:8443/", true},
		{"example.com:80", "example.com", 80, false, "http://example.com/", true},
		{"https://example.com/a?b=1", "example.com", 443, true, "https://example.com/a?b=1", true},
		{"http://example.com:8080/x", "example.com", 8080, false, "http://example.com:8080/x", true},
		{"http://example.com", "example.com", 80, false, "http://example.com", true},
		{"[::1]:8443", "::1", 8443, true, "https://[::1]:8443/", true},
		{"::1", "::1", 443, true, "https://[::1]/", true},
		{"192.0.2.1", "192.0.2.1", 443, true, "https://192.0.2.1/", true},
		{"", "", 0, false, "", false},
		{"ftp://example.com", "", 0, false, "", false},
		{"exa mple.com", "", 0, false, "", false},
		{"example.com:99999", "", 0, false, "", false},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if (err == nil) != c.valid {
			t.Errorf("ParseTarget(%q) error = %v, want valid=%v", c.in, err, c.valid)
			continue
		}
		if !c.valid {
			continue
		}
		if got.Host != c.host || got.Port != c.port || got.TLS != c.tls || got.URL.String() != c.url {
			t.Errorf("ParseTarget(%q) = %s %d tls=%v %s; want %s %d tls=%v %s", c.in, got.Host, got.Port, got.TLS, got.URL, c.host, c.port, c.tls, c.url)
		}
	}
}

func TestConcurrencyLimitsAreSet(t *testing.T) {
	for p, s := range specs {
		if s.concurrency < 1 || s.tcpPerFamily < 1 {
			t.Errorf("profile %s: %+v", p, s)
		}
	}
	if fmt.Sprint(DefaultProfile) != "standard" {
		t.Fatal("the default profile is standard")
	}
}
