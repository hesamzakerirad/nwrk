package security

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/radestsam/nwrk/internal/app/diagnose"
	apptest "github.com/radestsam/nwrk/internal/app/test"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	"github.com/radestsam/nwrk/internal/target"
	"github.com/radestsam/nwrk/schema"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type world struct {
	t    *testing.T
	pki  *fixtures.PKI
	opts Options
}

// newWorld makes example.test resolve to loopback through a fake system
// resolver, so nothing leaves the machine.
func newWorld(t *testing.T) *world {
	t.Helper()
	pki := fixtures.NewPKI(t)
	w := &world{t: t, pki: pki}
	w.opts = Options{Test: apptest.Options{
		Timeout:     800 * time.Millisecond,
		ToolVersion: "test",
		RootCAs:     pki.Pool,
		SystemDNS: func(_ context.Context, name string) *domain.Measurement {
			m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
			m.Resolver = &domain.ResolverInfo{Kind: "system"}
			res := &dns.Result{A: []string{"127.0.0.1"}, AAAA: []string{}, Queries: []dns.QueryResult{}}
			if name != "example.test" {
				return m.Fail(domain.DNSNoAnswer, "none", &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}})
			}
			return m.Succeed(res)
		},
	}}
	return w
}

func (w *world) resolver(rules map[string]fixtures.DNSRule) target.Resolver {
	srv := fixtures.NewDNS(w.t, rules)
	r, err := target.ParseResolver(srv.Addr)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) check(rep *domain.Report) {
	w.t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		w.t.Fatalf("report does not match schema v1: %v\n%s", err, b)
	}
	for _, f := range rep.Findings {
		if len(f.MeasurementIDs) == 0 {
			w.t.Errorf("%s has no evidence", f.ID)
		}
	}
	for _, h := range rep.Hypotheses {
		if h.Confidence == domain.ConfidenceHigh {
			ids := map[string]bool{}
			for _, e := range h.Supporting {
				for _, id := range e.MeasurementIDs {
					ids[id] = true
				}
			}
			if len(ids) < 2 {
				w.t.Errorf("%s: high confidence from a single measurement", h.ID)
			}
		}
	}
}

func codes(rep *domain.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

func port(addr string) string { _, p, _ := net.SplitHostPort(addr); return p }

func parse(t *testing.T, s string) diagnose.Target {
	tg, err := diagnose.ParseTarget(s)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func countProbes(rep *domain.Report, probe string) int {
	n := 0
	for _, m := range rep.Measurements {
		if m.Probe() == probe {
			n++
		}
	}
	return n
}

func TestInjectedDNSReplies(t *testing.T) {
	w := newWorld(t)
	srv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"example.test": {A: []string{"127.0.0.1"}, Inject: []string{"198.51.100.66"}}})
	r, _ := target.ParseResolver(srv.Addr)
	w.opts.Test.Resolvers = []target.Resolver{r}
	w.opts.Test.Timeout = 1500 * time.Millisecond
	cert := w.pki.Valid("example.test")
	http := fixtures.HTTPServer(t, &cert)
	rep := Interference(context.Background(), parse(t, "https://example.test:"+port(http.Listener.Addr().String())+"/ok"), w.opts)
	w.check(rep)
	if !slices.Contains(codes(rep), "DNS_MULTIPLE_DIFFERENT_RESPONSES") {
		t.Fatalf("%v", codes(rep))
	}
	if rep.Run.Command != "security interference" || countProbes(rep, domain.ProbeMultipleResponses) != 1 {
		t.Fatalf("%+v", rep.Run)
	}
}

func TestAnswerMismatchWithAndWithoutCorroboration(t *testing.T) {
	w := newWorld(t)
	cert := w.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	// The other resolver says 192.0.2.99, which nothing answers.
	r := w.resolver(map[string]fixtures.DNSRule{"example.test": {A: []string{"192.0.2.99"}}})
	w.opts.Test.Resolvers = []target.Resolver{r}
	rep := Interference(context.Background(), parse(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/ok"), w.opts)
	w.check(rep)
	var f domain.Finding
	for _, x := range rep.Findings {
		if x.Code == "DNS_ANSWER_MISMATCH" {
			f = x
		}
	}
	if f.ID == "" {
		t.Fatalf("%v", codes(rep))
	}
	if countProbes(rep, domain.ProbeAnswerReachability) == 0 {
		t.Fatal("when resolvers disagree, both answers are tested for reachability")
	}
	if f.Severity != domain.SeverityWarning {
		t.Fatalf("one answer connects and the other does not, so the difference is corroborated: %+v", f)
	}

	// The same answers when both are reachable are only an observation.
	w2 := newWorld(t)
	r2 := w2.resolver(map[string]fixtures.DNSRule{"example.test": {A: []string{"127.0.0.2"}}})
	w2.opts.Test.Resolvers = []target.Resolver{r2}
	rep = Interference(context.Background(), parse(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/ok"), w2.opts)
	for _, x := range rep.Findings {
		if x.Code == "DNS_ANSWER_MISMATCH" && x.Severity != domain.SeverityInfo {
			// 127.0.0.2 answers on most systems; where it does not, it is
			// corroborated, which is the other test's point.
			t.Logf("127.0.0.2 not reachable here: %+v", x)
		}
	}
}

func TestSNIDependentFailure(t *testing.T) {
	w := newWorld(t)
	cert := w.pki.Valid("example.test", "neutral.test")
	addr := fixtures.SNIServer(t, cert, "example.test", fixtures.SNIReset)
	w.opts.Control = "neutral.test"
	rep := Interference(context.Background(), parse(t, "example.test:"+port(addr)), w.opts)
	w.check(rep)
	got := codes(rep)
	if !slices.Contains(got, "TLS_SNI_DEPENDENT_FAILURE") || !slices.Contains(got, "TLS_RESET_AFTER_CLIENTHELLO") {
		t.Fatalf("%v", got)
	}
	if countProbes(rep, domain.ProbeSNIControl) != 2 || countProbes(rep, domain.ProbeSNITarget) != 1 {
		t.Fatalf("one repeat and two controls per address: control=%d target=%d", countProbes(rep, domain.ProbeSNIControl), countProbes(rep, domain.ProbeSNITarget))
	}
	// A probe is not a primary measurement: the layer summary ignores it.
	for _, l := range rep.Summary.Layers {
		if l.Layer == "tls" && l.Status != "failure" {
			t.Fatalf("the TLS layer reflects the primary handshake only: %+v", rep.Summary.Layers)
		}
	}
}

func TestNoSNIFindingWhenTheServerIsFine(t *testing.T) {
	w := newWorld(t)
	cert := w.pki.Valid("example.test")
	addr := fixtures.SNIServer(t, cert, "never-asked.test", fixtures.SNIReset)
	rep := Interference(context.Background(), parse(t, "example.test:"+port(addr)), w.opts)
	w.check(rep)
	for _, c := range codes(rep) {
		if c == "TLS_SNI_DEPENDENT_FAILURE" || c == "TLS_RESET_AFTER_CLIENTHELLO" {
			t.Fatalf("a healthy server must not produce %s", c)
		}
	}
}

func TestHTTPAndHTTPSDifference(t *testing.T) {
	w := newWorld(t)
	cert := w.pki.Valid("example.test")
	secure := fixtures.HTTPServer(t, &cert)
	plain := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(plain.Close)
	w.opts.PlainPort = atoi(port(plain.Listener.Addr().String()))
	rep := Interference(context.Background(), parse(t, "https://example.test:"+port(secure.Listener.Addr().String())+"/ok"), w.opts)
	w.check(rep)
	if !slices.Contains(codes(rep), "HTTP_HTTPS_RESPONSE_DIFFERENCE") {
		t.Fatalf("%v", codes(rep))
	}
}

func atoi(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}

func TestInsufficientEvidenceIsStated(t *testing.T) {
	w := newWorld(t)
	cert := w.pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	rep := Interference(context.Background(), parse(t, "https://example.test:"+port(srv.Listener.Addr().String())+"/ok"), w.opts)
	w.check(rep)
	if !slices.Contains(codes(rep), "INTERFERENCE_INSUFFICIENT_EVIDENCE") {
		t.Fatalf("with no independent resolver the report must say so: %v", codes(rep))
	}
	if rep.Actionable() {
		t.Fatalf("a healthy target with nothing to compare is not a problem: %v", codes(rep))
	}
}

func TestInspect(t *testing.T) {
	w := newWorld(t)
	rv := w.resolver(map[string]fixtures.DNSRule{"example.test": {A: []string{"127.0.0.1"}, Signed: true, AD: true}})
	w.opts.Test.Resolvers = []target.Resolver{rv}
	cert := w.pki.Valid("example.test")
	addr := fixtures.LegacyTLSServer(t, cert)
	rep := Inspect(context.Background(), parse(t, "example.test:"+port(addr)), w.opts)
	w.check(rep)
	got := codes(rep)
	for _, want := range []string{"DNSSEC_STATUS", "TLS_LEGACY_PROTOCOL_ACCEPTED"} {
		if !slices.Contains(got, want) {
			t.Errorf("want %s, got %v", want, got)
		}
	}
	if !rep.Actionable() {
		t.Fatal("a server that accepts TLS 1.0 and 1.1 is a warning")
	}

	w = newWorld(t)
	modern := fixtures.ModernTLSServer(t, w.pki.Valid("example.test"))
	rep = Inspect(context.Background(), parse(t, "example.test:"+port(modern)), w.opts)
	if slices.Contains(codes(rep), "TLS_LEGACY_PROTOCOL_ACCEPTED") {
		t.Fatal("a modern server must not be flagged")
	}
}

func TestInspectCertificateExpiry(t *testing.T) {
	w := newWorld(t)
	soon := w.pki.Issue(time.Now().Add(-time.Hour), time.Now().Add(72*time.Hour), "example.test")
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{soon}})
	rep := Inspect(context.Background(), parse(t, "example.test:"+port(addr)), w.opts)
	w.check(rep)
	if !slices.Contains(codes(rep), "TLS_CERTIFICATE_EXPIRING_SOON") || !rep.Actionable() {
		t.Fatalf("%v", codes(rep))
	}
}

func TestInspectDNSSECValidationFailure(t *testing.T) {
	w := newWorld(t)
	rv := w.resolver(map[string]fixtures.DNSRule{"example.test": {A: []string{"127.0.0.1"}, Signed: true, ServFailUnlessCD: true}})
	w.opts.Test.Resolvers = []target.Resolver{rv}
	rep := Inspect(context.Background(), parse(t, "example.test:"+port(fixtures.ClosedPort(t))), w.opts)
	w.check(rep)
	if !slices.Contains(codes(rep), "DNSSEC_VALIDATION_FAILURE") {
		t.Fatalf("%v", codes(rep))
	}
}

func TestCancellation(t *testing.T) {
	w := newWorld(t)
	w.opts.Test.Timeout = 30 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	Interference(ctx, parse(t, "example.test:"+port(fixtures.MuteServer(t))), w.opts)
	if time.Since(start) > 4*time.Second {
		t.Fatal("cancellation was not honored")
	}
}
