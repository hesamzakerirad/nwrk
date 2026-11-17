package reporting

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
	"github.com/hesamzakerirad/nwrk/internal/output"
	"github.com/hesamzakerirad/nwrk/schema"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// stamp fixes the volatile fields so output is reproducible.
func stamp(m *domain.Measurement, ms float64) *domain.Measurement {
	m.StartedAt = t0
	m.EndedAt = t0.Add(time.Duration(ms * float64(time.Millisecond)))
	m.DurationMS = ms
	return m
}

func ptr(v float64) *float64 { return &v }

// sample builds a report touching every measurement type and status.
func sample() *domain.Report {
	rep := domain.NewReport("test http", "https://example.com/", "0.0.2")
	rep.Run.ID = "run-000000000001"
	rep.Run.StartedAt = t0
	rep.Run.EndedAt = t0.Add(time.Second)
	rep.Run.Platform = domain.Platform{OS: "linux", Arch: "amd64"}

	d := domain.Begin(domain.TypeDNS, dns.Version, domain.Target{Host: "example.com"})
	d.Resolver = &domain.ResolverInfo{Kind: "system", Servers: []string{"192.0.2.53:53"}}
	rep.Add(stamp(d.Succeed(&dns.Result{
		A: []string{"203.0.113.10"}, AAAA: []string{},
		Queries: []dns.QueryResult{
			{Type: "A", Answers: []string{"203.0.113.10"}, DurationMS: 20},
			{Type: "AAAA", Answers: []string{}, DurationMS: 22, Error: &domain.Error{Code: domain.DNSNoAnswer, Message: "no records"}},
		},
	}), 22))

	d2 := domain.Begin(domain.TypeDNS, dns.Version, domain.Target{Host: "example.com"})
	d2.Resolver = &domain.ResolverInfo{Kind: "udp", Address: "198.51.100.1:53"}
	rep.Add(stamp(d2.Fail(domain.DNSTimeout, "no response from the resolver before the deadline", &dns.Result{
		A: []string{}, AAAA: []string{},
		Queries: []dns.QueryResult{{Type: "A", Answers: []string{}, DurationMS: 10000, Error: &domain.Error{Code: domain.DNSTimeout, Message: "no response"}}},
	}), 10000))

	c := domain.Begin(domain.TypeTCP, tcp.Version, domain.Target{Host: "example.com", IP: "203.0.113.10", Port: 443, Family: "ipv4"})
	rep.Add(stamp(c.Succeed(&tcp.Result{Address: "203.0.113.10:443", Family: "ipv4", ConnectMS: 41.5}), 41.5))

	l := domain.Begin(domain.TypeTLS, mtls.Version, domain.Target{Host: "example.com", IP: "203.0.113.10", Port: 443, Family: "ipv4"})
	rep.Add(stamp(l.Fail(domain.TLSCertExpired, "the certificate is expired or not yet valid", &mtls.Result{
		ServerName: "example.com", HandshakeMS: 80,
		Chain: mtls.Chain{Verified: false, Error: "x509: certificate has expired or is not yet valid"},
		Certificates: []mtls.Certificate{{
			Subject: "CN=example.com", Issuer: "CN=Example CA", NotBefore: t0.AddDate(-1, 0, 0), NotAfter: t0.AddDate(0, 0, -1),
			SANs: []string{"example.com"},
		}},
	}), 80))

	h := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: "example.com", URL: "https://example.com/"})
	h.Redacted = []string{"request.cookies", "response.set-cookie"}
	tm := mhttp.Timings{DNSMS: ptr(5), ConnectMS: ptr(40), TLSMS: ptr(60), TTFBMS: ptr(150), TotalMS: 160}
	rep.Add(stamp(h.Succeed(&mhttp.Result{
		Method: "GET", FinalURL: "https://example.com/home", StatusCode: 200, Protocol: "HTTP/2.0",
		Hops: []mhttp.Hop{
			{URL: "https://example.com/", StatusCode: 301, Location: "https://example.com/home", Timings: mhttp.Timings{TotalMS: 90}},
			{URL: "https://example.com/home", StatusCode: 200, Timings: tm},
		},
		Headers: map[string]string{"content-type": "text/html"}, BodyBytes: 1256, Timings: tm,
	}), 250))

	s := domain.Begin(domain.TypeTCP, tcp.Version, domain.Target{Host: "example.org", Port: 80})
	rep.Add(stamp(s.Skip("name resolution failed, so there is no address to connect to"), 0))
	return rep
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file.\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &output.Renderer{Out: &buf, Format: output.JSON}
	if err := r.JSON(sample()); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(buf.Bytes()); err != nil {
		t.Fatalf("the golden report must match schema v1: %v", err)
	}
	golden(t, "report.golden.json", buf.Bytes())
}

func TestGoldenHuman(t *testing.T) {
	var buf bytes.Buffer
	Human(&output.Renderer{Out: &buf, Format: output.Human}, sample(), false)
	golden(t, "report.golden.txt", buf.Bytes())
}

func TestGoldenHumanQuiet(t *testing.T) {
	var buf bytes.Buffer
	Human(&output.Renderer{Out: &buf, Format: output.Human}, sample(), true)
	golden(t, "report.quiet.golden.txt", buf.Bytes())
}

func TestJSONHasArraysNotNulls(t *testing.T) {
	b, _ := json.Marshal(domain.NewReport("x", "y", "z"))
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	for _, k := range []string{"measurements", "findings", "hypotheses", "recommendations"} {
		if _, ok := doc[k].([]any); !ok {
			t.Errorf("%s must be an array, got %v", k, doc[k])
		}
	}
}

func TestColorOnlyReinforcesWords(t *testing.T) {
	var plain, colored bytes.Buffer
	Human(&output.Renderer{Out: &plain}, sample(), false)
	Human(&output.Renderer{Out: &colored, Color: true}, sample(), false)
	stripped := stripANSI(colored.String())
	if stripped != plain.String() {
		t.Fatalf("colored output differs from plain beyond escape codes:\n%s\n%s", stripped, plain.String())
	}
}

func stripANSI(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
