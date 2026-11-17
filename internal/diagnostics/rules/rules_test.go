package rules

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
	"github.com/hesamzakerirad/nwrk/schema"
)

// Builders for synthetic measurements. Rules see only normalized
// measurements, so they are tested without a network.

func report(ms ...*domain.Measurement) *domain.Report {
	r := domain.NewReport("diagnose", "example.test", "test")
	for _, m := range ms {
		if m.EndedAt.IsZero() {
			m.Finish()
		}
		r.Add(m)
	}
	return r
}

func resolver(kind, addr string) *domain.ResolverInfo {
	if kind == "system" {
		return &domain.ResolverInfo{Kind: "system"}
	}
	return &domain.ResolverInfo{Kind: kind, Address: addr}
}

func dnsOK(kind, addr string, ips ...string) *domain.Measurement {
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: "example.test"})
	m.Resolver = resolver(kind, addr)
	res := &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}
	for _, ip := range ips {
		if len(ip) > 0 && (ip[0] == ':' || len(ip) > 4 && ip[4] == ':' || containsColon(ip)) {
			res.AAAA = append(res.AAAA, ip)
		} else {
			res.A = append(res.A, ip)
		}
	}
	return m.Succeed(res)
}

func containsColon(s string) bool {
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}

func dnsFail(kind, addr string, code domain.ErrorCode) *domain.Measurement {
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: "example.test"})
	m.Resolver = resolver(kind, addr)
	return m.Fail(code, string(code), &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}})
}

func family(ip string) string {
	if containsColon(ip) {
		return "ipv6"
	}
	return "ipv4"
}

func conn(t domain.Type, ip string, port int) *domain.Measurement {
	return domain.Begin(t, "1", domain.Target{Host: "example.test", IP: ip, Port: port, Family: family(ip)})
}

func tcpOK(ip string) *domain.Measurement {
	return conn(domain.TypeTCP, ip, 443).Succeed(&tcp.Result{Address: ip, Family: family(ip)})
}

func tcpFail(ip string, code domain.ErrorCode) *domain.Measurement {
	return conn(domain.TypeTCP, ip, 443).Fail(code, string(code), nil)
}

func tlsOK(ip string) *domain.Measurement {
	return conn(domain.TypeTLS, ip, 443).Succeed(&mtls.Result{ServerName: "example.test", Chain: mtls.Chain{Verified: true}, Certificates: []mtls.Certificate{}})
}

func tlsFail(ip string, code domain.ErrorCode, leaf *mtls.Certificate) *domain.Measurement {
	res := &mtls.Result{ServerName: "example.test", Certificates: []mtls.Certificate{}}
	if leaf != nil {
		res.Certificates = []mtls.Certificate{*leaf}
	}
	return conn(domain.TypeTLS, ip, 443).Fail(code, string(code), res)
}

func httpMeasurement(fam string) *domain.Measurement {
	return domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: "example.test", URL: "https://example.test/", Family: fam})
}

func httpStatus(fam string, status int) *domain.Measurement {
	return httpMeasurement(fam).Succeed(&mhttp.Result{Method: "GET", StatusCode: status, Hops: []mhttp.Hop{}, Headers: map[string]string{}})
}

func httpFail(fam string, code domain.ErrorCode) *domain.Measurement {
	return httpMeasurement(fam).Fail(code, string(code), nil)
}

func skipped(t domain.Type, why string) *domain.Measurement {
	return domain.Begin(t, "1", domain.Target{Host: "example.test"}).Skip(why)
}

func codesOf(r *domain.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

var (
	cert = &mtls.Certificate{
		Subject: "CN=example.test", Issuer: "CN=Example CA",
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), SANs: []string{"example.test"},
	}
	self = &mtls.Certificate{Subject: "CN=example.test", Issuer: "CN=example.test", NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC), SANs: []string{}}
)

// Every rule has positive cases (it fires, with the right severity) and
// negative cases (it stays quiet).
func TestRules(t *testing.T) {
	const v4, v6 = "192.0.2.10", "2001:db8::10"
	cases := []struct {
		name     string
		report   *domain.Report
		want     []string // rule IDs that must fire
		wantNot  []string // rule IDs that must not
		severity map[string]domain.Severity
	}{
		// DNS_RESOLUTION_FAILURE
		{"dns: all resolvers fail", report(
			dnsFail("system", "", domain.DNSNoAnswer), dnsFail("udp", "9.9.9.9:53", domain.DNSNXDomain)),
			[]string{"DNS_RESOLUTION_FAILURE"}, nil, map[string]domain.Severity{"DNS_RESOLUTION_FAILURE": domain.SeverityError}},
		{"dns: one resolver fails, another answers", report(
			dnsOK("system", "", v4), dnsFail("udp", "9.9.9.9:53", domain.DNSTimeout)),
			[]string{"DNS_RESOLUTION_FAILURE"}, nil, map[string]domain.Severity{"DNS_RESOLUTION_FAILURE": domain.SeverityWarning}},
		{"dns: timeout and servfail and refused", report(
			dnsFail("system", "", domain.DNSTimeout), dnsFail("udp", "a:53", domain.DNSServFail), dnsFail("udp", "b:53", domain.DNSRefused)),
			[]string{"DNS_RESOLUTION_FAILURE"}, nil, nil},
		{"dns: success is quiet", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpOK(v6)),
			nil, []string{"DNS_RESOLUTION_FAILURE", "NO_USABLE_ADDRESS"}, nil},

		// NO_USABLE_ADDRESS
		{"addr: placeholder answer", report(dnsOK("system", "", "0.0.0.0")),
			[]string{"NO_USABLE_ADDRESS"}, nil, map[string]domain.Severity{"NO_USABLE_ADDRESS": domain.SeverityError}},
		{"addr: placeholder from one resolver only", report(dnsOK("system", "", "0.0.0.0"), dnsOK("udp", "9.9.9.9:53", v4)),
			[]string{"NO_USABLE_ADDRESS"}, nil, nil},
		{"addr: no route to any address", report(dnsOK("system", "", v6), tcpFail(v6, domain.TCPUnreachable)),
			[]string{"NO_USABLE_ADDRESS"}, nil, nil},
		{"addr: one family unreachable, other works", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpFail(v6, domain.TCPUnreachable)),
			nil, []string{"NO_USABLE_ADDRESS"}, nil},
		{"addr: refused is not unreachable", report(dnsOK("system", "", v4), tcpFail(v4, domain.TCPRefused)),
			nil, []string{"NO_USABLE_ADDRESS"}, nil},

		// TCP_CONNECTION_REFUSED
		{"tcp refused: all addresses", report(dnsOK("system", "", v4), tcpFail(v4, domain.TCPRefused)),
			[]string{"TCP_CONNECTION_REFUSED"}, []string{"TCP_CONNECTION_TIMEOUT"}, map[string]domain.Severity{"TCP_CONNECTION_REFUSED": domain.SeverityError}},
		{"tcp refused: one address of two", report(dnsOK("system", "", v4, "192.0.2.11"), tcpOK(v4), tcpFail("192.0.2.11", domain.TCPRefused)),
			[]string{"TCP_CONNECTION_REFUSED"}, nil, map[string]domain.Severity{"TCP_CONNECTION_REFUSED": domain.SeverityWarning}},
		{"tcp refused: success is quiet", report(dnsOK("system", "", v4), tcpOK(v4)),
			nil, []string{"TCP_CONNECTION_REFUSED"}, nil},

		// TCP_CONNECTION_TIMEOUT
		{"tcp timeout: all addresses", report(dnsOK("system", "", v4), tcpFail(v4, domain.TCPTimeout)),
			[]string{"TCP_CONNECTION_TIMEOUT"}, []string{"TCP_CONNECTION_REFUSED"}, map[string]domain.Severity{"TCP_CONNECTION_TIMEOUT": domain.SeverityError}},
		{"tcp timeout: one family", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpFail(v6, domain.TCPTimeout)),
			[]string{"TCP_CONNECTION_TIMEOUT"}, nil, map[string]domain.Severity{"TCP_CONNECTION_TIMEOUT": domain.SeverityWarning}},
		{"tcp timeout: success is quiet", report(dnsOK("system", "", v4), tcpOK(v4)),
			nil, []string{"TCP_CONNECTION_TIMEOUT"}, nil},

		// TLS_CERTIFICATE_INVALID
		{"cert: expired", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSCertExpired, cert)),
			[]string{"TLS_CERTIFICATE_INVALID"}, []string{"TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, map[string]domain.Severity{"TLS_CERTIFICATE_INVALID": domain.SeverityError}},
		{"cert: self-signed", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSCertUntrusted, self)),
			[]string{"TLS_CERTIFICATE_INVALID"}, nil, nil},
		{"cert: wrong host", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSHostnameMismatch, cert)),
			[]string{"TLS_CERTIFICATE_INVALID"}, nil, nil},
		{"cert: invalid on one address, valid on another", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpOK(v6), tlsOK(v4), tlsFail(v6, domain.TLSCertExpired, cert)),
			[]string{"TLS_CERTIFICATE_INVALID"}, nil, map[string]domain.Severity{"TLS_CERTIFICATE_INVALID": domain.SeverityWarning}},
		{"cert: valid is quiet", report(dnsOK("system", "", v4), tcpOK(v4), tlsOK(v4)),
			nil, []string{"TLS_CERTIFICATE_INVALID", "TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, nil},

		// TLS_HANDSHAKE_FAILURE_AFTER_TCP
		{"handshake: alert after tcp", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSHandshakeFailure, nil)),
			[]string{"TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, []string{"TLS_CERTIFICATE_INVALID"}, map[string]domain.Severity{"TLS_HANDSHAKE_FAILURE_AFTER_TCP": domain.SeverityError}},
		{"handshake: reset after tcp", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSReset, nil)),
			[]string{"TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, nil, nil},
		{"handshake: timeout after tcp", report(dnsOK("system", "", v4), tcpOK(v4), tlsFail(v4, domain.TLSTimeout, nil)),
			[]string{"TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, nil, nil},
		{"handshake: failure without a successful tcp is not this rule", report(dnsOK("system", "", v4), tcpFail(v4, domain.TCPRefused), tlsFail(v4, domain.TLSHandshakeFailure, nil)),
			nil, []string{"TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, nil},

		// HTTP_ERROR_RESPONSE
		{"http: 503", report(dnsOK("system", "", v4), tcpOK(v4), tlsOK(v4), httpStatus("ipv4", 503)),
			[]string{"HTTP_ERROR_RESPONSE"}, nil, map[string]domain.Severity{"HTTP_ERROR_RESPONSE": domain.SeverityWarning}},
		{"http: 429", report(httpStatus("", 429), dnsOK("system", "", v4)),
			[]string{"HTTP_ERROR_RESPONSE"}, nil, map[string]domain.Severity{"HTTP_ERROR_RESPONSE": domain.SeverityWarning}},
		{"http: 404 is informational", report(dnsOK("system", "", v4), httpStatus("", 404)),
			[]string{"HTTP_ERROR_RESPONSE"}, nil, map[string]domain.Severity{"HTTP_ERROR_RESPONSE": domain.SeverityInfo}},
		{"http: 403", report(dnsOK("system", "", v4), httpStatus("", 403)),
			[]string{"HTTP_ERROR_RESPONSE"}, nil, nil},
		{"http: 200 is quiet", report(dnsOK("system", "", v4), httpStatus("", 200)),
			nil, []string{"HTTP_ERROR_RESPONSE", "HTTP_REQUEST_FAILURE"}, nil},
		{"http: 301 final is quiet", report(dnsOK("system", "", v4), httpStatus("", 301)),
			nil, []string{"HTTP_ERROR_RESPONSE"}, nil},

		// HTTP_REQUEST_FAILURE
		{"http failure: timeout", report(dnsOK("system", "", v4), httpFail("", domain.HTTPTimeout)),
			[]string{"HTTP_REQUEST_FAILURE"}, nil, map[string]domain.Severity{"HTTP_REQUEST_FAILURE": domain.SeverityError}},
		{"http failure: redirect loop", report(dnsOK("system", "", v4), httpFail("", domain.HTTPRedirectLoop)),
			[]string{"HTTP_REQUEST_FAILURE"}, nil, nil},
		{"http failure: protocol error and reset", report(dnsOK("system", "", v4), httpFail("ipv4", domain.HTTPProtocolError), httpFail("ipv6", domain.HTTPReset)),
			[]string{"HTTP_REQUEST_FAILURE"}, nil, nil},

		// IP_FAMILY_BEHAVIOR_DIFFERENCE
		{"family: ipv6 times out, ipv4 works", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpFail(v6, domain.TCPTimeout)),
			[]string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil, map[string]domain.Severity{"IP_FAMILY_BEHAVIOR_DIFFERENCE": domain.SeverityWarning}},
		{"family: ipv6 has no route is informational", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpFail(v6, domain.TCPUnreachable)),
			[]string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil, map[string]domain.Severity{"IP_FAMILY_BEHAVIOR_DIFFERENCE": domain.SeverityInfo}},
		{"family: ipv4 fails, ipv6 works", report(dnsOK("system", "", v4, v6), tcpFail(v4, domain.TCPRefused), tcpOK(v6)),
			[]string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil, nil},
		{"family: tls differs", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpOK(v6), tlsOK(v4), tlsFail(v6, domain.TLSHandshakeFailure, nil)),
			[]string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil, nil},
		{"family: both work", report(dnsOK("system", "", v4, v6), tcpOK(v4), tcpOK(v6)),
			nil, []string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil},
		{"family: both fail the same way", report(dnsOK("system", "", v4, v6), tcpFail(v4, domain.TCPTimeout), tcpFail(v6, domain.TCPTimeout)),
			nil, []string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil},
		{"family: no AAAA record is not a difference", report(dnsOK("system", "", v4), tcpOK(v4)),
			nil, []string{"IP_FAMILY_BEHAVIOR_DIFFERENCE"}, nil},

		// skipped measurements are not failures
		{"skipped layers are quiet", report(dnsOK("system", "", v4), tcpOK(v4), skipped(domain.TypeTLS, "plain http"), skipped(domain.TypeHTTP, "n/a")),
			nil, []string{"UNCLASSIFIED_FAILURE", "TLS_HANDSHAKE_FAILURE_AFTER_TCP"}, nil},

		// the safety net
		{"unclassified: tcp reset", report(dnsOK("system", "", v4), tcpFail(v4, domain.TCPReset)),
			[]string{"UNCLASSIFIED_FAILURE"}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			engine.Evaluate(All(), c.report)
			got := codesOf(c.report)
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Errorf("want finding %s, got %v", w, got)
				}
			}
			for _, w := range c.wantNot {
				if slices.Contains(got, w) {
					t.Errorf("finding %s must not fire, got %v", w, got)
				}
			}
			for code, sev := range c.severity {
				for _, f := range c.report.Findings {
					if f.Code == code && f.Severity != sev {
						t.Errorf("%s severity %s, want %s", code, f.Severity, sev)
					}
				}
			}
			checkInvariants(t, c.report)
		})
	}
}

// checkInvariants holds for the output of every rule on every input.
func checkInvariants(t *testing.T, r *domain.Report) {
	t.Helper()
	ids := map[string]bool{}
	for _, m := range r.Measurements {
		ids[m.ID] = true
	}
	covered := map[string]bool{}
	findings := map[string]bool{}
	prev := 4
	for _, f := range r.Findings {
		findings[f.ID] = true
		if len(f.MeasurementIDs) == 0 {
			t.Errorf("%s references no measurement", f.ID)
		}
		for _, id := range f.MeasurementIDs {
			if !ids[id] {
				t.Errorf("%s references unknown measurement %s", f.ID, id)
			}
			covered[id] = true
		}
		if f.Title == "" || f.RuleVersion == 0 || f.Layer == "" || f.Summary == "" || len(f.Caveats) == 0 && f.Code != "UNCLASSIFIED_FAILURE" {
			t.Errorf("%s is missing rule metadata: %+v", f.ID, f)
		}
		rank := map[domain.Severity]int{domain.SeverityError: 3, domain.SeverityWarning: 2, domain.SeverityInfo: 1}[f.Severity]
		if rank > prev {
			t.Errorf("findings are not ordered by severity at %s", f.ID)
		}
		prev = rank
	}
	for _, m := range r.Measurements {
		if m.Status == domain.StatusFailure && m.Probe() == "" && !covered[m.ID] {
			t.Errorf("failed measurement %s is not referenced by any finding", m.ID)
		}
	}
	for _, h := range r.Hypotheses {
		if h.Confidence == domain.ConfidenceHigh {
			distinct := map[string]bool{}
			for _, e := range h.Supporting {
				for _, id := range e.MeasurementIDs {
					distinct[id] = true
				}
			}
			if len(distinct) < 2 {
				t.Errorf("hypothesis %s is high confidence from a single measurement", h.ID)
			}
		}
		if h.Summary == "" || len(h.FindingIDs) == 0 || len(h.Supporting) == 0 || len(h.Missing) == 0 {
			t.Errorf("hypothesis %s lacks an explanation, a finding, supporting evidence or missing evidence: %+v", h.ID, h)
		}
		for _, id := range h.FindingIDs {
			if !findings[id] {
				t.Errorf("hypothesis %s references unknown finding %s", h.ID, id)
			}
		}
		for _, e := range append(append(h.Supporting, h.Contradicting...), h.Missing...) {
			for _, id := range e.MeasurementIDs {
				if !ids[id] {
					t.Errorf("hypothesis %s cites unknown measurement %s", h.ID, id)
				}
			}
		}
	}
	for _, rec := range r.Recommendations {
		if rec.Summary == "" || len(rec.FindingIDs) == 0 {
			t.Errorf("recommendation %s is incomplete: %+v", rec.ID, rec)
		}
	}
	// Wording policy (SPEC 8.5): findings use technical vocabulary and never
	// label an event with a political or accusatory term.
	text := strings.ToLower(fmt.Sprint(r.Findings, r.Hypotheses, r.Recommendations))
	for _, w := range []string{"censor", "surveil", "regime", "government", "hijack", "attack", "malicious", "spy", "circumvent", "bypass"} {
		if strings.Contains(text, w) {
			t.Errorf("finding text contains %q", w)
		}
	}
	r.Summarize()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		t.Errorf("report does not match the schema: %v", err)
	}
}

func TestEvaluationIsDeterministic(t *testing.T) {
	build := func() *domain.Report {
		r := report(dnsOK("system", "", "192.0.2.10", "2001:db8::10"), dnsFail("udp", "9.9.9.9:53", domain.DNSTimeout),
			tcpOK("192.0.2.10"), tcpFail("2001:db8::10", domain.TCPTimeout), tlsFail("192.0.2.10", domain.TLSCertExpired, cert), httpStatus("ipv4", 503))
		// Normalize the volatile fields.
		r.Run.ID = "run-x"
		r.Run.StartedAt = time.Time{}
		for i := range r.Measurements {
			r.Measurements[i].StartedAt = time.Time{}
			r.Measurements[i].EndedAt = time.Time{}
			r.Measurements[i].DurationMS = 0
		}
		return r
	}
	a, b := build(), build()
	engine.Evaluate(All(), a)
	engine.Evaluate(All(), b)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("two evaluations differ:\n%s\n%s", ja, jb)
	}
	if len(a.Findings) < 4 {
		t.Fatalf("expected several findings, got %v", codesOf(a))
	}
}

func TestRuleMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if r.ID == "" || r.Version < 1 || r.Title == "" || r.Description == "" || r.Layer == "" || len(r.Requires) == 0 || len(r.Caveats) == 0 || r.Evaluate == nil {
			t.Errorf("rule %q is incomplete", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
	}
	if len(seen) != 9 {
		t.Errorf("expected nine rules, got %d", len(seen))
	}
}

func TestRulesNeedTheirMeasurements(t *testing.T) {
	// A report with no TLS measurement must not trigger TLS rules, however
	// the other measurements look.
	r := report(dnsOK("system", "", "192.0.2.10"), tcpOK("192.0.2.10"))
	engine.Evaluate(All(), r)
	if len(r.Findings) != 0 {
		t.Fatalf("unexpected findings: %v", codesOf(r))
	}
}

func TestHypothesesAreRankedByConfidence(t *testing.T) {
	r := report(dnsFail("system", "", domain.DNSNoAnswer), dnsFail("udp", "9.9.9.9:53", domain.DNSNXDomain), dnsFail("udp", "1.1.1.1:53", domain.DNSTimeout))
	engine.Evaluate(All(), r)
	rank := map[domain.Confidence]int{domain.ConfidenceHigh: 3, domain.ConfidenceMedium: 2, domain.ConfidenceLow: 1}
	for i := 1; i < len(r.Hypotheses); i++ {
		if rank[r.Hypotheses[i].Confidence] > rank[r.Hypotheses[i-1].Confidence] {
			t.Fatalf("hypotheses are not ranked: %+v", r.Hypotheses)
		}
	}
	if r.Hypotheses[0].Confidence != domain.ConfidenceHigh {
		t.Fatalf("two resolvers agreeing on NXDOMAIN should be high confidence: %+v", r.Hypotheses[0])
	}
}

func TestContradictingEvidenceLowersConfidence(t *testing.T) {
	r := report(dnsFail("system", "", domain.DNSNoAnswer), dnsOK("udp", "9.9.9.9:53", "192.0.2.10"))
	engine.Evaluate(All(), r)
	for _, h := range r.Hypotheses {
		if h.Summary == "The name does not exist or has no address records" && (h.Confidence != domain.ConfidenceLow || len(h.Contradicting) == 0) {
			t.Fatalf("an answering resolver must contradict it: %+v", h)
		}
	}
}

func TestNoPoliticalOrCircumventionVocabulary(t *testing.T) {
	// Wording policy (SPEC 8.5): technical vocabulary only.
	banned := []string{"censor", "block", "bypass", "circumvent", "vpn", "proxy bypass", "government", "regime"}
	r := report(dnsFail("system", "", domain.DNSNoAnswer), dnsOK("udp", "9.9.9.9:53", "0.0.0.0"),
		tcpFail("192.0.2.10", domain.TCPTimeout), tcpFail("192.0.2.11", domain.TCPRefused), tlsFail("192.0.2.10", domain.TLSReset, nil), httpStatus("", 403))
	r.Measurements[3].Target.IP = "192.0.2.10"
	engine.Evaluate(All(), r)
	b, _ := json.Marshal(r)
	text := string(b)
	for _, w := range banned {
		if containsFold(text, w) {
			t.Errorf("report text contains %q", w)
		}
	}
}

func containsFold(s, sub string) bool {
	s, sub = lower(s), lower(sub)
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
