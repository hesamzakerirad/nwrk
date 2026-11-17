package rules

import (
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
	"github.com/hesamzakerirad/nwrk/internal/platform"
)

func withProbe(m *domain.Measurement, probe string, kv ...any) *domain.Measurement {
	if m.Params == nil {
		m.Params = map[string]any{}
	}
	m.Params["probe"] = probe
	for i := 0; i+1 < len(kv); i += 2 {
		m.Params[kv[i].(string)] = kv[i+1]
	}
	return m
}

func resolverM(m *domain.Measurement, kind, addr string) *domain.Measurement {
	if kind == "system" {
		m.Resolver = &domain.ResolverInfo{Kind: "system"}
	} else {
		m.Resolver = &domain.ResolverInfo{Kind: kind, Address: addr}
	}
	return m
}

func dnsAnswer(host, kind, addr string, ips ...string) *domain.Measurement {
	m := resolverM(domain.Begin(domain.TypeDNS, "1", domain.Target{Host: host}), kind, addr)
	res := &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}}
	res.A = append(res.A, ips...)
	return m.Succeed(res)
}

func multi(addr string, replies ...[]string) *domain.Measurement {
	m := resolverM(domain.Begin(domain.TypeDNS, "1", domain.Target{Host: "example.test"}), "udp", addr)
	res := &dns.ProbeResult{WindowMS: 500, Responses: []dns.ProbeResponse{}}
	seen := map[string]bool{}
	for i, r := range replies {
		res.Responses = append(res.Responses, dns.ProbeResponse{DelayMS: float64(10 * (i + 1)), RCode: "NOERROR", Answers: r})
		seen[r[0]] = true
	}
	res.Distinct = len(seen)
	return withProbe(m.Succeed(res), domain.ProbeMultipleResponses)
}

func dnssec(signed, ad, vf bool, cnames ...string) *domain.Measurement {
	m := resolverM(domain.Begin(domain.TypeDNS, "1", domain.Target{Host: "example.test"}), "udp", "9.9.9.9:53")
	return withProbe(m.Succeed(&dns.InspectResult{RCode: "NOERROR", Answers: []string{"192.0.2.1"}, CNAMEs: append([]string{}, cnames...), Signed: signed, Authenticated: ad, ValidationFailure: vf}), domain.ProbeDNSSEC)
}

func reachProbe(source, ip string, ok bool) *domain.Measurement {
	m := conn(domain.TypeTCP, ip, 443)
	m = withProbe(m, domain.ProbeAnswerReachability, "source", source)
	if ok {
		return m.Succeed(&tcp.Result{Address: ip, Family: family(ip)})
	}
	return m.Fail(domain.TCPTimeout, "t", nil)
}

func hs(ip, probe, sni, outcome string) *domain.Measurement {
	m := conn(domain.TypeTLS, ip, 443)
	if probe != "" {
		m = withProbe(m, probe, "sni", sni)
	}
	certs := []mtls.Certificate{{Subject: "CN=x", Issuer: "CN=y", SANs: []string{}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}}
	switch outcome {
	case mtls.OutcomeCompleted:
		return m.Succeed(&mtls.Result{ServerName: sni, Version: "TLS 1.3", Chain: mtls.Chain{Verified: true}, Certificates: certs})
	case mtls.OutcomeAnswered:
		return m.Fail(domain.TLSHostnameMismatch, "mismatch", &mtls.Result{ServerName: sni, Certificates: certs})
	case mtls.OutcomeReset:
		return m.Fail(domain.TLSReset, "reset", &mtls.Result{ServerName: sni, Certificates: []mtls.Certificate{}})
	case mtls.OutcomeTimeout:
		return m.Fail(domain.TLSTimeout, "timeout", &mtls.Result{ServerName: sni, Certificates: []mtls.Certificate{}})
	}
	return m.Fail(domain.TLSHandshakeFailure, "the TLS handshake failed: remote error: tls: handshake failure", &mtls.Result{ServerName: sni, Certificates: []mtls.Certificate{}})
}

type hop struct {
	url      string
	status   int
	location string
}

func httpWith(probe, host, final string, status int, hops []hop, headers map[string]string) *domain.Measurement {
	m := domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: host, URL: "https://" + host + "/"})
	if probe != "" {
		m = withProbe(m, probe)
	}
	if headers == nil {
		headers = map[string]string{}
	}
	res := &mhttp.Result{Method: "GET", FinalURL: final, StatusCode: status, Hops: []mhttp.Hop{}, Headers: headers}
	for _, h := range hops {
		res.Hops = append(res.Hops, mhttp.Hop{URL: h.url, StatusCode: h.status, Location: h.location})
	}
	return m.Succeed(res)
}

func TestInterferenceRules(t *testing.T) {
	const v4a, v4b = "192.0.2.10", "198.51.100.20"
	sysA := func() *domain.Measurement { return dnsAnswer("example.test", "system", "", v4a) }
	cases := []struct {
		name     string
		ms       []*domain.Measurement
		want     []string
		wantNot  []string
		severity map[string]domain.Severity
	}{
		// DNS_ANSWER_MISMATCH
		{"mismatch: disjoint answers, nothing else", []*domain.Measurement{sysA(), dnsAnswer("example.test", "udp", "9.9.9.9:53", v4b)},
			[]string{"DNS_ANSWER_MISMATCH"}, nil, map[string]domain.Severity{"DNS_ANSWER_MISMATCH": domain.SeverityInfo}},
		{"mismatch: system answers do not connect, the other's do", []*domain.Measurement{sysA(), dnsAnswer("example.test", "udp", "9.9.9.9:53", v4b), reachProbe("system", v4a, false), reachProbe("9.9.9.9:53", v4b, true)},
			[]string{"DNS_ANSWER_MISMATCH"}, nil, map[string]domain.Severity{"DNS_ANSWER_MISMATCH": domain.SeverityWarning}},
		{"mismatch: a private address on one side", []*domain.Measurement{dnsAnswer("example.test", "system", "", "10.0.0.5"), dnsAnswer("example.test", "udp", "9.9.9.9:53", v4b)},
			[]string{"DNS_ANSWER_MISMATCH"}, nil, map[string]domain.Severity{"DNS_ANSWER_MISMATCH": domain.SeverityWarning}},
		{"mismatch: overlapping answers", []*domain.Measurement{sysA(), dnsAnswer("example.test", "udp", "9.9.9.9:53", v4a, v4b)},
			nil, []string{"DNS_ANSWER_MISMATCH"}, nil},
		{"mismatch: only the system resolver", []*domain.Measurement{sysA()},
			nil, []string{"DNS_ANSWER_MISMATCH"}, nil},

		// DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME
		{"private: public name to RFC 1918", []*domain.Measurement{dnsAnswer("www.example.com", "system", "", "192.168.1.1")},
			[]string{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME"}, nil, map[string]domain.Severity{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME": domain.SeverityWarning}},
		{"private: loopback and CGNAT too", []*domain.Measurement{dnsAnswer("a.example.com", "udp", "1.1.1.1:53", "127.0.0.1"), dnsAnswer("b.example.com", "udp", "1.1.1.1:53", "100.64.1.1")},
			[]string{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME"}, nil, nil},
		{"private: reserved local names are expected", []*domain.Measurement{dnsAnswer("nas.local", "system", "", "192.168.1.9"), dnsAnswer("printer.home.arpa", "system", "", "192.168.1.8"), dnsAnswer("intranet", "system", "", "10.0.0.1"), dnsAnswer("localhost", "system", "", "127.0.0.1")},
			nil, []string{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME"}, nil},
		{"private: public address is quiet", []*domain.Measurement{dnsAnswer("www.example.com", "system", "", "93.184.216.34")},
			nil, []string{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME"}, nil},
		{"private: an IP target is not a name", []*domain.Measurement{dnsAnswer("192.168.1.1", "system", "", "192.168.1.1")},
			nil, []string{"DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME"}, nil},

		// DNS_MULTIPLE_DIFFERENT_RESPONSES
		{"multi: two different replies", []*domain.Measurement{sysA(), multi("8.8.8.8:53", []string{"198.51.100.66"}, []string{v4a})},
			[]string{"DNS_MULTIPLE_DIFFERENT_RESPONSES"}, nil, map[string]domain.Severity{"DNS_MULTIPLE_DIFFERENT_RESPONSES": domain.SeverityWarning}},
		{"multi: a single reply", []*domain.Measurement{sysA(), multi("8.8.8.8:53", []string{v4a})},
			nil, []string{"DNS_MULTIPLE_DIFFERENT_RESPONSES"}, nil},
		{"multi: duplicate identical replies", []*domain.Measurement{sysA(), multi("8.8.8.8:53", []string{v4a}, []string{v4a})},
			nil, []string{"DNS_MULTIPLE_DIFFERENT_RESPONSES"}, nil},

		// TLS_RESET_AFTER_CLIENTHELLO and TLS_SNI_DEPENDENT_FAILURE
		{"sni: target resets, control answers", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeAnswered)},
			[]string{"TLS_RESET_AFTER_CLIENTHELLO", "TLS_SNI_DEPENDENT_FAILURE"}, nil, map[string]domain.Severity{"TLS_SNI_DEPENDENT_FAILURE": domain.SeverityWarning}},
		{"sni: target silent, control completes", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeTimeout), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeTimeout), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeAlert)},
			[]string{"TLS_SNI_DEPENDENT_FAILURE"}, nil, nil},
		{"sni: control fails the same way", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeReset)},
			[]string{"TLS_RESET_AFTER_CLIENTHELLO"}, []string{"TLS_SNI_DEPENDENT_FAILURE"}, nil},
		{"sni: one failure among successes", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeCompleted), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeAnswered)},
			nil, []string{"TLS_RESET_AFTER_CLIENTHELLO", "TLS_SNI_DEPENDENT_FAILURE"}, nil},
		{"sni: no repeat attempt, no interference finding", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeReset)},
			nil, []string{"TLS_RESET_AFTER_CLIENTHELLO", "TLS_SNI_DEPENDENT_FAILURE"}, nil},
		{"sni: everything works", []*domain.Measurement{sysA(), tcpOK(v4a), hs(v4a, "", "example.test", mtls.OutcomeCompleted), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeCompleted), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeAnswered)},
			nil, []string{"TLS_RESET_AFTER_CLIENTHELLO", "TLS_SNI_DEPENDENT_FAILURE"}, nil},
		{"sni: failure without a TCP connection is not this", []*domain.Measurement{sysA(), tcpFail(v4a, domain.TCPRefused), hs(v4a, "", "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNITarget, "example.test", mtls.OutcomeReset), hs(v4a, domain.ProbeSNIControl, "www.example.org", mtls.OutcomeAnswered)},
			nil, []string{"TLS_RESET_AFTER_CLIENTHELLO", "TLS_SNI_DEPENDENT_FAILURE"}, nil},

		// HTTP_REDIRECT_TO_UNRELATED_HOST
		{"redirect: leaves the domain", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://other-site.net/", 200, []hop{{"https://example.com/", 302, "https://other-site.net/"}, {"https://other-site.net/", 200, ""}}, nil)},
			[]string{"HTTP_REDIRECT_TO_UNRELATED_HOST"}, nil, map[string]domain.Severity{"HTTP_REDIRECT_TO_UNRELATED_HOST": domain.SeverityInfo}},
		{"redirect: to a bare private address", []*domain.Measurement{sysA(), httpWith("", "example.com", "http://10.1.1.1/login", 200, []hop{{"https://example.com/", 302, "http://10.1.1.1/login"}, {"http://10.1.1.1/login", 200, ""}}, nil)},
			[]string{"HTTP_REDIRECT_TO_UNRELATED_HOST"}, nil, map[string]domain.Severity{"HTTP_REDIRECT_TO_UNRELATED_HOST": domain.SeverityWarning}},
		{"redirect: same registered domain", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://www.example.com/", 200, []hop{{"https://example.com/", 301, "https://www.example.com/"}, {"https://www.example.com/", 200, ""}}, nil)},
			nil, []string{"HTTP_REDIRECT_TO_UNRELATED_HOST"}, nil},
		{"redirect: a multi-label suffix is respected", []*domain.Measurement{sysA(), httpWith("", "shop.example.co.uk", "https://www.example.co.uk/", 200, []hop{{"https://shop.example.co.uk/", 301, "https://www.example.co.uk/"}, {"https://www.example.co.uk/", 200, ""}}, nil)},
			nil, []string{"HTTP_REDIRECT_TO_UNRELATED_HOST"}, nil},

		// HTTP_HTTPS_RESPONSE_DIFFERENCE
		{"scheme: http ends on another domain", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://example.com/", 200, nil, nil), httpWith(domain.ProbePlainHTTP, "example.com", "http://portal.other.net/", 200, []hop{{"http://example.com/", 302, "http://portal.other.net/"}}, nil)},
			[]string{"HTTP_HTTPS_RESPONSE_DIFFERENCE"}, nil, map[string]domain.Severity{"HTTP_HTTPS_RESPONSE_DIFFERENCE": domain.SeverityWarning}},
		{"scheme: status differs over http", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://example.com/", 200, nil, nil), httpWith(domain.ProbePlainHTTP, "example.com", "http://example.com/", 403, nil, nil)},
			[]string{"HTTP_HTTPS_RESPONSE_DIFFERENCE"}, nil, map[string]domain.Severity{"HTTP_HTTPS_RESPONSE_DIFFERENCE": domain.SeverityInfo}},
		{"scheme: the normal upgrade to https is not a difference", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://example.com/", 200, nil, nil), httpWith(domain.ProbePlainHTTP, "example.com", "https://example.com/", 200, []hop{{"http://example.com/", 301, "https://example.com/"}}, nil)},
			nil, []string{"HTTP_HTTPS_RESPONSE_DIFFERENCE"}, nil},
		{"scheme: without the plain probe", []*domain.Measurement{sysA(), httpWith("", "example.com", "https://example.com/", 200, nil, nil)},
			nil, []string{"HTTP_HTTPS_RESPONSE_DIFFERENCE"}, nil},

		// INTERFERENCE_INSUFFICIENT_EVIDENCE
		{"evidence: no independent resolver", []*domain.Measurement{sysA(), dnssec(false, false, false)},
			[]string{"INTERFERENCE_INSUFFICIENT_EVIDENCE"}, nil, map[string]domain.Severity{"INTERFERENCE_INSUFFICIENT_EVIDENCE": domain.SeverityInfo}},
		{"evidence: all comparisons were made", []*domain.Measurement{sysA(), dnsAnswer("example.test", "udp", "9.9.9.9:53", v4a), dnssec(false, false, false)},
			nil, []string{"INTERFERENCE_INSUFFICIENT_EVIDENCE"}, nil},
		{"evidence: a plain diagnose is not an interference run", []*domain.Measurement{sysA()},
			nil, []string{"INTERFERENCE_INSUFFICIENT_EVIDENCE"}, nil},
	}
	rulesList := append(append(All(), Interference()...), Security()...)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := report(c.ms...)
			engine.Evaluate(rulesList, rep)
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

func TestSecurityRules(t *testing.T) {
	soon, later := time.Now().Add(5*24*time.Hour), time.Now().Add(90*24*time.Hour)
	cert := func(notAfter time.Time) *domain.Measurement {
		m := conn(domain.TypeTLS, "192.0.2.10", 443)
		return m.Succeed(&mtls.Result{ServerName: "example.test", Version: "TLS 1.3", Chain: mtls.Chain{Verified: true},
			Certificates: []mtls.Certificate{{Subject: "CN=example.test", Issuer: "CN=ca", NotBefore: time.Now().AddDate(0, -1, 0), NotAfter: notAfter, SANs: []string{"example.test"}}}})
	}
	legacy := func(ok bool) *domain.Measurement {
		m := withProbe(conn(domain.TypeTLS, "192.0.2.10", 443), domain.ProbeLegacyTLS)
		if ok {
			return m.Succeed(&mtls.Result{ServerName: "example.test", Version: "TLS 1.1", Certificates: []mtls.Certificate{}})
		}
		return m.Fail(domain.TLSHandshakeFailure, "the TLS handshake failed: remote error: tls: protocol version not supported", &mtls.Result{Certificates: []mtls.Certificate{}})
	}
	cases := []struct {
		name    string
		ms      []*domain.Measurement
		want    []string
		wantNot []string
	}{
		{"dnssec: validation failure", []*domain.Measurement{dnsAnswer("example.test", "system", "", "192.0.2.1"), dnssec(true, false, true)}, []string{"DNSSEC_VALIDATION_FAILURE"}, []string{"DNSSEC_STATUS"}},
		{"dnssec: signed and validated", []*domain.Measurement{dnsAnswer("example.test", "system", "", "192.0.2.1"), dnssec(true, true, false)}, []string{"DNSSEC_STATUS"}, []string{"DNSSEC_VALIDATION_FAILURE"}},
		{"dnssec: unsigned", []*domain.Measurement{dnsAnswer("example.test", "system", "", "192.0.2.1"), dnssec(false, false, false)}, []string{"DNSSEC_STATUS"}, []string{"DNSSEC_VALIDATION_FAILURE"}},
		{"cert: expires soon", []*domain.Measurement{cert(soon)}, []string{"TLS_CERTIFICATE_EXPIRING_SOON"}, nil},
		{"cert: far from expiry", []*domain.Measurement{cert(later)}, nil, []string{"TLS_CERTIFICATE_EXPIRING_SOON"}},
		{"cert: already expired is another rule", []*domain.Measurement{cert(time.Now().Add(-time.Hour))}, nil, []string{"TLS_CERTIFICATE_EXPIRING_SOON"}},
		{"legacy: accepted", []*domain.Measurement{cert(later), legacy(true)}, []string{"TLS_LEGACY_PROTOCOL_ACCEPTED"}, nil},
		{"legacy: refused", []*domain.Measurement{cert(later), legacy(false)}, nil, []string{"TLS_LEGACY_PROTOCOL_ACCEPTED"}},
		{"upgrade: http stays http", []*domain.Measurement{httpWith("", "example.com", "https://example.com/", 200, nil, map[string]string{"strict-transport-security": "max-age=1"}), httpWith(domain.ProbePlainHTTP, "example.com", "http://example.com/", 200, nil, nil)}, []string{"HTTP_NOT_UPGRADED_TO_HTTPS"}, []string{"HTTP_HSTS_MISSING"}},
		{"upgrade: http redirects to https", []*domain.Measurement{httpWith("", "example.com", "https://example.com/", 200, nil, map[string]string{"strict-transport-security": "max-age=1"}), httpWith(domain.ProbePlainHTTP, "example.com", "https://example.com/", 200, []hop{{"http://example.com/", 301, "https://example.com/"}}, nil)}, nil, []string{"HTTP_NOT_UPGRADED_TO_HTTPS"}},
		{"hsts: missing", []*domain.Measurement{httpWith("", "example.com", "https://example.com/", 200, nil, nil)}, []string{"HTTP_HSTS_MISSING"}, nil},
		{"hsts: present", []*domain.Measurement{httpWith("", "example.com", "https://example.com/", 200, nil, map[string]string{"strict-transport-security": "max-age=31536000"})}, nil, []string{"HTTP_HSTS_MISSING"}},
	}
	list := append(All(), Security()...)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := report(c.ms...)
			engine.Evaluate(list, rep)
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
			checkInvariants(t, rep)
		})
	}
}

func TestNoHypothesisIsHighFromASingleMeasurement(t *testing.T) {
	// An unusually clear single observation: one expired certificate, one
	// interface check. Both used to be "high".
	r1 := report(dnsAnswer("example.test", "system", "", "192.0.2.10"), tcpOK("192.0.2.10"), tlsFail("192.0.2.10", domain.TLSCertExpired, cert))
	r2 := doctorReport(local1()...)
	for _, r := range []*domain.Report{r1, r2} {
		engine.Evaluate(append(append(All(), Doctor()...), Interference()...), r)
		for _, h := range r.Hypotheses {
			ids := map[string]bool{}
			for _, e := range h.Supporting {
				for _, id := range e.MeasurementIDs {
					ids[id] = true
				}
			}
			if h.Confidence == domain.ConfidenceHigh && len(ids) < 2 {
				t.Errorf("high confidence from %d measurement(s): %+v", len(ids), h)
			}
		}
	}
}

func local1() []*domain.Measurement {
	return healthyLocal(osFake{ifs: []platform.Interface{{Name: "lo", Up: true, Loopback: true}}})
}

func TestInterferenceRuleMetadata(t *testing.T) {
	if len(Interference()) != 8 || len(Security()) != 6 {
		t.Fatalf("%d interference rules, %d security rules", len(Interference()), len(Security()))
	}
	seen := map[string]bool{}
	for _, r := range append(append(append(All(), Doctor()...), Interference()...), Security()...) {
		if r.ID == "" || r.Version < 1 || r.Title == "" || r.Description == "" || len(r.Caveats) == 0 || len(r.Requires) == 0 || r.Evaluate == nil {
			t.Errorf("rule %q is incomplete", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		text := strings.ToLower(r.Title + " " + r.Description + " " + strings.Join(r.Caveats, " "))
		for _, w := range []string{"censor", "surveil", "regime", "government", "hijack", "attack", "malicious", "circumvent", "bypass"} {
			if strings.Contains(text, w) {
				t.Errorf("rule %s metadata contains %q", r.ID, w)
			}
		}
	}
}
