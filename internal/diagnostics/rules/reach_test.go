package rules

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
)

func reachHTTP(host, fam string) *domain.Measurement {
	return domain.Begin(domain.TypeHTTP, "1", domain.Target{Host: host, URL: "https://" + host + "/", Family: fam})
}

func reachOK(host, fam string, status int, headers map[string]string) *domain.Measurement {
	if headers == nil {
		headers = map[string]string{}
	}
	return reachHTTP(host, fam).Succeed(&mhttp.Result{Method: "GET", StatusCode: status, Hops: []mhttp.Hop{}, Headers: headers})
}

func reachFail(host, fam string, code domain.ErrorCode) *domain.Measurement {
	return reachHTTP(host, fam).Fail(code, string(code), nil)
}

func h3Probe(host string, ok bool) *domain.Measurement {
	m := reachHTTP(host, "ipv4")
	m.Params = map[string]any{"probe": domain.ProbeHTTP3}
	if ok {
		return m.Succeed(&mhttp.Result{Method: "HEAD", StatusCode: 200, Hops: []mhttp.Hop{}, Headers: map[string]string{}})
	}
	return m.Fail(domain.HTTPTimeout, "timeout", nil)
}

func evalReach(ms ...*domain.Measurement) *domain.Report {
	r := report(ms...)
	engine.Evaluate(Reach(), r)
	return r
}

func TestReachRules(t *testing.T) {
	altSvc := map[string]string{"alt-svc": `h3=":443"; ma=86400`}
	cases := []struct {
		name string
		ms   []*domain.Measurement
		want []string
		sev  domain.Severity
	}{
		{"403 is a server-side restriction", []*domain.Measurement{reachOK("a.example", "ipv4", 403, nil)}, []string{"REACH_SERVER_SIDE_RESTRICTION"}, domain.SeverityWarning},
		{"451 is a server-side restriction", []*domain.Measurement{reachOK("a.example", "ipv4", 451, nil)}, []string{"REACH_SERVER_SIDE_RESTRICTION"}, domain.SeverityWarning},
		{"401 is not a restriction", []*domain.Measurement{reachOK("a.example", "ipv4", 401, nil)}, nil, ""},
		{"200 is quiet", []*domain.Measurement{reachOK("a.example", "ipv4", 200, nil)}, nil, ""},
		{"reset is interference", []*domain.Measurement{reachFail("a.example", "ipv4", domain.HTTPReset)}, []string{"REACH_NETWORK_INTERFERENCE"}, domain.SeverityWarning},
		{"tls timeout is interference", []*domain.Measurement{reachFail("a.example", "ipv4", domain.TLSTimeout)}, []string{"REACH_NETWORK_INTERFERENCE"}, domain.SeverityWarning},
		{"refused is not interference", []*domain.Measurement{reachFail("a.example", "ipv4", domain.TCPRefused)}, []string{"UNCLASSIFIED_FAILURE"}, ""},
		{"a certificate error is not interference", []*domain.Measurement{reachFail("a.example", "ipv4", domain.TLSCertExpired)}, []string{"UNCLASSIFIED_FAILURE"}, ""},
		{"a failure that another family overcame is not interference",
			[]*domain.Measurement{reachFail("a.example", "ipv6", domain.HTTPReset), reachOK("a.example", "ipv4", 200, nil)}, []string{"REACH_IP_FAMILY_DIFFERENCE"}, domain.SeverityWarning},
		{"no IPv6 route is informational",
			[]*domain.Measurement{reachFail("a.example", "ipv6", domain.TCPUnreachable), reachOK("a.example", "ipv4", 200, nil)}, []string{"REACH_IP_FAMILY_DIFFERENCE"}, domain.SeverityInfo},
		{"both families failing is not a difference",
			[]*domain.Measurement{reachFail("a.example", "ipv6", domain.TCPUnreachable), reachFail("a.example", "ipv4", domain.TCPUnreachable)}, []string{"UNCLASSIFIED_FAILURE"}, ""},
		{"http3 fails while the server advertises it",
			[]*domain.Measurement{reachOK("a.example", "ipv4", 200, altSvc), h3Probe("a.example", false)}, []string{"REACH_HTTP3_FAILS_TCP_WORKS"}, domain.SeverityInfo},
		{"http3 failure without an advertisement is quiet",
			[]*domain.Measurement{reachOK("a.example", "ipv4", 200, nil), h3Probe("a.example", false)}, nil, ""},
		{"http3 working is quiet",
			[]*domain.Measurement{reachOK("a.example", "ipv4", 200, altSvc), h3Probe("a.example", true)}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evalReach(c.ms...)
			if got := codesOf(r); !slices.Equal(got, c.want) {
				t.Fatalf("findings = %v, want %v", got, c.want)
			}
			if c.sev != "" && r.Findings[0].Severity != c.sev {
				t.Errorf("severity = %s, want %s", r.Findings[0].Severity, c.sev)
			}
			checkInvariants(t, r)
		})
	}
}

func TestReachInterferenceFromPrivateAnswer(t *testing.T) {
	d := dnsOK("system", "", "10.1.2.3")
	d.Target.Host = "a.example.com"
	r := evalReach(d, reachOK("a.example.com", "ipv4", 200, nil))
	if got := codesOf(r); !slices.Equal(got, []string{"REACH_NETWORK_INTERFERENCE"}) {
		t.Fatalf("findings = %v", got)
	}
}

func TestReachConfidence(t *testing.T) {
	one := evalReach(reachFail("a.example", "ipv4", domain.HTTPReset))
	if c := one.Hypotheses[0].Confidence; c != domain.ConfidenceLow {
		t.Errorf("one failing endpoint: confidence %s, want low", c)
	}
	many := evalReach(
		reachFail("a.example", "ipv4", domain.HTTPReset), reachFail("b.example", "ipv4", domain.TLSTimeout),
		reachOK("c.example", "ipv4", 200, nil))
	if c := many.Hypotheses[0].Confidence; c != domain.ConfidenceMedium {
		t.Errorf("two failing endpoints beside a working one: confidence %s, want medium", c)
	}
	for _, r := range []*domain.Report{one, many, evalReach(reachOK("a.example", "ipv4", 451, nil))} {
		for _, h := range r.Hypotheses {
			if h.Confidence == domain.ConfidenceHigh {
				t.Error("no reach rule may report high confidence")
			}
		}
	}
}

func TestReachWording(t *testing.T) {
	banned := []string{"censor", "block", "bypass", "circumvent", "vpn", "proxy bypass", "government", "regime", "sanction"}
	d := dnsOK("system", "", "10.1.2.3")
	d.Target.Host = "d.example.com"
	r := evalReach(
		reachOK("a.example", "ipv4", 403, nil), reachOK("e.example", "ipv4", 451, nil),
		reachFail("b.example", "ipv4", domain.HTTPReset), reachOK("c.example", "ipv4", 200, map[string]string{"alt-svc": "h3"}),
		h3Probe("c.example", false), reachFail("f.example", "ipv6", domain.TCPUnreachable), reachOK("f.example", "ipv4", 200, nil), d)
	b, _ := json.Marshal(r)
	for _, w := range banned {
		if containsFold(string(b), w) {
			t.Errorf("report text contains %q", w)
		}
	}
	for _, rule := range Reach() {
		if rule.ID == "" || rule.Version < 1 || rule.Title == "" || rule.Description == "" || len(rule.Caveats) == 0 || rule.Evaluate == nil {
			t.Errorf("rule %q is incomplete", rule.ID)
		}
	}
}
