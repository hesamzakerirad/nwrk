package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
)

// Reach returns the rules of nw reach. They sort a failing endpoint into
// one of two groups, with neutral wording: a server-side restriction (the
// server answered, and its answer refuses the request) or network
// interference (the path altered or dropped the exchange).
func Reach() []engine.Rule {
	return []engine.Rule{
		DNSResolutionFailure,
		ReachServerSideRestriction,
		ReachNetworkInterference,
		ReachHTTP3Blocked,
		ReachFamilyDifference,
	}
}

// hostGroups groups the ordinary HTTP measurements by endpoint URL, in
// report order. The keys are URLs; hostName gives the name to show.
func hostGroups(in *engine.Input) ([]string, map[string][]domain.Measurement) {
	var hosts []string
	by := map[string][]domain.Measurement{}
	for _, m := range in.Measurements(domain.TypeHTTP) {
		if m.Status == domain.StatusSkipped {
			continue
		}
		if _, ok := by[m.Target.URL]; !ok {
			hosts = append(hosts, m.Target.URL)
		}
		by[m.Target.URL] = append(by[m.Target.URL], m)
	}
	return hosts, by
}

func hostName(ms []domain.Measurement) string { return ms[0].Target.Host }

func statusOf(m domain.Measurement) int {
	if res, ok := engine.ResultOf[mhttp.Result](m); ok {
		return res.StatusCode
	}
	return 0
}

// ReachServerSideRestriction fires when a server answered and the answer
// refuses the request.
var ReachServerSideRestriction = engine.Rule{
	ID:          "REACH_SERVER_SIDE_RESTRICTION",
	Version:     1,
	Title:       "The server answered with a refusal",
	Description: "An endpoint completed the exchange, and the final response has status 403 (forbidden) or 451 (unavailable for legal reasons). The network delivered the request; the server side declined it.",
	Layer:       engine.LayerReachability,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"A 403 is also the normal answer to a request that lacks credentials, a path or a header the server expects. nw sends no cookies and a minimal User-Agent.",
		"CDNs and bot protection answer a command-line client differently from a browser.",
		"nw does not keep the response body, so it cannot tell a provider error page from an ordinary one.",
		"One network is one vantage point. The same answer from another network would show whether the refusal depends on the address or the region.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		hosts, by := hostGroups(in)
		var bad []domain.Measurement
		var parts []string
		has451 := false
		for _, h := range hosts {
			for _, m := range succeeded(by[h]) {
				if s := statusOf(m); s == 403 || s == 451 {
					bad = append(bad, m)
					parts = append(parts, fmt.Sprintf("%s (%d)", hostName(by[h]), s))
					has451 = has451 || s == 451
					break
				}
			}
		}
		if len(bad) == 0 {
			return nil
		}
		ids := engine.IDs(bad)
		h := domain.Hypothesis{
			Summary:    "The server, a CDN or a hosting provider restricts access from this address or region. Access rules, geographic policy and legal compliance are examples of causes",
			Confidence: domain.ConfidenceLow,
			Supporting: []domain.Evidence{ev("The server completed the exchange and its final answer was a refusal", ids...)},
			Missing: []domain.Evidence{
				missing("The same request from another network was not made"),
				missing("The response body was not kept, so a provider error page was not identified"),
			},
		}
		if has451 {
			h.Confidence = domain.ConfidenceMedium
			h.Supporting = append(h.Supporting, ev("Status 451 means the resource is unavailable for legal reasons", ids...))
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityWarning,
			Summary:        "Server-side restriction pattern: " + strings.Join(parts, ", "),
			MeasurementIDs: ids,
			Hypotheses:     []domain.Hypothesis{h},
			Recommendations: []domain.Recommendation{
				{Summary: "Request the same URL from another network and compare the status code", Command: cmd("test", "http", "<url>")},
			},
		}}
	},
}

// interferenceCodes are failures that a device on the path can cause.
var interferenceCodes = []domain.ErrorCode{
	domain.TCPReset, domain.TCPTimeout, domain.TLSReset, domain.TLSTimeout,
	domain.TLSHandshakeFailure, domain.HTTPReset, domain.HTTPTimeout,
}

// ReachNetworkInterference fires when an endpoint fails in a way a device
// on the path can cause, or resolves to an address that does not belong to
// a public name.
var ReachNetworkInterference = engine.Rule{
	ID:          "REACH_NETWORK_INTERFERENCE",
	Version:     1,
	Title:       "The exchange failed in a way the network can cause",
	Description: "Every request to an endpoint failed with a reset, a timeout or a failed handshake, or the system resolver answered with a private, loopback or link-local address. The pattern fits interference on the path. It does not prove it.",
	Layer:       engine.LayerReachability,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"An overloaded or offline server, a firewall at the server and a broken route produce the same resets and timeouts.",
		"Split-horizon DNS, corporate networks, tunnels and captive portals return private addresses for public names on purpose.",
		"nw measures from one network. Without a second vantage point the cause stays open.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		hosts, by := hostGroups(in)
		private := privateAnswers(in)
		var bad []domain.Measurement
		var parts []string
		okHosts := 0
		for _, h := range hosts {
			ms := by[h]
			if len(succeeded(ms)) > 0 {
				okHosts++
				continue
			}
			failures := withCode(ms, interferenceCodes...)
			if len(failures) == len(failed(ms)) && len(failures) > 0 {
				bad = append(bad, failures...)
				parts = append(parts, fmt.Sprintf("%s (%s)", hostName(by[h]), codes(failures)))
			}
		}
		var dnsIDs []string
		for _, h := range private {
			parts = append(parts, h.host+" (resolved to "+h.kind+" address)")
			dnsIDs = append(dnsIDs, h.id)
		}
		if len(bad) == 0 && len(dnsIDs) == 0 {
			return nil
		}
		ids := append(engine.IDs(bad), dnsIDs...)
		h := domain.Hypothesis{
			Summary:    "A device on the path alters, resets or drops the exchange. Reset, drop and answer rewriting are examples of what the evidence fits",
			Confidence: domain.ConfidenceLow,
			Supporting: []domain.Evidence{ev("The failures are of a kind that a device on the path can cause", ids...)},
			Missing: []domain.Evidence{
				missing("The same request from another network was not made"),
				missing("A server outage looks the same from this vantage point"),
			},
			NextMeasurements: []string{cmd("security", "interference", "<host>")},
		}
		if okHosts > 0 && len(parts) >= 2 {
			h.Confidence = domain.ConfidenceMedium
			h.Supporting = append(h.Supporting, ev(fmt.Sprintf("%d other endpoints answered, so this machine can reach the internet", okHosts)))
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityWarning,
			Summary:        "Network interference pattern: " + strings.Join(parts, ", "),
			MeasurementIDs: ids,
			Hypotheses:     []domain.Hypothesis{h},
			Recommendations: []domain.Recommendation{
				{Summary: "Run the interference checks for the first failing host", Command: cmd("security", "interference", "<host>")},
			},
		}}
	},
}

type privateAnswer struct{ host, kind, id string }

// privateAnswers lists the system resolver answers that are private.
func privateAnswers(in *engine.Input) []privateAnswer {
	var out []privateAnswer
	for _, m := range succeeded(in.Measurements(domain.TypeDNS)) {
		if m.Resolver == nil || m.Resolver.Kind != "system" || isSpecialUse(m.Target.Host) {
			continue
		}
		res, ok := engine.ResultOf[dns.Result](m)
		if !ok {
			continue
		}
		for _, a := range append(append([]string{}, res.A...), res.AAAA...) {
			if k, priv := privateKind(a); priv {
				out = append(out, privateAnswer{m.Target.Host, k, m.ID})
				break
			}
		}
	}
	return out
}

// ReachHTTP3Blocked fires when a server advertises HTTP/3 and the HTTP/3
// probe fails while HTTPS over TCP works.
var ReachHTTP3Blocked = engine.Rule{
	ID:          "REACH_HTTP3_FAILS_TCP_WORKS",
	Version:     1,
	Title:       "HTTP/3 fails while HTTPS over TCP works",
	Description: "The server advertises HTTP/3 in its Alt-Svc header, the HTTPS request over TCP succeeded, and the HTTP/3 probe over UDP got no response. The finding is informational: browsers and tools fall back to TCP.",
	Layer:       engine.LayerReachability,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"Many networks and firewalls drop UDP port 443 without any intent to restrict a service.",
		"A server can advertise HTTP/3 for some of its hosts only.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		hosts, by := hostGroups(in)
		probes := in.Probes(domain.TypeHTTP, domain.ProbeHTTP3)
		var bad []domain.Measurement
		var parts []string
		for _, h := range hosts {
			if !advertisesH3(succeeded(by[h])) {
				continue
			}
			for _, p := range failed(filter(probes, func(m domain.Measurement) bool { return m.Target.URL == h })) {
				bad = append(bad, p)
				parts = append(parts, hostName(by[h]))
				break
			}
		}
		if len(bad) == 0 {
			return nil
		}
		ids := engine.IDs(bad)
		return []engine.Outcome{{
			Severity:       domain.SeverityInfo,
			Summary:        "HTTP/3 got no response although HTTPS over TCP works: " + strings.Join(parts, ", "),
			MeasurementIDs: ids,
			Hypotheses: []domain.Hypothesis{{
				Summary:    "UDP port 443 is filtered on this network or on the path to the server",
				Confidence: domain.ConfidenceLow,
				Supporting: []domain.Evidence{ev("The HTTP/3 probe failed while the TCP request to the same host worked", ids...)},
				Missing:    []domain.Evidence{missing("Whether other UDP traffic passes was not checked")},
			}},
		}}
	},
}

func advertisesH3(ms []domain.Measurement) bool {
	for _, m := range ms {
		if res, ok := engine.ResultOf[mhttp.Result](m); ok && strings.Contains(res.Headers["alt-svc"], "h3") {
			return true
		}
	}
	return false
}

// ReachFamilyDifference fires when an endpoint answers over one address
// family and not over the other.
var ReachFamilyDifference = engine.Rule{
	ID:          "REACH_IP_FAMILY_DIFFERENCE",
	Version:     1,
	Title:       "An endpoint works over one IP family only",
	Description: "The endpoint has IPv4 and IPv6 addresses, and the request succeeded over one family and failed over the other.",
	Layer:       engine.LayerIPFamily,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"A name with no AAAA record is not an IPv6 failure, and this rule does not fire for it.",
		"Many networks have no IPv6 connectivity at all. A missing route is reported as informational.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		hosts, by := hostGroups(in)
		var out []engine.Outcome
		sort.Strings(hosts)
		for _, h := range hosts {
			v4 := filter(by[h], func(m domain.Measurement) bool { return m.Target.Family == "ipv4" })
			v6 := filter(by[h], func(m domain.Measurement) bool { return m.Target.Family == "ipv6" })
			if len(v4) == 0 || len(v6) == 0 {
				continue
			}
			var good, bad []domain.Measurement
			var workingName, brokenName string
			switch {
			case len(succeeded(v4)) > 0 && len(succeeded(v6)) == 0:
				good, bad, workingName, brokenName = succeeded(v4), failed(v6), "IPv4", "IPv6"
			case len(succeeded(v6)) > 0 && len(succeeded(v4)) == 0:
				good, bad, workingName, brokenName = succeeded(v6), failed(v4), "IPv6", "IPv4"
			default:
				continue
			}
			if len(bad) == 0 {
				continue
			}
			ids := append(engine.IDs(good), engine.IDs(bad)...)
			sev := domain.SeverityWarning
			hyp := domain.Hypothesis{
				Summary:    brokenName + " is handled differently from " + workingName + " on this network or at the server",
				Confidence: domain.ConfidenceLow,
				Supporting: []domain.Evidence{ev(fmt.Sprintf("The request worked over %s and failed over %s (%s)", workingName, brokenName, codes(bad)), ids...)},
				Missing:    []domain.Evidence{missing("The same request from another network was not made")},
			}
			if len(withCode(bad, domain.TCPUnreachable)) == len(bad) {
				sev = domain.SeverityInfo
				hyp.Summary = "This network has no " + brokenName + " route"
				hyp.Confidence = domain.ConfidenceMedium
			}
			out = append(out, engine.Outcome{
				Severity:       sev,
				Summary:        fmt.Sprintf("%s works over %s and fails over %s (%s)", hostName(by[h]), workingName, brokenName, codes(bad)),
				MeasurementIDs: ids,
				Hypotheses:     []domain.Hypothesis{hyp},
			})
		}
		return out
	},
}
