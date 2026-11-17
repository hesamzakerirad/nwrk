package rules

import (
	"fmt"
	"net/netip"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
)

// DNSResolutionFailure fires when a resolver could not give an address.
var DNSResolutionFailure = engine.Rule{
	ID:          "DNS_RESOLUTION_FAILURE",
	Version:     1,
	Title:       "Name resolution failed",
	Description: "At least one DNS resolver did not return an address for the name.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A differing or missing DNS answer is an observation, not proof of manipulation: split-horizon DNS, CDNs, caches and geography can all explain differences.",
		"The system resolver is queried through the operating system, which does not report response codes. For it, dns.no_answer can also mean the name does not exist.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeDNS)
		bad, good := failed(all), succeeded(all)
		if len(bad) == 0 {
			return nil
		}
		host := in.Target()
		o := engine.Outcome{
			Severity:       severityByCoverage(len(bad), len(good)),
			MeasurementIDs: engine.IDs(bad),
		}
		if len(good) == 0 {
			o.Summary = fmt.Sprintf("No resolver returned an address for %s (%s)", host, codes(bad))
		} else {
			o.Summary = fmt.Sprintf("%s failed (%s) while %s returned addresses for %s",
				resolverNames(bad), codes(bad), resolverNames(good), host)
		}
		o.Hypotheses = dnsHypotheses(host, bad, good, len(all))
		o.Recommendations = dnsRecommendations(host, len(all))
		return []engine.Outcome{o}
	},
}

func dnsHypotheses(host string, bad, good []domain.Measurement, total int) []domain.Hypothesis {
	var out []domain.Hypothesis
	notFound := withCode(bad, domain.DNSNXDomain, domain.DNSNoAnswer)
	unreachable := withCode(bad, domain.DNSTimeout, domain.DNSTransport)
	servfail := withCode(bad, domain.DNSServFail, domain.DNSError)
	refused := withCode(bad, domain.DNSRefused)

	independent := missing("No independent resolver was compared; only the system resolver was measured")
	if len(notFound) > 0 {
		h := domain.Hypothesis{
			Summary:    "The name does not exist or has no address records",
			Confidence: domain.ConfidenceLow,
			Supporting: []domain.Evidence{ev(fmt.Sprintf("%s answered without an address (%s)", resolverNames(notFound), codes(notFound)), engine.IDs(notFound)...)},
		}
		switch {
		case len(good) == 0 && len(notFound) >= 2:
			h.Confidence = domain.ConfidenceHigh
		case len(good) == 0:
			h.Confidence = domain.ConfidenceMedium
		default:
			h.Contradicting = []domain.Evidence{ev(resolverNames(good)+" returned addresses", engine.IDs(good)...)}
		}
		h.Missing = append(h.Missing, missing("The domain's registration and delegation were not checked; nw does not query registries"))
		if total == 1 {
			h.Missing = append(h.Missing, independent)
		}
		h.NextMeasurements = []string{cmd("test", "dns", host, "--resolver", "<ip>")}
		out = append(out, h)

		if len(good) > 0 {
			out = append(out, domain.Hypothesis{
				Summary:    "The resolver that failed applies filtering, split-horizon views or a stale cache that the others do not",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{
					ev(resolverNames(notFound)+" gave no address", engine.IDs(notFound)...),
					ev(resolverNames(good)+" gave an address", engine.IDs(good)...),
				},
				Missing:          []domain.Evidence{missing("Which of the answers is the intended one has not been established")},
				NextMeasurements: []string{cmd("test", "dns", host, "--resolver", "<ip>")},
			})
		}
	}
	if len(unreachable) > 0 {
		h := domain.Hypothesis{
			Summary:    "The resolver could not be reached from this network: the server may be down, or its traffic may be blocked or dropped",
			Confidence: domain.ConfidenceMedium,
			Supporting: []domain.Evidence{ev(resolverNames(unreachable)+" did not respond ("+codes(unreachable)+")", engine.IDs(unreachable)...)},
			Missing: []domain.Evidence{
				missing("Reachability of the same resolver over TCP was not tested"),
				missing("Local network connectivity was not checked"),
			},
			NextMeasurements: []string{cmd("test", "dns", host, "--resolver", "tcp://<ip>")},
		}
		if len(good) > 0 {
			h.Contradicting = []domain.Evidence{ev(resolverNames(good)+" answered", engine.IDs(good)...)}
		} else {
			h.Confidence = domain.ConfidenceLow
		}
		out = append(out, h)
	}
	if len(servfail) > 0 {
		out = append(out, domain.Hypothesis{
			Summary:          "The resolver could not obtain an answer upstream: an authoritative server failure, or a DNSSEC validation problem",
			Confidence:       domain.ConfidenceMedium,
			Supporting:       []domain.Evidence{ev(resolverNames(servfail)+" reported a failure ("+codes(servfail)+")", engine.IDs(servfail)...)},
			Missing:          []domain.Evidence{missing("The authoritative servers of the zone were not queried directly")},
			NextMeasurements: []string{cmd("test", "dns", host, "--resolver", "<ip>")},
		})
	}
	if len(refused) > 0 {
		out = append(out, domain.Hypothesis{
			Summary:    "The resolver only serves certain clients and refused this one",
			Confidence: domain.ConfidenceMedium,
			Supporting: []domain.Evidence{ev(resolverNames(refused)+" refused the query", engine.IDs(refused)...)},
			Missing:    []domain.Evidence{missing("The resolver's access policy is unknown")},
		})
	}
	return out
}

func dnsRecommendations(host string, total int) []domain.Recommendation {
	recs := []domain.Recommendation{
		{Summary: "Check the spelling of the name and that its domain is registered and delegated", Command: ""},
	}
	if total == 1 {
		recs = append(recs, domain.Recommendation{
			Summary: "Compare with a resolver you choose, for example a public one or your organization's",
			Command: cmd("test", "dns", host, "--resolver", "<ip>"),
		})
	}
	return recs
}

// NoUsableAddress fires when DNS gave addresses but none can be connected to.
var NoUsableAddress = engine.Rule{
	ID:          "NO_USABLE_ADDRESS",
	Version:     1,
	Title:       "Name resolved, but no usable address",
	Description: "The name resolved, but every address is a placeholder, or no route exists to any of them.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A placeholder address such as 0.0.0.0 is a convention used by many kinds of DNS filters, and also appears in misconfigured zones; the address alone does not say which.",
		"No route to an address is a property of this network at this moment, not of the destination.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		if o := placeholderAnswer(in); o != nil {
			out = append(out, *o)
		}
		if o := noRoute(in); o != nil {
			out = append(out, *o)
		}
		return out
	},
}

// unusable reports addresses nothing can connect to.
func unusable(a netip.Addr) bool {
	return a.IsUnspecified() || a.IsMulticast()
}

func placeholderAnswer(in *engine.Input) *engine.Outcome {
	good := succeeded(in.Measurements(domain.TypeDNS))
	var bad []domain.Measurement
	var usable []domain.Measurement
	for _, m := range good {
		addrs := dns.Addresses(&m)
		if len(addrs) == 0 {
			continue
		}
		all := true
		for _, a := range addrs {
			if !unusable(a) {
				all = false
			}
		}
		if all {
			bad = append(bad, m)
		} else {
			usable = append(usable, m)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	h := domain.Hypothesis{
		Summary:    "A DNS filter or policy returned a placeholder instead of the real address, or the zone is misconfigured",
		Confidence: domain.ConfidenceMedium,
		Supporting: []domain.Evidence{ev(resolverNames(bad)+" returned only unspecified or multicast addresses", engine.IDs(bad)...)},
		Missing:    []domain.Evidence{missing("Which party operates the resolver's filtering, if any, is unknown")},
	}
	if len(usable) > 0 {
		h.Contradicting = []domain.Evidence{ev(resolverNames(usable)+" returned usable addresses", engine.IDs(usable)...)}
	} else {
		h.Missing = append(h.Missing, missing("No other resolver was compared"))
	}
	return &engine.Outcome{
		Severity:        domain.SeverityError,
		Summary:         fmt.Sprintf("%s returned only addresses that cannot be connected to", resolverNames(bad)),
		MeasurementIDs:  engine.IDs(bad),
		Hypotheses:      []domain.Hypothesis{h},
		Recommendations: []domain.Recommendation{{Summary: "Compare with a resolver you choose", Command: cmd("test", "dns", in.Target(), "--resolver", "<ip>")}},
	}
}

func noRoute(in *engine.Input) *engine.Outcome {
	tcps := in.Measurements(domain.TypeTCP)
	bad := withCode(tcps, domain.TCPUnreachable)
	if len(bad) == 0 || len(bad) != len(failed(tcps)) || len(succeeded(tcps)) > 0 {
		return nil
	}
	onlyV6 := true
	for _, m := range bad {
		if m.Target.Family != "ipv6" {
			onlyV6 = false
		}
	}
	h := domain.Hypothesis{
		Summary:    "This network has no route for the address family the name resolved to",
		Confidence: domain.ConfidenceMedium,
		Supporting: []domain.Evidence{ev("No route to "+endpoints(bad), engine.IDs(bad)...)},
		Missing:    []domain.Evidence{missing("Local network configuration (routes, interfaces) was not inspected")},
	}
	if onlyV6 {
		h.Summary = "The name resolved only to IPv6 addresses and this network has no IPv6 route"
		h.Confidence = domain.ConfidenceHigh
	}
	return &engine.Outcome{
		Severity:       domain.SeverityError,
		Summary:        "Addresses were returned, but there is no route to any of them: " + endpoints(bad),
		MeasurementIDs: engine.IDs(bad),
		Hypotheses:     []domain.Hypothesis{h},
		Recommendations: []domain.Recommendation{
			{Summary: "Check that this machine has a working network connection and a default route"},
		},
	}
}
