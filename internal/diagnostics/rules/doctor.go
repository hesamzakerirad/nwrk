package rules

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	"github.com/hesamzakerirad/nwrk/internal/measurement/local"
)

// Doctor returns the rules of nw doctor, in the order they are evaluated.
func Doctor() []engine.Rule {
	return []engine.Rule{
		LocalNoActiveInterface,
		LocalNoDefaultRoute,
		LocalNoResolverConfigured,
		SystemResolverFailing,
		InternationalUnreachable,
		DomesticUnreachable,
		ReferenceResolverFailing,
		ResolverAnswerDifference,
		ProxyConfigured,
	}
}

// Rule IDs that place the problem in the local layer.
const (
	idNoInterface = "LOCAL_NO_ACTIVE_INTERFACE"
	idNoRoute     = "LOCAL_NO_DEFAULT_ROUTE"
	idNoResolver  = "LOCAL_NO_RESOLVER_CONFIGURED"
	idSystemDNS   = "SYSTEM_RESOLVER_FAILING"
)

// LocalFindingCodes are the findings that mean the problem is on this
// machine or in its network configuration.
var LocalFindingCodes = []string{idNoInterface, idNoRoute, idNoResolver, idSystemDNS}

func localCheck(in *engine.Input, check string) []domain.Measurement {
	return filter(in.Measurements(domain.TypeLocal), func(m domain.Measurement) bool { return m.Params["check"] == check })
}

func scoped(ms []domain.Measurement, s domain.Scope) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool { return m.Scope == s })
}

func notSkipped(ms []domain.Measurement) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool { return m.Status != domain.StatusSkipped })
}

func isSystem(m domain.Measurement) bool { return m.Resolver != nil && m.Resolver.Kind == "system" }

func hosts(ms []domain.Measurement) string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if h := m.Target.Host; h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// LocalNoActiveInterface fires when no interface can reach beyond this machine.
var LocalNoActiveInterface = engine.Rule{
	ID:          idNoInterface,
	Version:     1,
	Title:       "No usable network interface",
	Description: "No network interface is up with an address that can reach beyond this machine.",
	Layer:       engine.LayerLocal,
	Requires:    []domain.Type{domain.TypeLocal},
	Caveats: []string{
		"Interfaces are read from the operating system. A connection that is still being set up, or an adapter the system does not report, shows up here as missing.",
		"Link-local addresses alone (169.254.x.x, fe80::) are not enough to reach beyond the local link, so they do not count.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		bad := failed(localCheck(in, local.CheckInterfaces))
		if len(bad) == 0 {
			return nil
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityError,
			Summary:        "No network interface is up with an address that can reach beyond this machine",
			MeasurementIDs: engine.IDs(bad),
			Hypotheses: []domain.Hypothesis{{
				Summary:    "This machine is not connected to a network: Wi-Fi or cable is off, or the connection has not obtained an address yet",
				Confidence: domain.ConfidenceHigh,
				Supporting: []domain.Evidence{ev("No interface is up with a usable address", engine.IDs(bad)...)},
				Missing:    []domain.Evidence{missing("The state of the network adapter and its driver was not inspected")},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Check that Wi-Fi or the network cable is connected, then look at the interfaces", Command: cmd("network", "interfaces")},
			},
		}}
	},
}

// LocalNoDefaultRoute fires when the system has no route to the internet.
var LocalNoDefaultRoute = engine.Rule{
	ID:          idNoRoute,
	Version:     1,
	Title:       "No default route",
	Description: "The operating system has no route to the internet for IPv4 or IPv6.",
	Layer:       engine.LayerLocal,
	Requires:    []domain.Type{domain.TypeLocal},
	Caveats: []string{
		"The check asks the operating system for a route to a public address and sends no packet. A route that exists but leads nowhere still passes; the reachability checks cover that.",
		"A VPN client can change the routing table, and a route that appears a moment later passes on the next run.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		bad := failed(localCheck(in, local.CheckRoute))
		if len(bad) == 0 {
			return nil
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityError,
			Summary:        "The operating system has no route to the internet",
			MeasurementIDs: engine.IDs(bad),
			Hypotheses: []domain.Hypothesis{{
				Summary:    "The network connection has no gateway: it is not fully set up, the router is not providing one, or a VPN or firewall client removed the route",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{ev("The system could not select a route for IPv4 or IPv6", engine.IDs(bad)...)},
				Missing:    []domain.Evidence{missing("The routing table and the router were not inspected from here")},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Look at the routing table and the default gateway", Command: cmd("network", "routes")},
				{Summary: "Check that the router or access point is on and handing out a gateway"},
			},
		}}
	},
}

// LocalNoResolverConfigured fires when no DNS server is configured.
var LocalNoResolverConfigured = engine.Rule{
	ID:          idNoResolver,
	Version:     1,
	Title:       "No DNS server configured",
	Description: "The operating system has no DNS server configured.",
	Layer:       engine.LayerLocal,
	Requires:    []domain.Type{domain.TypeLocal},
	Caveats: []string{
		"nw reads the configuration the platform keeps in files or adapter settings. A system that resolves names through another mechanism may be misreported; see docs/platform-support.md.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		bad := failed(localCheck(in, local.CheckResolvers))
		if len(bad) == 0 {
			return nil
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityWarning,
			Summary:        "The operating system has no DNS server configured",
			MeasurementIDs: engine.IDs(bad),
			Hypotheses: []domain.Hypothesis{{
				Summary:    "The network did not provide DNS servers, or they were removed by a configuration change",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{ev("The configuration lists no name server", engine.IDs(bad)...)},
				Missing:    []domain.Evidence{missing("Whether names resolve through another mechanism was not checked; see the DNS checks in this report")},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Look at the configured resolvers", Command: cmd("network", "dns-config")},
			},
		}}
	},
}

// SystemResolverFailing fires when the system resolver fails to resolve
// the reference names.
var SystemResolverFailing = engine.Rule{
	ID:          idSystemDNS,
	Version:     1,
	Title:       "The system resolver is failing",
	Description: "The system resolver could not resolve reference names. It is an error when every lookup failed.",
	Layer:       engine.LayerLocal,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A name can fail to resolve for reasons specific to that name. That is why one failing name is only a warning; the finding is an error when every reference lookup failed.",
		"The system resolver is queried through the operating system, which does not report response codes.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeDNS)
		sys := notSkipped(filter(all, isSystem))
		bad := failed(sys)
		if len(bad) == 0 {
			return nil
		}
		others := succeeded(filter(all, func(m domain.Measurement) bool { return !isSystem(m) }))
		o := engine.Outcome{
			Severity:       domain.SeverityWarning,
			Summary:        fmt.Sprintf("The system resolver failed for %s (%s)", hosts(bad), codes(bad)),
			MeasurementIDs: engine.IDs(bad),
			Recommendations: []domain.Recommendation{
				{Summary: "Look at the configured resolvers", Command: cmd("network", "dns-config")},
				{Summary: "Compare with a resolver you choose", Command: cmd("test", "dns", "<host>", "--resolver", "<ip>")},
			},
		}
		if len(succeeded(sys)) == 0 {
			o.Severity = domain.SeverityError
		}
		h := domain.Hypothesis{Supporting: []domain.Evidence{ev("The system resolver failed ("+codes(bad)+")", engine.IDs(bad)...)}}
		if len(others) > 0 {
			h.Summary = "The resolver configured on this machine is unreachable or failing, while other resolvers work from the same network"
			h.Confidence = domain.ConfidenceMedium
			if len(others) >= 2 {
				h.Confidence = domain.ConfidenceHigh
			}
			h.Supporting = append(h.Supporting, ev("Other resolvers answered", engine.IDs(others)...))
			h.Missing = []domain.Evidence{missing("Why the configured resolver fails (the server, the path to it, or its policy) was not determined")}
		} else {
			h.Summary = "Name resolution does not work from here at all: the connection is down beyond this machine, or DNS traffic is dropped"
			h.Confidence = domain.ConfidenceLow
			h.Missing = []domain.Evidence{missing("No other resolver answered, so the resolver cannot be told apart from the network")}
		}
		if len(succeeded(sys)) > 0 {
			h.Summary = "The system resolver fails for some names only, which points at those names rather than at the resolver"
			h.Confidence = domain.ConfidenceLow
			h.Contradicting = []domain.Evidence{ev("The system resolver answered for other names", engine.IDs(succeeded(sys))...)}
		}
		o.Hypotheses = []domain.Hypothesis{h}
		return []engine.Outcome{o}
	},
}

func reachabilityRule(id, title, desc string, scope, other domain.Scope, otherName string) engine.Rule {
	return engine.Rule{
		ID:          id,
		Version:     1,
		Title:       title,
		Description: desc,
		Layer:       engine.LayerReachability,
		Requires:    []domain.Type{domain.TypeHTTP},
		Caveats: []string{
			"Reachability is judged from a few reference targets. A single target can be down for its own reasons, which is why one failure among several is only a warning.",
			"A target that fails here may work elsewhere and the reverse; the result is about this network at this moment.",
		},
		Evaluate: func(in *engine.Input) []engine.Outcome {
			all := notSkipped(scoped(in.Measurements(domain.TypeHTTP), scope))
			bad := failed(all)
			if len(bad) == 0 {
				return nil
			}
			good := succeeded(all)
			o := engine.Outcome{
				Severity:       severityByCoverage(len(bad), len(good)),
				Summary:        fmt.Sprintf("%d of %d %s reference targets did not answer (%s)", len(bad), len(all), scope, codes(bad)),
				MeasurementIDs: engine.IDs(bad),
				Recommendations: []domain.Recommendation{
					{Summary: "Repeat the check to see whether the failure is consistent", Command: cmd("doctor")},
					{Summary: "Diagnose one failing target for the detail of each layer", Command: cmd("diagnose", "<host>")},
				},
			}
			otherAll := notSkipped(scoped(in.Measurements(domain.TypeHTTP), other))
			otherGood := succeeded(otherAll)
			evidence := ev("Reference targets did not answer ("+codes(bad)+")", engine.IDs(bad)...)
			h := domain.Hypothesis{Supporting: []domain.Evidence{evidence}}
			switch {
			case len(good) == 0 && len(otherGood) > 0:
				h.Summary = fmt.Sprintf("Traffic from this network to %s destinations is blocked, dropped or stalled beyond this machine, while %s destinations work", scope, otherName)
				h.Confidence = domain.ConfidenceMedium
				h.Supporting = append(h.Supporting, ev(otherName+" reference targets answered, so this machine's own setup works", engine.IDs(otherGood)...))
				h.Missing = []domain.Evidence{
					missing("Where on the path the traffic stops was not measured"),
					missing("No comparison from a different network was made"),
				}
			case len(good) == 0 && len(otherAll) > 0:
				h.Summary = "No reference target answers, domestic or international: the connection is down beyond this machine, for example at the provider"
				h.Confidence = domain.ConfidenceMedium
				h.Supporting = append(h.Supporting, ev(otherName+" reference targets did not answer either", engine.IDs(failed(otherAll))...))
				h.Missing = []domain.Evidence{missing("Where on the path the traffic stops was not measured")}
			case len(good) == 0:
				h.Summary = "The connection is down beyond this machine, or traffic to these destinations is dropped"
				h.Confidence = domain.ConfidenceLow
				h.Missing = []domain.Evidence{
					missing("No " + otherName + " anchors were tested, so the failure cannot be placed; select a region that has them with --region"),
					missing("Where on the path the traffic stops was not measured"),
				}
			default:
				h.Summary = "Some reference targets are unreachable while others answer: those targets or the paths to them are failing, not this machine's connection"
				h.Confidence = domain.ConfidenceMedium
				h.Contradicting = []domain.Evidence{ev("Other "+string(scope)+" targets answered", engine.IDs(good)...)}
				h.Missing = []domain.Evidence{missing("Whether the failing targets are down for everyone was not checked")}
			}
			o.Hypotheses = []domain.Hypothesis{h}
			return []engine.Outcome{o}
		},
	}
}

// InternationalUnreachable fires when international reference targets fail.
var InternationalUnreachable = reachabilityRule(
	"INTERNATIONAL_UNREACHABLE",
	"International reference targets are not reachable",
	"Some or all international reference targets did not answer an HTTPS request.",
	domain.ScopeInternational, domain.ScopeDomestic, "domestic")

// DomesticUnreachable fires when domestic reference targets fail.
var DomesticUnreachable = reachabilityRule(
	"DOMESTIC_UNREACHABLE",
	"Domestic reference targets are not reachable",
	"Some or all domestic reference targets did not answer an HTTPS request.",
	domain.ScopeDomestic, domain.ScopeInternational, "international")

// ReferenceResolverFailing fires when a resolver other than the system one
// could not answer.
var ReferenceResolverFailing = engine.Rule{
	ID:          "REFERENCE_RESOLVER_FAILING",
	Version:     1,
	Title:       "A compared resolver did not answer",
	Description: "A resolver from the region preset or chosen by you did not return an address. A chosen resolver is a warning; a preset one is informational.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A resolver can be unreachable from this network, refuse this client, or be down; the error alone does not say which.",
		"A public resolver that does not answer from here does not mean this machine's own resolver is wrong.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		bad := failed(filter(in.Measurements(domain.TypeDNS), func(m domain.Measurement) bool { return m.Resolver != nil && !isSystem(m) }))
		if len(bad) == 0 {
			return nil
		}
		byResolver := map[string][]domain.Measurement{}
		var order []string
		for _, m := range bad {
			k := m.Resolver.Address
			if _, ok := byResolver[k]; !ok {
				order = append(order, k)
			}
			byResolver[k] = append(byResolver[k], m)
		}
		var out []engine.Outcome
		for _, k := range order {
			ms := byResolver[k]
			sev := domain.SeverityInfo
			for _, m := range ms {
				if chosen, _ := m.Params["chosen"].(bool); chosen {
					sev = domain.SeverityWarning
				}
			}
			out = append(out, engine.Outcome{
				Severity:       sev,
				Summary:        fmt.Sprintf("Resolver %s did not answer for %s (%s)", k, hosts(ms), codes(ms)),
				MeasurementIDs: engine.IDs(ms),
				Hypotheses: []domain.Hypothesis{{
					Summary:    "The resolver is unreachable from this network, refuses this client, or is down",
					Confidence: domain.ConfidenceLow,
					Supporting: []domain.Evidence{ev("No answer from "+k+" ("+codes(ms)+")", engine.IDs(ms)...)},
					Missing: []domain.Evidence{
						missing("Reachability of the same resolver over TCP was not tested"),
						missing("No comparison from a different network was made"),
					},
					NextMeasurements: []string{cmd("test", "dns", ms[0].Target.Host, "--resolver", "tcp://"+strings.TrimSuffix(k, ":53"))},
				}},
				Recommendations: []domain.Recommendation{
					{Summary: "Test the resolver over TCP, which some networks treat differently from UDP", Command: cmd("test", "dns", ms[0].Target.Host, "--resolver", "tcp://"+strings.TrimSuffix(k, ":53"))},
				},
			})
		}
		return out
	},
}

// ResolverAnswerDifference reports, as an observation, names for which the
// system resolver and another resolver return no address in common.
var ResolverAnswerDifference = engine.Rule{
	ID:          "RESOLVER_ANSWER_DIFFERENCE",
	Version:     1,
	Title:       "Resolvers returned different addresses",
	Description: "For a name, the system resolver and another resolver returned no address in common. Informational.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A differing DNS answer is an observation, not proof of manipulation. CDNs return different addresses by location and by resolver, split-horizon DNS serves internal views, and caches differ.",
		"Disjoint answers for a CDN-hosted name are the normal case, not a fault.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := succeeded(in.Measurements(domain.TypeDNS))
		byHost := map[string][]domain.Measurement{}
		var hostOrder []string
		for _, m := range all {
			h := m.Target.Host
			if _, ok := byHost[h]; !ok {
				hostOrder = append(hostOrder, h)
			}
			byHost[h] = append(byHost[h], m)
		}
		var differing []domain.Measurement
		var names []string
		for _, h := range hostOrder {
			ms := byHost[h]
			var sys *domain.Measurement
			for i := range ms {
				if isSystem(ms[i]) {
					sys = &ms[i]
				}
			}
			if sys == nil {
				continue
			}
			sysSet := addrSet(dns.Addresses(sys))
			hostDiffers := false
			for _, m := range ms {
				if isSystem(m) {
					continue
				}
				if !overlaps(sysSet, addrSet(dns.Addresses(&m))) {
					differing = append(differing, m)
					hostDiffers = true
				}
			}
			if hostDiffers {
				differing = append(differing, *sys)
				names = append(names, h)
			}
		}
		if len(names) == 0 {
			return nil
		}
		slices.Sort(names)
		ids := engine.IDs(differing)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		return []engine.Outcome{{
			Severity:       domain.SeverityInfo,
			Summary:        fmt.Sprintf("For %s, the system resolver and another resolver returned no address in common", strings.Join(names, ", ")),
			MeasurementIDs: ids,
			Hypotheses: []domain.Hypothesis{{
				Summary:    "The names are served from several locations and each resolver was directed to a different one, which is normal for CDNs",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{ev("The answer sets do not overlap", ids...)},
				Missing: []domain.Evidence{
					missing("Whether either answer is wrong was not established"),
					missing("The answers were not compared with the authoritative servers"),
				},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Check whether the addresses answer, which is what matters in practice", Command: cmd("diagnose", names[0], "--resolver", "<ip>")},
			},
		}}
	},
}

func addrSet(addrs []netipAddr) map[netipAddr]bool {
	s := map[netipAddr]bool{}
	for _, a := range addrs {
		s[a] = true
	}
	return s
}

func overlaps(a, b map[netipAddr]bool) bool {
	for k := range b {
		if a[k] {
			return true
		}
	}
	return false
}

// ProxyConfigured reports proxy settings, which nw ignores.
var ProxyConfigured = engine.Rule{
	ID:          "PROXY_CONFIGURED",
	Version:     1,
	Title:       "A proxy is configured",
	Description: "A proxy is set in the environment or the system settings. Informational.",
	Layer:       engine.LayerLocal,
	Requires:    []domain.Type{domain.TypeLocal},
	Caveats: []string{
		"A proxy setting does not mean the proxy is in use for any given program, and nw measures the direct path without it.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var with []domain.Measurement
		for _, m := range localCheck(in, local.CheckProxy) {
			if res, ok := engine.ResultOf[local.ProxyResult](m); ok && res.Detected {
				with = append(with, m)
			}
		}
		if len(with) == 0 {
			return nil
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityInfo,
			Summary:        "A proxy is configured for applications on this machine; nw ignores it and measured the direct path",
			MeasurementIDs: engine.IDs(with),
			Hypotheses: []domain.Hypothesis{{
				Summary:    "Applications that use the proxy can behave differently from the direct measurements in this report",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{ev("A proxy is set for applications", engine.IDs(with)...)},
				Missing:    []domain.Evidence{missing("Whether the proxy works was not measured; nw does not send traffic through proxies")},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Look at the proxy settings", Command: cmd("network", "proxy")},
			},
		}}
	},
}
