package rules

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
	mtls "github.com/radestsam/nwrk/internal/measurement/tls"
	"github.com/radestsam/nwrk/internal/platform"
)

// Interference returns the rules that look for signs of interference with
// DNS, TLS and HTTP. They never reach `high` confidence: a local
// observation rarely establishes who or what changed the traffic, and every
// finding says what else could explain it.
func Interference() []engine.Rule {
	return []engine.Rule{
		DNSAnswerMismatch,
		DNSPrivateAddressForPublicName,
		DNSMultipleDifferentResponses,
		TLSResetAfterClientHello,
		TLSSNIDependentFailure,
		HTTPRedirectToUnrelatedHost,
		HTTPHTTPSResponseDifference,
		InterferenceInsufficientEvidence,
	}
}

func nonSystem(m domain.Measurement) bool { return m.Resolver != nil && !isSystem(m) }

func addrStrings(m *domain.Measurement) []string {
	var out []string
	for _, a := range dns.Addresses(m) {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}

func overlap(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// isSpecialUse reports names that are expected to resolve to private
// addresses or not to resolve publicly at all.
func isSpecialUse(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(name, ".") {
		return true
	}
	for _, suf := range []string{".local", ".localhost", ".internal", ".home.arpa", ".lan", ".test", ".example", ".invalid", ".corp", ".intranet"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return name == "localhost"
}

func privateKind(a string) (string, bool) {
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return "", false
	}
	k := platform.AddrKind(ip.Unmap())
	return k, k != "global"
}

// DNSAnswerMismatch fires when two resolvers return no address in common.
var DNSAnswerMismatch = engine.Rule{
	ID:          "DNS_ANSWER_MISMATCH",
	Version:     1,
	Title:       "Resolvers returned different addresses",
	Description: "For a name, the system resolver and another resolver returned no address in common. A warning when something else supports the difference, informational otherwise.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A differing DNS answer is an observation, not proof of manipulation. CDNs return different addresses by location and by resolver, split-horizon DNS serves internal views, and caches differ.",
		"Disjoint answers for a name served by a CDN are the normal case. The finding is stronger only when the addresses also behave differently.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := succeeded(in.Measurements(domain.TypeDNS))
		reach := in.Probes(domain.TypeTCP, domain.ProbeAnswerReachability)
		var out []engine.Outcome
		byHost := map[string][]domain.Measurement{}
		var order []string
		for _, m := range all {
			if _, ok := byHost[m.Target.Host]; !ok {
				order = append(order, m.Target.Host)
			}
			byHost[m.Target.Host] = append(byHost[m.Target.Host], m)
		}
		for _, host := range order {
			ms := byHost[host]
			var sys *domain.Measurement
			for i := range ms {
				if isSystem(ms[i]) {
					sys = &ms[i]
				}
			}
			if sys == nil {
				continue
			}
			sysAddrs := addrStrings(sys)
			for i := range ms {
				other := ms[i]
				if !nonSystem(other) || overlap(sysAddrs, addrStrings(&other)) {
					continue
				}
				out = append(out, mismatchOutcome(host, *sys, other, sysAddrs, addrStrings(&other), reach))
			}
		}
		return out
	},
}

func reachOf(reach []domain.Measurement, source string) (ok, bad []domain.Measurement) {
	for _, r := range reach {
		if r.Params["source"] != source {
			continue
		}
		if r.Status == domain.StatusSuccess {
			ok = append(ok, r)
		} else if r.Status == domain.StatusFailure {
			bad = append(bad, r)
		}
	}
	return
}

func mismatchOutcome(host string, sys, other domain.Measurement, sysAddrs, otherAddrs []string, reach []domain.Measurement) engine.Outcome {
	ids := []string{sys.ID, other.ID}
	sysOK, sysBad := reachOf(reach, "system")
	otherOK, otherBad := reachOf(reach, other.Resolver.Address)

	var corroboration []domain.Evidence
	for _, a := range sysAddrs {
		if k, priv := privateKind(a); priv {
			corroboration = append(corroboration, ev("The system resolver returned "+k+" address "+a+" for a public name", sys.ID))
		}
	}
	for _, a := range otherAddrs {
		if k, priv := privateKind(a); priv {
			corroboration = append(corroboration, ev(resolverName(other)+" returned "+k+" address "+a+" for a public name", other.ID))
		}
	}
	if len(sysBad) > 0 && len(sysOK) == 0 && len(otherOK) > 0 {
		corroboration = append(corroboration, ev("None of the system resolver's addresses answered, while the other resolver's did", append(engine.IDs(sysBad), engine.IDs(otherOK)...)...))
		ids = append(ids, engine.IDs(sysBad)...)
		ids = append(ids, engine.IDs(otherOK)...)
	}
	if len(otherBad) > 0 && len(otherOK) == 0 && len(sysOK) > 0 {
		corroboration = append(corroboration, ev("None of "+resolverName(other)+"'s addresses answered, while the system resolver's did", append(engine.IDs(otherBad), engine.IDs(sysOK)...)...))
		ids = append(ids, engine.IDs(otherBad)...)
		ids = append(ids, engine.IDs(sysOK)...)
	}

	benign := domain.Hypothesis{
		Summary:    "Both answers are legitimate: the name is served from several locations, or the resolvers hold different views or caches",
		Confidence: domain.ConfidenceMedium,
		Supporting: []domain.Evidence{ev("The answer sets do not overlap, which is normal for CDNs", sys.ID, other.ID)},
		Missing:    []domain.Evidence{missing("The answers were not compared with the authoritative servers")},
	}
	altered := domain.Hypothesis{
		Summary:       "One resolver returns altered, filtered or stale answers",
		Confidence:    domain.ConfidenceLow,
		Supporting:    []domain.Evidence{ev("The two resolvers disagree about "+host, sys.ID, other.ID)},
		Contradicting: []domain.Evidence{ev("Disagreement alone is also what CDNs and split-horizon DNS produce", sys.ID, other.ID)},
		Missing: []domain.Evidence{
			missing("Which answer is correct was not established"),
			missing("No third resolver was compared"),
		},
		NextMeasurements: []string{cmd("security", "interference", host, "--resolver", "<ip>")},
	}
	sev := domain.SeverityInfo
	if len(corroboration) > 0 {
		sev = domain.SeverityWarning
		altered.Confidence = domain.ConfidenceMedium
		benign.Confidence = domain.ConfidenceLow
		altered.Supporting = append(altered.Supporting, corroboration...)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return engine.Outcome{
		Severity:       sev,
		Summary:        fmt.Sprintf("For %s, %s and %s returned no address in common", host, resolverName(sys), resolverName(other)),
		MeasurementIDs: ids,
		Hypotheses:     []domain.Hypothesis{altered, benign},
		Recommendations: []domain.Recommendation{
			{Summary: "Compare with a further resolver, ideally over an encrypted transport", Command: cmd("security", "interference", host, "--resolver", "tls://<host>")},
		},
	}
}

// DNSPrivateAddressForPublicName fires when a public name resolves to a
// private, loopback or link-local address.
var DNSPrivateAddressForPublicName = engine.Rule{
	ID:          "DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME",
	Version:     1,
	Title:       "A public name resolved to a private address",
	Description: "A resolver returned a private, loopback, link-local or shared-address-space address for a name that is not reserved for local use.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"Split-horizon DNS, corporate and home networks, local development setups and VPNs return private addresses for public names on purpose.",
		"The system resolver honors the hosts file, so an entry there produces exactly this result.",
		"Captive portals and some filters answer with a private address as well; the address alone does not say which applies.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := succeeded(in.Measurements(domain.TypeDNS))
		var out []engine.Outcome
		for _, m := range all {
			host := m.Target.Host
			if _, err := netip.ParseAddr(host); err == nil || isSpecialUse(host) {
				continue
			}
			var bad []string
			for _, a := range addrStrings(&m) {
				if _, priv := privateKind(a); priv {
					bad = append(bad, a)
				}
			}
			if len(bad) == 0 {
				continue
			}
			ids := []string{m.ID}
			var cleanElsewhere []domain.Measurement
			for _, o := range all {
				if o.ID != m.ID && o.Target.Host == host && !anyPrivate(addrStrings(&o)) {
					cleanElsewhere = append(cleanElsewhere, o)
				}
			}
			local := domain.Hypothesis{
				Summary:    "A local override or an internal DNS view is in effect: a hosts file entry, a VPN, or a corporate or home DNS server",
				Confidence: domain.ConfidenceMedium,
				Supporting: []domain.Evidence{ev(fmt.Sprintf("%s returned %s for %s", resolverName(m), strings.Join(bad, ", "), host), m.ID)},
				Missing:    []domain.Evidence{missing("The hosts file and the resolver's configuration were not inspected")},
			}
			altered := domain.Hypothesis{
				Summary:    "The resolver replaces the real address with a private one, as a filter, a captive portal or an altered answer would",
				Confidence: domain.ConfidenceLow,
				Supporting: []domain.Evidence{ev("A public name has no ordinary reason to resolve to a private address", m.ID)},
				Missing:    []domain.Evidence{missing("Which party operates the resolver and what it filters is unknown")},
			}
			if len(cleanElsewhere) > 0 {
				ids = append(ids, engine.IDs(cleanElsewhere)...)
				local.Contradicting = []domain.Evidence{ev("Another resolver returned only public addresses", engine.IDs(cleanElsewhere)...)}
				altered.Confidence = domain.ConfidenceMedium
				altered.Supporting = append(altered.Supporting, ev("Another resolver returned only public addresses", engine.IDs(cleanElsewhere)...))
				local.Confidence = domain.ConfidenceLow
			} else {
				altered.Missing = append(altered.Missing, missing("No other resolver was compared"))
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("%s resolved %s to private-range address %s", resolverName(m), host, strings.Join(bad, ", ")),
				MeasurementIDs: ids,
				Hypotheses:     []domain.Hypothesis{local, altered},
				Recommendations: []domain.Recommendation{
					{Summary: "Compare with a resolver outside this network", Command: cmd("test", "dns", host, "--resolver", "<ip>")},
					{Summary: "Check the hosts file and VPN or proxy software for an entry for this name"},
				},
			})
		}
		return out
	},
}

func anyPrivate(addrs []string) bool {
	for _, a := range addrs {
		if _, priv := privateKind(a); priv {
			return true
		}
	}
	return false
}

// DNSMultipleDifferentResponses fires when one query got several different replies.
var DNSMultipleDifferentResponses = engine.Rule{
	ID:          "DNS_MULTIPLE_DIFFERENT_RESPONSES",
	Version:     1,
	Title:       "One DNS query received several different replies",
	Description: "A single query to a resolver was answered more than once, with different answers.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A resolver normally answers once. Several different replies are consistent with a device on the path answering ahead of the real server, and also with unusual but legitimate setups, such as a load-balanced resolver address or a resolver that retries.",
		"The probe listens for a fixed short time. Replies after that are not seen, and a single probe is one observation.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		for _, m := range in.Probes(domain.TypeDNS, domain.ProbeMultipleResponses) {
			res, ok := engine.ResultOf[dns.ProbeResult](m)
			if !ok || res.Distinct < 2 {
				continue
			}
			first, last := res.Responses[0], res.Responses[len(res.Responses)-1]
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("One query to %s got %d different replies (%s first, then %s)", m.Resolver.Address, res.Distinct, strings.Join(first.Answers, ","), strings.Join(last.Answers, ",")),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{
					{
						Summary:       "A device on the path answers the query before the real resolver does, and the real reply follows",
						Confidence:    domain.ConfidenceMedium,
						Supporting:    []domain.Evidence{ev(fmt.Sprintf("%d distinct replies arrived for one query, the first after %.1f ms", res.Distinct, first.DelayMS), m.ID)},
						Contradicting: []domain.Evidence{ev("This was one probe; a second run was not made", m.ID)},
						Missing: []domain.Evidence{
							missing("The same query over an encrypted transport was not compared"),
							missing("Which reply is correct was not established"),
						},
						NextMeasurements: []string{cmd("test", "dns", m.Target.Host, "--resolver", "tls://<host>")},
					},
					{
						Summary:    "The resolver address is served by several machines, or the resolver retries and answers differently",
						Confidence: domain.ConfidenceLow,
						Supporting: []domain.Evidence{ev("Anycast and load-balanced resolvers can answer a query from more than one machine", m.ID)},
						Missing:    []domain.Evidence{missing("The resolver operator's setup is unknown")},
					},
				},
				Recommendations: []domain.Recommendation{
					{Summary: "Repeat the probe, and compare the same name over an encrypted resolver", Command: cmd("security", "interference", m.Target.Host, "--resolver", "tls://<host>")},
				},
			})
		}
		return out
	},
}

// observation is one handshake with one server name at one address.
type observation struct {
	m       domain.Measurement
	outcome string
}

func tlsObservations(in *engine.Input, probes ...string) map[string][]observation {
	out := map[string][]observation{}
	add := func(ms []domain.Measurement) {
		for _, m := range ms {
			if m.Status == domain.StatusSkipped {
				continue
			}
			mm := m
			out[endpoint(m)] = append(out[endpoint(m)], observation{m, mtls.Outcome(&mm)})
		}
	}
	if len(probes) == 0 {
		add(in.Measurements(domain.TypeTLS))
	}
	for _, p := range probes {
		add(in.Probes(domain.TypeTLS, p))
	}
	return out
}

func silent(o string) bool { return o == mtls.OutcomeReset || o == mtls.OutcomeTimeout }

func allSilent(obs []observation) bool {
	for _, o := range obs {
		if !silent(o.outcome) {
			return false
		}
	}
	return len(obs) > 0
}

func tcpWorked(in *engine.Input) map[string]bool {
	ok := map[string]bool{}
	for _, m := range succeeded(in.Measurements(domain.TypeTCP)) {
		ok[endpoint(m)] = true
	}
	return ok
}

// TLSResetAfterClientHello fires when a connection is accepted and then
// reset or left silent, every time it was tried.
var TLSResetAfterClientHello = engine.Rule{
	ID:          "TLS_RESET_AFTER_CLIENTHELLO",
	Version:     1,
	Title:       "The connection is reset or silent after the TLS hello, repeatedly",
	Description: "The TCP connection succeeded, and every handshake attempt with the target server name was then reset or went unanswered.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS, domain.TypeTCP},
	Caveats: []string{
		"A reset or silence after the hello is what a server with a broken or incompatible TLS setup produces, and what a device on the path that interferes with the connection produces. The attempt alone does not distinguish them.",
		"Without a comparison, such as a control name or a different network, this stays a low-confidence observation.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		if len(in.Probes(domain.TypeTLS, domain.ProbeSNITarget)) == 0 {
			return nil // only after repeated attempts, which the interference checks make
		}
		up := tcpWorked(in)
		target := tlsObservations(in)
		for k, v := range tlsObservations(in, domain.ProbeSNITarget) {
			target[k] = append(target[k], v...)
		}
		control := tlsObservations(in, domain.ProbeSNIControl)
		var out []engine.Outcome
		for _, ep := range sortedKeys(target) {
			obs := target[ep]
			if !up[ep] || len(obs) < 2 || !allSilent(obs) {
				continue
			}
			ids := ids(obs)
			conf := domain.ConfidenceLow
			var support, against []domain.Evidence
			support = append(support, ev(fmt.Sprintf("%d of %d handshakes with the target name ended in %s", len(obs), len(obs), obs[0].outcome), ids...))
			if c := control[ep]; len(c) > 0 {
				if !allSilent(c) {
					conf = domain.ConfidenceMedium
					support = append(support, ev("A handshake with a control name at the same address got an answer", idsOf(c)...))
				} else {
					against = append(against, ev("The control name was reset or silent too, which points at the server or the address, not at the name", idsOf(c)...))
				}
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("Every TLS handshake to %s ended in %s after the connection was established", ep, obs[0].outcome),
				MeasurementIDs: append(ids, idsOf(control[ep])...),
				Hypotheses: []domain.Hypothesis{
					{
						Summary:       "A device on the path interferes with the connection after the hello",
						Confidence:    conf,
						Supporting:    support,
						Contradicting: against,
						Missing: []domain.Evidence{
							missing("No comparison from a different network was made"),
							missing("No comparison with a known-good TLS client was made"),
						},
					},
					{
						Summary:    "The server's TLS setup is broken or incompatible with this client",
						Confidence: domain.ConfidenceLow,
						Supporting: []domain.Evidence{ev("The same failure repeated", ids...)},
						Missing:    []domain.Evidence{missing("The server's configuration is not visible")},
					},
				},
				Recommendations: []domain.Recommendation{
					{Summary: "Compare with a known-good TLS client on this machine, for example curl -v", Command: ""},
					{Summary: "Repeat from a different network or machine to see whether the failure depends on the path"},
				},
			})
		}
		return out
	},
}

func ids(obs []observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.m.ID)
	}
	return out
}

func idsOf(obs []observation) []string { return ids(obs) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TLSSNIDependentFailure fires when the failure depends on the server name.
var TLSSNIDependentFailure = engine.Rule{
	ID:          "TLS_SNI_DEPENDENT_FAILURE",
	Version:     1,
	Title:       "The handshake fails only for the target server name",
	Description: "At one address, handshakes with the target server name are reset or unanswered, while a handshake with a neutral control name gets an answer.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS, domain.TypeTCP},
	Caveats: []string{
		"A server that hosts many names may reject names it does not know, so a control name can be treated differently from the target for ordinary reasons.",
		"Many networks and servers are not affected by the server name at all; a difference is a prompt to compare, not a conclusion.",
		"Only one control name and a few attempts are used.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		up := tcpWorked(in)
		target := tlsObservations(in)
		for k, v := range tlsObservations(in, domain.ProbeSNITarget) {
			target[k] = append(target[k], v...)
		}
		control := tlsObservations(in, domain.ProbeSNIControl)
		var out []engine.Outcome
		for _, ep := range sortedKeys(target) {
			t, c := target[ep], control[ep]
			if !up[ep] || len(t) < 2 || len(c) == 0 || !allSilent(t) {
				continue
			}
			answered := 0
			for _, o := range c {
				if !silent(o.outcome) && o.outcome != mtls.OutcomeOther {
					answered++
				}
			}
			if answered == 0 {
				continue
			}
			all := append(ids(t), idsOf(c)...)
			name, _ := c[0].m.Params["sni"].(string)
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("At %s the handshake with the target name ended in %s every time, while the control name %q got an answer", ep, t[0].outcome, name),
				MeasurementIDs: all,
				Hypotheses: []domain.Hypothesis{
					{
						Summary:    "Something on the path treats connections differently depending on the server name in the hello",
						Confidence: domain.ConfidenceMedium,
						Supporting: []domain.Evidence{
							ev(fmt.Sprintf("%d handshakes with the target name were %s", len(t), t[0].outcome), ids(t)...),
							ev("A handshake with a control name at the same address was answered", idsOf(c)...),
						},
						Contradicting: []domain.Evidence{ev("A server may reject or ignore names it does not host, which would explain a difference without any interference", idsOf(c)...)},
						Missing: []domain.Evidence{
							missing("No second control name and no comparison from another network were made"),
							missing("What the server does with names it does not host is unknown"),
						},
					},
					{
						Summary:    "The server accepts only the names it hosts and the target name is handled by a failing virtual host",
						Confidence: domain.ConfidenceLow,
						Supporting: []domain.Evidence{ev("Servers sometimes fail for one hosted name only", ids(t)...)},
						Missing:    []domain.Evidence{missing("The server's configuration is not visible")},
					},
				},
				Recommendations: []domain.Recommendation{
					{Summary: "Repeat from a different network or machine; a difference that follows the network points at the path"},
					{Summary: "Try another name hosted at the same address, if you know one, and compare"},
				},
			})
		}
		return out
	},
}

func registrable(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// HTTPRedirectToUnrelatedHost fires when a redirect leaves the target's domain.
var HTTPRedirectToUnrelatedHost = engine.Rule{
	ID:          "HTTP_REDIRECT_TO_UNRELATED_HOST",
	Version:     1,
	Title:       "A redirect leads to an unrelated host",
	Description: "A redirect in the request chain points to a registered domain other than the target's. A warning when the destination is an IP address or a private address, informational otherwise.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"Sites redirect to other domains on purpose: sign-in providers, regional or brand domains, and CDNs and short-link services.",
		"A redirect to an address given as a bare IP is unusual for a public site but also common for devices and portals on a local network.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := append(in.Measurements(domain.TypeHTTP), in.Probes(domain.TypeHTTP, domain.ProbePlainHTTP)...)
		var out []engine.Outcome
		for _, m := range all {
			res, ok := engine.ResultOf[mhttp.Result](m)
			if !ok {
				continue
			}
			origin := registrable(m.Target.Host)
			for _, h := range res.Hops {
				if h.Location == "" {
					continue
				}
				u, err := url.Parse(h.Location)
				if err != nil || u.Hostname() == "" {
					continue
				}
				dest := u.Hostname()
				if registrable(dest) == origin {
					continue
				}
				sev := domain.SeverityInfo
				conf := domain.ConfidenceLow
				note := "The redirect leaves the target's registered domain"
				if ip, err := netip.ParseAddr(dest); err == nil {
					sev = domain.SeverityWarning
					note = "The redirect points at the bare address " + dest
					if _, priv := privateKind(ip.String()); priv {
						conf = domain.ConfidenceMedium
						note += ", which is in a private range"
					}
				}
				out = append(out, engine.Outcome{
					Severity:       sev,
					Summary:        fmt.Sprintf("A request for %s was redirected (%d) to %s, which is outside %s", m.Target.Host, h.StatusCode, dest, origin),
					MeasurementIDs: []string{m.ID},
					Hypotheses: []domain.Hypothesis{
						{
							Summary:    "The site redirects there on purpose, for sign-in, a regional or brand domain, or a CDN",
							Confidence: domain.ConfidenceMedium,
							Supporting: []domain.Evidence{ev("Sites commonly redirect across their own domains", m.ID)},
							Missing:    []domain.Evidence{missing("Whether the two domains belong to the same operator was not established")},
						},
						{
							Summary:       "A device on the path, such as a portal, filter or proxy, redirects the request",
							Confidence:    conf,
							Supporting:    []domain.Evidence{ev(note, m.ID)},
							Contradicting: []domain.Evidence{ev("Ordinary sites redirect across domains too", m.ID)},
							Missing:       []domain.Evidence{missing("No comparison from a different network was made")},
						},
					},
					Recommendations: []domain.Recommendation{
						{Summary: "Repeat from a different network and compare the redirect", Command: cmd("test", "http", m.Target.URL)},
					},
				})
			}
		}
		return out
	},
}

// HTTPHTTPSResponseDifference fires when http:// and https:// end differently.
var HTTPHTTPSResponseDifference = engine.Rule{
	ID:          "HTTP_HTTPS_RESPONSE_DIFFERENCE",
	Version:     1,
	Title:       "http and https lead to different places",
	Description: "The same target answered differently over http and over https: the requests end on different domains, or with status classes that differ.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"An http request that is redirected to https on the same host is normal and is not a difference.",
		"Servers legitimately answer the two schemes differently: an http-only status page, a redirect to a canonical host, or different virtual hosts.",
		"Only the status and the destination are compared; bodies are never stored.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		plain := in.Probes(domain.TypeHTTP, domain.ProbePlainHTTP)
		secure := succeeded(in.Measurements(domain.TypeHTTP))
		var out []engine.Outcome
		for _, p := range succeeded(plain) {
			pr, ok := engine.ResultOf[mhttp.Result](p)
			if !ok || len(secure) == 0 {
				continue
			}
			s := secure[0]
			sr, ok := engine.ResultOf[mhttp.Result](s)
			if !ok {
				continue
			}
			pu, _ := url.Parse(pr.FinalURL)
			su, _ := url.Parse(sr.FinalURL)
			if pu == nil || su == nil {
				continue
			}
			var diff string
			sev := domain.SeverityInfo
			switch {
			case registrable(pu.Hostname()) != registrable(su.Hostname()):
				diff = fmt.Sprintf("over http the request ended on %s, over https on %s", pu.Hostname(), su.Hostname())
				sev = domain.SeverityWarning
			case pu.Scheme == "http" && pr.StatusCode/100 != sr.StatusCode/100 && pr.StatusCode/100 != 3:
				diff = fmt.Sprintf("over http the final status is %d, over https %d", pr.StatusCode, sr.StatusCode)
			}
			if diff == "" {
				continue
			}
			out = append(out, engine.Outcome{
				Severity:       sev,
				Summary:        "For " + s.Target.Host + ": " + diff,
				MeasurementIDs: []string{p.ID, s.ID},
				Hypotheses: []domain.Hypothesis{
					{
						Summary:    "The site serves the two schemes differently on purpose, for example a canonical host or an http-only page",
						Confidence: domain.ConfidenceMedium,
						Supporting: []domain.Evidence{ev("Sites commonly treat http and https differently", p.ID, s.ID)},
						Missing:    []domain.Evidence{missing("The site's intended behavior is unknown")},
					},
					{
						Summary:       "Unencrypted http traffic is altered or answered by a device on the path, while https is not",
						Confidence:    domain.ConfidenceLow,
						Supporting:    []domain.Evidence{ev(diff, p.ID, s.ID)},
						Contradicting: []domain.Evidence{ev("A difference between schemes is ordinary for many sites", p.ID, s.ID)},
						Missing:       []domain.Evidence{missing("No comparison from a different network was made")},
					},
				},
				Recommendations: []domain.Recommendation{
					{Summary: "Repeat from a different network and compare both requests", Command: cmd("security", "interference", s.Target.Host)},
				},
			})
		}
		return out
	},
}

// InterferenceInsufficientEvidence states what an interference check could
// not establish, so silence is never mistaken for "nothing is wrong".
var InterferenceInsufficientEvidence = engine.Rule{
	ID:          "INTERFERENCE_INSUFFICIENT_EVIDENCE",
	Version:     1,
	Title:       "Not enough evidence to compare",
	Description: "The interference checks ran without an independent resolver or without a control, so some comparisons could not be made. Informational.",
	Layer:       engine.LayerOther,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"No finding does not mean nothing is wrong. It means the comparisons that ran showed nothing.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		if len(in.Probes(domain.TypeDNS, domain.ProbeMultipleResponses))+len(in.Probes(domain.TypeDNS, domain.ProbeDNSSEC)) == 0 {
			return nil // not an interference run
		}
		dnsAll := in.Measurements(domain.TypeDNS)
		var sys, other []domain.Measurement
		for _, m := range dnsAll {
			if isSystem(m) {
				sys = append(sys, m)
			} else if nonSystem(m) && m.Status == domain.StatusSuccess {
				other = append(other, m)
			}
		}
		var gaps []string
		if len(other) == 0 {
			gaps = append(gaps, "no independent resolver answered, so the system resolver's answers were not compared")
		}
		if len(in.Probes(domain.TypeTLS, domain.ProbeSNIControl)) == 0 && in.Ran(domain.TypeTLS) {
			gaps = append(gaps, "no control handshake was made, so server-name dependence was not tested")
		}
		if len(in.Probes(domain.TypeHTTP, domain.ProbePlainHTTP)) == 0 && in.Ran(domain.TypeHTTP) {
			gaps = append(gaps, "http and https were not compared")
		}
		if len(gaps) == 0 || len(sys) == 0 {
			return nil
		}
		return []engine.Outcome{{
			Severity:       domain.SeverityInfo,
			Summary:        "Some comparisons could not be made: " + strings.Join(gaps, "; "),
			MeasurementIDs: engine.IDs(sys),
			Hypotheses: []domain.Hypothesis{{
				Summary:    "The checks that ran cannot rule interference in or out",
				Confidence: domain.ConfidenceLow,
				Supporting: []domain.Evidence{ev("These comparisons were not available", engine.IDs(sys)...)},
				Missing:    []domain.Evidence{missing(strings.Join(gaps, "; "))},
			}},
			Recommendations: []domain.Recommendation{
				{Summary: "Add a resolver you trust, ideally over an encrypted transport, and repeat", Command: cmd("security", "interference", in.Target(), "--resolver", "tls://<host>")},
			},
		}}
	},
}
