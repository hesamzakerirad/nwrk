// Package doctor runs nw doctor: a bounded checklist that tells whether a
// problem is local, domestic or international.
//
// It inspects this machine, resolves the reference targets of a region
// preset, compares the system resolver with other resolvers, and requests
// each target. The rule engine turns the evidence into findings, and a
// layered verdict names the part of the path where the problem is.
package doctor

import (
	"context"
	"net/netip"
	"net/url"
	"sync"

	apptest "github.com/radestsam/nwrk/internal/app/test"
	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/diagnostics/rules"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
	"github.com/radestsam/nwrk/internal/measurement/local"
	"github.com/radestsam/nwrk/internal/regions"
	"github.com/radestsam/nwrk/internal/target"
)

const (
	concurrency = 8
	// hostsPerScope bounds how many names each compared resolver is asked.
	hostsPerScope = 2
)

// Options configure a run.
type Options struct {
	// Test carries the timeout, the resolvers to compare with the system
	// one, the tool version, and the test seams.
	Test apptest.Options
	// Region is the preset name, and Preset its loaded content.
	Region string
	Preset regions.Preset
	// ChosenResolvers is true when the user chose the resolvers in Test,
	// false when they come from the preset.
	ChosenResolvers bool
	// Inspector and Dial replace the real operating system in tests.
	Inspector local.Inspector
	Dial      local.Dial
}

type runner struct {
	rep *domain.Report
	o   Options
	sem chan struct{}
}

// Run executes the checklist and returns the finished report.
func Run(ctx context.Context, o Options) *domain.Report {
	if o.Inspector == nil {
		o.Inspector = local.System{}
	}
	rep := domain.NewReport("doctor", "region "+o.Region, o.Test.ToolVersion)
	rep.Run.Region = o.Region
	r := &runner{rep: rep, o: o, sem: make(chan struct{}, concurrency)}

	rep.Add(local.Interfaces(o.Inspector))
	rc, cancel := context.WithTimeout(ctx, o.Test.Timeout)
	rep.Add(local.Route(rc, o.Dial))
	cancel()
	rep.Add(local.Resolvers(o.Inspector))
	rep.Add(local.Proxy(o.Inspector))

	if why := r.cannotReachOut(); why != "" {
		for _, t := range o.Preset.Targets {
			m := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: t.Host(), URL: t.URL})
			m.Scope = t.Scope
			rep.Add(m.Skip(why))
		}
	} else {
		r.network(ctx)
	}

	engine.Evaluate(rules.Doctor(), rep)
	rep.Summarize()
	rep.Summary.Verdict, rep.Summary.Scopes = Verdict(rep)
	rep.Finish()
	return rep
}

// cannotReachOut returns a reason when the local checks show that nothing
// can leave this machine, so asking the network would prove nothing.
func (r *runner) cannotReachOut() string {
	for _, m := range r.rep.Measurements {
		if m.Status != domain.StatusFailure {
			continue
		}
		switch m.Params["check"] {
		case local.CheckInterfaces:
			return "no network interface can reach beyond this machine, so the reference targets cannot be reached"
		case local.CheckRoute:
			return "there is no route to the internet, so the reference targets cannot be reached"
		}
	}
	return ""
}

// do runs f under the concurrency limit and a per-measurement deadline.
func (r *runner) do(ctx context.Context, wg *sync.WaitGroup, out **domain.Measurement, f func(context.Context) *domain.Measurement) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.sem <- struct{}{}
		defer func() { <-r.sem }()
		c, cancel := context.WithTimeout(ctx, r.o.Test.Timeout)
		defer cancel()
		*out = f(c)
	}()
}

func (r *runner) network(ctx context.Context) {
	targets := r.o.Preset.Targets
	systemFn := dns.System
	if r.o.Test.SystemDNS != nil {
		systemFn = r.o.Test.SystemDNS
	}

	// 1. The system resolver, for every distinct reference host.
	type hostScope struct {
		host  string
		scope domain.Scope
	}
	var hs []hostScope
	seen := map[string]bool{}
	for _, t := range targets {
		if h := t.Host(); !seen[h] {
			seen[h] = true
			hs = append(hs, hostScope{h, t.Scope})
		}
	}
	system := make([]*domain.Measurement, len(hs))
	// 2. Each compared resolver, for the first hosts of each scope.
	type job struct {
		hs hostScope
		r  target.Resolver
	}
	var jobs []job
	for _, rv := range r.o.Test.Resolvers {
		perScope := map[domain.Scope]int{}
		for _, h := range hs {
			if perScope[h.scope] < hostsPerScope {
				perScope[h.scope]++
				jobs = append(jobs, job{h, rv})
			}
		}
	}
	compared := make([]*domain.Measurement, len(jobs))

	var wg sync.WaitGroup
	for i, h := range hs {
		r.do(ctx, &wg, &system[i], func(c context.Context) *domain.Measurement {
			m := systemFn(c, h.host)
			m.Scope = h.scope
			return m
		})
	}
	for i, j := range jobs {
		r.do(ctx, &wg, &compared[i], func(c context.Context) *domain.Measurement {
			m := dns.LookupWith(c, j.hs.host, j.r, dns.Options{RootCAs: r.o.Test.RootCAs})
			m.Scope = j.hs.scope
			m.Params["chosen"] = r.o.ChosenResolvers
			return m
		})
	}
	wg.Wait()
	for _, m := range append(append([]*domain.Measurement{}, system...), compared...) {
		r.rep.Add(m)
	}

	// 3. Every reference target.
	bySystem := map[string]*domain.Measurement{}
	for i, h := range hs {
		bySystem[h.host] = system[i]
	}
	byResolver := map[string][]netip.Addr{}
	for _, m := range compared {
		if a := dns.Addresses(m); len(a) > 0 {
			if _, ok := byResolver[m.Target.Host]; !ok {
				byResolver[m.Target.Host] = a
			}
		}
	}
	results := make([]*domain.Measurement, len(targets))
	for i, t := range targets {
		r.do(ctx, &wg, &results[i], func(c context.Context) *domain.Measurement {
			return r.request(c, t, bySystem[t.Host()], byResolver[t.Host()])
		})
	}
	wg.Wait()
	for _, m := range results {
		r.rep.Add(m)
	}
}

// request fetches one reference target. It connects to the addresses the
// system resolver returned; when that failed but a compared resolver gave an
// answer, it uses those, so a failing system resolver is not mistaken for a
// network outage.
func (r *runner) request(ctx context.Context, t regions.Target, sys *domain.Measurement, alt []netip.Addr) *domain.Measurement {
	host := t.Host()
	u, err := url.Parse(t.URL)
	base := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: host, URL: t.URL})
	base.Scope = t.Scope
	if err != nil {
		return base.Skip("the target URL is invalid")
	}
	addrs, from := dns.Addresses(sys), "the system resolver"
	if len(addrs) == 0 {
		addrs, from = alt, "a compared resolver"
	}
	if len(addrs) == 0 {
		return base.Skip("name resolution failed with every resolver tried, so there is no address to connect to")
	}
	m := mhttp.Get(ctx, u, mhttp.Options{
		DialContext: apptest.ViaResolver(nil, host, addrs, r.o.Test.Timeout),
		RootCAs:     r.o.Test.RootCAs,
	})
	m.Scope = t.Scope
	m.Params["name"] = t.Name
	m.Params["addresses_from"] = from
	return m
}

// scopeStatus summarizes reachability from the HTTP measurements of a scope.
func scopeStatus(rep *domain.Report, s domain.Scope) (status string, present bool) {
	var ok, fail, total int
	for _, m := range rep.Measurements {
		if m.Type != domain.TypeHTTP || m.Scope != s {
			continue
		}
		total++
		switch m.Status {
		case domain.StatusSuccess:
			ok++
		case domain.StatusFailure:
			fail++
		}
	}
	switch {
	case total == 0:
		return "not_checked", false
	case ok+fail == 0:
		return "not_checked", true
	case fail == 0:
		return "reachable", true
	case ok == 0:
		return "unreachable", true
	}
	return "partial", true
}

// Verdict names the layer where the problem is, and the status of each
// scope. The layers are local (this machine and its configuration),
// domestic and international (the reference targets of the region), and
// upstream when nothing beyond this machine answers.
func Verdict(rep *domain.Report) (string, []domain.ScopeStatus) {
	localProblem := false
	for _, f := range rep.Findings {
		if !f.Severity.Actionable() {
			continue
		}
		switch f.Code {
		case "LOCAL_NO_ACTIVE_INTERFACE", "LOCAL_NO_DEFAULT_ROUTE", "LOCAL_NO_RESOLVER_CONFIGURED":
			localProblem = true
		case "SYSTEM_RESOLVER_FAILING":
			// Only when every lookup failed; one failing name says little
			// about the resolver.
			localProblem = localProblem || f.Severity == domain.SeverityError
		}
	}
	dom, hasDomestic := scopeStatus(rep, domain.ScopeDomestic)
	intl, _ := scopeStatus(rep, domain.ScopeInternational)

	scopes := []domain.ScopeStatus{{Scope: domain.ScopeLocal, Status: "ok"}}
	if localProblem {
		scopes[0].Status = "problem"
	}
	if hasDomestic {
		scopes = append(scopes, domain.ScopeStatus{Scope: domain.ScopeDomestic, Status: dom})
	}
	scopes = append(scopes, domain.ScopeStatus{Scope: domain.ScopeInternational, Status: intl})

	up := func(s string) bool { return s == "reachable" || s == "partial" }
	switch {
	case localProblem:
		return domain.VerdictLocal, scopes
	case hasDomestic && dom == "unreachable" && intl == "unreachable":
		return domain.VerdictUpstream, scopes
	case hasDomestic && dom == "unreachable" && up(intl):
		return domain.VerdictDomestic, scopes
	case hasDomestic && up(dom) && intl == "unreachable":
		return domain.VerdictInternational, scopes
	case !hasDomestic && intl == "unreachable":
		return domain.VerdictUpstream, scopes
	case dom == "partial" || intl == "partial":
		return domain.VerdictPartial, scopes
	case intl == "not_checked" && (!hasDomestic || dom == "not_checked"):
		return domain.VerdictPartial, scopes
	}
	return domain.VerdictHealthy, scopes
}
