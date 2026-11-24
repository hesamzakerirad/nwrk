// Package reach runs nw reach: it requests every endpoint of an endpoint
// preset and says, with neutral wording, whether a failure looks like a
// server-side restriction or like network interference.
//
// For each endpoint it resolves the name with the system resolver, requests
// the URL once per address family that has an address, and probes HTTP/3
// over UDP. The rule engine turns the evidence into findings.
package reach

import (
	"context"
	"net/netip"
	"net/url"
	"sync"

	apptest "github.com/radestsam/nwrk/internal/app/test"
	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/diagnostics/rules"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/endpoints"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
	"github.com/radestsam/nwrk/internal/measurement/quic"
)

const concurrency = 6

// Options configure a run.
type Options struct {
	// Test carries the timeout, the tool version and the test seams.
	Test apptest.Options
	// Preset lists the endpoints to request.
	Preset endpoints.Preset
	// SkipHTTP3 leaves out the HTTP/3 probe.
	SkipHTTP3 bool
}

// Run requests every endpoint and returns the finished report.
func Run(ctx context.Context, o Options) *domain.Report {
	rep := domain.NewReport("reach", "preset "+o.Preset.Name, o.Test.ToolVersion)
	results := make([][]*domain.Measurement, len(o.Preset.Endpoints))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, e := range o.Preset.Endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = endpoint(ctx, e, o)
		}()
	}
	wg.Wait()
	for _, ms := range results {
		for _, m := range ms {
			rep.Add(m)
		}
	}
	engine.Evaluate(rules.Reach(), rep)
	rep.Summarize()
	rep.Finish()
	return rep
}

// endpoint measures one endpoint: DNS, then HTTP per address family, then
// the HTTP/3 probe.
func endpoint(ctx context.Context, e endpoints.Endpoint, o Options) []*domain.Measurement {
	var out []*domain.Measurement
	host := e.Host()
	u, err := url.Parse(e.URL)
	if err != nil {
		m := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: host, URL: e.URL})
		return []*domain.Measurement{m.Skip("the endpoint URL is invalid")}
	}
	timed := func(f func(context.Context) *domain.Measurement) *domain.Measurement {
		c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
		defer cancel()
		return f(c)
	}

	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		systemFn := dns.System
		if o.Test.SystemDNS != nil {
			systemFn = o.Test.SystemDNS
		}
		m := timed(func(c context.Context) *domain.Measurement { return systemFn(c, host) })
		out = append(out, m)
		addrs = dns.Addresses(m)
	}
	if len(addrs) == 0 {
		m := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: host, URL: e.URL})
		return append(out, m.Skip("name resolution gave no address to connect to"))
	}

	byFamily := map[string][]netip.Addr{}
	var families []string
	for _, a := range addrs {
		f := family(a)
		if _, ok := byFamily[f]; !ok {
			families = append(families, f)
		}
		byFamily[f] = append(byFamily[f], a)
	}
	var working *netip.Addr
	for _, f := range families {
		fa := byFamily[f]
		m := timed(func(c context.Context) *domain.Measurement {
			return mhttp.Get(c, u, mhttp.Options{
				DialContext: apptest.ViaResolver(nil, host, fa, o.Test.Timeout),
				RootCAs:     o.Test.RootCAs,
			})
		})
		m.Target.Family = f
		m.Params["name"] = e.Name
		out = append(out, m)
		if m.Status == domain.StatusSuccess && working == nil {
			working = &fa[0]
		}
	}
	if o.SkipHTTP3 || u.Scheme != "https" {
		return out
	}
	// Probe HTTP/3 against an address that answered over TCP; when none
	// did, against the first address, so the evidence is still recorded.
	target := addrs[0]
	if working != nil {
		target = *working
	}
	out = append(out, timed(func(c context.Context) *domain.Measurement {
		return quic.Probe(c, u, target, quic.Options{RootCAs: o.Test.RootCAs})
	}))
	return out
}

func family(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}
