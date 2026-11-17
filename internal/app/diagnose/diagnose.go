// Package diagnose runs the standard investigation of one destination: it
// measures DNS, TCP, TLS and HTTP in dependency order, skips what cannot run
// with a stated reason, and hands the evidence to the rule engine.
package diagnose

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	apptest "github.com/hesamzakerirad/nwrk/internal/app/test"
	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/diagnostics/rules"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

// Profile selects how much to measure.
type Profile string

const (
	Quick    Profile = "quick"
	Standard Profile = "standard"
	Deep     Profile = "deep"
)

// DefaultProfile is used when none is chosen.
const DefaultProfile = Standard

// ParseProfile validates a --profile value.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(s); p {
	case Quick, Standard, Deep:
		return p, nil
	}
	return "", fmt.Errorf("invalid --profile %q (want quick, standard or deep)", s)
}

// spec is the fixed definition of a profile. Profiles are hard-coded and
// documented in docs/diagnostics.md; they become configurable later.
type spec struct {
	tcpPerFamily int  // addresses per IP family to connect to
	tls, http    bool // whether those layers are part of the profile
	tlsAll       bool // handshake with every reachable address, not one per family
	concurrency  int  // simultaneous measurements
}

var specs = map[Profile]spec{
	Quick:    {tcpPerFamily: 2, concurrency: 4},
	Standard: {tcpPerFamily: 4, tls: true, http: true, concurrency: 6},
	Deep:     {tcpPerFamily: 8, tls: true, http: true, tlsAll: true, concurrency: 8},
}

// Target is what to diagnose.
type Target struct {
	Host string
	Port int
	// TLS is true for https targets. Port 80 and http:// URLs are plain.
	TLS bool
	// URL is the HTTP request to make.
	URL *url.URL
}

// ParseTarget reads a host, host:port or URL. A bare host means https on
// port 443; port 80 means http; any other explicit port means https.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := target.URL(s)
		if err != nil {
			return Target{}, err
		}
		port := 80
		if u.Scheme == "https" {
			port = 443
		}
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		return Target{Host: u.Hostname(), Port: port, TLS: u.Scheme == "https", URL: u}, nil
	}
	host, port, err := target.HostPort(s, 0)
	if err != nil {
		host, port, err = target.HostPort(s, 443)
		if err != nil {
			return Target{}, err
		}
	}
	t := Target{Host: host, Port: port, TLS: port != 80}
	scheme := "https"
	if !t.TLS {
		scheme = "http"
	}
	t.URL = &url.URL{Scheme: scheme, Host: hostPort(host, port, scheme), Path: "/"}
	return t, nil
}

func hostPort(host string, port int, scheme string) string {
	def := 443
	if scheme == "http" {
		def = 80
	}
	if port == def {
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Options configure a diagnosis.
type Options struct {
	Test    apptest.Options
	Profile Profile
}

type runner struct {
	rep *domain.Report
	t   Target
	o   Options
	sp  spec
	sem chan struct{}
}

// Run investigates t and returns the finished report, findings included.
func Run(ctx context.Context, t Target, o Options) *domain.Report {
	if o.Profile == "" {
		o.Profile = DefaultProfile
	}
	sp := specs[o.Profile]
	rep := domain.NewReport("diagnose", t.Host, o.Test.ToolVersion)
	if t.Port != 0 {
		rep.Run.Target = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	rep.Run.Profile = string(o.Profile)
	r := &runner{rep: rep, t: t, o: o, sp: sp, sem: make(chan struct{}, sp.concurrency)}

	r.run(ctx)

	engine.Evaluate(rules.All(), rep)
	rep.Summarize()
	rep.Finish()
	return rep
}

func (r *runner) run(ctx context.Context) {
	addrs := r.resolve(ctx)
	if len(addrs) == 0 {
		r.skipAll("name resolution failed, so there is no address to connect to")
		return
	}
	v4, v6 := r.selectAddrs(addrs)
	if len(v4)+len(v6) == 0 {
		r.skipAll("the name resolved only to addresses that cannot be connected to")
		return
	}

	tcpOK := r.tcp(ctx, v4, v6)
	if !r.sp.tls && !r.sp.http {
		return
	}
	var tlsOK map[string]bool
	if r.sp.tls {
		tlsOK = r.tls(ctx, v4, v6, tcpOK)
	}
	if r.sp.http {
		r.http(ctx, v4, v6, tcpOK, tlsOK)
	}
}

func (r *runner) resolve(ctx context.Context) []netip.Addr {
	if ip, err := netip.ParseAddr(r.t.Host); err == nil {
		m := domain.Begin(domain.TypeDNS, dns.Version, domain.Target{Host: r.t.Host})
		r.rep.Add(m.Skip("the target is an IP address, so there is nothing to resolve"))
		return []netip.Addr{ip.Unmap()}
	}
	return apptest.Resolve(ctx, r.rep, r.t.Host, r.o.Test)
}

// skipAll records the layers of the profile that cannot run, with a reason.
func (r *runner) skipAll(reason string) {
	base := domain.Target{Host: r.t.Host, Port: r.t.Port}
	r.rep.Add(domain.Begin(domain.TypeTCP, tcp.Version, base).Skip(reason))
	if r.sp.tls {
		r.rep.Add(domain.Begin(domain.TypeTLS, mtls.Version, base).Skip(reason))
	}
	if r.sp.http {
		r.rep.Add(domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: r.t.Host, URL: r.t.URL.String()}).Skip(reason))
	}
}

// selectAddrs drops addresses nothing can connect to and splits the rest by
// family, keeping the resolver's order and the profile's per-family limit.
func (r *runner) selectAddrs(addrs []netip.Addr) (v4, v6 []netip.Addr) {
	for _, a := range addrs {
		if a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	limit := func(l []netip.Addr) []netip.Addr {
		if len(l) > r.sp.tcpPerFamily {
			return l[:r.sp.tcpPerFamily]
		}
		return l
	}
	return limit(v4), limit(v6)
}

// each runs f for every address under the profile's concurrency limit and
// adds the results to the report in address order.
func (r *runner) each(ctx context.Context, addrs []netip.Addr, f func(context.Context, netip.Addr) *domain.Measurement) []*domain.Measurement {
	results := make([]*domain.Measurement, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.sem <- struct{}{}
			defer func() { <-r.sem }()
			c, cancel := context.WithTimeout(ctx, r.o.Test.Timeout)
			defer cancel()
			results[i] = f(c, a)
		}()
	}
	wg.Wait()
	for _, m := range results {
		r.rep.Add(m)
	}
	return results
}

// tcp connects to every selected address and returns the ones that worked,
// as a set of IP strings.
func (r *runner) tcp(ctx context.Context, v4, v6 []netip.Addr) map[string]bool {
	all := append(append([]netip.Addr{}, v4...), v6...)
	ok := map[string]bool{}
	for i, m := range r.each(ctx, all, func(c context.Context, a netip.Addr) *domain.Measurement {
		return tcp.Connect(c, r.t.Host, netip.AddrPortFrom(a, uint16(r.t.Port)), nil)
	}) {
		if m.Status == domain.StatusSuccess {
			ok[all[i].String()] = true
		}
	}
	return ok
}

func family(a netip.Addr) string { return tcp.Family(a) }

func reachable(addrs []netip.Addr, ok map[string]bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if ok[a.String()] {
			out = append(out, a)
		}
	}
	return out
}

// tls handshakes per family and returns the addresses that completed it.
func (r *runner) tls(ctx context.Context, v4, v6 []netip.Addr, tcpOK map[string]bool) map[string]bool {
	ok := map[string]bool{}
	if !r.t.TLS {
		r.rep.Add(domain.Begin(domain.TypeTLS, mtls.Version, domain.Target{Host: r.t.Host, Port: r.t.Port}).
			Skip("the target is plain HTTP, so there is no TLS to test"))
		return ok
	}
	var chosen []netip.Addr
	for _, fam := range [][]netip.Addr{v4, v6} {
		if len(fam) == 0 {
			continue
		}
		up := reachable(fam, tcpOK)
		if len(up) == 0 {
			m := domain.Begin(domain.TypeTLS, mtls.Version, domain.Target{Host: r.t.Host, Port: r.t.Port, Family: family(fam[0])})
			r.rep.Add(m.Skip("no TCP connection to an " + family(fam[0]) + " address succeeded"))
			continue
		}
		if !r.sp.tlsAll {
			up = up[:1]
		}
		chosen = append(chosen, up...)
	}
	for i, m := range r.each(ctx, chosen, func(c context.Context, a netip.Addr) *domain.Measurement {
		return mtls.Handshake(c, r.t.Host, netip.AddrPortFrom(a, uint16(r.t.Port)), mtls.Options{
			RootCAs:    r.o.Test.RootCAs,
			NextProtos: []string{"h2", "http/1.1"},
		})
	}) {
		if m.Status == domain.StatusSuccess {
			ok[chosen[i].String()] = true
		}
	}
	return ok
}

// http makes one request per IP family that is ready, each pinned to the
// addresses that worked for that family.
func (r *runner) http(ctx context.Context, v4, v6 []netip.Addr, tcpOK, tlsOK map[string]bool) {
	type job struct {
		fam   string
		addrs []netip.Addr
	}
	var jobs []job
	ready := func(a netip.Addr) bool {
		if r.t.TLS {
			return tlsOK[a.String()]
		}
		return tcpOK[a.String()]
	}
	for _, fam := range [][]netip.Addr{v4, v6} {
		if len(fam) == 0 {
			continue
		}
		var up []netip.Addr
		for _, a := range fam {
			if ready(a) {
				up = append(up, a)
			}
		}
		if len(up) == 0 {
			reason := "no TCP connection to an " + family(fam[0]) + " address succeeded"
			if r.t.TLS && len(reachable(fam, tcpOK)) > 0 {
				reason = "no TLS handshake with an " + family(fam[0]) + " address succeeded"
			}
			m := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: r.t.Host, URL: r.t.URL.String(), Family: family(fam[0])})
			r.rep.Add(m.Skip(reason))
			continue
		}
		jobs = append(jobs, job{family(fam[0]), up})
	}

	var resolver *target.Resolver
	if len(r.o.Test.Resolvers) > 0 {
		rv := r.o.Test.Resolvers[0]
		resolver = &rv
	}
	results := make([]*domain.Measurement, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.sem <- struct{}{}
			defer func() { <-r.sem }()
			c, cancel := context.WithTimeout(ctx, r.o.Test.Timeout)
			defer cancel()
			m := mhttp.Get(c, r.t.URL, mhttp.Options{
				DialContext: apptest.ViaResolver(resolver, r.t.Host, j.addrs, r.o.Test.Timeout),
				RootCAs:     r.o.Test.RootCAs,
			})
			m.Target.Family = j.fam
			m.Params["family"] = j.fam
			results[i] = m
		}()
	}
	wg.Wait()
	for _, m := range results {
		r.rep.Add(m)
	}
}
