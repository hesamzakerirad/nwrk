// Package probes makes the extra measurements that interference rules need:
// repeated and comparative checks, each marked as a probe so the ordinary
// rules ignore it. A probe never replaces an ordinary measurement; it adds
// evidence next to it.
package probes

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	apptest "github.com/hesamzakerirad/nwrk/internal/app/test"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
	"github.com/hesamzakerirad/nwrk/internal/platform"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

// DefaultControlSNI is the server name used as the control in the
// server-name comparison. example.org is reserved by IANA for documentation:
// it is neutral, and no real service answers to it.
const DefaultControlSNI = "www.example.org"

// perAddress bounds how many addresses of one name get the TLS probes.
const perAddress = 2

// Options configure the probes.
type Options struct {
	Test apptest.Options
	// ControlSNI is the neutral server name for the comparison.
	ControlSNI string
	// Window is how long the multiple-reply probe listens.
	Window time.Duration
	// PlainPort is the port of the http comparison; zero means 80, and only
	// targets on port 443 get the comparison then. Tests set it.
	PlainPort int
}

func (o Options) control() string {
	if o.ControlSNI != "" {
		return o.ControlSNI
	}
	return DefaultControlSNI
}

// Interference adds every interference probe that applies to the target.
// host, port, https and u describe it; the primary measurements are already
// in rep.
func Interference(ctx context.Context, rep *domain.Report, host string, port int, https bool, u *url.URL, o Options) {
	MultipleResponses(ctx, rep, host, o)
	AnswerReachability(ctx, rep, host, port, o)
	if https {
		SNIComparison(ctx, rep, host, port, o)
	}
	PlainHTTP(ctx, rep, host, port, https, u, o)
}

// Security adds the probes of nw security inspect.
func Security(ctx context.Context, rep *domain.Report, host string, port int, https bool, u *url.URL, o Options) {
	DNSSEC(ctx, rep, host, o)
	if https {
		LegacyTLS(ctx, rep, host, port, o)
	}
	PlainHTTP(ctx, rep, host, port, https, u, o)
}

// primary returns the ordinary measurements of a type.
func primary(rep *domain.Report, t domain.Type) []domain.Measurement {
	var out []domain.Measurement
	for _, m := range rep.Measurements {
		if m.Type == t && m.Probe() == "" {
			out = append(out, m)
		}
	}
	return out
}

// reachable returns the addresses with a successful TCP connection, in the
// order the connections were made.
func reachable(rep *domain.Report) []netip.Addr {
	var out []netip.Addr
	for _, m := range primary(rep, domain.TypeTCP) {
		if m.Status != domain.StatusSuccess {
			continue
		}
		if a, err := netip.ParseAddr(m.Target.IP); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func skipped(typ domain.Type, version, host, probe, why string) *domain.Measurement {
	m := domain.Begin(typ, version, domain.Target{Host: host})
	m.Params = map[string]any{"probe": probe}
	return m.Skip(why)
}

// resolverOf returns the plain resolvers to probe: those the user chose,
// else the first system name server.
func plainResolvers(rep *domain.Report, o Options) []target.Resolver {
	var out []target.Resolver
	for _, r := range o.Test.Resolvers {
		if r.Transport == "udp" {
			out = append(out, r)
		}
	}
	if len(out) > 0 {
		return out
	}
	servers, _ := platform.SystemResolvers()
	for _, s := range servers {
		if r, err := target.ParseResolver(s); err == nil && r.Transport == "udp" {
			return []target.Resolver{r}
		}
	}
	return nil
}

// MultipleResponses listens for several replies to one query, once per
// plain UDP resolver.
func MultipleResponses(ctx context.Context, rep *domain.Report, host string, o Options) {
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	rs := plainResolvers(rep, o)
	if len(rs) == 0 {
		rep.Add(skipped(domain.TypeDNS, dns.Version, host, domain.ProbeMultipleResponses, "no plain UDP resolver is available to probe"))
		return
	}
	out := make([]*domain.Measurement, len(rs))
	var wg sync.WaitGroup
	for i, r := range rs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
			defer cancel()
			out[i] = dns.MultipleResponses(c, host, r, o.Window)
		}()
	}
	wg.Wait()
	for _, m := range out {
		rep.Add(m)
	}
}

// DNSSEC inspects the signature state and alias chain through the first
// chosen resolver, or through the first system name server.
func DNSSEC(ctx context.Context, rep *domain.Report, host string, o Options) {
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	var r target.Resolver
	switch {
	case len(o.Test.Resolvers) > 0:
		r = o.Test.Resolvers[0]
	default:
		rs := plainResolvers(rep, o)
		if len(rs) == 0 {
			rep.Add(skipped(domain.TypeDNS, dns.Version, host, domain.ProbeDNSSEC, "no resolver can be asked directly: the system resolver does not expose DNSSEC data"))
			return
		}
		r = rs[0]
	}
	c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
	defer cancel()
	rep.Add(dns.Inspect(c, host, r, dns.Options{RootCAs: o.Test.RootCAs}))
}

// AnswerReachability connects to the addresses each resolver returned when
// the system resolver and another resolver disagree, so the report can say
// whether the two answers behave differently.
func AnswerReachability(ctx context.Context, rep *domain.Report, host string, port int, o Options) {
	type set struct {
		source string
		addrs  []netip.Addr
	}
	var sets []set
	var sys *set
	for _, m := range primary(rep, domain.TypeDNS) {
		if m.Status != domain.StatusSuccess || m.Resolver == nil {
			continue
		}
		s := set{source: m.Resolver.Address, addrs: dns.Addresses(&m)}
		if m.Resolver.Kind == "system" {
			s.source = "system"
			sys = &s
			continue
		}
		sets = append(sets, s)
	}
	if sys == nil {
		return
	}
	disjoint := func(a, b []netip.Addr) bool {
		for _, x := range a {
			for _, y := range b {
				if x == y {
					return false
				}
			}
		}
		return true
	}
	var differ []set
	for _, s := range sets {
		if disjoint(sys.addrs, s.addrs) {
			differ = append(differ, s)
		}
	}
	if len(differ) == 0 {
		return
	}
	jobs := []set{*sys}
	jobs = append(jobs, differ...)
	type job struct {
		source string
		addr   netip.Addr
	}
	var all []job
	for _, s := range jobs {
		for i, a := range s.addrs {
			if i == perAddress {
				break
			}
			all = append(all, job{s.source, a})
		}
	}
	out := make([]*domain.Measurement, len(all))
	var wg sync.WaitGroup
	for i, j := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
			defer cancel()
			m := tcp.Connect(c, host, netip.AddrPortFrom(j.addr, uint16(port)), nil)
			m.Params["probe"] = domain.ProbeAnswerReachability
			m.Params["source"] = j.source
			out[i] = m
		}()
	}
	wg.Wait()
	for _, m := range out {
		rep.Add(m)
	}
}

// SNIComparison repeats the handshake with the target name once, and makes
// two handshakes with a neutral control name, at each address that accepted
// a TCP connection. The difference, if any, is what the rules look at.
func SNIComparison(ctx context.Context, rep *domain.Report, host string, port int, o Options) {
	addrs := reachable(rep)
	if len(addrs) > perAddress {
		addrs = addrs[:perAddress]
	}
	if len(addrs) == 0 {
		return
	}
	control := o.control()
	type job struct {
		addr  netip.Addr
		probe string
		sni   string
	}
	var jobs []job
	for _, a := range addrs {
		jobs = append(jobs, job{a, domain.ProbeSNITarget, host}, job{a, domain.ProbeSNIControl, control}, job{a, domain.ProbeSNIControl, control})
	}
	out := make([]*domain.Measurement, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
			defer cancel()
			m := mtls.Handshake(c, j.sni, netip.AddrPortFrom(j.addr, uint16(port)), mtls.Options{
				RootCAs:    o.Test.RootCAs,
				NextProtos: []string{"h2", "http/1.1"},
			})
			// The address belongs to the target, whichever name was sent.
			m.Target.Host = host
			m.Params["probe"] = j.probe
			m.Params["sni"] = j.sni
			out[i] = m
		}()
	}
	wg.Wait()
	for _, m := range out {
		rep.Add(m)
	}
}

// LegacyTLS offers only TLS 1.0 and 1.1 to the first reachable address, to
// see whether the server still accepts them. Verification stays on.
func LegacyTLS(ctx context.Context, rep *domain.Report, host string, port int, o Options) {
	addrs := reachable(rep)
	if len(addrs) == 0 {
		rep.Add(skipped(domain.TypeTLS, mtls.Version, host, domain.ProbeLegacyTLS, "no TCP connection succeeded"))
		return
	}
	c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
	defer cancel()
	m := mtls.Handshake(c, host, netip.AddrPortFrom(addrs[0], uint16(port)), mtls.Options{
		RootCAs:    o.Test.RootCAs,
		MaxVersion: tls.VersionTLS11,
	})
	m.Params["probe"] = domain.ProbeLegacyTLS
	rep.Add(m)
}

// PlainHTTP makes the same request over http that the primary request made
// over https, for the comparison between the two. It connects to the
// addresses of the target, port 80.
func PlainHTTP(ctx context.Context, rep *domain.Report, host string, port int, https bool, u *url.URL, o Options) {
	if !https || u == nil || (port != 443 && o.PlainPort == 0) {
		return
	}
	addrs := reachable(rep)
	if len(addrs) == 0 {
		rep.Add(skipped(domain.TypeHTTP, mhttp.Version, host, domain.ProbePlainHTTP, "no TCP connection succeeded"))
		return
	}
	plain := *u
	plain.Scheme = "http"
	plain.Host = host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		plain.Host = "[" + host + "]"
	}
	if o.PlainPort != 0 && o.PlainPort != 80 {
		plain.Host = net.JoinHostPort(host, strconv.Itoa(o.PlainPort))
	}
	var resolver *target.Resolver
	if len(o.Test.Resolvers) > 0 {
		rv := o.Test.Resolvers[0]
		resolver = &rv
	}
	c, cancel := context.WithTimeout(ctx, o.Test.Timeout)
	defer cancel()
	m := mhttp.Get(c, &plain, mhttp.Options{
		DialContext: apptest.ViaResolver(resolver, host, addrs[:1], o.Test.Timeout),
		RootCAs:     o.Test.RootCAs,
	})
	m.Params["probe"] = domain.ProbePlainHTTP
	rep.Add(m)
}
