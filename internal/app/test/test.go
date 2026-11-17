// Package test runs the four measurements behind the nw test commands and
// assembles their reports. It decides what to measure and in which order;
// the measurement packages decide how.
package test

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/dns"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

// maxAddresses bounds how many addresses of one name are connected to.
const maxAddresses = 16

// Options configure a run.
type Options struct {
	// Timeout is the deadline of each measurement.
	Timeout time.Duration
	// Resolvers are the resolvers chosen by the user. The system resolver
	// is always measured as well, as the baseline.
	Resolvers []target.Resolver
	// ToolVersion is recorded in the report.
	ToolVersion string
	// RootCAs replaces the system trust store; for tests only.
	RootCAs *x509.CertPool
	// SystemDNS replaces the system resolver measurement; for tests only.
	SystemDNS func(ctx context.Context, name string) *domain.Measurement
}

// DNS resolves host with the system resolver and with every chosen one.
func DNS(ctx context.Context, host string, o Options) *domain.Report {
	rep := domain.NewReport("test dns", host, o.ToolVersion)
	if _, ok := parseIP(host); ok {
		m := domain.Begin(domain.TypeDNS, dns.Version, domain.Target{Host: host})
		rep.Add(m.Skip("the target is an IP address, so there is nothing to resolve"))
	} else {
		resolve(ctx, rep, host, o)
	}
	rep.Finish()
	return rep
}

// TCP connects to every address of host on port.
func TCP(ctx context.Context, host string, port int, o Options) *domain.Report {
	rep := domain.NewReport("test tcp", net.JoinHostPort(host, strconv.Itoa(port)), o.ToolVersion)
	addrs, why := resolveTarget(ctx, rep, host, o)
	if len(addrs) == 0 {
		m := domain.Begin(domain.TypeTCP, tcp.Version, domain.Target{Host: host, Port: port})
		rep.Add(m.Skip(why))
	}
	run(ctx, rep, addrs, func(c context.Context, a netip.Addr) *domain.Measurement {
		return tcp.Connect(c, host, netip.AddrPortFrom(a, uint16(port)), nil)
	}, o)
	rep.Finish()
	return rep
}

// TLS handshakes with every address of host on port, verifying the
// certificate against host.
func TLS(ctx context.Context, host string, port int, o Options) *domain.Report {
	rep := domain.NewReport("test tls", net.JoinHostPort(host, strconv.Itoa(port)), o.ToolVersion)
	addrs, why := resolveTarget(ctx, rep, host, o)
	if len(addrs) == 0 {
		m := domain.Begin(domain.TypeTLS, mtls.Version, domain.Target{Host: host, Port: port})
		rep.Add(m.Skip(why))
	}
	run(ctx, rep, addrs, func(c context.Context, a netip.Addr) *domain.Measurement {
		return mtls.Handshake(c, host, netip.AddrPortFrom(a, uint16(port)), mtls.Options{
			RootCAs:    o.RootCAs,
			NextProtos: []string{"h2", "http/1.1"},
		})
	}, o)
	rep.Finish()
	return rep
}

// HTTP requests u. method is GET or HEAD.
func HTTP(ctx context.Context, u *url.URL, method string, maxRedirects int, o Options) *domain.Report {
	rep := domain.NewReport("test http", u.String(), o.ToolVersion)
	host := u.Hostname()
	addrs, why := resolveTarget(ctx, rep, host, o)
	if len(addrs) == 0 {
		m := domain.Begin(domain.TypeHTTP, mhttp.Version, domain.Target{Host: host, URL: u.String()})
		rep.Add(m.Skip(why))
		rep.Finish()
		return rep
	}
	opts := mhttp.Options{Method: method, MaxRedirects: maxRedirects, RootCAs: o.RootCAs}
	if len(o.Resolvers) > 0 {
		opts.DialContext = viaResolver(o.Resolvers[0], host, addrs, o.Timeout)
	}
	c, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	rep.Add(mhttp.Get(c, u, opts))
	rep.Finish()
	return rep
}

// resolveTarget returns the addresses to connect to. For an IP literal that
// is the address itself and no DNS measurement is made. Otherwise the DNS
// measurements are added to rep, and why explains an empty result.
func resolveTarget(ctx context.Context, rep *domain.Report, host string, o Options) (addrs []netip.Addr, why string) {
	if a, ok := parseIP(host); ok {
		return []netip.Addr{a}, ""
	}
	addrs = resolve(ctx, rep, host, o)
	if len(addrs) == 0 {
		return nil, "name resolution failed, so there is no address to connect to"
	}
	return addrs, ""
}

func parseIP(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	return a.Unmap(), err == nil
}

// resolve measures host with the system resolver first, as the baseline,
// then with each chosen resolver, all at once. It returns the addresses of
// the first chosen resolver, or of the system resolver when none was chosen.
func resolve(ctx context.Context, rep *domain.Report, host string, o Options) []netip.Addr {
	results := make([]*domain.Measurement, 1+len(o.Resolvers))
	var wg sync.WaitGroup
	do := func(i int, f func(context.Context) *domain.Measurement) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			results[i] = f(c)
		}()
	}
	system := dns.System
	if o.SystemDNS != nil {
		system = o.SystemDNS
	}
	do(0, func(c context.Context) *domain.Measurement { return system(c, host) })
	for i, r := range o.Resolvers {
		do(i+1, func(c context.Context) *domain.Measurement { return dns.Lookup(c, host, r) })
	}
	wg.Wait()
	for _, m := range results {
		rep.Add(m)
	}
	preferred := results[0]
	if len(o.Resolvers) > 0 {
		preferred = results[1]
	}
	return dns.Addresses(preferred)
}

// run measures every address at once and adds the results in address order.
func run(ctx context.Context, rep *domain.Report, addrs []netip.Addr, f func(context.Context, netip.Addr) *domain.Measurement, o Options) {
	if len(addrs) > maxAddresses {
		addrs = addrs[:maxAddresses]
	}
	results := make([]*domain.Measurement, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			results[i] = f(c, a)
		}()
	}
	wg.Wait()
	for _, m := range results {
		rep.Add(m)
	}
}

// viaResolver returns a dial function that connects to host using the
// addresses already resolved through r, and resolves any other name (a
// redirect target) through r as well, so the whole request follows the
// resolver the user chose.
func viaResolver(r target.Resolver, host string, known []netip.Addr, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	var mu sync.Mutex
	cache := map[string][]netip.Addr{host: known}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		if _, ok := parseIP(h); ok {
			return d.DialContext(ctx, network, address)
		}
		mu.Lock()
		addrs, ok := cache[h]
		mu.Unlock()
		if !ok {
			c, cancel := context.WithTimeout(ctx, timeout)
			addrs = dns.Addresses(dns.Lookup(c, h, r))
			cancel()
			mu.Lock()
			cache[h] = addrs
			mu.Unlock()
		}
		if len(addrs) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
		}
		var last error
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), p))
			if err == nil {
				return conn, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
}
