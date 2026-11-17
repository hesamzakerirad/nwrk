// Package dns measures name resolution: A and AAAA lookups against the
// system's resolvers or against a resolver chosen explicitly.
package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/errclass"
	"github.com/hesamzakerirad/nwrk/internal/platform"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

// Version is the implementation version recorded in every measurement.
const Version = "1"

// QueryResult is the outcome of one query type against one resolver.
type QueryResult struct {
	Type        string        `json:"type"`
	RCode       string        `json:"rcode,omitempty"`
	Answers     []string      `json:"answers"`
	CNAMEs      []string      `json:"cnames,omitempty"`
	DurationMS  float64       `json:"duration_ms"`
	TCPFallback bool          `json:"tcp_fallback,omitempty"`
	Error       *domain.Error `json:"error,omitempty"`
}

// Result is the structured result of a DNS measurement.
type Result struct {
	A       []string      `json:"a"`
	AAAA    []string      `json:"aaaa"`
	Queries []QueryResult `json:"queries"`
}

// Details describes the result in plain lines for the human report.
func (r *Result) Details() []string {
	var out []string
	for _, q := range r.Queries {
		line := fmt.Sprintf("%-5s", q.Type)
		switch {
		case q.Error == nil:
			line += " " + strings.Join(q.Answers, ", ")
		case q.Error.Code == domain.DNSNoAnswer:
			line += " no records"
		case q.RCode != "":
			line += " " + q.RCode
		default:
			line += " " + q.Error.Message
		}
		out = append(out, line)
	}
	return out
}

// Options tune a lookup. The zero value is the normal one.
type Options struct {
	// RootCAs replaces the system trust store for DoT and DoH. Tests use it.
	RootCAs *x509.CertPool
}

// Lookup measures resolution of name through the resolver r, asking for A
// and AAAA records at the same time. ctx carries the deadline.
func Lookup(ctx context.Context, name string, r target.Resolver) *domain.Measurement {
	return LookupWith(ctx, name, r, Options{})
}

// LookupWith is Lookup with options.
func LookupWith(ctx context.Context, name string, r target.Resolver, o Options) *domain.Measurement {
	m := begin(name, &domain.ResolverInfo{Kind: r.Transport, Address: r.Endpoint()})
	m.Params = map[string]any{"qtypes": []string{"A", "AAAA"}, "encrypted": r.Encrypted()}
	return finish(m, both(func(qtype uint16) QueryResult {
		return exchange(ctx, name, qtype, r, o)
	}))
}

// System measures resolution of name the way applications get it: through
// the operating system's resolver, which honors the hosts file, search
// domains and platform specific sources. The configured name servers are
// listed for context.
//
// That API does not report response codes, so an NXDOMAIN and an empty
// answer both appear as dns.no_answer. Use a chosen resolver, which is
// queried directly, when the exact response code matters.
func System(ctx context.Context, name string) *domain.Measurement {
	servers, _ := platform.SystemResolvers()
	m := begin(name, &domain.ResolverInfo{Kind: "system", Servers: servers})
	m.Params = map[string]any{"qtypes": []string{"A", "AAAA"}, "api": "os"}
	return finish(m, both(func(qtype uint16) QueryResult {
		start := time.Now()
		network := "ip4"
		if qtype == mdns.TypeAAAA {
			network = "ip6"
		}
		q := QueryResult{Type: mdns.TypeToString[qtype], Answers: []string{}}
		addrs, err := lookupIP(ctx, network, name)
		q.DurationMS = domain.Millis(time.Since(start))
		if err != nil {
			code := errclass.DNS(err)
			msg := "the operating system resolver reported: " + err.Error()
			if code == domain.DNSNXDomain {
				code = domain.DNSNoAnswer
				msg = "no records returned (the operating system resolver does not report the response code)"
			}
			q.Error = &domain.Error{Code: code, Message: msg}
			return q
		}
		for _, a := range addrs {
			q.Answers = append(q.Answers, a.Unmap().String())
		}
		return q
	}))
}

// lookupIP is the operating system resolver, replaceable in tests.
var lookupIP = func(ctx context.Context, network, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, name)
}

func begin(name string, res *domain.ResolverInfo) *domain.Measurement {
	m := domain.Begin(domain.TypeDNS, Version, domain.Target{Host: name})
	m.Resolver = res
	return m
}

// both runs the A and AAAA queries concurrently.
func both(q func(qtype uint16) QueryResult) []QueryResult {
	out := make([]QueryResult, 2)
	var wg sync.WaitGroup
	for i, t := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = q(t)
		}()
	}
	wg.Wait()
	return out
}

// exchange sends one query and classifies the response.
func exchange(ctx context.Context, name string, qtype uint16, r target.Resolver, o Options) QueryResult {
	q := QueryResult{Type: mdns.TypeToString[qtype], Answers: []string{}}
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, false)

	start := time.Now()
	resp, err := sendVia(ctx, msg, r, o)
	if err == nil && resp.Truncated && r.Transport == "udp" {
		q.TCPFallback = true
		tcp := r
		tcp.Transport = "tcp"
		resp, err = sendVia(ctx, msg, tcp, o)
	}
	q.DurationMS = domain.Millis(time.Since(start))
	if err != nil {
		code := domain.DNSTransport
		if errclass.Timeout(err) {
			code = domain.DNSTimeout
		}
		q.Error = &domain.Error{Code: code, Message: transportMessage(err, code)}
		return q
	}

	q.RCode = mdns.RcodeToString[resp.Rcode]
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *mdns.A:
			if qtype == mdns.TypeA {
				q.Answers = append(q.Answers, v.A.String())
			}
		case *mdns.AAAA:
			if qtype == mdns.TypeAAAA {
				q.Answers = append(q.Answers, v.AAAA.String())
			}
		case *mdns.CNAME:
			q.CNAMEs = append(q.CNAMEs, strings.TrimSuffix(v.Target, "."))
		}
	}
	switch resp.Rcode {
	case mdns.RcodeSuccess:
		if len(q.Answers) == 0 {
			q.Error = &domain.Error{Code: domain.DNSNoAnswer, Message: "the resolver answered without any " + q.Type + " records"}
		}
	case mdns.RcodeNameError:
		q.Error = &domain.Error{Code: domain.DNSNXDomain, Message: "the name does not exist (NXDOMAIN)"}
	case mdns.RcodeServerFailure:
		q.Error = &domain.Error{Code: domain.DNSServFail, Message: "the resolver failed to answer (SERVFAIL)"}
	case mdns.RcodeRefused:
		q.Error = &domain.Error{Code: domain.DNSRefused, Message: "the resolver refused the query (REFUSED)"}
	default:
		q.Error = &domain.Error{Code: domain.DNSError, Message: "the resolver returned " + q.RCode}
	}
	return q
}

// sendVia sends msg through r over its own transport.
func sendVia(ctx context.Context, msg *mdns.Msg, r target.Resolver, o Options) (*mdns.Msg, error) {
	switch r.Transport {
	case "https":
		return sendDoH(ctx, msg, r, o)
	case "tls":
		return send(ctx, msg, "tcp-tls", r.Address(), &tls.Config{ServerName: r.Host, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12})
	}
	return send(ctx, msg, r.Transport, r.Address(), nil)
}

func send(ctx context.Context, msg *mdns.Msg, transport, addr string, tlsCfg *tls.Config) (*mdns.Msg, error) {
	c := &mdns.Client{Net: transport, Timeout: 10 * time.Second, TLSConfig: tlsCfg}
	// The client's own timeouts default to two seconds; the context
	// deadline, which comes from --timeout, is the one that must rule.
	if dl, ok := ctx.Deadline(); ok {
		c.Timeout = time.Until(dl)
		if c.Timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	conn, err := c.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Closing the connection is the only way to interrupt a blocked read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	resp, _, err := c.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return resp, err
}

func transportMessage(err error, code domain.ErrorCode) string {
	if code == domain.DNSTimeout {
		return "no response from the resolver before the deadline"
	}
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Err != nil {
		return "could not reach the resolver: " + ne.Err.Error()
	}
	return "could not reach the resolver: " + err.Error()
}

// priority orders error codes from most to least informative when both
// queries fail. A transport problem hides what the resolver would have said.
var priority = []domain.ErrorCode{
	domain.DNSTimeout, domain.DNSTransport, domain.DNSRefused, domain.DNSServFail,
	domain.DNSError, domain.DNSNXDomain, domain.DNSNoAnswer,
}

// finish folds the per-type results into one measurement. The lookup
// succeeds when at least one address came back: a missing AAAA record is
// normal and never a failure.
func finish(m *domain.Measurement, queries []QueryResult) *domain.Measurement {
	res := &Result{A: []string{}, AAAA: []string{}, Queries: queries}
	for _, q := range queries {
		switch q.Type {
		case "A":
			res.A = append(res.A, q.Answers...)
		case "AAAA":
			res.AAAA = append(res.AAAA, q.Answers...)
		}
	}
	if len(res.A)+len(res.AAAA) > 0 {
		return m.Succeed(res)
	}
	for _, code := range priority {
		for _, q := range queries {
			if q.Error != nil && q.Error.Code == code {
				return m.Fail(code, q.Error.Message, res)
			}
		}
	}
	return m.Fail(domain.DNSError, "no addresses returned", res)
}

// Addresses returns the addresses of a successful measurement, IPv4 first.
func Addresses(m *domain.Measurement) []netip.Addr {
	res, ok := m.Result.(*Result)
	if !ok || m.Status != domain.StatusSuccess {
		return nil
	}
	var out []netip.Addr
	for _, list := range [][]string{res.A, res.AAAA} {
		for _, s := range list {
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}
