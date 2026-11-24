package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/errclass"
	"github.com/radestsam/nwrk/internal/target"
)

// Probe names recorded in params.probe. A probe is evidence for the
// interference rules; the ordinary rules and the layer summary ignore it.
const (
	ProbeMultipleResponses = domain.ProbeMultipleResponses
	ProbeDNSSEC            = domain.ProbeDNSSEC
)

// DefaultWindow is how long the multiple-response probe keeps listening
// after sending its query.
const DefaultWindow = 500 * time.Millisecond

// maxResponses bounds how many replies the probe keeps.
const maxResponses = 8

// ProbeResponse is one reply to the probe's query.
type ProbeResponse struct {
	DelayMS float64  `json:"delay_ms"`
	RCode   string   `json:"rcode"`
	Answers []string `json:"answers"`
	TTL     uint32   `json:"ttl"`
}

// ProbeResult is what came back for a single query.
type ProbeResult struct {
	WindowMS  float64         `json:"window_ms"`
	Responses []ProbeResponse `json:"responses"`
	// Distinct counts the different replies, by response code and answers.
	Distinct int `json:"distinct"`
}

// Details describes the result in plain lines for the human report.
func (r *ProbeResult) Details() []string {
	out := []string{fmt.Sprintf("%d repl%s within %.0f ms, %d distinct", len(r.Responses), map[bool]string{true: "y", false: "ies"}[len(r.Responses) == 1], r.WindowMS, r.Distinct)}
	for _, x := range r.Responses {
		out = append(out, fmt.Sprintf("  +%.1f ms %s %s", x.DelayMS, x.RCode, strings.Join(x.Answers, ", ")))
	}
	return out
}

// MultipleResponses sends one A query to a plain UDP resolver and keeps
// listening for window afterwards. A resolver normally answers once;
// several different replies to one query are what an on-path device that
// races the real answer would produce, and also what some unusual but
// legitimate setups produce, so this is evidence and never a verdict.
func MultipleResponses(ctx context.Context, name string, r target.Resolver, window time.Duration) *domain.Measurement {
	m := begin(name, &domain.ResolverInfo{Kind: r.Transport, Address: r.Endpoint()})
	m.Params = map[string]any{"probe": ProbeMultipleResponses, "qtype": "A"}
	if r.Transport != "udp" {
		return m.Skip("the probe needs plain UDP DNS, where a second reply can arrive unnoticed")
	}
	if window <= 0 {
		window = DefaultWindow
	}
	raddr, err := net.ResolveUDPAddr("udp", r.Address())
	if err != nil {
		return m.Fail(domain.DNSTransport, "the resolver address is invalid: "+err.Error(), nil)
	}
	// An unconnected socket also sees replies that come from another source
	// address than the one queried.
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return m.Fail(domain.DNSTransport, "could not open a UDP socket: "+err.Error(), nil)
	}
	defer pc.Close()

	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	q.RecursionDesired = true
	wire, err := q.Pack()
	if err != nil {
		return m.Fail(domain.DNSError, err.Error(), nil)
	}
	start := time.Now()
	if _, err := pc.WriteTo(wire, raddr); err != nil {
		return m.Fail(domain.DNSTransport, "could not send the query: "+err.Error(), nil)
	}
	stop := context.AfterFunc(ctx, func() { _ = pc.SetReadDeadline(time.Now()) })
	defer stop()

	res := &ProbeResult{WindowMS: domain.Millis(window), Responses: []ProbeResponse{}}
	deadline := start.Add(window)
	first := time.Time{}
	// Until the first reply, wait up to the context deadline; after it, only
	// for the window.
	if dl, ok := ctx.Deadline(); ok && dl.After(deadline) {
		deadline = dl
	}
	buf := make([]byte, 4096)
	for len(res.Responses) < maxResponses {
		_ = pc.SetReadDeadline(deadline)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		resp := new(mdns.Msg)
		if resp.Unpack(buf[:n]) != nil || resp.Id != q.Id || !resp.Response {
			continue
		}
		now := time.Now()
		if first.IsZero() {
			first = now
			if w := now.Add(window); w.Before(deadline) {
				deadline = w
			}
		}
		res.Responses = append(res.Responses, summarize(resp, now.Sub(start)))
	}
	res.Distinct = distinct(res.Responses)
	if len(res.Responses) == 0 {
		if ctx.Err() != nil && !errclass.Timeout(ctx.Err()) {
			return m.Fail(domain.DNSError, "stopped before a reply arrived", res)
		}
		return m.Fail(domain.DNSTimeout, "no reply from the resolver before the deadline", res)
	}
	return m.Succeed(res)
}

func summarize(resp *mdns.Msg, d time.Duration) ProbeResponse {
	out := ProbeResponse{DelayMS: domain.Millis(d), RCode: mdns.RcodeToString[resp.Rcode], Answers: []string{}}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *mdns.A:
			out.Answers = append(out.Answers, v.A.String())
			if out.TTL == 0 || v.Hdr.Ttl < out.TTL {
				out.TTL = v.Hdr.Ttl
			}
		case *mdns.AAAA:
			out.Answers = append(out.Answers, v.AAAA.String())
		}
	}
	sort.Strings(out.Answers)
	return out
}

func distinct(rs []ProbeResponse) int {
	seen := map[string]bool{}
	for _, r := range rs {
		seen[r.RCode+"|"+strings.Join(r.Answers, ",")] = true
	}
	return len(seen)
}

// InspectResult is the DNSSEC and CNAME information of one lookup.
type InspectResult struct {
	RCode   string   `json:"rcode"`
	Answers []string `json:"answers"`
	// CNAMEs is the alias chain in the order the resolver returned it.
	CNAMEs []string `json:"cnames"`
	// Signed is true when the answer carried RRSIG records.
	Signed bool `json:"signed"`
	// Authenticated is true when the resolver set the AD flag, saying it
	// validated the answer.
	Authenticated bool `json:"authenticated"`
	// ValidationFailure is true when the normal query got SERVFAIL but the
	// same query with checking disabled got an answer.
	ValidationFailure bool `json:"validation_failure"`
}

// Details describes the result in plain lines for the human report.
func (r *InspectResult) Details() []string {
	state := "not signed (no RRSIG in the answer)"
	switch {
	case r.ValidationFailure:
		state = "validation failed: the resolver returns SERVFAIL, but an answer exists when checking is disabled"
	case r.Signed && r.Authenticated:
		state = "signed, and the resolver reports it validated the answer (AD flag)"
	case r.Signed:
		state = "signed, but the resolver did not report validating it"
	}
	out := []string{"DNSSEC: " + state}
	if len(r.CNAMEs) > 0 {
		out = append(out, "CNAME chain: "+strings.Join(r.CNAMEs, " -> "))
	}
	return out
}

// Inspect asks one resolver for the A records of name with DNSSEC
// requested, and records the signature state and the alias chain. When the
// resolver answers SERVFAIL it asks once more with checking disabled, to
// tell a validation failure from an ordinary server failure.
func Inspect(ctx context.Context, name string, r target.Resolver, o Options) *domain.Measurement {
	m := begin(name, &domain.ResolverInfo{Kind: r.Transport, Address: r.Endpoint()})
	m.Params = map[string]any{"probe": ProbeDNSSEC, "qtype": "A", "encrypted": r.Encrypted()}
	ask := func(cd bool) (*mdns.Msg, error) {
		q := new(mdns.Msg)
		q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
		q.RecursionDesired = true
		q.CheckingDisabled = cd
		q.SetEdns0(1232, true) // DO: ask for DNSSEC records
		return sendVia(ctx, q, r, o)
	}
	resp, err := ask(false)
	if err != nil {
		code := domain.DNSTransport
		if errclass.Timeout(err) {
			code = domain.DNSTimeout
		}
		return m.Fail(code, transportMessage(err, code), nil)
	}
	res := &InspectResult{RCode: mdns.RcodeToString[resp.Rcode], Answers: []string{}, CNAMEs: []string{}}
	if resp.Rcode == mdns.RcodeServerFailure {
		if cd, err := ask(true); err == nil && cd.Rcode == mdns.RcodeSuccess && len(cd.Answer) > 0 {
			res.ValidationFailure = true
			resp = cd
		}
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *mdns.A:
			res.Answers = append(res.Answers, v.A.String())
		case *mdns.CNAME:
			res.CNAMEs = append(res.CNAMEs, strings.TrimSuffix(v.Target, "."))
		case *mdns.RRSIG:
			res.Signed = true
		}
	}
	res.Authenticated = resp.AuthenticatedData && !res.ValidationFailure
	return m.Succeed(res)
}
