// Package http measures one HTTP or HTTPS request, with timings for each
// stage and a bounded redirect chain.
package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/radestsam/nwrk/internal/buildinfo"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/errclass"
)

// Version is the implementation version recorded in every measurement.
const Version = "1"

const (
	// DefaultMaxRedirects bounds how many redirects are followed.
	DefaultMaxRedirects = 10
	// MaxBody bounds how much of a response body is read. The body is
	// counted and discarded, never stored.
	MaxBody = 1 << 20
)

// SelectedHeaders are the only response headers recorded. Cookies and
// anything that could carry credentials are deliberately not among them.
var SelectedHeaders = []string{
	"Server", "Content-Type", "Content-Length", "Content-Encoding", "Cache-Control",
	"Via", "Alt-Svc", "Strict-Transport-Security", "Retry-After", "Date",
}

// Timings are the stages of one request, in milliseconds. A stage that did
// not happen, such as TLS on plain HTTP, is omitted.
type Timings struct {
	DNSMS     *float64 `json:"dns_ms,omitempty"`
	ConnectMS *float64 `json:"connect_ms,omitempty"`
	TLSMS     *float64 `json:"tls_ms,omitempty"`
	TTFBMS    *float64 `json:"ttfb_ms,omitempty"`
	TotalMS   float64  `json:"total_ms"`
}

// Hop is one request in the chain, the last one being the response kept.
type Hop struct {
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Location   string  `json:"location,omitempty"`
	Timings    Timings `json:"timings"`

	started time.Time
}

// Result is the structured result of an HTTP measurement.
type Result struct {
	Method        string            `json:"method"`
	FinalURL      string            `json:"final_url"`
	StatusCode    int               `json:"status_code"`
	Protocol      string            `json:"protocol"`
	Hops          []Hop             `json:"hops"`
	Headers       map[string]string `json:"headers"`
	BodyBytes     int64             `json:"body_bytes"`
	BodyTruncated bool              `json:"body_truncated"`
	Timings       Timings           `json:"timings"`
}

// Details describes the result in plain lines for the human report.
func (r *Result) Details() []string {
	out := []string{fmt.Sprintf("%d %s (%s)", r.StatusCode, http.StatusText(r.StatusCode), r.Protocol)}
	for _, h := range r.Hops[:len(r.Hops)-1] {
		out = append(out, fmt.Sprintf("redirect %d from %s to %s", h.StatusCode, h.URL, h.Location))
	}
	if len(r.Hops) > 1 {
		out = append(out, "final URL "+r.FinalURL)
	}
	out = append(out, timingLine(r.Timings))
	return out
}

func timingLine(t Timings) string {
	var parts []string
	add := func(name string, v *float64) {
		if v != nil {
			parts = append(parts, fmt.Sprintf("%s %.1f", name, *v))
		}
	}
	add("dns", t.DNSMS)
	add("connect", t.ConnectMS)
	add("tls", t.TLSMS)
	add("first byte", t.TTFBMS)
	parts = append(parts, fmt.Sprintf("total %.1f", t.TotalMS))
	return "timing (ms): " + strings.Join(parts, ", ")
}

// Options tune a request. The zero value is a conservative GET.
type Options struct {
	// Method is GET (the default) or HEAD.
	Method string
	// MaxRedirects bounds the redirects followed; zero means the default.
	MaxRedirects int
	// NoRedirect returns the first response and follows no redirect. The
	// status code is then the one of the first response.
	NoRedirect bool
	// MaxBody bounds how many body bytes are read; zero means MaxBody.
	MaxBody int64
	// DialContext opens connections. Nil means a default dialer.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAs replaces the system trust store. Tests use it.
	RootCAs *x509.CertPool
}

// Get requests u and follows redirects. ctx carries the deadline for the
// whole chain.
func Get(ctx context.Context, u *url.URL, opts Options) *domain.Measurement {
	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	maxBody := opts.MaxBody
	if maxBody <= 0 {
		maxBody = MaxBody
	}
	m := domain.Begin(domain.TypeHTTP, Version, domain.Target{Host: u.Hostname(), URL: u.String()})
	m.Params = map[string]any{"method": method, "max_redirects": maxRedirects, "max_body_bytes": maxBody, "no_redirect": opts.NoRedirect}
	m.Redacted = []string{"request.cookies", "request.authorization", "response.set-cookie", "response.body"}

	res := &Result{Method: method, Hops: []Hop{}, Headers: map[string]string{}}
	visited := map[string]bool{}
	cur := u
	for {
		key := cur.String()
		if visited[key] {
			return m.Fail(domain.HTTPRedirectLoop, "redirect loop: "+key+" was requested twice", partial(res))
		}
		visited[key] = true

		hop, resp, code, err := do(ctx, cur, method, opts)
		if err != nil {
			return m.Fail(code, err.Error(), partial(res))
		}
		res.Hops = append(res.Hops, *hop)

		var loc *redirect
		if !opts.NoRedirect {
			loc = redirectTarget(resp, cur)
		}
		if loc == nil {
			finalize(res, hop, resp, cur)
			if err := drain(ctx, resp, res, maxBody); err != nil {
				return m.Fail(readCode(err), "reading the response body failed: "+err.Error(), res)
			}
			resp.Body.Close()
			// The final hop's total covers the body transfer too.
			total := domain.Millis(time.Since(hop.started))
			res.Timings.TotalMS = total
			res.Hops[len(res.Hops)-1].Timings.TotalMS = total
			return m.Succeed(res)
		}
		resp.Body.Close()
		if loc.err != nil {
			return m.Fail(domain.HTTPProtocolError, loc.err.Error(), partial(res))
		}
		hop.Location = loc.url.String()
		res.Hops[len(res.Hops)-1] = *hop
		if len(res.Hops) > maxRedirects {
			return m.Fail(domain.HTTPRedirectLoop, fmt.Sprintf("more than %d redirects", maxRedirects), partial(res))
		}
		cur = loc.url
	}
}

func partial(res *Result) any {
	if len(res.Hops) == 0 {
		return nil
	}
	return res
}

type redirect struct {
	url *url.URL
	err error
}

// redirectTarget returns where resp sends the client, or nil when it is not
// a redirect.
func redirectTarget(resp *http.Response, from *url.URL) *redirect {
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
	default:
		return nil
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	next, err := from.Parse(loc)
	if err != nil {
		return &redirect{err: fmt.Errorf("invalid Location header %q", loc)}
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return &redirect{err: fmt.Errorf("redirect to unsupported scheme %q", next.Scheme)}
	}
	if next.User != nil {
		return &redirect{err: errors.New("redirect target carries credentials")}
	}
	next.Fragment = ""
	return &redirect{url: next}
}

// recorder collects httptrace events. Callbacks can run concurrently, for
// example when several addresses are tried at once.
type recorder struct {
	mu                  sync.Mutex
	start               time.Time
	dnsStart, dnsDone   time.Time
	connStart, connDone time.Time
	tlsStart, tlsDone   time.Time
	firstByte           time.Time
}

func (r *recorder) trace() *httptrace.ClientTrace {
	at := func(dst *time.Time, keepFirst bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if keepFirst && !dst.IsZero() {
			return
		}
		*dst = time.Now()
	}
	return &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { at(&r.dnsStart, true) },
		DNSDone:      func(httptrace.DNSDoneInfo) { at(&r.dnsDone, false) },
		ConnectStart: func(_, _ string) { at(&r.connStart, true) },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				at(&r.connDone, false)
			}
		},
		TLSHandshakeStart:    func() { at(&r.tlsStart, true) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { at(&r.tlsDone, false) },
		GotFirstResponseByte: func() { at(&r.firstByte, true) },
	}
}

func (r *recorder) timings(total time.Duration) Timings {
	r.mu.Lock()
	defer r.mu.Unlock()
	span := func(a, b time.Time) *float64 {
		if a.IsZero() || b.IsZero() || b.Before(a) {
			return nil
		}
		v := domain.Millis(b.Sub(a))
		return &v
	}
	return Timings{
		DNSMS:     span(r.dnsStart, r.dnsDone),
		ConnectMS: span(r.connStart, r.connDone),
		TLSMS:     span(r.tlsStart, r.tlsDone),
		TTFBMS:    span(r.start, r.firstByte),
		TotalMS:   domain.Millis(total),
	}
}

// stalledIn names the stage a request was in when it timed out.
func (r *recorder) stalledIn() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case !r.dnsStart.IsZero() && r.dnsDone.IsZero():
		return "dns"
	case !r.connStart.IsZero() && r.connDone.IsZero():
		return "connect"
	case !r.tlsStart.IsZero() && r.tlsDone.IsZero():
		return "tls"
	}
	return "http"
}

// do performs one request without following redirects.
func do(ctx context.Context, u *url.URL, method string, opts Options) (*Hop, *http.Response, domain.ErrorCode, error) {
	rec := &recorder{start: time.Now()}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, rec.trace()), method, u.String(), nil)
	if err != nil {
		return nil, nil, domain.HTTPProtocolError, err
	}
	req.Header.Set("User-Agent", "nw/"+buildinfo.Get().Version)
	req.Header.Set("Accept", "*/*")

	tr := &http.Transport{
		// Measure the direct path: never use proxy settings from the
		// environment, and never reuse a connection from an earlier hop.
		Proxy:             nil,
		DialContext:       opts.DialContext,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: opts.RootCAs},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		code, msg := classify(err, rec)
		return nil, nil, code, errors.New(msg)
	}
	hop := &Hop{URL: u.String(), StatusCode: resp.StatusCode, Timings: rec.timings(time.Since(rec.start)), started: rec.start}
	return hop, resp, "", nil
}

func classify(err error, rec *recorder) (domain.ErrorCode, string) {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	switch {
	case errclass.IsCertificate(err):
		code := errclass.TLS(err)
		return code, "TLS certificate verification failed: " + err.Error()
	case errclass.Timeout(err):
		switch rec.stalledIn() {
		case "dns":
			return domain.DNSTimeout, "name resolution did not finish before the deadline"
		case "connect":
			return domain.TCPTimeout, "the connection was not established before the deadline"
		case "tls":
			return domain.TLSTimeout, "the TLS handshake did not finish before the deadline"
		}
		return domain.HTTPTimeout, "no complete response before the deadline"
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return errclass.DNS(err), "name resolution failed: " + de.Error()
	}
	switch {
	case errclass.Refused(err):
		return domain.TCPRefused, "the connection was refused"
	case errclass.Unreachable(err):
		return domain.TCPUnreachable, "no route to the destination"
	case errclass.Reset(err):
		if rec.stalledIn() == "tls" {
			return domain.TLSReset, "the connection was reset during the TLS handshake"
		}
		return domain.HTTPReset, "the connection was reset"
	}
	if code := errclass.TLS(err); code == domain.TLSHandshakeFailure {
		return code, "the TLS handshake failed: " + err.Error()
	}
	return domain.HTTPProtocolError, "the exchange failed: " + err.Error()
}

func finalize(res *Result, hop *Hop, resp *http.Response, u *url.URL) {
	res.FinalURL = u.String()
	res.StatusCode = resp.StatusCode
	res.Protocol = resp.Proto
	res.Timings = hop.Timings
	for _, name := range SelectedHeaders {
		if v := resp.Header.Values(name); len(v) > 0 {
			res.Headers[strings.ToLower(name)] = strings.Join(v, ", ")
		}
	}
}

// drain reads and discards up to limit bytes, so total time includes the
// body transfer. The body itself is never kept.
func drain(ctx context.Context, resp *http.Response, res *Result, limit int64) error {
	stop := context.AfterFunc(ctx, func() { resp.Body.Close() })
	defer stop()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
	if n > limit {
		n = limit
		res.BodyTruncated = true
	}
	res.BodyBytes = n
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func readCode(err error) domain.ErrorCode {
	if errclass.Timeout(err) {
		return domain.HTTPTimeout
	}
	if errclass.Reset(err) {
		return domain.HTTPReset
	}
	return domain.HTTPProtocolError
}
