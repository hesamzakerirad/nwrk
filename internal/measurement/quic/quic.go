// Package quic probes HTTP/3, which runs over QUIC on UDP. It makes one
// small request to one address and records whether a response came back.
//
// The probe is a companion to the HTTP measurement, which uses TCP. A
// network can treat the two differently, for example by dropping UDP.
package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/radestsam/nwrk/internal/buildinfo"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/errclass"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
)

// Version is the implementation version recorded in the measurement.
const Version = "1"

// Options tune the probe.
type Options struct {
	// RootCAs replaces the system trust store; for tests only.
	RootCAs *x509.CertPool
}

// Probe requests u over HTTP/3 from addr. The request is a HEAD request,
// redirects are not followed, and no body is read. The result has the same
// form as an HTTP measurement, so one status code is comparable with the
// other.
func Probe(ctx context.Context, u *url.URL, addr netip.Addr, o Options) *domain.Measurement {
	m := domain.Begin(domain.TypeHTTP, Version, domain.Target{Host: u.Hostname(), URL: u.String(), IP: addr.String(), Family: family(addr)})
	m.Params = map[string]any{"probe": domain.ProbeHTTP3, "method": http.MethodHead}
	if u.Scheme != "https" {
		return m.Skip("HTTP/3 needs an https URL")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if p, err := strconv.Atoi(port); err == nil {
		m.Target.Port = p
	}
	host := u.Hostname()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: o.RootCAs, ServerName: host},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quicgo.Config) (*quicgo.Conn, error) {
			return quicgo.DialAddr(ctx, net.JoinHostPort(addr.String(), port), tlsCfg, cfg)
		},
	}
	defer tr.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return m.Fail(domain.HTTPProtocolError, err.Error(), nil)
	}
	req.Header.Set("User-Agent", "nw/"+buildinfo.Get().Version)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		code, msg := classify(err)
		return m.Fail(code, msg, nil)
	}
	defer resp.Body.Close()
	res := &mhttp.Result{
		Method: http.MethodHead, FinalURL: u.String(), StatusCode: resp.StatusCode,
		Protocol: resp.Proto, Hops: []mhttp.Hop{{URL: u.String(), StatusCode: resp.StatusCode}},
		Headers: map[string]string{},
	}
	return m.Succeed(res)
}

func family(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}

func classify(err error) (domain.ErrorCode, string) {
	var idle *quicgo.IdleTimeoutError
	var hs *quicgo.HandshakeTimeoutError
	var reset *quicgo.StatelessResetError
	switch {
	case errors.As(err, &hs), errors.As(err, &idle), errclass.Timeout(err):
		return domain.HTTPTimeout, "no HTTP/3 response before the deadline"
	case errors.As(err, &reset):
		return domain.HTTPReset, "the QUIC connection was reset"
	case errclass.IsCertificate(err):
		return errclass.TLS(err), "TLS certificate verification failed: " + err.Error()
	case strings.Contains(err.Error(), "failed to verify certificate"):
		// quic-go reports the failure as text from the TLS alert, so the
		// certificate error type is lost. Read the reason from the text.
		msg := err.Error()
		code := domain.TLSCertUntrusted
		switch {
		case strings.Contains(msg, "expired"):
			code = domain.TLSCertExpired
		case strings.Contains(msg, "valid for"):
			code = domain.TLSHostnameMismatch
		}
		return code, "TLS certificate verification failed: " + msg
	}
	return domain.HTTPProtocolError, "the HTTP/3 exchange failed: " + err.Error()
}
