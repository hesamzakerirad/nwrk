// Package tls measures a TLS handshake with certificate verification on.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/measurement/errclass"
	"github.com/hesamzakerirad/nwrk/internal/measurement/tcp"
)

// Version is the implementation version recorded in every measurement.
const Version = "1"

// Certificate is the part of a certificate that matters for diagnosis.
type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SANs      []string  `json:"sans"`
	IsCA      bool      `json:"is_ca"`
}

// Chain is the outcome of verifying the certificate chain.
type Chain struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// Result is the structured result of a TLS measurement. On a certificate
// failure it still carries the certificates, as evidence.
type Result struct {
	ServerName   string        `json:"server_name"`
	Version      string        `json:"version,omitempty"`
	CipherSuite  string        `json:"cipher_suite,omitempty"`
	ALPN         string        `json:"alpn,omitempty"`
	HandshakeMS  float64       `json:"handshake_ms"`
	Chain        Chain         `json:"chain"`
	Certificates []Certificate `json:"certificates"`
}

// Details describes the result in plain lines for the human report.
func (r *Result) Details() []string {
	var out []string
	if r.Version != "" {
		line := r.Version + " " + r.CipherSuite
		if r.ALPN != "" {
			line += ", ALPN " + r.ALPN
		}
		out = append(out, line)
	}
	if r.Chain.Verified {
		out = append(out, "certificate chain verified")
	} else if r.Chain.Error != "" {
		out = append(out, "certificate chain not verified: "+r.Chain.Error)
	}
	if len(r.Certificates) > 0 {
		c := r.Certificates[0]
		out = append(out,
			"subject "+c.Subject,
			"issuer  "+c.Issuer,
			fmt.Sprintf("valid   %s to %s", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02")),
		)
		if len(c.SANs) > 0 {
			out = append(out, "names   "+strings.Join(c.SANs, ", "))
		}
	}
	return out
}

// Options tune a handshake. The zero value is the normal, strict check.
type Options struct {
	// RootCAs replaces the system trust store. Tests use it; the command
	// line does not expose it, so verification cannot be weakened there.
	RootCAs *x509.CertPool
	// NextProtos is the ALPN list offered. Empty means none.
	NextProtos []string
	// Dialer opens the TCP connection. Nil means a default dialer.
	Dialer tcp.Dialer
}

// Handshake connects to addr, performs a TLS handshake that verifies the
// certificate chain and the name serverName, and closes the connection.
func Handshake(ctx context.Context, serverName string, addr netip.AddrPort, opts Options) *domain.Measurement {
	ip := addr.Addr().Unmap()
	m := domain.Begin(domain.TypeTLS, Version, domain.Target{
		Host: serverName, IP: ip.String(), Port: int(addr.Port()), Family: tcp.Family(ip),
	})
	m.Params = map[string]any{"server_name": serverName, "alpn": opts.NextProtos}
	res := &Result{ServerName: serverName, Certificates: []Certificate{}}

	var d tcp.Dialer = &net.Dialer{}
	if opts.Dialer != nil {
		d = opts.Dialer
	}
	address := netip.AddrPortFrom(ip, addr.Port()).String()
	start := time.Now()
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		code := errclass.TCP(err)
		return m.Fail(code, "TCP connection to "+address+" failed before the handshake: "+err.Error(), nil)
	}
	defer raw.Close()

	cfg := &tls.Config{
		ServerName: serverName,
		NextProtos: opts.NextProtos,
		MinVersion: tls.VersionTLS10,
		// Verification is done in VerifyConnection, so the certificates can
		// be kept as evidence even when it fails. It is never skipped: the
		// callback below returns an error whenever the chain is not valid.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			res.Certificates = describe(cs.PeerCertificates)
			err := verify(cs, serverName, opts.RootCAs)
			res.Chain = Chain{Verified: err == nil}
			if err != nil {
				res.Chain.Error = err.Error()
			}
			return err
		},
	}
	conn := tls.Client(raw, cfg)
	// Closing the connection is the only way to interrupt a blocked handshake
	// when the context is canceled without a deadline.
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	err = conn.HandshakeContext(ctx)
	res.HandshakeMS = domain.Millis(time.Since(start))
	if err != nil {
		if ctx.Err() != nil && !errclass.IsCertificate(err) {
			err = ctx.Err()
		}
		code := errclass.TLS(err)
		if code == domain.TLSError && res.Chain.Error != "" {
			// Some platform verifiers (macOS, Windows) return their own error
			// types; a failed verification is still an untrusted chain.
			code = domain.TLSCertUntrusted
		}
		return m.Fail(code, failureMessage(code, serverName, err), res)
	}
	cs := conn.ConnectionState()
	res.Version = tls.VersionName(cs.Version)
	res.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
	res.ALPN = cs.NegotiatedProtocol
	return m.Succeed(res)
}

func verify(cs tls.ConnectionState, serverName string, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("the server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

func describe(certs []*x509.Certificate) []Certificate {
	out := make([]Certificate, 0, len(certs))
	for _, c := range certs {
		sans := []string{}
		sans = append(sans, c.DNSNames...)
		for _, ip := range c.IPAddresses {
			sans = append(sans, ip.String())
		}
		out = append(out, Certificate{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore.UTC(),
			NotAfter:  c.NotAfter.UTC(),
			SANs:      sans,
			IsCA:      c.IsCA,
		})
	}
	return out
}

func failureMessage(code domain.ErrorCode, name string, err error) string {
	switch code {
	case domain.TLSCertExpired:
		return "the certificate is expired or not yet valid"
	case domain.TLSCertUntrusted:
		return "the certificate chain is not trusted: " + err.Error()
	case domain.TLSHostnameMismatch:
		return "the certificate does not match the name " + name
	case domain.TLSTimeout:
		return "the handshake did not finish before the deadline"
	case domain.TLSReset:
		return "the connection was reset during the handshake"
	}
	return "the TLS handshake failed: " + err.Error()
}
