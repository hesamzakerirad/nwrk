package errclass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/domain"
)

func TestTCP(t *testing.T) {
	// Socket errors are platform specific: the package's own lists say which
	// numbers this operating system uses.
	op := func(err error) error { return &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", err)} }
	cases := []struct {
		err  error
		want domain.ErrorCode
	}{
		{context.DeadlineExceeded, domain.TCPTimeout},
		{op(os.ErrDeadlineExceeded), domain.TCPTimeout},
		{op(refusedErrnos[0]), domain.TCPRefused},
		{op(unreachableErrnos[0]), domain.TCPUnreachable},
		{op(unreachableErrnos[1]), domain.TCPUnreachable},
		{op(resetErrnos[0]), domain.TCPReset},
		{errors.New("other"), domain.TCPError},
	}
	for _, c := range cases {
		if got := TCP(c.err); got != c.want {
			t.Errorf("TCP(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestTLS(t *testing.T) {
	cases := []struct {
		err  error
		want domain.ErrorCode
	}{
		{x509.HostnameError{Host: "a"}, domain.TLSHostnameMismatch},
		{x509.CertificateInvalidError{Reason: x509.Expired}, domain.TLSCertExpired},
		{x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, domain.TLSCertUntrusted},
		{x509.UnknownAuthorityError{}, domain.TLSCertUntrusted},
		{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, domain.TLSCertUntrusted},
		{fmt.Errorf("wrapped: %w", x509.HostnameError{Host: "a"}), domain.TLSHostnameMismatch},
		{context.DeadlineExceeded, domain.TLSTimeout},
		{tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, domain.TLSHandshakeFailure},
		{io.EOF, domain.TLSHandshakeFailure},
		{errors.New("remote error: tls: handshake failure"), domain.TLSHandshakeFailure},
		{errors.New("unrelated"), domain.TLSError},
	}
	for _, c := range cases {
		if got := TLS(c.err); got != c.want {
			t.Errorf("TLS(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestCertificateErrorsAreDistinguished(t *testing.T) {
	if !IsCertificate(x509.HostnameError{}) || IsCertificate(io.EOF) {
		t.Fatal("IsCertificate must separate verification failures from handshake failures")
	}
}

func TestDNS(t *testing.T) {
	cases := []struct {
		err  error
		want domain.ErrorCode
	}{
		{&net.DNSError{IsNotFound: true}, domain.DNSNXDomain},
		{&net.DNSError{IsTimeout: true}, domain.DNSTimeout},
		{&net.DNSError{Err: "server misbehaving"}, domain.DNSServFail},
		{&net.DNSError{Err: "other"}, domain.DNSTransport},
		{context.DeadlineExceeded, domain.DNSTimeout},
		{errors.New("x"), domain.DNSTransport},
	}
	for _, c := range cases {
		if got := DNS(c.err); got != c.want {
			t.Errorf("DNS(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}
