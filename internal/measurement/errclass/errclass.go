// Package errclass turns Go network errors into the stable error codes of
// the report contract. The classification is shared by every measurement,
// because an HTTP request can fail in DNS, TCP or TLS.
package errclass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/domain"
)

// Timeout reports whether err means a deadline passed.
func Timeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Refused reports an actively refused connection.
func Refused(err error) bool { return isErrno(err, refusedErrnos) }

// Reset reports a connection reset or aborted by the peer or the path.
func Reset(err error) bool { return isErrno(err, resetErrnos) }

// Unreachable reports that no route to the network or host exists.
func Unreachable(err error) bool { return isErrno(err, unreachableErrnos) }

// TCP classifies an error from establishing a TCP connection.
func TCP(err error) domain.ErrorCode {
	switch {
	case Timeout(err):
		return domain.TCPTimeout
	case Refused(err):
		return domain.TCPRefused
	case Unreachable(err):
		return domain.TCPUnreachable
	case Reset(err):
		return domain.TCPReset
	}
	return domain.TCPError
}

// TLS classifies an error from a TLS handshake. Certificate verification
// failures are kept apart from handshake and transport failures, because
// they have different causes and different next steps.
func TLS(err error) domain.ErrorCode {
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.As(err, &hostname):
		return domain.TLSHostnameMismatch
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return domain.TLSCertExpired
		}
		return domain.TLSCertUntrusted
	case errors.As(err, &unknown):
		return domain.TLSCertUntrusted
	case Timeout(err):
		return domain.TLSTimeout
	case Reset(err):
		return domain.TLSReset
	case errors.As(err, &record), errors.As(err, &alert),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return domain.TLSHandshakeFailure
	}
	var ve *tls.CertificateVerificationError
	if errors.As(err, &ve) {
		return domain.TLSCertUntrusted
	}
	// An alert from the peer is reported by crypto/tls as an unexported type.
	if strings.Contains(err.Error(), "remote error: tls:") {
		return domain.TLSHandshakeFailure
	}
	return domain.TLSError
}

// IsCertificate reports whether err is a certificate verification failure.
func IsCertificate(err error) bool {
	switch TLS(err) {
	case domain.TLSCertExpired, domain.TLSCertUntrusted, domain.TLSHostnameMismatch:
		return true
	}
	return false
}

// DNS classifies an error from the operating system's resolver.
func DNS(err error) domain.ErrorCode {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsTimeout:
			return domain.DNSTimeout
		case de.IsNotFound:
			return domain.DNSNXDomain
		case strings.Contains(de.Err, "server misbehaving"):
			return domain.DNSServFail
		}
		return domain.DNSTransport
	}
	if Timeout(err) {
		return domain.DNSTimeout
	}
	return domain.DNSTransport
}
