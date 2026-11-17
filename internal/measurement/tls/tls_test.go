package tls

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func handshake(t *testing.T, name, addr string, opts Options, d time.Duration) *domain.Measurement {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return Handshake(ctx, name, netip.MustParseAddrPort(addr), opts)
}

func TestHandshakeSuccess(t *testing.T) {
	pki := fixtures.NewPKI(t)
	cert := pki.Valid("example.test", "127.0.0.1")
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	m := handshake(t, "example.test", addr, Options{RootCAs: pki.Pool, NextProtos: []string{"h2"}}, 3*time.Second)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%v", m.Error)
	}
	res := m.Result.(*Result)
	if res.Version == "" || res.CipherSuite == "" || res.ALPN != "h2" || !res.Chain.Verified {
		t.Fatalf("%+v", res)
	}
	if len(res.Certificates) != 1 || res.Certificates[0].SANs[0] != "example.test" || res.Certificates[0].Issuer == "" {
		t.Fatalf("certificates %+v", res.Certificates)
	}
}

func TestHandshakeToIPLiteral(t *testing.T) {
	pki := fixtures.NewPKI(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Valid("127.0.0.1")}})
	m := handshake(t, "127.0.0.1", addr, Options{RootCAs: pki.Pool}, 3*time.Second)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%v", m.Error)
	}
}

func TestCertificateFailures(t *testing.T) {
	pki := fixtures.NewPKI(t)
	cases := []struct {
		name string
		cert tls.Certificate
		code domain.ErrorCode
	}{
		{"expired", pki.Expired("example.test"), domain.TLSCertExpired},
		{"self-signed", fixtures.SelfSigned(t, "example.test"), domain.TLSCertUntrusted},
		{"wrong host", pki.Valid("other.test"), domain.TLSHostnameMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{c.cert}})
			m := handshake(t, "example.test", addr, Options{RootCAs: pki.Pool}, 3*time.Second)
			if m.Status != domain.StatusFailure || m.Error == nil || m.Error.Code != c.code {
				t.Fatalf("status %s error %v; want %s", m.Status, m.Error, c.code)
			}
			res := m.Result.(*Result)
			if res.Chain.Verified || res.Chain.Error == "" {
				t.Fatalf("chain %+v", res.Chain)
			}
			if len(res.Certificates) != 1 {
				t.Fatal("a certificate failure must keep the certificate as evidence")
			}
		})
	}
}

func TestVerificationCannotBeSkippedForUntrustedRoot(t *testing.T) {
	// With no RootCAs the system store is used, which does not trust the
	// fixture CA: this proves the check runs on the default path too.
	pki := fixtures.NewPKI(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Valid("example.test")}})
	m := handshake(t, "example.test", addr, Options{}, 3*time.Second)
	if m.Error == nil || m.Error.Code != domain.TLSCertUntrusted {
		t.Fatalf("got %v", m.Error)
	}
}

func TestHandshakeFailureIsNotACertificateError(t *testing.T) {
	// A server that sends an alert instead of a certificate.
	addr := fixtures.TLSServer(t, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, context.Canceled },
	})
	m := handshake(t, "example.test", addr, Options{}, 3*time.Second)
	if m.Error == nil || m.Error.Code != domain.TLSHandshakeFailure {
		t.Fatalf("got %v", m.Error)
	}
}

func TestNotTLSServer(t *testing.T) {
	addr := fixtures.RawServer(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	m := handshake(t, "example.test", addr, Options{}, 3*time.Second)
	// The server closes right after writing, without reading the hello. Most
	// systems deliver the reply first; Windows can deliver a reset instead.
	if m.Error == nil || (m.Error.Code != domain.TLSHandshakeFailure && m.Error.Code != domain.TLSReset) {
		t.Fatalf("got %v", m.Error)
	}
}

func TestServerThatClosesImmediately(t *testing.T) {
	addr := fixtures.RawServer(t, nil)
	m := handshake(t, "example.test", addr, Options{}, 3*time.Second)
	if m.Error == nil || m.Status != domain.StatusFailure {
		t.Fatalf("got %+v", m)
	}
	if m.Error.Code != domain.TLSHandshakeFailure && m.Error.Code != domain.TLSReset {
		t.Fatalf("got %v", m.Error)
	}
}

func TestMuteServerTimesOut(t *testing.T) {
	addr := fixtures.MuteServer(t)
	m := handshake(t, "example.test", addr, Options{}, 300*time.Millisecond)
	if m.Error == nil || m.Error.Code != domain.TLSTimeout {
		t.Fatalf("got %v", m.Error)
	}
}

func TestConnectionRefusedIsATCPError(t *testing.T) {
	m := handshake(t, "example.test", fixtures.ClosedPort(t), Options{}, 10*time.Second)
	if m.Error == nil || m.Error.Code != domain.TCPRefused {
		t.Fatalf("got %v", m.Error)
	}
}

func TestCancellation(t *testing.T) {
	addr := fixtures.MuteServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	m := Handshake(ctx, "example.test", netip.MustParseAddrPort(addr), Options{})
	if time.Since(start) > 2*time.Second || m.Status != domain.StatusFailure {
		t.Fatalf("cancellation not honored: %v %s", time.Since(start), m.Status)
	}
}
