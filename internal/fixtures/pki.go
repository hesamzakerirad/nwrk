package fixtures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// PKI is a throwaway certificate authority.
type PKI struct {
	// Pool trusts the CA. Pass it as the root pool to make Valid certs verify.
	Pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	t    testing.TB
}

// NewPKI creates a CA valid for one day.
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "nw fixture CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &PKI{Pool: pool, cert: cert, key: key, t: t}
}

// Issue returns a server certificate signed by the CA for the given names
// (host names or IP addresses), valid between notBefore and notAfter.
func (p *PKI) Issue(notBefore, notAfter time.Time, names ...string) tls.Certificate {
	p.t.Helper()
	return issue(p.t, p.cert, p.key, notBefore, notAfter, names)
}

// Valid returns a currently valid certificate for names.
func (p *PKI) Valid(names ...string) tls.Certificate {
	return p.Issue(time.Now().Add(-time.Hour), time.Now().Add(time.Hour), names...)
}

// Expired returns a certificate that expired an hour ago.
func (p *PKI) Expired(names ...string) tls.Certificate {
	return p.Issue(time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), names...)
}

// SelfSigned returns a valid certificate signed by no known authority.
func SelfSigned(t testing.TB, names ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := leafTemplate(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), names)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func issue(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, nb, na time.Time, names []string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate(t, nb, na, names), ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func leafTemplate(t testing.TB, nb, na time.Time, names []string) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"nw fixtures"}},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return tmpl
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TLSServer listens on 127.0.0.1 and completes TLS handshakes with cfg,
// then closes the connection. It returns its address.
func TLSServer(t testing.TB, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String()
}

// SNIBehavior says what SNIServer does when a client asks for the blocked
// server name.
type SNIBehavior int

const (
	// SNIReset closes the connection with a TCP reset.
	SNIReset SNIBehavior = iota
	// SNISilent leaves the handshake unanswered until the client gives up.
	SNISilent
)

// SNIServer is a TLS server that behaves normally, except that a client
// asking for blockedSNI gets the given behavior. Other names get cert.
func SNIServer(t testing.TB, cert tls.Certificate, blockedSNI string, b SNIBehavior) string {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if h.ServerName != blockedSNI {
				return nil, nil
			}
			switch b {
			case SNIReset:
				if tc, ok := h.Conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = h.Conn.Close()
			case SNISilent:
				// Wait until the client gives up and closes the connection.
				_, _ = io.Copy(io.Discard, h.Conn)
			}
			return nil, errBlocked
		},
	}
	return TLSServer(t, cfg)
}

var errBlocked = errors.New("blocked server name")

// LegacyTLSServer accepts every protocol version from TLS 1.0 up.
func LegacyTLSServer(t testing.TB, cert tls.Certificate) string {
	t.Helper()
	return TLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
}

// ModernTLSServer accepts only TLS 1.2 and later.
func ModernTLSServer(t testing.TB, cert tls.Certificate) string {
	t.Helper()
	return TLSServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
}
