package quic

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
)

// h3Server serves HTTP/3 on 127.0.0.1 with a random UDP port and returns
// the URL and the PKI whose CA signed the certificate.
func h3Server(t *testing.T, status int) (*url.URL, *fixtures.PKI) {
	t.Helper()
	pki := fixtures.NewPKI(t)
	cert := pki.Valid("localhost", "127.0.0.1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }),
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close() })
	u, _ := url.Parse("https://localhost:" + portOf(pc.LocalAddr()))
	return u, pki
}

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}

func TestProbeSucceeds(t *testing.T) {
	u, pki := h3Server(t, http.StatusNoContent)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := Probe(ctx, u, netip.MustParseAddr("127.0.0.1"), Options{RootCAs: pki.Pool})
	if m.Status != domain.StatusSuccess {
		t.Fatalf("status %s, error %+v", m.Status, m.Error)
	}
	res := m.Result.(*mhttp.Result)
	if res.StatusCode != 204 || res.Protocol != "HTTP/3.0" {
		t.Errorf("result %+v", res)
	}
	if m.Probe() != domain.ProbeHTTP3 || m.Target.Family != "ipv4" {
		t.Errorf("probe %q family %q", m.Probe(), m.Target.Family)
	}
}

func TestProbeTimesOutWhenNothingAnswers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // listens, never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u, _ := url.Parse("https://localhost:" + portOf(pc.LocalAddr()))
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	m := Probe(ctx, u, netip.MustParseAddr("127.0.0.1"), Options{})
	if m.Status != domain.StatusFailure || m.Error.Code != domain.HTTPTimeout {
		t.Fatalf("status %s, error %+v", m.Status, m.Error)
	}
}

func TestProbeNeedsHTTPS(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	m := Probe(context.Background(), u, netip.MustParseAddr("192.0.2.1"), Options{})
	if m.Status != domain.StatusSkipped {
		t.Fatalf("status %s", m.Status)
	}
}

func TestProbeRejectsUntrustedCertificate(t *testing.T) {
	u, _ := h3Server(t, 200)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := Probe(ctx, u, netip.MustParseAddr("127.0.0.1"), Options{})
	if m.Status != domain.StatusFailure || m.Error.Code != domain.TLSCertUntrusted {
		t.Fatalf("status %s, error %+v", m.Status, m.Error)
	}
}
