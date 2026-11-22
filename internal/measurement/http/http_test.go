package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func get(t *testing.T, rawURL string, opts Options, d time.Duration) *domain.Measurement {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return Get(ctx, u, opts)
}

func TestSuccess(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/ok", Options{}, 3*time.Second)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%v", m.Error)
	}
	res := m.Result.(*Result)
	if res.StatusCode != 200 || res.BodyBytes != 5 || res.Headers["server"] != "nw-fixture" || res.Method != "GET" {
		t.Fatalf("%+v", res)
	}
	if res.Timings.ConnectMS == nil || res.Timings.TTFBMS == nil || res.Timings.TLSMS != nil || res.Timings.TotalMS <= 0 {
		t.Fatalf("timings %+v", res.Timings)
	}
	if len(res.Hops) != 1 || res.FinalURL != srv.URL+"/ok" {
		t.Fatalf("hops %+v", res.Hops)
	}
}

func TestNeverRecordsCookiesOrBodies(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/ok", Options{}, 3*time.Second)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Result.(*Result).Headers["set-cookie"]; ok {
		t.Fatal("Set-Cookie was recorded")
	}
	for _, leak := range []string{"secret", "hello"} {
		if strings.Contains(strings.ToLower(string(b)), leak) {
			t.Fatalf("the report leaks %q: %s", leak, b)
		}
	}
	if len(m.Redacted) == 0 {
		t.Fatal("redaction metadata missing")
	}
}

func TestRedirectChain(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/chain", Options{}, 3*time.Second)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%v", m.Error)
	}
	res := m.Result.(*Result)
	if len(res.Hops) != 3 || res.Hops[0].StatusCode != 302 || res.Hops[0].Location != srv.URL+"/redirect" || res.StatusCode != 200 {
		t.Fatalf("%+v", res.Hops)
	}
}

func TestRedirectLoop(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/loop-a", Options{}, 3*time.Second)
	if m.Error == nil || m.Error.Code != domain.HTTPRedirectLoop {
		t.Fatalf("got %v", m.Error)
	}
	if res := m.Result.(*Result); len(res.Hops) != 2 {
		t.Fatalf("the evidence must show the hops: %+v", res.Hops)
	}
}

func TestTooManyRedirects(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/endless/0", Options{MaxRedirects: 3}, 3*time.Second)
	if m.Error == nil || m.Error.Code != domain.HTTPRedirectLoop || !strings.Contains(m.Error.Message, "3 redirects") {
		t.Fatalf("got %v", m.Error)
	}
}

func TestRedirectToUnsupportedScheme(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/ftp", Options{}, 3*time.Second)
	if m.Error == nil || m.Error.Code != domain.HTTPProtocolError {
		t.Fatalf("got %v", m.Error)
	}
}

func TestErrorStatusIsStillAResponse(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/status/503", Options{}, 3*time.Second)
	if m.Status != domain.StatusSuccess || m.Result.(*Result).StatusCode != 503 {
		t.Fatalf("%+v", m)
	}
}

func TestBodyIsBounded(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/big", Options{}, 5*time.Second)
	res := m.Result.(*Result)
	if m.Status != domain.StatusSuccess || !res.BodyTruncated || res.BodyBytes != MaxBody {
		t.Fatalf("%+v %v", res, m.Error)
	}
}

func TestHead(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/ok", Options{Method: "HEAD"}, 3*time.Second)
	res := m.Result.(*Result)
	if m.Status != domain.StatusSuccess || res.Method != "HEAD" || res.BodyBytes != 0 {
		t.Fatalf("%+v %v", res, m.Error)
	}
}

func TestSlowResponseTimesOut(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/slow", Options{}, 300*time.Millisecond)
	if m.Error == nil || m.Error.Code != domain.HTTPTimeout {
		t.Fatalf("got %v", m.Error)
	}
}

func TestRefused(t *testing.T) {
	m := get(t, "http://"+fixtures.ClosedPort(t)+"/", Options{}, 10*time.Second)
	if m.Error == nil || m.Error.Code != domain.TCPRefused {
		t.Fatalf("got %v", m.Error)
	}
}

func TestMuteServerTimesOutInHTTP(t *testing.T) {
	m := get(t, "http://"+fixtures.MuteServer(t)+"/", Options{}, 300*time.Millisecond)
	if m.Error == nil || m.Error.Code != domain.HTTPTimeout {
		t.Fatalf("got %v", m.Error)
	}
}

func TestMuteTLSServerTimesOutInTLS(t *testing.T) {
	m := get(t, "https://"+fixtures.MuteServer(t)+"/", Options{}, 300*time.Millisecond)
	if m.Error == nil || m.Error.Code != domain.TLSTimeout {
		t.Fatalf("got %v", m.Error)
	}
}

func TestNotHTTPServer(t *testing.T) {
	addr := fixtures.RawServer(t, []byte("\x00\x01garbage\r\n\r\n"))
	m := get(t, "http://"+addr+"/", Options{}, 2*time.Second)
	if m.Error == nil || m.Error.Code != domain.HTTPProtocolError {
		t.Fatalf("got %v", m.Error)
	}
}

func TestHTTPSWithTimingsAndALPN(t *testing.T) {
	pki := fixtures.NewPKI(t)
	cert := pki.Valid("127.0.0.1")
	srv := fixtures.HTTPServer(t, &cert)
	m := get(t, srv.URL+"/ok", Options{RootCAs: pki.Pool}, 3*time.Second)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%v", m.Error)
	}
	res := m.Result.(*Result)
	if res.Timings.TLSMS == nil || res.Protocol != "HTTP/2.0" {
		t.Fatalf("%+v", res)
	}
}

func TestCertificateErrorsAreTLSErrors(t *testing.T) {
	pki := fixtures.NewPKI(t)
	cases := map[domain.ErrorCode]tls.Certificate{
		domain.TLSCertExpired:      pki.Expired("127.0.0.1"),
		domain.TLSHostnameMismatch: pki.Valid("other.test"),
		domain.TLSCertUntrusted:    fixtures.SelfSigned(t, "127.0.0.1"),
	}
	for code, cert := range cases {
		cert := cert
		srv := fixtures.HTTPServer(t, &cert)
		m := get(t, srv.URL+"/ok", Options{RootCAs: pki.Pool}, 3*time.Second)
		if m.Error == nil || m.Error.Code != code {
			t.Errorf("want %s, got %v", code, m.Error)
		}
	}
}

func TestCancellation(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	u, _ := url.Parse(srv.URL + "/slow")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	m := Get(ctx, u, Options{})
	if time.Since(start) > 2*time.Second || m.Status != domain.StatusFailure {
		t.Fatalf("cancellation not honored: %v %s", time.Since(start), m.Status)
	}
}

func TestUsesThePluggedDialer(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	called := false
	opts := Options{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		called = true
		return dialLoop(ctx, network, srv)
	}}
	m := get(t, "http://example.test/ok", opts, 3*time.Second)
	if m.Status != domain.StatusSuccess || !called {
		t.Fatalf("called=%v %v", called, m.Error)
	}
}

func dialLoop(ctx context.Context, network string, srv *httptest.Server) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, srv.Listener.Addr().String())
}

func TestNoRedirectReturnsTheFirstResponse(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/chain", Options{NoRedirect: true}, 3*time.Second)
	res := m.Result.(*Result)
	if m.Status != domain.StatusSuccess || res.StatusCode != 302 || len(res.Hops) != 1 {
		t.Fatalf("%+v %v", res, m.Error)
	}
}

func TestMaxBodyOptionBoundsTheRead(t *testing.T) {
	srv := fixtures.HTTPServer(t, nil)
	m := get(t, srv.URL+"/big", Options{MaxBody: 1000}, 5*time.Second)
	res := m.Result.(*Result)
	if m.Status != domain.StatusSuccess || !res.BodyTruncated || res.BodyBytes != 1000 {
		t.Fatalf("%+v %v", res, m.Error)
	}
}
