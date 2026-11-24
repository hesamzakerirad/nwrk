package test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/internal/target"
	"github.com/radestsam/nwrk/schema"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// fixture builds options whose chosen resolver is a local DNS server that
// maps example.test to 127.0.0.1, and whose "system" resolver is a fake
// that answers with the same names, so nothing leaves the machine.
func fixture(t *testing.T) (Options, *fixtures.DNSServer) {
	t.Helper()
	srv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{
		"example.test": {A: []string{"127.0.0.1"}},
		"gone.test":    {Behavior: fixtures.DNSNXDomain},
	})
	r, err := target.ParseResolver(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Timeout:     2 * time.Second,
		Resolvers:   []target.Resolver{r},
		ToolVersion: "test",
		SystemDNS: func(ctx context.Context, name string) *domain.Measurement {
			m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
			m.Resolver = &domain.ResolverInfo{Kind: "system"}
			if name == "example.test" {
				return m.Succeed(fakeResult("127.0.0.1"))
			}
			return m.Fail(domain.DNSNoAnswer, "no records", nil)
		},
	}, srv
}

func validate(t *testing.T, rep *domain.Report) {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		t.Fatalf("report does not match schema v1: %v\n%s", err, b)
	}
}

func TestDNSMeasuresSystemFirstThenChosen(t *testing.T) {
	o, _ := fixture(t)
	rep := DNS(context.Background(), "example.test", o)
	validate(t, rep)
	if len(rep.Measurements) != 2 || rep.Measurements[0].Resolver.Kind != "system" || rep.Measurements[1].Resolver.Kind != "udp" {
		t.Fatalf("%+v", rep.Measurements)
	}
	if rep.Measurements[0].ID != "m-001" || rep.Measurements[1].ID != "m-002" || rep.HasFailure() {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestDNSFailureIsReported(t *testing.T) {
	o, _ := fixture(t)
	rep := DNS(context.Background(), "gone.test", o)
	validate(t, rep)
	if !rep.HasFailure() || rep.Measurements[1].Error.Code != domain.DNSNXDomain {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestDNSOfAnIPIsSkipped(t *testing.T) {
	o, _ := fixture(t)
	rep := DNS(context.Background(), "192.0.2.1", o)
	validate(t, rep)
	if rep.Measurements[0].Status != domain.StatusSkipped || rep.HasFailure() {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestTCPUsesTheChosenResolver(t *testing.T) {
	o, _ := fixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	rep := TCP(context.Background(), "example.test", port, o)
	validate(t, rep)
	last := rep.Measurements[len(rep.Measurements)-1]
	if rep.HasFailure() || last.Type != domain.TypeTCP || last.Target.Host != "example.test" || last.Target.IP != "127.0.0.1" {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestTCPToIPLiteralNeedsNoDNS(t *testing.T) {
	o, _ := fixture(t)
	o.Timeout = 10 * time.Second // Windows is slow to report a refused loopback connection
	rep := TCP(context.Background(), "127.0.0.1", mustPort(t, fixtures.ClosedPort(t)), o)
	validate(t, rep)
	if len(rep.Measurements) != 1 || rep.Measurements[0].Error.Code != domain.TCPRefused {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestDependentMeasurementsAreSkippedWhenDNSFails(t *testing.T) {
	o, _ := fixture(t)
	u, _ := url.Parse("http://gone.test/")
	for name, rep := range map[string]*domain.Report{
		"tcp":  TCP(context.Background(), "gone.test", 80, o),
		"tls":  TLS(context.Background(), "gone.test", 443, o),
		"http": HTTP(context.Background(), u, "GET", 10, o),
	} {
		validate(t, rep)
		last := rep.Measurements[len(rep.Measurements)-1]
		if last.Status != domain.StatusSkipped || last.Note == "" {
			t.Errorf("%s: %+v", name, last)
		}
	}
}

func TestTLS(t *testing.T) {
	o, _ := fixture(t)
	pki := fixtures.NewPKI(t)
	o.RootCAs = pki.Pool
	good := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Valid("example.test")}})
	rep := TLS(context.Background(), "example.test", mustPort(t, good), o)
	validate(t, rep)
	if rep.HasFailure() || rep.Measurements[len(rep.Measurements)-1].Type != domain.TypeTLS {
		t.Fatalf("%+v", rep.Measurements)
	}

	bad := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Expired("example.test")}})
	rep = TLS(context.Background(), "example.test", mustPort(t, bad), o)
	validate(t, rep)
	if got := rep.Measurements[len(rep.Measurements)-1].Error; got == nil || got.Code != domain.TLSCertExpired {
		t.Fatalf("%v", got)
	}
}

func TestHTTPFollowsTheChosenResolver(t *testing.T) {
	o, _ := fixture(t)
	srv := fixtures.HTTPServer(t, nil)
	port := mustPort(t, srv.Listener.Addr().String())
	// The system fake knows the name too, but only the chosen resolver may
	// be used to connect, including after the redirect.
	u, _ := url.Parse(fmt.Sprintf("http://example.test:%d/chain", port))
	rep := HTTP(context.Background(), u, "GET", 10, o)
	validate(t, rep)
	m := rep.Measurements[len(rep.Measurements)-1]
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%+v %v", m, m.Error)
	}
}

func TestHTTPFailureValidates(t *testing.T) {
	o, _ := fixture(t)
	srv := fixtures.HTTPServer(t, nil)
	u, _ := url.Parse(srv.URL + "/loop-a")
	rep := HTTP(context.Background(), u, "GET", 10, o)
	validate(t, rep)
	if !rep.HasFailure() {
		t.Fatal("a redirect loop must be a failure")
	}
}

func TestCancellationStopsARun(t *testing.T) {
	o, _ := fixture(t)
	o.Timeout = 30 * time.Second
	addr := fixtures.MuteServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	rep := TLS(ctx, "127.0.0.1", mustPort(t, addr), o)
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancellation was not honored")
	}
	if ctx.Err() == nil || rep == nil {
		t.Fatal("expected a canceled context")
	}
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
