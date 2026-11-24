package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/schema"
)

// offline keeps the system resolver and trust store out of the test.
func offline(t *testing.T) *fixtures.PKI {
	t.Helper()
	pki := fixtures.NewPKI(t)
	seams.rootCAs = pki.Pool
	seams.systemDNS = func(_ context.Context, name string) *domain.Measurement {
		return domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name}).
			Fail(domain.DNSNoAnswer, "offline test", nil)
	}
	t.Cleanup(func() { seams.rootCAs, seams.systemDNS = nil, nil })
	return pki
}

func jsonReport(t *testing.T, out string) domain.Report {
	t.Helper()
	if err := schema.ValidateReport([]byte(out)); err != nil {
		t.Fatalf("output does not match schema v1: %v\n%s", err, out)
	}
	var rep domain.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestTestTCPJSON(t *testing.T) {
	offline(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	code, out, errOut := run(t, "test", "tcp", ln.Addr().String(), "-o", "json")
	if code != exit.OK || errOut != "" {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	rep := jsonReport(t, out)
	if rep.Run.Command != "test tcp" || len(rep.Measurements) != 1 || rep.Measurements[0].Status != domain.StatusSuccess {
		t.Fatalf("%+v", rep)
	}
}

func TestFailingMeasurementExitsOneAndPrintsNoError(t *testing.T) {
	offline(t)
	code, out, errOut := run(t, "test", "tcp", fixtures.ClosedPort(t), "-o", "json")
	if code != exit.Findings || errOut != "" {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	if rep := jsonReport(t, out); rep.Measurements[0].Error.Code != domain.TCPRefused {
		t.Fatalf("%+v", rep.Measurements[0])
	}
	code, out, errOut = run(t, "test", "tcp", fixtures.ClosedPort(t), "--no-color")
	if code != exit.Findings || errOut != "" || !strings.Contains(out, "FAIL") || !strings.Contains(out, "tcp.refused") {
		t.Fatalf("exit %d out %q stderr %q", code, out, errOut)
	}
}

func TestQuietShowsOnlyProblems(t *testing.T) {
	offline(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	code, out, _ := run(t, "test", "tcp", ln.Addr().String(), "-q")
	if code != exit.OK || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
}

func TestTestTLSJSON(t *testing.T) {
	pki := offline(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Valid("127.0.0.1")}})
	code, out, _ := run(t, "test", "tls", addr, "-o", "json")
	if code != exit.OK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	rep := jsonReport(t, out)
	if rep.Measurements[0].Type != domain.TypeTLS {
		t.Fatalf("%+v", rep.Measurements)
	}
}

func TestTestHTTPJSONAndHuman(t *testing.T) {
	offline(t)
	srv := fixtures.HTTPServer(t, nil)
	code, out, _ := run(t, "test", "http", srv.URL+"/chain", "-o", "json")
	if code != exit.OK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if rep := jsonReport(t, out); len(rep.Measurements[0].Result.(map[string]any)["hops"].([]any)) != 3 {
		t.Fatalf("%s", out)
	}
	code, out, _ = run(t, "test", "http", srv.URL+"/ok")
	if code != exit.OK || !strings.Contains(out, "200 OK") || !strings.Contains(out, "timing (ms)") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestTestDNSWithResolverFlagAndEnv(t *testing.T) {
	offline(t)
	srv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"ok.test": {A: []string{"192.0.2.7"}}})
	code, out, _ := run(t, "test", "dns", "ok.test", "--resolver", srv.Addr, "-o", "json")
	if code != exit.Findings { // the faked system resolver fails, the chosen one succeeds
		t.Fatalf("exit %d", code)
	}
	rep := jsonReport(t, out)
	if len(rep.Measurements) != 2 || rep.Measurements[1].Status != domain.StatusSuccess {
		t.Fatalf("%+v", rep.Measurements)
	}

	t.Setenv("NW_RESOLVERS", srv.Addr)
	_, out, _ = run(t, "test", "dns", "ok.test", "-o", "json")
	if rep := jsonReport(t, out); len(rep.Measurements) != 2 {
		t.Fatal("NW_RESOLVERS was not used")
	}
	other := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"ok.test": {A: []string{"192.0.2.8"}}})
	_, out, _ = run(t, "test", "dns", "ok.test", "--resolver", other.Addr, "-o", "json")
	if !strings.Contains(out, "192.0.2.8") || strings.Contains(out, "192.0.2.7") {
		t.Fatal("the flag must win over the environment")
	}
}

func TestTestUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"no target":          {"test", "dns"},
		"bad host":           {"test", "dns", "exa mple"},
		"tcp needs a port":   {"test", "tcp", "example.com"},
		"bad port":           {"test", "tcp", "example.com:99999"},
		"bad resolver":       {"test", "dns", "example.com", "--resolver", "dns.google"},
		"bad tls resolver":   {"test", "dns", "example.com", "--resolver", "tls://"},
		"bad doh resolver":   {"test", "dns", "example.com", "--resolver", "https://h/q?x=1"},
		"bad url":            {"test", "http", "ftp://example.com"},
		"credentials in url": {"test", "http", "https://user:pw@example.com"},
		"bad method":         {"test", "http", "example.com", "--method", "POST"},
		"bad redirects":      {"test", "http", "example.com", "--max-redirects", "0"},
		"unknown subcommand": {"test", "icmp", "example.com"},
	}
	for name, args := range cases {
		if code, _, errOut := run(t, args...); code != exit.Failure || errOut == "" {
			t.Errorf("%s: exit %d stderr %q", name, code, errOut)
		}
	}
	t.Setenv("NW_RESOLVERS", "nonsense")
	if code, _, errOut := run(t, "test", "dns", "example.com"); code != exit.Failure || !strings.Contains(errOut, "NW_RESOLVERS") {
		t.Errorf("bad NW_RESOLVERS: exit %d stderr %q", code, errOut)
	}
}

func TestInterruptExitsWith130(t *testing.T) {
	offline(t)
	addr := fixtures.MuteServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	var out, errb bytes.Buffer
	start := time.Now()
	code := Execute(ctx, []string{"test", "tls", addr, "--timeout", "30s"}, &out, &errb)
	if code != exit.Interrupted {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, exit.Interrupted, out.String(), errb.String())
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the command did not stop promptly")
	}
	if out.Len() != 0 {
		t.Fatalf("an interrupted run must not print a partial report: %q", out.String())
	}
}

func TestHelpListsTestCommands(t *testing.T) {
	_, out, _ := run(t, "test", "--help")
	for _, sub := range []string{"dns", "tcp", "tls", "http"} {
		if !strings.Contains(out, fmt.Sprintf("  %s ", sub)) {
			t.Errorf("help does not list %q:\n%s", sub, out)
		}
	}
}
