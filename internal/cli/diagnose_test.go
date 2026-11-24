package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/internal/measurement/dns"
)

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// resolveToLoopback makes example.test resolve to 127.0.0.1 without
// touching the host's resolver.
func resolveToLoopback(t *testing.T) *fixtures.PKI {
	t.Helper()
	pki := offline(t)
	seams.systemDNS = func(_ context.Context, name string) *domain.Measurement {
		m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
		m.Resolver = &domain.ResolverInfo{Kind: "system"}
		if name == "example.test" {
			return m.Succeed(&dns.Result{A: []string{"127.0.0.1"}, AAAA: []string{}, Queries: []dns.QueryResult{}})
		}
		return m.Fail(domain.DNSNoAnswer, "no records", &dns.Result{A: []string{}, AAAA: []string{}, Queries: []dns.QueryResult{}})
	}
	return pki
}

// The four exit codes of SPEC 13.3, each through the real command.

func TestDiagnoseExitZeroWhenHealthy(t *testing.T) {
	pki := resolveToLoopback(t)
	cert := pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	code, out, errOut := run(t, "diagnose", "https://example.test:"+portOf(t, srv.Listener.Addr().String())+"/ok", "--no-color")
	if code != exit.OK || errOut != "" {
		t.Fatalf("exit %d stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{"nw diagnose", "Summary", "No actionable findings", "Measurements", "Environment", "Nothing was uploaded"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Findings") {
		t.Errorf("a clean run has no Findings section:\n%s", out)
	}
}

func TestDiagnoseExitOneWhenTheTargetHasAProblem(t *testing.T) {
	pki := resolveToLoopback(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Expired("example.test")}})
	code, out, errOut := run(t, "diagnose", "example.test:"+portOf(t, addr), "--no-color")
	if code != exit.Findings || errOut != "" {
		t.Fatalf("exit %d stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{"Problem found", "TLS_CERTIFICATE_INVALID", "Hypotheses", "possible explanations, not conclusions", "supported by", "not observed", "Next steps", "skip  http"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDiagnoseExitTwoOnUsageErrors(t *testing.T) {
	resolveToLoopback(t)
	for name, args := range map[string][]string{
		"no target":     {"diagnose"},
		"bad target":    {"diagnose", "exa mple"},
		"bad profile":   {"diagnose", "example.test", "--profile", "thorough"},
		"bad resolver":  {"diagnose", "example.test", "--resolver", "dns.google"},
		"two targets":   {"diagnose", "a.test", "b.test"},
		"bad scheme":    {"diagnose", "ftp://example.test"},
		"verbose+quiet": {"diagnose", "example.test", "-v", "-q"},
		"zero timeout":  {"diagnose", "example.test", "--timeout", "0s"},
	} {
		if code, _, errOut := run(t, args...); code != exit.Failure || errOut == "" {
			t.Errorf("%s: exit %d stderr %q", name, code, errOut)
		}
	}
}

func TestDiagnoseExit130WhenInterrupted(t *testing.T) {
	resolveToLoopback(t)
	addr := fixtures.MuteServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	var out, errb bytes.Buffer
	start := time.Now()
	code := Execute(ctx, []string{"diagnose", "example.test:" + portOf(t, addr), "--timeout", "30s"}, &out, &errb)
	if code != exit.Interrupted || out.Len() != 0 || time.Since(start) > 3*time.Second {
		t.Fatalf("exit %d stdout %q after %v", code, out.String(), time.Since(start))
	}
}

func TestDiagnoseJSONMatchesTheSchemaAndExitCode(t *testing.T) {
	pki := resolveToLoopback(t)
	cert := pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	code, out, _ := run(t, "diagnose", "https://example.test:"+portOf(t, srv.Listener.Addr().String())+"/status/503", "-o", "json")
	if code != exit.Findings {
		t.Fatalf("exit %d", code)
	}
	rep := jsonReport(t, out)
	if rep.Summary == nil || rep.Summary.Outcome != "problem" || rep.Run.Profile != "standard" || len(rep.Findings) == 0 || rep.Findings[0].Code != "HTTP_ERROR_RESPONSE" {
		t.Fatalf("%+v", rep)
	}
}

func TestDiagnoseQuietPrintsOnlyFindings(t *testing.T) {
	pki := resolveToLoopback(t)
	cert := pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	u := "https://example.test:" + portOf(t, srv.Listener.Addr().String())
	code, out, _ := run(t, "diagnose", u+"/ok", "-q")
	if code != exit.OK || out != "" {
		t.Fatalf("a clean quiet run prints nothing: exit %d %q", code, out)
	}
	code, out, _ = run(t, "diagnose", u+"/status/503", "-q", "--no-color")
	if code != exit.Findings || !strings.Contains(out, "HTTP_ERROR_RESPONSE") || strings.Contains(out, "Measurements") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDiagnoseVerboseShowsMeasurementDetails(t *testing.T) {
	pki := resolveToLoopback(t)
	cert := pki.Valid("example.test")
	srv := fixtures.HTTPServer(t, &cert)
	u := "https://example.test:" + portOf(t, srv.Listener.Addr().String()) + "/ok"
	_, plain, _ := run(t, "diagnose", u, "--no-color")
	_, verbose, _ := run(t, "diagnose", u, "--no-color", "-v")
	if strings.Contains(plain, "timing (ms)") || !strings.Contains(verbose, "timing (ms)") {
		t.Fatalf("verbose must add details:\n%s\n---\n%s", plain, verbose)
	}
}
