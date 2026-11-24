package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	"github.com/radestsam/nwrk/internal/platform"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NW_CONFIG", p)
	return p
}

func TestConfigPath(t *testing.T) {
	p := writeConfig(t, "")
	code, out, _ := run(t, "config", "path")
	if code != exit.OK || strings.TrimSpace(out) != p {
		t.Fatalf("%d %q want %q", code, out, p)
	}
	code, out, _ = run(t, "config", "path", "-o", "json")
	var doc configPathDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exit.OK || doc.Path != p || !doc.Exists || doc.SchemaVersion != "1" {
		t.Fatalf("%v %+v", err, doc)
	}
}

func TestConfigShowReportsEachSource(t *testing.T) {
	writeConfig(t, "region = \"ir\"\nresolvers = [\"9.9.9.9\"]\ntimeout = \"4s\"\n")
	t.Setenv("NW_COLOR", "never")
	code, out, _ := run(t, "config", "show", "--timeout", "2s", "-o", "json")
	if code != exit.OK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var doc configShowDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"region": "config file", "resolvers": "config file", "timeout": "flag", "color": "env NW_COLOR"}
	for k, src := range want {
		if doc.Settings[k].Source != src {
			t.Errorf("%s: source %q, want %q (%+v)", k, doc.Settings[k].Source, src, doc.Settings[k])
		}
	}
	if doc.Settings["timeout"].Value != "2s" || doc.Settings["region"].Value != "ir" {
		t.Fatalf("%+v", doc.Settings)
	}
	code, out, _ = run(t, "config", "show", "--no-color")
	if code != exit.OK || !strings.Contains(out, "region") || !strings.Contains(out, "(config file)") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestConfigShowDefaultsWithoutAFile(t *testing.T) {
	code, out, _ := run(t, "config", "show", "--no-color")
	if code != exit.OK || !strings.Contains(out, "not found") || !strings.Contains(out, "(default)") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestBrokenConfigIsAUsageErrorButDoesNotBlockTheEscapeHatches(t *testing.T) {
	writeConfig(t, "regoin = \"ir\"\n")
	code, _, errOut := run(t, "diagnose", "example.test")
	if code != exit.Failure || !strings.Contains(errOut, "regoin") {
		t.Fatalf("%d %q", code, errOut)
	}
	for _, args := range [][]string{{"version"}, {"config", "path"}, {"completion", "bash"}} {
		if code, _, errOut := run(t, args...); code != exit.OK {
			t.Errorf("%v must work with a broken config: %d %q", args, code, errOut)
		}
	}
	if code, _, _ := run(t, "config", "show"); code != exit.Failure {
		t.Error("config show must report the problem")
	}
}

func TestInvalidRegionAndEnvironment(t *testing.T) {
	if code, _, errOut := run(t, "doctor", "--region", "zz"); code != exit.Failure || !strings.Contains(errOut, "global, ir") {
		t.Fatalf("%d %q", code, errOut)
	}
	t.Setenv("NW_REGION", "zz")
	if code, _, errOut := run(t, "config", "show"); code != exit.Failure || !strings.Contains(errOut, "NW_REGION") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestConfigTimeoutAppliesAndFlagWins(t *testing.T) {
	writeConfig(t, "timeout = \"250ms\"\n")
	offline(t)
	addr := fixtures.MuteServer(t)
	start := time.Now()
	code, _, _ := run(t, "test", "tls", addr, "--no-color")
	if code != exit.Findings || time.Since(start) > 3*time.Second {
		t.Fatalf("the 250ms config timeout must apply: exit %d after %v", code, time.Since(start))
	}
	start = time.Now()
	run(t, "test", "tls", addr, "--timeout", "600ms")
	if d := time.Since(start); d < 500*time.Millisecond || d > 3*time.Second {
		t.Fatalf("the flag must win over the config: %v", d)
	}
}

func TestConfigColorAlways(t *testing.T) {
	writeConfig(t, "color = \"always\"\n")
	_, out, _ := run(t, "config", "show")
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("color = always must color even a buffer: %q", out)
	}
	_, out, _ = run(t, "config", "show", "--no-color")
	if strings.Contains(out, "\x1b[") {
		t.Fatal("--no-color wins")
	}
	t.Setenv("NO_COLOR", "1")
	_, out, _ = run(t, "config", "show")
	if strings.Contains(out, "\x1b[") {
		t.Fatal("NO_COLOR wins over the config file")
	}
}

func TestResolversFromConfigReachDiagnose(t *testing.T) {
	offline(t)
	srv := fixtures.NewDNS(t, map[string]fixtures.DNSRule{"ok.test": {A: []string{"192.0.2.7"}}})
	writeConfig(t, fmt.Sprintf("resolvers = [%q]\n", srv.Addr))
	_, out, _ := run(t, "test", "dns", "ok.test", "-o", "json")
	if !strings.Contains(out, srv.Addr) {
		t.Fatalf("the resolver from the config file was not used:\n%s", out)
	}
}

// --- nw doctor, end to end ---

type osFake struct {
	ifs     []platform.Interface
	servers []string
}

func (f osFake) Interfaces() ([]platform.Interface, error) { return f.ifs, nil }
func (f osFake) DNS() (platform.DNSConfig, error) {
	return platform.DNSConfig{Servers: f.servers, Source: "test"}, nil
}
func (osFake) Proxies() []platform.ProxySetting { return nil }

func doctorEnv(t *testing.T) {
	t.Helper()
	offline(t)
	seams.inspector = osFake{
		ifs:     []platform.Interface{{Name: "en0", Up: true, Addresses: []platform.Address{{Family: "ipv4", Kind: "private"}}}},
		servers: []string{"192.168.1.1:53"},
	}
	seams.dial = func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	seams.systemDNS = func(_ context.Context, name string) *domain.Measurement {
		m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name})
		m.Resolver = &domain.ResolverInfo{Kind: "system"}
		return m.Succeed(&dns.Result{A: []string{"127.0.0.1"}, AAAA: []string{}, Queries: []dns.QueryResult{}})
	}
	t.Cleanup(func() { seams.inspector, seams.dial = nil, nil })
}

func TestDoctorRegionPresetsAreUsedOnlyWhenSelected(t *testing.T) {
	doctorEnv(t)
	code, out, _ := run(t, "doctor", "--region", "ir", "--timeout", "300ms", "-o", "json", "--resolver", fixtures.SilentUDP(t))
	// The shipped targets are not reachable from a test, so doctor must find
	// a problem; the point here is which targets and region were used.
	var rep domain.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exit.Findings || rep.Run.Region != "ir" || rep.Summary.Verdict == "" {
		t.Fatalf("exit %d %+v", code, rep.Run)
	}
	var domestic bool
	for _, m := range rep.Measurements {
		domestic = domestic || m.Scope == domain.ScopeDomestic
	}
	if !domestic {
		t.Fatal("the ir preset must contribute domestic targets")
	}
}

func TestDoctorUsageErrorsAndDefaultRegion(t *testing.T) {
	doctorEnv(t)
	for _, args := range [][]string{{"doctor", "extra"}, {"doctor", "--region", "nowhere"}, {"doctor", "--resolver", "dns.example"}} {
		if code, _, errOut := run(t, args...); code != exit.Failure || errOut == "" {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

func TestDoctorInterrupted(t *testing.T) {
	doctorEnv(t)
	// A resolver that never answers keeps the run busy until it is stopped.
	seams.systemDNS = func(ctx context.Context, name string) *domain.Measurement {
		<-ctx.Done()
		return domain.Begin(domain.TypeDNS, "1", domain.Target{Host: name}).Fail(domain.DNSTimeout, "stopped", nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	code := Execute(ctx, []string{"doctor", "--timeout", "30s"}, discard{}, discard{})
	if code != exit.Interrupted || time.Since(start) > 5*time.Second {
		t.Fatalf("exit %d after %v", code, time.Since(start))
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// --- nw network ---

type netFake struct {
	routesErr error
}

func (netFake) Interfaces() ([]platform.Interface, error) {
	return []platform.Interface{
		{Name: "lo0", Index: 1, MTU: 16384, Up: true, Loopback: true, Addresses: []platform.Address{{CIDR: "127.0.0.1/8", Family: "ipv4", Kind: "loopback"}}},
		{Name: "en0", Index: 2, MTU: 1500, Up: true, Addresses: []platform.Address{{CIDR: "192.168.1.20/24", Family: "ipv4", Kind: "private"}}},
	}, nil
}
func (f netFake) Routes() ([]platform.Route, error) {
	if f.routesErr != nil {
		return nil, f.routesErr
	}
	return []platform.Route{{Destination: "default", Gateway: "192.168.1.1", Interface: "en0", Family: "ipv4", Default: true, Metric: 100}}, nil
}
func (netFake) DNS() (platform.DNSConfig, error) {
	return platform.DNSConfig{Servers: []string{"192.168.1.1:53"}, SearchDomains: []string{"home.test"}, Source: "test"}, nil
}
func (netFake) Proxies() []platform.ProxySetting {
	return []platform.ProxySetting{{Source: "HTTPS_PROXY", Scheme: "http", Host: "proxy.test:3128"}}
}

func TestNetworkCommands(t *testing.T) {
	seams.network = netFake{}
	t.Cleanup(func() { seams.network = nil })

	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"network", "show", "--no-color"}, []string{"interfaces:", "en0", "via 192.168.1.1 on en0", "192.168.1.1:53", "configured"}},
		{[]string{"network", "interfaces", "--no-color"}, []string{"NAME", "lo0", "up (loopback)", "192.168.1.20/24 private"}},
		{[]string{"network", "routes", "--no-color"}, []string{"DESTINATION", "default", "192.168.1.1", "en0"}},
		{[]string{"network", "dns-config", "--no-color"}, []string{"source: test", "server: 192.168.1.1:53", "search: home.test"}},
		{[]string{"network", "proxy", "--no-color"}, []string{"HTTPS_PROXY: http proxy.test:3128", "ignores proxies"}},
	} {
		code, out, errOut := run(t, c.args...)
		if code != exit.OK || errOut != "" {
			t.Fatalf("%v: %d %q", c.args, code, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: output lacks %q:\n%s", c.args, w, out)
			}
		}
	}
	for _, sub := range []string{"show", "interfaces", "routes", "dns-config", "proxy"} {
		code, out, _ := run(t, "network", sub, "-o", "json")
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exit.OK || doc["schema_version"] != "1" {
			t.Errorf("%s: %v %v\n%s", sub, code, err, out)
		}
	}
}

func TestNetworkRoutesUnsupportedIsAToolLimit(t *testing.T) {
	seams.network = netFake{routesErr: fmt.Errorf("routes: %w", platform.ErrUnsupported)}
	t.Cleanup(func() { seams.network = nil })
	code, _, errOut := run(t, "network", "routes")
	if code != exit.Failure || !strings.Contains(errOut, "platform-support") {
		t.Fatalf("%d %q", code, errOut)
	}
	// The summary still works, and says the route is unavailable.
	code, out, _ := run(t, "network", "show", "--no-color")
	if code != exit.OK || !strings.Contains(out, "not available on this platform") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestNetworkInterfacesRunsForReal(t *testing.T) {
	code, out, errOut := run(t, "network", "interfaces", "-o", "json")
	if code != exit.OK || errOut != "" || !strings.Contains(out, "loopback") {
		t.Fatalf("%d %q\n%s", code, errOut, out)
	}
}
