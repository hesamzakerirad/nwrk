package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/internal/path"
)

func listener(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), ln.Addr().(*net.TCPAddr).Port
}

func TestPathPingTCP(t *testing.T) {
	_, port := listener(t)
	code, out, errOut := run(t, "path", "ping", "127.0.0.1", "--method", "tcp", "--port", fmt.Sprint(port), "-c", "2", "--interval", "1ms", "--no-color")
	if code != exit.OK || errOut != "" {
		t.Fatalf("%d %q\n%s", code, errOut, out)
	}
	for _, w := range []string{"nw path ping", "tcp connect to port", "2 sent, 2 received", "0.0% loss", "min/avg/max"} {
		if !strings.Contains(out, w) {
			t.Errorf("lacks %q:\n%s", w, out)
		}
	}
	code, out, _ = run(t, "path", "ping", "127.0.0.1", "--method", "tcp", "--port", fmt.Sprint(port), "-c", "1", "-o", "json")
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Method        string `json:"method"`
		Received      int    `json:"received"`
		Replies       []struct {
			RTT *float64 `json:"rtt_ms"`
		} `json:"replies"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exit.OK || doc.SchemaVersion != "1" || doc.Method != "tcp" || doc.Received != 1 || doc.Replies[0].RTT == nil {
		t.Fatalf("%v %d %+v\n%s", err, code, doc, out)
	}
}

func TestPathPingFallbackAndPrivilegeErrors(t *testing.T) {
	_, port := listener(t)
	denied := fmt.Errorf("ICMP echo is %w: operation not permitted (on Linux, allow your group in net.ipv4.ping_group_range)", path.ErrPrivilege)
	seams.pingICMP = func(netip.Addr) (path.Pinger, error) { return nil, denied }
	t.Cleanup(func() { seams.pingICMP = nil })

	code, out, _ := run(t, "path", "ping", "127.0.0.1", "--port", fmt.Sprint(port), "-c", "1", "--no-color")
	if code != exit.OK || !strings.Contains(out, "note: ICMP echo is not permitted") || !strings.Contains(out, "measuring with TCP instead") {
		t.Fatalf("auto must fall back and say why: %d\n%s", code, out)
	}
	code, _, errOut := run(t, "path", "ping", "127.0.0.1", "--method", "icmp", "-c", "1")
	if code != exit.Failure || !strings.Contains(errOut, "ping_group_range") {
		t.Fatalf("an explicit icmp request must fail and explain the privilege: %d %q", code, errOut)
	}
}

func TestPathPingNoReplyExitsOne(t *testing.T) {
	seams.pingTCP = func(int) path.Pinger { return deadPinger{} }
	t.Cleanup(func() { seams.pingTCP = nil })
	code, out, _ := run(t, "path", "ping", "192.0.2.1", "--method", "tcp", "-c", "1", "--no-color")
	if code != exit.Findings || !strings.Contains(out, "1 sent, 0 received") || !strings.Contains(out, "not proof") {
		t.Fatalf("%d\n%s", code, out)
	}
}

type deadPinger struct{}

func (deadPinger) Name() string { return "tcp" }
func (deadPinger) Close() error { return nil }
func (deadPinger) Ping(context.Context, netip.Addr, int, time.Duration) (time.Duration, error) {
	return 0, context.DeadlineExceeded
}

func TestPathTraceTCPAndFakeICMP(t *testing.T) {
	_, port := listener(t)
	code, out, _ := run(t, "path", "trace", "127.0.0.1", "--method", "tcp", "--port", fmt.Sprint(port), "--queries", "1", "--no-color")
	if code != exit.OK || !strings.Contains(out, "<- destination") || !strings.Contains(out, "cannot see the routers") || !strings.Contains(out, "not evidence") {
		t.Fatalf("%d\n%s", code, out)
	}
	seams.traceICMP = func(netip.Addr) (path.Prober, error) {
		return routerProber{}, nil
	}
	t.Cleanup(func() { seams.traceICMP = nil })
	code, out, _ = run(t, "path", "trace", "127.0.0.1", "--method", "icmp", "--queries", "1", "--no-color")
	if code != exit.OK || !strings.Contains(out, "10.0.0.1") || !strings.Contains(out, "<- destination") {
		t.Fatalf("%d\n%s", code, out)
	}
	_, out, _ = run(t, "path", "trace", "127.0.0.1", "--method", "icmp", "--queries", "1", "-o", "json")
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Reached       bool   `json:"reached"`
		Hops          []struct {
			Address string `json:"address"`
		} `json:"hops"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || !doc.Reached || len(doc.Hops) != 2 || doc.Hops[0].Address != "10.0.0.1" || doc.SchemaVersion != "1" {
		t.Fatalf("%v %+v\n%s", err, doc, out)
	}
}

type routerProber struct{}

func (routerProber) Name() string      { return "icmp" }
func (routerProber) SeesRouters() bool { return true }
func (routerProber) Close() error      { return nil }
func (routerProber) Probe(_ context.Context, ttl int, _ time.Duration) (path.ProbeReply, error) {
	if ttl == 1 {
		return path.ProbeReply{From: netip.MustParseAddr("10.0.0.1"), RTT: time.Millisecond}, nil
	}
	return path.ProbeReply{From: netip.MustParseAddr("127.0.0.1"), RTT: 2 * time.Millisecond, Reached: true}, nil
}

func TestPathTraceNotReachedExitsOne(t *testing.T) {
	seams.traceICMP = func(netip.Addr) (path.Prober, error) { return silentICMP{}, nil }
	t.Cleanup(func() { seams.traceICMP = nil })
	code, out, _ := run(t, "path", "trace", "192.0.2.1", "--method", "icmp", "--queries", "1", "--max-silent", "2", "--no-color")
	if code != exit.Findings || !strings.Contains(out, "stopped after 2 hops") {
		t.Fatalf("%d\n%s", code, out)
	}
}

type silentICMP struct{}

func (silentICMP) Name() string      { return "icmp" }
func (silentICMP) SeesRouters() bool { return true }
func (silentICMP) Close() error      { return nil }
func (silentICMP) Probe(context.Context, int, time.Duration) (path.ProbeReply, error) {
	return path.ProbeReply{}, context.DeadlineExceeded
}

func TestPathMTU(t *testing.T) {
	_, port := listener(t)
	code, out, errOut := run(t, "path", "mtu", "127.0.0.1", "--port", fmt.Sprint(port), "--no-color")
	if code != exit.OK || errOut != "" || !strings.Contains(out, "interface MTU:") || !strings.Contains(out, "hint, not a discovery") {
		t.Fatalf("%d %q\n%s", code, errOut, out)
	}
	code, out, _ = run(t, "path", "mtu", "127.0.0.1", "--port", fmt.Sprint(port), "-o", "json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exit.OK || doc["schema_version"] != "1" || doc["interface_mtu"] == nil {
		t.Fatalf("%v\n%s", err, out)
	}
	closed := fixtures.ClosedPort(t)
	code, _, _ = run(t, "path", "mtu", "127.0.0.1", "--port", closed[strings.LastIndex(closed, ":")+1:], "--timeout", "10s")
	if code != exit.Findings {
		t.Fatalf("a connection that cannot be made exits 1: %d", code)
	}
}

func TestPathUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no host":        {"path", "ping"},
		"bad method":     {"path", "ping", "127.0.0.1", "--method", "udp"},
		"bad count":      {"path", "ping", "127.0.0.1", "-c", "0"},
		"bad port":       {"path", "ping", "127.0.0.1", "--port", "70000"},
		"bad host":       {"path", "trace", "exa mple"},
		"bad hops":       {"path", "trace", "127.0.0.1", "--max-hops", "0"},
		"trace bad wait": {"path", "trace", "127.0.0.1", "--wait", "0s"},
		"mtu bad port":   {"path", "mtu", "127.0.0.1", "--port", "0"},
		"unknown subcmd": {"path", "route", "127.0.0.1"},
	} {
		if code, _, errOut := run(t, args...); code != exit.Failure || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

func TestPathInterrupted(t *testing.T) {
	seams.pingTCP = func(int) path.Pinger { return blockingPinger{} }
	t.Cleanup(func() { seams.pingTCP = nil })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	code := Execute(ctx, []string{"path", "ping", "127.0.0.1", "--method", "tcp", "-c", "5"}, discard{}, discard{})
	if code != exit.Interrupted || time.Since(start) > 3*time.Second {
		t.Fatalf("%d after %v", code, time.Since(start))
	}
}

type blockingPinger struct{}

func (blockingPinger) Name() string { return "tcp" }
func (blockingPinger) Close() error { return nil }
func (blockingPinger) Ping(ctx context.Context, _ netip.Addr, _ int, _ time.Duration) (time.Duration, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// --- nw security ---

func TestSecurityInterferenceEndToEnd(t *testing.T) {
	pki := resolveToLoopback(t)
	cert := pki.Valid("example.test", "neutral.test")
	addr := fixtures.SNIServer(t, cert, "example.test", fixtures.SNIReset)
	_, p, _ := net.SplitHostPort(addr)
	code, out, errOut := run(t, "security", "interference", "example.test:"+p, "--control", "neutral.test", "--no-color", "--timeout", "1s")
	if code != exit.Findings || errOut != "" {
		t.Fatalf("%d %q\n%s", code, errOut, out)
	}
	for _, w := range []string{"nw security interference", "TLS_SNI_DEPENDENT_FAILURE", "Hypotheses", "not conclusions", "caveat:"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	for _, banned := range []string{"censor", "blocked by", "hijack"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("the report must not assert %q", banned)
		}
	}
	code, out, _ = run(t, "security", "interference", "example.test:"+p, "--control", "neutral.test", "-o", "json", "--timeout", "1s")
	rep := jsonReport(t, out)
	if code != exit.Findings || rep.Run.Command != "security interference" {
		t.Fatalf("%d %+v", code, rep.Run)
	}
}

func TestSecurityInspectEndToEnd(t *testing.T) {
	pki := resolveToLoopback(t)
	addr := fixtures.LegacyTLSServer(t, pki.Valid("example.test"))
	_, p, _ := net.SplitHostPort(addr)
	code, out, _ := run(t, "security", "inspect", "example.test:"+p, "--no-color", "--timeout", "1s")
	if code != exit.Findings || !strings.Contains(out, "TLS_LEGACY_PROTOCOL_ACCEPTED") {
		t.Fatalf("%d\n%s", code, out)
	}
	modern := fixtures.ModernTLSServer(t, pki.Valid("example.test"))
	_, p, _ = net.SplitHostPort(modern)
	code, out, _ = run(t, "security", "inspect", "example.test:"+p, "--no-color", "--timeout", "1s")
	if strings.Contains(out, "TLS_LEGACY_PROTOCOL_ACCEPTED") {
		t.Fatalf("a modern server must not be flagged:\n%s", out)
	}
	if code != exit.OK && code != exit.Findings {
		t.Fatalf("exit %d", code)
	}
}

func TestSecurityUsageErrorsAndInterrupt(t *testing.T) {
	resolveToLoopback(t)
	for name, args := range map[string][]string{
		"no target":    {"security", "interference"},
		"bad target":   {"security", "inspect", "exa mple"},
		"bad resolver": {"security", "interference", "example.test", "--resolver", "not a resolver"},
	} {
		if code, _, errOut := run(t, args...); code != exit.Failure || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	addr := fixtures.MuteServer(t)
	_, p, _ := net.SplitHostPort(addr)
	code := Execute(ctx, []string{"security", "interference", "example.test:" + p, "--timeout", "30s"}, discard{}, discard{})
	if code != exit.Interrupted {
		t.Fatalf("%d", code)
	}
}

func TestDeepProfileAddsTheInterferenceProbes(t *testing.T) {
	pki := resolveToLoopback(t)
	addr := fixtures.TLSServer(t, &tls.Config{Certificates: []tls.Certificate{pki.Valid("example.test", "www.example.org")}})
	_, p, _ := net.SplitHostPort(addr)
	count := func(profile string) int {
		_, out, _ := run(t, "diagnose", "example.test:"+p, "--profile", profile, "-o", "json", "--timeout", "1s")
		rep := jsonReport(t, out)
		n := 0
		for _, m := range rep.Measurements {
			if m.Params["probe"] != nil {
				n++
			}
		}
		return n
	}
	if count("standard") != 0 {
		t.Fatal("the standard profile makes no probes")
	}
	if count("deep") == 0 {
		t.Fatal("the deep profile includes the interference probes")
	}
}
