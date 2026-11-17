package path

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hesamzakerirad/nwrk/internal/fixtures"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type fakePinger struct {
	name  string
	rtts  []time.Duration // zero means lost
	calls int
}

func (f *fakePinger) Name() string { return f.name }
func (f *fakePinger) Close() error { return nil }
func (f *fakePinger) Ping(context.Context, netip.Addr, int, time.Duration) (time.Duration, error) {
	d := f.rtts[f.calls%len(f.rtts)]
	f.calls++
	if d == 0 {
		return 0, context.DeadlineExceeded
	}
	return d, nil
}

var addr = netip.MustParseAddr("192.0.2.1")

func TestPingStatistics(t *testing.T) {
	p := &fakePinger{name: "icmp", rtts: []time.Duration{10 * time.Millisecond, 0, 30 * time.Millisecond, 20 * time.Millisecond}}
	res, err := Ping(context.Background(), "example.test", addr, PingOptions{
		Count: 4, Interval: time.Millisecond, Timeout: time.Second, Method: MethodICMP,
		ICMP: func(netip.Addr) (Pinger, error) { return p, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 4 || res.Received != 3 || res.LossPct != 25 || res.MinMS != 10 || res.MaxMS != 30 || res.AvgMS != 20 || res.Method != "icmp" {
		t.Fatalf("%+v", res)
	}
	if res.Replies[1].RTTMS != nil || res.Replies[1].Note != "no reply before the deadline" || res.Replies[0].RTTMS == nil {
		t.Fatalf("%+v", res.Replies)
	}
}

func TestPingFallsBackToTCPAndSaysWhy(t *testing.T) {
	tcp := &fakePinger{name: "tcp", rtts: []time.Duration{time.Millisecond}}
	opts := func(icmpErr error) PingOptions {
		return PingOptions{
			Count: 1, Timeout: time.Second, Method: MethodAuto, Port: 443,
			ICMP: func(netip.Addr) (Pinger, error) { return nil, icmpErr },
			TCP:  func(int) Pinger { return tcp },
		}
	}
	res, err := Ping(context.Background(), "x", addr, opts(fmt.Errorf("ICMP echo is %w: operation not permitted", ErrPrivilege)))
	if err != nil || res.Method != "tcp" || res.Port != 443 || !strings.Contains(res.Fallback, "not permitted") {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err = Ping(context.Background(), "x", addr, opts(fmt.Errorf("raw sockets: %w", ErrUnsupported))); err != nil || res.Method != "tcp" {
		t.Fatalf("%+v %v", res, err)
	}
	// Any other failure is a real error, not a reason to switch silently.
	if _, err = Ping(context.Background(), "x", addr, opts(errors.New("boom"))); err == nil {
		t.Fatal("an unrelated error must not be hidden by the fallback")
	}
	// Asking for ICMP explicitly never falls back.
	o := opts(fmt.Errorf("x: %w", ErrPrivilege))
	o.Method = MethodICMP
	if _, err = Ping(context.Background(), "x", addr, o); !errors.Is(err, ErrPrivilege) {
		t.Fatalf("%v", err)
	}
}

func TestPingCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	p := &fakePinger{name: "tcp", rtts: []time.Duration{time.Millisecond}}
	start := time.Now()
	_, err := Ping(ctx, "x", addr, PingOptions{Count: 100, Interval: time.Second, Timeout: time.Second, Method: MethodTCP, TCP: func(int) Pinger { return p }})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestTCPPinger(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	p := NewTCPPinger(port)
	d, err := p.Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, time.Second)
	if err != nil || d <= 0 {
		t.Fatalf("%v %v", d, err)
	}
	// A refused connection still proves the host answered.
	_, closed, _ := net.SplitHostPort(fixtures.ClosedPort(t))
	var cp int
	fmt.Sscanf(closed, "%d", &cp)
	if _, err := NewTCPPinger(cp).Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, 10*time.Second); err != nil {
		t.Fatalf("a refusal is a reply: %v", err)
	}
}

func TestICMPPingerIfPermitted(t *testing.T) {
	p, err := NewICMPPinger(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		if !errors.Is(err, ErrPrivilege) || !strings.Contains(err.Error(), "ping_group_range") {
			t.Fatalf("the privilege error must say what would allow it: %v", err)
		}
		t.Skip("ICMP is not permitted here: " + err.Error())
	}
	defer p.Close()
	if _, err := p.Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, 2*time.Second); err != nil {
		t.Fatalf("loopback must answer an echo: %v", err)
	}
}

// --- trace ---

type fakeProber struct {
	sees    bool
	replies map[int]ProbeReply // by TTL; missing means no reply
}

func (f *fakeProber) Name() string {
	if f.sees {
		return "icmp"
	}
	return "tcp"
}
func (f *fakeProber) SeesRouters() bool { return f.sees }
func (f *fakeProber) Close() error      { return nil }
func (f *fakeProber) Probe(_ context.Context, ttl int, _ time.Duration) (ProbeReply, error) {
	if r, ok := f.replies[ttl]; ok {
		return r, nil
	}
	return ProbeReply{}, context.DeadlineExceeded
}

func traceWith(p Prober, o TraceOptions) (*TraceResult, error) {
	o.Method = MethodICMP
	o.ICMP = func(netip.Addr) (Prober, error) { return p, nil }
	if o.MaxHops == 0 {
		o.MaxHops = 30
	}
	if o.Queries == 0 {
		o.Queries = 2
	}
	return Trace(context.Background(), "example.test", addr, o)
}

func TestTraceListsRoutersAndStopsAtTheDestination(t *testing.T) {
	p := &fakeProber{sees: true, replies: map[int]ProbeReply{
		1: {From: netip.MustParseAddr("10.0.0.1"), RTT: time.Millisecond},
		2: {From: netip.MustParseAddr("10.0.1.1"), RTT: 5 * time.Millisecond},
		4: {From: addr, RTT: 20 * time.Millisecond, Reached: true}, // hop 3 is silent
	}}
	res, err := traceWith(p, TraceOptions{MaxSilent: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached || len(res.Hops) != 4 || res.Hops[0].Address != "10.0.0.1" || res.Hops[3].Address != "192.0.2.1" || !res.Hops[3].Reached {
		t.Fatalf("%+v", res.Hops)
	}
	if res.Hops[2].Address != "" || res.Hops[2].RTTMS[0] != nil {
		t.Fatalf("a silent hop has no address and no time: %+v", res.Hops[2])
	}
	if !strings.Contains(res.Note, "not evidence") {
		t.Fatalf("every trace must say that a missing reply proves nothing: %s", res.Note)
	}
}

func TestTraceStopsAfterManySilentHops(t *testing.T) {
	res, err := traceWith(&fakeProber{sees: true, replies: map[int]ProbeReply{1: {From: netip.MustParseAddr("10.0.0.1"), RTT: time.Millisecond}}}, TraceOptions{MaxSilent: 3})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reached || len(res.Hops) != 4 || !strings.Contains(res.Hops[3].Note, "stopped after 3 hops without a reply") {
		t.Fatalf("%d hops: %+v", len(res.Hops), res.Hops)
	}
	if !strings.Contains(res.Note, "did not answer") || !strings.Contains(res.Note, "not evidence") {
		t.Fatal(res.Note)
	}
}

func TestTraceRespectsMaxHops(t *testing.T) {
	p := &fakeProber{sees: true, replies: map[int]ProbeReply{}}
	for i := 1; i <= 10; i++ {
		p.replies[i] = ProbeReply{From: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i)), RTT: time.Millisecond}
	}
	res, _ := traceWith(p, TraceOptions{MaxHops: 5})
	if len(res.Hops) != 5 || res.Reached {
		t.Fatalf("%d hops reached=%v", len(res.Hops), res.Reached)
	}
}

func TestTCPTraceCannotSeeRoutersAndSaysSo(t *testing.T) {
	p := &fakeProber{sees: false, replies: map[int]ProbeReply{3: {RTT: time.Millisecond, Reached: true}}}
	res, _ := traceWith(p, TraceOptions{MaxSilent: 5})
	if !res.Reached || len(res.Hops) != 3 || res.Hops[2].Address != "" {
		t.Fatalf("%+v", res.Hops)
	}
	if !strings.Contains(res.Note, "at most 3 hops") || !strings.Contains(res.Note, "cannot see the routers") {
		t.Fatal(res.Note)
	}
}

func TestTraceFallsBackWhenICMPIsNotPermitted(t *testing.T) {
	tcp := &fakeProber{sees: false, replies: map[int]ProbeReply{1: {RTT: time.Millisecond, Reached: true}}}
	res, err := Trace(context.Background(), "x", addr, TraceOptions{
		Method: MethodAuto, MaxHops: 5, Queries: 1, Timeout: time.Second, Port: 443,
		ICMP: func(netip.Addr) (Prober, error) { return nil, fmt.Errorf("x: %w", ErrPrivilege) },
		TCP:  func(netip.Addr, int) Prober { return tcp },
	})
	if err != nil || res.Method != "tcp" || res.Fallback == "" || res.Port != 443 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestTCPProberReachesALocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	res, err := Trace(context.Background(), "localhost", netip.MustParseAddr("127.0.0.1"), TraceOptions{
		Method: MethodTCP, MaxHops: 5, Queries: 1, Timeout: time.Second, Port: port, MaxSilent: 3,
	})
	if err != nil || !res.Reached || len(res.Hops) != 1 || res.Method != "tcp" {
		t.Fatalf("loopback is one hop away: %+v %v", res, err)
	}
}

func TestMTUOnLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res, err := MTU(context.Background(), "localhost", netip.MustParseAddr("127.0.0.1"), port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports neither the interface MTU of loopback nor the segment size.
	if res.Family != "ipv4" || runtime.GOOS != "windows" && (res.InterfaceMTU < 1000 || !strings.Contains(res.Note, "hint, not a discovery")) {
		t.Fatalf("%+v", res)
	}
	if res.MSS > 0 && res.ImpliedPathMTU != res.MSS+40 {
		t.Fatalf("%+v", res)
	}
}

func TestMTUNoteWhenReduced(t *testing.T) {
	r := &MTUResult{MSS: 1200, ImpliedPathMTU: 1240, InterfaceMTU: 1500, Reduced: true}
	if n := mtuNote(r); !strings.Contains(n, "1240") || !strings.Contains(n, "clamps") {
		t.Fatal(n)
	}
	if n := mtuNote(&MTUResult{}); !strings.Contains(n, "does not report") {
		t.Fatal(n)
	}
}

func TestMatchesQuotedEcho(t *testing.T) {
	// A 20-byte IPv4 header followed by the first 8 bytes of our echo.
	q := make([]byte, 28)
	q[0] = 0x45
	q[20+4], q[20+5], q[20+6], q[20+7] = 0x12, 0x34, 0x00, 0x07
	if !matches(q, 0x1234, 7, false) || matches(q, 0x1234, 8, false) || matches(q[:10], 0x1234, 7, false) {
		t.Fatal("quoted packet matching is wrong")
	}
}

func TestTraceWithoutRouterVisibilityKeepsGoingThroughSilence(t *testing.T) {
	p := &fakeProber{sees: false, replies: map[int]ProbeReply{9: {RTT: time.Millisecond, Reached: true}}}
	res, _ := traceWith(p, TraceOptions{MaxSilent: 3, Queries: 3})
	if !res.Reached || len(res.Hops) != 9 {
		t.Fatalf("silence is expected until the destination is in range: reached=%v hops=%d", res.Reached, len(res.Hops))
	}
	for _, h := range res.Hops {
		if len(h.RTTMS) != 1 {
			t.Fatalf("one probe per hop is enough when routers cannot answer: %+v", h)
		}
	}
}
