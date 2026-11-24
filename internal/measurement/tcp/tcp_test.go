package tcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/fixtures"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func ctx(t *testing.T, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

func TestConnectSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	m := Connect(ctx(t, 2*time.Second), "example.test", ap, nil)
	if m.Status != domain.StatusSuccess {
		t.Fatalf("%+v", m.Error)
	}
	if m.Target.Family != "ipv4" || m.Target.Port != int(ap.Port()) || m.Target.Host != "example.test" || m.Target.IP != "127.0.0.1" {
		t.Fatalf("target %+v", m.Target)
	}
	if res := m.Result.(*Result); res.Family != "ipv4" || res.Address != ap.String() {
		t.Fatalf("result %+v", res)
	}
}

func TestConnectIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer ln.Close()
	m := Connect(ctx(t, 2*time.Second), "", netip.MustParseAddrPort(ln.Addr().String()), nil)
	if m.Status != domain.StatusSuccess || m.Target.Family != "ipv6" {
		t.Fatalf("%+v %+v", m.Target, m.Error)
	}
}

func TestConnectRefused(t *testing.T) {
	// Windows needs about two seconds to report a refused loopback connection.
	m := Connect(ctx(t, 10*time.Second), "", netip.MustParseAddrPort(fixtures.ClosedPort(t)), nil)
	if m.Status != domain.StatusFailure || m.Error.Code != domain.TCPRefused {
		t.Fatalf("status %s error %v", m.Status, m.Error)
	}
}

// hangDialer never connects: it waits until the context ends, which is what
// a destination that drops packets looks like.
type hangDialer struct{}

func (hangDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestConnectTimeout(t *testing.T) {
	m := Connect(ctx(t, 200*time.Millisecond), "", netip.MustParseAddrPort("192.0.2.1:80"), hangDialer{})
	if m.Error == nil || m.Error.Code != domain.TCPTimeout {
		t.Fatalf("got %v", m.Error)
	}
}

type errDialer struct{ err error }

func (d errDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, d.err }

func TestConnectClassifiesOtherErrors(t *testing.T) {
	m := Connect(ctx(t, time.Second), "", netip.MustParseAddrPort("192.0.2.1:80"), errDialer{net.UnknownNetworkError("x")})
	if m.Error.Code != domain.TCPError {
		t.Fatalf("got %v", m.Error)
	}
}

func TestConnectCancellation(t *testing.T) {
	c, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	m := Connect(c, "", netip.MustParseAddrPort("192.0.2.1:80"), hangDialer{})
	if time.Since(start) > time.Second || m.Status != domain.StatusFailure {
		t.Fatalf("cancellation not honored: %v %s", time.Since(start), m.Status)
	}
}
