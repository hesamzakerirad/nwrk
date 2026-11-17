package platform

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	conf := `# comment
search example.org
nameserver 192.0.2.1
nameserver 2001:db8::53
nameserver fe80::1%en0
nameserver not-an-ip
options ndots:2
`
	got, err := ParseResolvConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1:53", "[2001:db8::53]:53", "[fe80::1]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSystemResolversDoesNotFail(t *testing.T) {
	if _, err := SystemResolvers(); err != nil {
		t.Fatal(err)
	}
}

const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eth0	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0
lo	0000007F	00000000	0000	0	0	0	000000FF	0	0	0
`

func TestParseProcNetRoute(t *testing.T) {
	rs, err := ParseProcNetRoute(strings.NewReader(procRoute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 4 { // the last entry is not UP
		t.Fatalf("got %d routes: %+v", len(rs), rs)
	}
	def := rs[0]
	if !def.Default || def.Destination != "default" || def.Gateway != "192.168.0.1" || def.Interface != "eth0" || def.Metric != 100 || def.Family != "ipv4" {
		t.Fatalf("default route: %+v", def)
	}
	if rs[1].Destination != "192.168.0.0/24" || rs[1].Gateway != "" || rs[1].Default {
		t.Fatalf("%+v", rs[1])
	}
	if rs[2].Destination != "172.17.0.0/16" || rs[3].Destination != "169.254.0.0/16" {
		t.Fatalf("%+v %+v", rs[2], rs[3])
	}
}

func TestParseProcNetRouteIgnoresGarbage(t *testing.T) {
	rs, err := ParseProcNetRoute(strings.NewReader("header\nshort line\neth0 zz 00 0003 0 0 0 00\n"))
	if err != nil || len(rs) != 0 {
		t.Fatalf("%v %v", rs, err)
	}
}

func TestParseProcNetIPv6Route(t *testing.T) {
	const data = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000001 00000000 00000003 eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001 lo
`
	rs, err := ParseProcNetIPv6Route(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 || !rs[0].Default || rs[0].Gateway != "fe80::1" || rs[0].Family != "ipv6" || rs[1].Destination != "fe80::/64" {
		t.Fatalf("%+v", rs)
	}
}

func TestProxiesFromEnvDropCredentials(t *testing.T) {
	env := map[string]string{
		"HTTPS_PROXY": "http://alice:s3cret@proxy.example.test:3128",
		"http_proxy":  "proxy.example.test:8080",
		"NO_PROXY":    "localhost,.example.test",
		"ALL_PROXY":   "socks5://[::1]:1080",
	}
	ps := ProxiesFromEnv(func(k string) string { return env[k] })
	byName := map[string]ProxySetting{}
	for _, p := range ps {
		byName[p.Source] = p
	}
	if p := byName["HTTPS_PROXY"]; p.Scheme != "http" || p.Host != "proxy.example.test:3128" {
		t.Fatalf("%+v", p)
	}
	if p := byName["HTTP_PROXY"]; p.Host != "proxy.example.test:8080" {
		t.Fatalf("lowercase variables must be honored: %+v", p)
	}
	if p := byName["ALL_PROXY"]; p.Scheme != "socks5" || p.Host != "[::1]:1080" {
		t.Fatalf("%+v", p)
	}
	if byName["NO_PROXY"].NoProxy != "localhost,.example.test" {
		t.Fatalf("%+v", byName["NO_PROXY"])
	}
	b := fmt.Sprintf("%+v", ps)
	if strings.Contains(b, "alice") || strings.Contains(b, "s3cret") {
		t.Fatalf("credentials leaked: %s", b)
	}
	if len(ProxiesFromEnv(func(string) string { return "" })) != 0 {
		t.Fatal("no variables, no proxies")
	}
}

func TestAddrKind(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1": "loopback", "::1": "loopback", "10.1.2.3": "private", "192.168.0.5": "private",
		"172.16.0.1": "private", "100.64.0.9": "private", "fd00::1": "private", "169.254.1.1": "link-local",
		"fe80::1": "link-local", "8.8.8.8": "global", "2606:4700::1111": "global",
	}
	for in, want := range cases {
		if got := AddrKind(netip.MustParseAddr(in)); got != want {
			t.Errorf("AddrKind(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestInterfaceUsable(t *testing.T) {
	addr := func(kind string) []Address { return []Address{{Kind: kind}} }
	cases := []struct {
		name string
		i    Interface
		want bool
	}{
		{"up with private", Interface{Up: true, Addresses: addr("private")}, true},
		{"up with global", Interface{Up: true, Addresses: addr("global")}, true},
		{"down", Interface{Up: false, Addresses: addr("private")}, false},
		{"loopback", Interface{Up: true, Loopback: true, Addresses: addr("loopback")}, false},
		{"link-local only", Interface{Up: true, Addresses: addr("link-local")}, false},
		{"no address", Interface{Up: true}, false},
	}
	for _, c := range cases {
		if got := c.i.Usable(); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestInterfacesAndDNSRunHere(t *testing.T) {
	ifs, err := Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Fatalf("%v %v", ifs, err)
	}
	loop := false
	for _, i := range ifs {
		loop = loop || i.Loopback
	}
	if !loop {
		t.Error("every machine has a loopback interface")
	}
	if _, err := DNS(); err != nil {
		t.Fatal(err)
	}
	if _, err := Routes(); err != nil && !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
