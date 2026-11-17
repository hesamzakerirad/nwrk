package target

import (
	"strings"
	"testing"
)

func TestHost(t *testing.T) {
	good := map[string]string{
		"example.com":        "example.com",
		"  Example.COM.  ":   "example.com",
		"192.0.2.1":          "192.0.2.1",
		"::1":                "::1",
		"[2001:db8::1]":      "2001:db8::1",
		"::ffff:192.0.2.1":   "192.0.2.1",
		"_dmarc.example.com": "_dmarc.example.com",
		"a-b.example.org":    "a-b.example.org",
	}
	for in, want := range good {
		got, err := Host(in)
		if err != nil || got != want {
			t.Errorf("Host(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", " ", ".", "a..b", "-a.example", "a-.example", "exa mple.com",
		"example.com/path", "user@example.com", "example.com:80", "1.2.3",
		"fe80::1%eth0", "[1.2.3.4]", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 130) + "com", "ex!ample.com",
	}
	for _, in := range bad {
		if got, err := Host(in); err == nil {
			t.Errorf("Host(%q) = %q; want an error", in, got)
		}
	}
}

// Inputs use Unicode escapes so that the source has no non-Latin glyphs.
// Expected values come from golang.org/x/net/idna (Lookup profile).
func TestHostIDN(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"persian-script label", "\u0627\u06cc\u0631\u0627\u0646.ir", "xn--mgba3a4f16a.ir"},
		{"cyrillic-script label", "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444", "xn--e1afmkfd.xn--p1ai"},
		{"han-script label", "\u4e2d\u6587.\u4e2d\u56fd", "xn--fiq228c.xn--fiqs8s"},
		{"latin-diacritic label", "t\u00fcrkiye.tr", "xn--trkiye-3ya.tr"},
		{"iran.ir", "iran.ir", "iran.ir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Host(c.in)
			if err != nil || got != c.want {
				t.Errorf("Host(%+q) = %q, %v; want %q", c.in, got, err, c.want)
			}
		})
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		host string
		port int
		ok   bool
	}{
		{"example.com:443", 0, "example.com", 443, true},
		{"example.com", 443, "example.com", 443, true},
		{"example.com", 0, "", 0, false},
		{"[::1]:8080", 0, "::1", 8080, true},
		{"::1", 443, "::1", 443, true},
		{"[::1]", 443, "::1", 443, true},
		{"192.0.2.1:80", 0, "192.0.2.1", 80, true},
		{"example.com:0", 0, "", 0, false},
		{"example.com:65536", 0, "", 0, false},
		{"example.com:http", 0, "", 0, false},
		{"example.com:", 0, "", 0, false},
		{":80", 0, "", 0, false},
	}
	for _, c := range cases {
		h, p, err := HostPort(c.in, c.def)
		if (err == nil) != c.ok || h != c.host || p != c.port {
			t.Errorf("HostPort(%q, %d) = %q, %d, %v; want %q, %d, ok=%v", c.in, c.def, h, p, err, c.host, c.port, c.ok)
		}
	}
}

func TestURL(t *testing.T) {
	good := map[string]string{
		"example.com":                 "https://example.com",
		"http://Example.com/a?b=c#d":  "http://example.com/a?b=c",
		"https://example.com:8443/x":  "https://example.com:8443/x",
		"https://[2001:db8::1]:8443/": "https://[2001:db8::1]:8443/",
		"example.com/path":            "https://example.com/path",
	}
	for in, want := range good {
		u, err := URL(in)
		if err != nil || u.String() != want {
			t.Errorf("URL(%q) = %v, %v; want %q", in, u, err, want)
		}
	}
	for _, in := range []string{"", "ftp://example.com", "https://", "https://user:pw@example.com", "https://example.com:99999", "http://exa mple.com"} {
		if u, err := URL(in); err == nil {
			t.Errorf("URL(%q) = %v; want an error", in, u)
		}
	}
}

func TestParseResolver(t *testing.T) {
	good := map[string]Resolver{
		"1.1.1.1":           {"udp", "1.1.1.1", 53, ""},
		"1.1.1.1:5353":      {"udp", "1.1.1.1", 5353, ""},
		"tcp://9.9.9.9":     {"tcp", "9.9.9.9", 53, ""},
		"tcp://9.9.9.9:853": {"tcp", "9.9.9.9", 853, ""},
		"[2606:4700::1111]": {"udp", "2606:4700::1111", 53, ""},
		"::1":               {"udp", "::1", 53, ""},
		"[::1]:5353":        {"udp", "::1", 5353, ""},
		"tcp://[::1]:5353":  {"tcp", "::1", 5353, ""},
	}
	for in, want := range good {
		got, err := ParseResolver(in)
		if err != nil || got != want {
			t.Errorf("ParseResolver(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		if err == nil {
			again, err2 := ParseResolver(got.String())
			if err2 != nil || again != got {
				t.Errorf("String round trip of %q gave %+v, %v", in, again, err2)
			}
		}
	}
	for _, in := range []string{"", "dns.google", "udp://1.1.1.1", "1.1.1.1:0", "tcp://", "tls://", "https://", "https:///dns-query", "tls://a b", "https://h/q?x=1", "https://h:99999/q", "tls://u@h"} {
		if r, err := ParseResolver(in); err == nil {
			t.Errorf("ParseResolver(%q) = %+v; want an error", in, r)
		}
	}
}

func TestResolversPrecedence(t *testing.T) {
	env := func(k string) string {
		if k == EnvResolvers {
			return "8.8.8.8, tcp://1.1.1.1"
		}
		return ""
	}
	got, err := Resolvers([]string{"9.9.9.9"}, env)
	if err != nil || len(got) != 1 || got[0].Host != "9.9.9.9" {
		t.Fatalf("flags must win over the environment: %+v, %v", got, err)
	}
	got, err = Resolvers(nil, env)
	if err != nil || len(got) != 2 || got[1].Transport != "tcp" {
		t.Fatalf("environment: %+v, %v", got, err)
	}
	got, err = Resolvers(nil, func(string) string { return "" })
	if err != nil || got != nil {
		t.Fatalf("no source: %+v, %v", got, err)
	}
	if _, err = Resolvers(nil, func(string) string { return "nope" }); err == nil || !strings.Contains(err.Error(), EnvResolvers) {
		t.Fatalf("a bad environment value must name the variable: %v", err)
	}
	got, _ = Resolvers([]string{"1.1.1.1", "1.1.1.1:53"}, env)
	if len(got) != 1 {
		t.Fatalf("duplicates must collapse: %+v", got)
	}
}

func FuzzHost(f *testing.F) {
	for _, s := range []string{"example.com", "[::1]", "a..b", "bücher.example", "1.2.3", "::ffff:1.2.3.4", "%", "\x00", strings.Repeat("a", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, err := Host(s)
		if err != nil {
			return
		}
		again, err := Host(h)
		if err != nil || again != h {
			t.Fatalf("Host(%q) = %q is not stable: %q, %v", s, h, again, err)
		}
	})
}

func FuzzHostPort(f *testing.F) {
	for _, s := range []string{"example.com:443", "[::1]:80", "::1", ":", "a:b:c", "example.com:99999"} {
		f.Add(s, 443)
	}
	f.Fuzz(func(t *testing.T, s string, def int) {
		h, p, err := HostPort(s, def)
		if err != nil {
			return
		}
		if h == "" || p < 1 || p > 65535 {
			t.Fatalf("HostPort(%q, %d) = %q, %d, nil", s, def, h, p)
		}
	})
}

func FuzzURL(f *testing.F) {
	for _, s := range []string{"example.com", "http://[::1]:80/", "https://u:p@h/", "//x", "http://", "https://a b/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := URL(s)
		if err != nil {
			return
		}
		if u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			t.Fatalf("URL(%q) = %v", s, u)
		}
		if _, err := URL(u.String()); err != nil {
			t.Fatalf("URL(%q) = %v does not re-parse: %v", s, u, err)
		}
	})
}

func FuzzResolver(f *testing.F) {
	for _, s := range []string{"1.1.1.1", "tcp://[::1]:53", "tls://x", "https://h/p", "", "::", "[::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseResolver(s)
		if err != nil {
			return
		}
		again, err := ParseResolver(r.String())
		if err != nil || again != r {
			t.Fatalf("ParseResolver(%q) = %+v does not round trip: %+v, %v", s, r, again, err)
		}
	})
}
