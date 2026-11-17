// Package target parses and validates what the user asks nw to measure:
// hosts, host:port pairs, URLs and DNS resolver addresses.
//
// Everything here is pure. Parsers never resolve names or touch the
// network, and they must never panic on any input.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const maxHostLen = 253

// Host validates a host name or IP address and returns its canonical form:
// lowercase, internationalized names converted to ASCII (punycode), IPv6
// brackets and a trailing root dot removed.
func Host(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("host is empty")
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return "", fmt.Errorf("invalid IPv6 address %q", s)
		}
		return a.Unmap().String(), nil
	}
	if strings.ContainsAny(s, "%/\\@?# \t\r\n") {
		return "", fmt.Errorf("invalid host %q", s)
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), nil
	}
	if strings.Contains(s, ":") {
		return "", fmt.Errorf("invalid host %q", s)
	}
	return domainName(s)
}

func domainName(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("host is empty")
	}
	if !isASCII(s) {
		a, err := idna.Lookup.ToASCII(s)
		if err != nil {
			return "", fmt.Errorf("invalid host %q: %v", s, err)
		}
		s = a
	}
	s = strings.ToLower(s)
	if len(s) > maxHostLen {
		return "", fmt.Errorf("host is longer than %d characters", maxHostLen)
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return "", fmt.Errorf("invalid host %q: %v", s, err)
		}
	}
	// A name that ends in digits only, such as 1.2.3, is an attempt at an
	// IP address, not a domain; browsers and resolvers disagree on it.
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("invalid host %q: not a domain name or IP address", s)
	}
	return s, nil
}

func checkLabel(l string) error {
	if l == "" {
		return errors.New("empty label")
	}
	if len(l) > 63 {
		return errors.New("label longer than 63 characters")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return errors.New("label starts or ends with a hyphen")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("character %q is not allowed", c)
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// Port parses a TCP or UDP port number, 1 to 65535.
func Port(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 || s != strconv.Itoa(n) {
		return 0, fmt.Errorf("invalid port %q (want 1 to 65535)", s)
	}
	return n, nil
}

// HostPort parses host:port, [v6]:port, or a bare host when defaultPort is
// non-zero. A bare IPv6 address is a host, never host:port.
func HostPort(s string, defaultPort int) (string, int, error) {
	if defaultPort < 0 || defaultPort > 65535 {
		return "", 0, fmt.Errorf("invalid default port %d", defaultPort)
	}
	s = strings.TrimSpace(s)
	if _, err := netip.ParseAddr(s); err == nil || !strings.Contains(s, ":") ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		return bareHost(s, defaultPort)
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q (want host:port)", s)
	}
	port, err := Port(p)
	if err != nil {
		return "", 0, err
	}
	host, err := Host(h)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func bareHost(s string, defaultPort int) (string, int, error) {
	if defaultPort == 0 {
		return "", 0, fmt.Errorf("missing port in %q (want host:port)", s)
	}
	h, err := Host(s)
	if err != nil {
		return "", 0, err
	}
	return h, defaultPort, nil
}

// URL parses an http or https URL. A missing scheme means https. URLs that
// carry credentials are refused: nw never handles them.
func URL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("URL is empty")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (want http or https)", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("URLs with credentials are not supported")
	}
	if u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	host, err := Host(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port != "" {
		if _, err := Port(port); err != nil {
			return nil, err
		}
	}
	u.Host = hostPortString(host, port)
	u.Fragment = ""
	return u, nil
}

func hostPortString(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// Resolver is a DNS server chosen with --resolver.
type Resolver struct {
	Transport string // "udp" or "tcp"
	Host      string // an IP address
	Port      int
}

// Address returns host:port in the form net.Dial accepts.
func (r Resolver) Address() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
}

// String returns the flag syntax that produces r.
func (r Resolver) String() string {
	if r.Transport == "tcp" {
		return "tcp://" + r.Address()
	}
	return r.Address()
}

// ParseResolver parses one resolver address:
//
//	host, host:port, [v6]:port   plain DNS over UDP
//	tcp://host[:port]            plain DNS over TCP
//
// The host must be an IP address, because a name would need a resolver of
// its own. DNS over TLS and HTTPS arrive in a later release.
func ParseResolver(s string) (Resolver, error) {
	s = strings.TrimSpace(s)
	r := Resolver{Transport: "udp", Port: 53}
	switch {
	case strings.HasPrefix(s, "tcp://"):
		r.Transport = "tcp"
		s = strings.TrimPrefix(s, "tcp://")
	case strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "https://"):
		return r, fmt.Errorf("resolver %q: DNS over TLS and HTTPS are not supported yet", s)
	case strings.Contains(s, "://"):
		return r, fmt.Errorf("resolver %q: unknown scheme (want host, host:port or tcp://host[:port])", s)
	}
	if s == "" {
		return r, errors.New("resolver is empty")
	}
	host, port, err := HostPort(s, 53)
	if err != nil {
		return r, fmt.Errorf("resolver %q: %v", s, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return r, fmt.Errorf("resolver %q: the host must be an IP address", s)
	}
	r.Host, r.Port = a.String(), port
	return r, nil
}

// ParseResolvers parses a list of resolver addresses, keeping order and
// dropping exact duplicates.
func ParseResolvers(list []string) ([]Resolver, error) {
	var out []Resolver
	seen := map[Resolver]bool{}
	for _, s := range list {
		r, err := ParseResolver(s)
		if err != nil {
			return nil, err
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// EnvResolvers is the environment variable that sets resolvers when no
// --resolver flag is given. Its value is comma-separated.
const EnvResolvers = "NW_RESOLVERS"

// Resolvers returns the resolvers to use, taking the first source that sets
// any: the flags, then the environment.
func Resolvers(flags []string, getenv func(string) string) ([]Resolver, error) {
	if len(flags) > 0 {
		return ParseResolvers(flags)
	}
	if v := strings.TrimSpace(getenv(EnvResolvers)); v != "" {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		rs, err := ParseResolvers(parts)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", EnvResolvers, err)
		}
		return rs, nil
	}
	return nil, nil
}

// OSEnv is os.Getenv, named so call sites read clearly.
var OSEnv = os.Getenv
