package platform

import (
	"os"
	"strings"

	"github.com/miekg/dns"
)

// DNS configuration lives in resolvers.go (servers) and here (the rest).

func dnsConfig() (DNSConfig, error) {
	servers, err := SystemResolvers()
	if err != nil {
		return DNSConfig{}, err
	}
	cfg := DNSConfig{Servers: servers, Source: dnsSource}
	if servers == nil {
		cfg.Servers = []string{}
	}
	cfg.SearchDomains = searchDomains()
	return cfg, nil
}

// searchDomains reads the search list where the platform keeps it in a file.
func searchDomains() []string {
	if dnsSource != resolvConfPathValue {
		return nil
	}
	f, err := os.Open(resolvConfPathValue)
	if err != nil {
		return nil
	}
	defer f.Close()
	cfg, err := dns.ClientConfigFromReader(f)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range cfg.Search {
		out = append(out, strings.TrimSuffix(s, "."))
	}
	return out
}
