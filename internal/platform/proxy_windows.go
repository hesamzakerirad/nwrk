//go:build windows

package platform

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// systemProxies reads the per-user Internet Settings, which the system and
// most browsers use.
func systemProxies() []ProxySetting {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if enabled, _, err := k.GetIntegerValue("ProxyEnable"); err != nil || enabled == 0 {
		return nil
	}
	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil || server == "" {
		return nil
	}
	var out []ProxySetting
	// The value is either "host:port" or "http=host:port;https=host:port".
	for _, part := range strings.Split(server, ";") {
		scheme, host := "", part
		if i := strings.Index(part, "="); i >= 0 {
			scheme, host = part[:i], part[i+1:]
		}
		_, h := splitProxy(host)
		out = append(out, ProxySetting{Source: "Windows Internet Settings", Scheme: scheme, Host: h})
	}
	if override, _, err := k.GetStringValue("ProxyOverride"); err == nil && override != "" {
		out = append(out, ProxySetting{Source: "Windows Internet Settings", NoProxy: override})
	}
	return out
}
