//go:build !windows

package platform

// systemProxies returns nothing: on Linux and macOS only the environment is
// read. The macOS system proxy settings need the SystemConfiguration
// framework, which nw does not link; see docs/platform-support.md.
func systemProxies() []ProxySetting { return nil }
