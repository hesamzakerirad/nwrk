//go:build linux

package platform

import (
	"os"
)

func routes() ([]Route, error) {
	var out []Route
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		rs, err := ParseProcNetRoute(f)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	} else {
		return nil, err
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		defer f.Close()
		rs, err := ParseProcNetIPv6Route(f)
		if err == nil {
			out = append(out, rs...)
		}
	}
	return out, nil
}
