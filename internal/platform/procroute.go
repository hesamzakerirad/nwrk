package platform

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ParseProcNetRoute parses Linux /proc/net/route (IPv4). Addresses in that
// file are hexadecimal in host byte order, which is little-endian on every
// platform Linux nw is built for.
func ParseProcNetRoute(r io.Reader) ([]Route, error) {
	var out []Route
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		dst, ok1 := hexV4(f[1])
		gw, ok2 := hexV4(f[2])
		mask, ok3 := hexV4(f[7])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		bits := maskBits(mask)
		metric, _ := strconv.Atoi(f[6])
		rt := Route{Interface: f[0], Metric: metric, Family: "ipv4", Default: dst.IsUnspecified() && bits == 0}
		if !gw.IsUnspecified() {
			rt.Gateway = gw.String()
		}
		if rt.Default {
			rt.Destination = "default"
		} else {
			rt.Destination = fmt.Sprintf("%s/%d", dst, bits)
		}
		out = append(out, rt)
	}
	return out, sc.Err()
}

func hexV4(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), true
}

func maskBits(a netip.Addr) int {
	n := 0
	for _, b := range a.As4() {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				return n
			}
			n++
		}
	}
	return n
}

// ParseProcNetIPv6Route parses Linux /proc/net/ipv6_route.
func ParseProcNetIPv6Route(r io.Reader) ([]Route, error) {
	var out []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		dst, ok1 := hexV6(f[0])
		gw, ok2 := hexV6(f[4])
		bits, err := strconv.ParseUint(f[1], 16, 8)
		if !ok1 || !ok2 || err != nil {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 32)
		rt := Route{Interface: f[9], Metric: int(metric), Family: "ipv6", Default: dst.IsUnspecified() && bits == 0}
		if !gw.IsUnspecified() {
			rt.Gateway = gw.String()
		}
		if rt.Default {
			rt.Destination = "default"
		} else {
			rt.Destination = fmt.Sprintf("%s/%d", dst, bits)
		}
		out = append(out, rt)
	}
	return out, sc.Err()
}

func hexV6(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(b)), true
}
