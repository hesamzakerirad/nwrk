// Package rules holds the diagnostic rules of nw. Each rule is explicit and
// deterministic; docs/findings.md documents every one with its caveats.
package rules

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
)

// All returns the rules in the order they are evaluated.
func All() []engine.Rule {
	return []engine.Rule{
		DNSResolutionFailure,
		NoUsableAddress,
		TCPConnectionRefused,
		TCPConnectionTimeout,
		TLSCertificateInvalid,
		TLSHandshakeFailureAfterTCP,
		HTTPErrorResponse,
		HTTPRequestFailure,
		IPFamilyBehaviorDifference,
	}
}

func failed(ms []domain.Measurement) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool { return m.Status == domain.StatusFailure })
}

func succeeded(ms []domain.Measurement) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool { return m.Status == domain.StatusSuccess })
}

func withCode(ms []domain.Measurement, codes ...domain.ErrorCode) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool {
		if m.Status != domain.StatusFailure || m.Error == nil {
			return false
		}
		for _, c := range codes {
			if m.Error.Code == c {
				return true
			}
		}
		return false
	})
}

func filter(ms []domain.Measurement, keep func(domain.Measurement) bool) []domain.Measurement {
	var out []domain.Measurement
	for _, m := range ms {
		if keep(m) {
			out = append(out, m)
		}
	}
	return out
}

func codes(ms []domain.Measurement) string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if m.Error != nil && !seen[string(m.Error.Code)] {
			seen[string(m.Error.Code)] = true
			out = append(out, string(m.Error.Code))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// resolverName says which resolver produced a DNS measurement.
func resolverName(m domain.Measurement) string {
	if m.Resolver == nil {
		return "unknown resolver"
	}
	if m.Resolver.Kind == "system" {
		return "the system resolver"
	}
	return "resolver " + m.Resolver.Address + " (" + m.Resolver.Kind + ")"
}

func resolverNames(ms []domain.Measurement) string {
	var out []string
	for _, m := range ms {
		out = append(out, resolverName(m))
	}
	return strings.Join(out, ", ")
}

// endpoint is ip:port of a connection measurement.
func endpoint(m domain.Measurement) string {
	if m.Target.IP == "" {
		return m.Target.Host
	}
	return net.JoinHostPort(m.Target.IP, strconv.Itoa(m.Target.Port))
}

func endpoints(ms []domain.Measurement) string {
	var out []string
	for _, m := range ms {
		out = append(out, endpoint(m))
	}
	return strings.Join(out, ", ")
}

func ev(text string, ids ...string) domain.Evidence {
	return domain.Evidence{Text: text, MeasurementIDs: ids}
}

func missing(text string) domain.Evidence { return domain.Evidence{Text: text} }

// severityByCoverage is an error when nothing of the layer worked, and a
// warning when only some of it failed.
func severityByCoverage(failedN, okN int) domain.Severity {
	if okN == 0 && failedN > 0 {
		return domain.SeverityError
	}
	return domain.SeverityWarning
}

// cmd builds the nw command that repeats a measurement.
func cmd(parts ...string) string { return "nw " + strings.Join(parts, " ") }

type netipAddr = netip.Addr
