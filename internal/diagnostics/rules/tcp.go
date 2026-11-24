package rules

import (
	"fmt"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
)

func portOf(ms []domain.Measurement) int {
	for _, m := range ms {
		if m.Target.Port != 0 {
			return m.Target.Port
		}
	}
	return 0
}

// TCPConnectionRefused fires when a destination answers that nothing listens.
var TCPConnectionRefused = engine.Rule{
	ID:          "TCP_CONNECTION_REFUSED",
	Version:     1,
	Title:       "TCP connection refused",
	Description: "A destination actively refused the TCP connection.",
	Layer:       engine.LayerTCP,
	Requires:    []domain.Type{domain.TypeTCP},
	Caveats: []string{
		"A refusal can come from the destination host, from a firewall in front of it, or from a device on the path that rejects connections; the error alone does not say which.",
		"A refusal on one address while others succeed is common during maintenance or with load balancers.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeTCP)
		bad := withCode(all, domain.TCPRefused)
		if len(bad) == 0 {
			return nil
		}
		good := succeeded(all)
		port := portOf(bad)
		h1 := domain.Hypothesis{
			Summary:    fmt.Sprintf("Nothing is listening on port %d at the destination: the service is down, not started, or the port is wrong", port),
			Confidence: domain.ConfidenceMedium,
			Supporting: []domain.Evidence{ev("Connection refused by "+endpoints(bad), engine.IDs(bad)...)},
			Missing:    []domain.Evidence{missing("The service's state on the destination host is unknown")},
		}
		if len(good) == len(all)-len(bad) && len(good) == 0 && len(bad) >= 2 {
			h1.Confidence = domain.ConfidenceHigh
		}
		if len(good) > 0 {
			h1.Contradicting = []domain.Evidence{ev("Connection succeeded to "+endpoints(good), engine.IDs(good)...)}
		}
		h2 := domain.Hypothesis{
			Summary:    "A firewall or other device on the path rejects the connection on purpose",
			Confidence: domain.ConfidenceLow,
			Supporting: []domain.Evidence{ev("A refusal looks the same whether it comes from the host or from a device in front of it", engine.IDs(bad)...)},
			Missing:    []domain.Evidence{missing("No comparison from a different network was made")},
		}
		return []engine.Outcome{{
			Severity:       severityByCoverage(len(bad), len(good)),
			Summary:        fmt.Sprintf("Connection to %s was refused", endpoints(bad)),
			MeasurementIDs: engine.IDs(bad),
			Hypotheses:     []domain.Hypothesis{h1, h2},
			Recommendations: []domain.Recommendation{
				{Summary: fmt.Sprintf("Check that port %d is the right port for the service", port)},
				{Summary: "Repeat the test from a different network or machine to see whether the refusal depends on the path"},
			},
		}}
	},
}

// TCPConnectionTimeout fires when a destination never answers the connection.
var TCPConnectionTimeout = engine.Rule{
	ID:          "TCP_CONNECTION_TIMEOUT",
	Version:     1,
	Title:       "TCP connection timed out",
	Description: "A destination did not answer the TCP connection attempt before the deadline.",
	Layer:       engine.LayerTCP,
	Requires:    []domain.Type{domain.TypeTCP},
	Caveats: []string{
		"A timeout means no answer arrived in time. Packet loss, a slow path, a dropped SYN and a filtered port all look the same.",
		"The deadline is set by --timeout. A slow but working path can time out when the deadline is short.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeTCP)
		bad := withCode(all, domain.TCPTimeout)
		if len(bad) == 0 {
			return nil
		}
		good := succeeded(all)
		h1 := domain.Hypothesis{
			Summary:    "Packets to or from the destination are dropped or filtered on the path, or by the destination's firewall",
			Confidence: domain.ConfidenceMedium,
			Supporting: []domain.Evidence{ev("No answer from "+endpoints(bad)+" before the deadline", engine.IDs(bad)...)},
			Missing:    []domain.Evidence{missing("No path measurement (routing, MTU) has been run")},
		}
		h2 := domain.Hypothesis{
			Summary:    "The destination host is down, unreachable, or too overloaded to answer",
			Confidence: domain.ConfidenceLow,
			Supporting: []domain.Evidence{ev("A host that is off gives the same silence", engine.IDs(bad)...)},
			Missing:    []domain.Evidence{missing("No comparison from a different network was made")},
		}
		if len(good) > 0 {
			h1.Confidence, h2.Confidence = domain.ConfidenceLow, domain.ConfidenceLow
			c := ev("Connection succeeded to "+endpoints(good), engine.IDs(good)...)
			h1.Contradicting, h2.Contradicting = []domain.Evidence{c}, []domain.Evidence{c}
		}
		return []engine.Outcome{{
			Severity:       severityByCoverage(len(bad), len(good)),
			Summary:        fmt.Sprintf("No answer from %s before the deadline", endpoints(bad)),
			MeasurementIDs: engine.IDs(bad),
			Hypotheses:     []domain.Hypothesis{h1, h2},
			Recommendations: []domain.Recommendation{
				{Summary: "Repeat with a longer deadline to rule out a slow path", Command: cmd("test", "tcp", fmt.Sprintf("%s:%d", in.Target(), portOf(bad)), "--timeout", "30s")},
				{Summary: "Repeat the test from a different network or machine to see whether the timeout depends on the path"},
			},
		}}
	},
}
