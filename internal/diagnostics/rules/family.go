package rules

import (
	"fmt"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
)

// IPFamilyBehaviorDifference fires when IPv4 and IPv6 behave differently.
var IPFamilyBehaviorDifference = engine.Rule{
	ID:          "IP_FAMILY_BEHAVIOR_DIFFERENCE",
	Version:     1,
	Title:       "IPv4 and IPv6 behave differently",
	Description: "The name has both IPv4 and IPv6 addresses, and one family works at a layer where the other fails.",
	Layer:       engine.LayerIPFamily,
	Requires:    []domain.Type{domain.TypeDNS, domain.TypeTCP},
	Caveats: []string{
		"A name with no AAAA record is not an IPv6 failure, and this rule does not fire for it.",
		"Many networks have no IPv6 connectivity at all. When IPv6 fails only because there is no route, the finding is informational.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		for _, t := range []domain.Type{domain.TypeTCP, domain.TypeTLS, domain.TypeHTTP} {
			ms := in.Measurements(t)
			v4, v6 := byFamily(ms, "ipv4"), byFamily(ms, "ipv6")
			if len(v4) == 0 || len(v6) == 0 {
				continue
			}
			ok4, ok6 := len(succeeded(v4)) > 0, len(succeeded(v6)) > 0
			bad4, bad6 := failed(v4), failed(v6)
			switch {
			case ok4 && !ok6 && len(bad6) > 0:
				return []engine.Outcome{familyOutcome(t, "ipv4", "ipv6", succeeded(v4), bad6)}
			case ok6 && !ok4 && len(bad4) > 0:
				return []engine.Outcome{familyOutcome(t, "ipv6", "ipv4", succeeded(v6), bad4)}
			}
		}
		return nil
	},
}

func byFamily(ms []domain.Measurement, family string) []domain.Measurement {
	return filter(ms, func(m domain.Measurement) bool {
		return m.Target.Family == family && m.Status != domain.StatusSkipped
	})
}

func familyOutcome(layer domain.Type, working, broken string, good, bad []domain.Measurement) engine.Outcome {
	ids := append(engine.IDs(good), engine.IDs(bad)...)
	severity := domain.SeverityWarning
	noRoute := len(withCode(bad, domain.TCPUnreachable)) == len(bad)
	if broken == "ipv6" && noRoute {
		severity = domain.SeverityInfo
	}
	h := domain.Hypothesis{
		Supporting: []domain.Evidence{
			ev(fmt.Sprintf("%s worked at the %s layer", working, layer), engine.IDs(good)...),
			ev(fmt.Sprintf("%s failed at the %s layer (%s)", broken, layer, codes(bad)), engine.IDs(bad)...),
		},
	}
	switch {
	case broken == "ipv6" && noRoute:
		h.Summary = "This network has no IPv6 connectivity, which is normal and not a fault of the destination"
		h.Confidence = domain.ConfidenceHigh
		h.Missing = []domain.Evidence{missing("Local IPv6 configuration was not inspected")}
	case broken == "ipv6":
		h.Summary = "The IPv6 path or the destination's IPv6 service is broken or filtered, while IPv4 works"
		h.Confidence = domain.ConfidenceMedium
		h.Missing = []domain.Evidence{missing("Whether this network offers IPv6 at all was not checked")}
	default:
		h.Summary = "The IPv4 path or the destination's IPv4 service is broken or filtered, while IPv6 works"
		h.Confidence = domain.ConfidenceMedium
		h.Missing = []domain.Evidence{missing("Whether the IPv4 failure is specific to this network was not checked")}
	}
	return engine.Outcome{
		Severity:       severity,
		Summary:        fmt.Sprintf("%s works and %s fails at the %s layer (%s)", working, broken, layer, codes(bad)),
		MeasurementIDs: ids,
		Hypotheses:     []domain.Hypothesis{h},
		Recommendations: []domain.Recommendation{
			{Summary: fmt.Sprintf("Repeat the %s measurement for the %s addresses to check the failure is consistent", layer, broken)},
		},
	}
}
