package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/radestsam/nwrk/internal/diagnostics/engine"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	mhttp "github.com/radestsam/nwrk/internal/measurement/http"
	mtls "github.com/radestsam/nwrk/internal/measurement/tls"
)

// Security returns the rules of nw security inspect: security-oriented
// observations about a target, independent of interference.
func Security() []engine.Rule {
	return []engine.Rule{
		DNSSECValidationFailure,
		DNSSECStatus,
		TLSCertificateExpiringSoon,
		TLSLegacyProtocolAccepted,
		HTTPNotUpgradedToHTTPS,
		HTTPHSTSMissing,
	}
}

// ExpiringSoon is how close to expiry a certificate gets a finding.
const ExpiringSoon = 14 * 24 * time.Hour

// DNSSECValidationFailure fires when the resolver cannot validate an answer
// that exists.
var DNSSECValidationFailure = engine.Rule{
	ID:          "DNSSEC_VALIDATION_FAILURE",
	Version:     1,
	Title:       "DNSSEC validation fails for this name",
	Description: "A validating resolver answers SERVFAIL, while the same query with validation disabled returns an answer.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"A name's signatures can be broken or expired because of a mistake at its zone, and also by a change in transit.",
		"The check says the answer fails validation, not why; resolvers differ in how strictly they validate.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		for _, m := range in.Probes(domain.TypeDNS, domain.ProbeDNSSEC) {
			res, ok := engine.ResultOf[dns.InspectResult](m)
			if !ok || !res.ValidationFailure {
				continue
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("%s answers SERVFAIL for %s unless validation is disabled, which means DNSSEC validation fails", m.Resolver.Address, m.Target.Host),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{
					{
						Summary:    "The zone's DNSSEC signatures are broken or expired, a mistake at the domain's operator",
						Confidence: domain.ConfidenceMedium,
						Supporting: []domain.Evidence{ev("The answer exists but does not validate", m.ID)},
						Missing:    []domain.Evidence{missing("The zone was not checked with another validating resolver")},
					},
					{
						Summary:    "The answer was altered on its way to the resolver, so it no longer matches its signatures",
						Confidence: domain.ConfidenceLow,
						Supporting: []domain.Evidence{ev("A changed answer fails validation exactly this way", m.ID)},
						Missing:    []domain.Evidence{missing("No second validating resolver was compared")},
					},
				},
				Recommendations: []domain.Recommendation{
					{Summary: "Compare with another validating resolver", Command: cmd("security", "inspect", m.Target.Host, "--resolver", "<ip>")},
				},
			})
		}
		return out
	},
}

// DNSSECStatus reports whether the name is signed, as information.
var DNSSECStatus = engine.Rule{
	ID:          "DNSSEC_STATUS",
	Version:     1,
	Title:       "DNSSEC status of the name",
	Description: "Whether the answer carries DNSSEC signatures and whether the resolver validated them. Informational.",
	Layer:       engine.LayerDNS,
	Requires:    []domain.Type{domain.TypeDNS},
	Caveats: []string{
		"Many names are not signed, and that is not a fault.",
		"The authenticated-data flag is the resolver's own statement; it is only as trustworthy as the path to the resolver.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		for _, m := range succeeded(in.Probes(domain.TypeDNS, domain.ProbeDNSSEC)) {
			res, ok := engine.ResultOf[dns.InspectResult](m)
			if !ok || res.ValidationFailure {
				continue
			}
			var state string
			switch {
			case res.Signed && res.Authenticated:
				state = "is signed, and the resolver reports it validated the answer"
			case res.Signed:
				state = "is signed, but the resolver did not report validating the answer"
			default:
				state = "is not signed"
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityInfo,
				Summary:        fmt.Sprintf("%s %s (asked of %s)", m.Target.Host, state, m.Resolver.Address),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{{
					Summary:    "This is the name's DNSSEC deployment as seen through one resolver",
					Confidence: domain.ConfidenceMedium,
					Supporting: []domain.Evidence{ev("The answer was inspected for signatures and the AD flag", m.ID)},
					Missing:    []domain.Evidence{missing("The chain of trust was not walked from the root; only the resolver's report is used")},
				}},
			})
		}
		return out
	},
}

// TLSCertificateExpiringSoon fires when a valid certificate is close to expiry.
var TLSCertificateExpiringSoon = engine.Rule{
	ID:          "TLS_CERTIFICATE_EXPIRING_SOON",
	Version:     1,
	Title:       "The certificate expires soon",
	Description: "The server's certificate is valid now and expires within 14 days.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS},
	Caveats: []string{
		"Servers that renew automatically may replace the certificate shortly before it expires, so a near expiry can be normal.",
		"The date is compared with this machine's clock.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		now := time.Now()
		var out []engine.Outcome
		seen := map[string]bool{}
		for _, m := range succeeded(in.Measurements(domain.TypeTLS)) {
			res, ok := engine.ResultOf[mtls.Result](m)
			if !ok || len(res.Certificates) == 0 {
				continue
			}
			left := res.Certificates[0].NotAfter.Sub(now)
			key := res.Certificates[0].NotAfter.String()
			if left <= 0 || left > ExpiringSoon || seen[key] {
				continue
			}
			seen[key] = true
			days := int(left.Hours() / 24)
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("The certificate of %s expires in %d days (%s)", m.Target.Host, days, res.Certificates[0].NotAfter.Format("2006-01-02")),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{{
					Summary:    "Renewal is overdue or has failed, or automatic renewal will replace it shortly",
					Confidence: domain.ConfidenceLow,
					Supporting: []domain.Evidence{ev("The validity period ends soon", m.ID)},
					Missing:    []domain.Evidence{missing("Whether renewal is automated is unknown")},
				}},
				Recommendations: []domain.Recommendation{{Summary: "Tell the operator of the site if renewal is not automatic"}},
			})
		}
		return out
	},
}

// TLSLegacyProtocolAccepted fires when a server still accepts TLS 1.0 or 1.1.
var TLSLegacyProtocolAccepted = engine.Rule{
	ID:          "TLS_LEGACY_PROTOCOL_ACCEPTED",
	Version:     1,
	Title:       "The server accepts TLS 1.0 or 1.1",
	Description: "A handshake limited to TLS 1.0 and 1.1 succeeded. Both versions are deprecated.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS},
	Caveats: []string{
		"This is a property of the server's configuration, not of this connection. A client that supports TLS 1.2 or later negotiates the newer version.",
		"Some servers keep old versions on for legacy clients on purpose.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		for _, m := range succeeded(in.Probes(domain.TypeTLS, domain.ProbeLegacyTLS)) {
			res, _ := engine.ResultOf[mtls.Result](m)
			v := ""
			if res != nil {
				v = res.Version
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityWarning,
				Summary:        fmt.Sprintf("%s accepted a handshake limited to deprecated versions (%s)", endpoint(m), v),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{{
					Summary:    "The server's TLS configuration still enables TLS 1.0 and 1.1",
					Confidence: domain.ConfidenceMedium,
					Supporting: []domain.Evidence{ev("A handshake offering only TLS 1.0 and 1.1 succeeded", m.ID)},
					Missing:    []domain.Evidence{missing("Whether the setting is deliberate is unknown")},
				}},
				Recommendations: []domain.Recommendation{{Summary: "Tell the operator of the site that TLS 1.0 and 1.1 are deprecated (RFC 8996)"}},
			})
		}
		return out
	},
}

// HTTPNotUpgradedToHTTPS fires when plain http is served without a redirect to https.
var HTTPNotUpgradedToHTTPS = engine.Rule{
	ID:          "HTTP_NOT_UPGRADED_TO_HTTPS",
	Version:     1,
	Title:       "Plain http is not upgraded to https",
	Description: "A request over http gets a final response over http, with no redirect to https, although the site is reachable over https. Informational.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"Some sites deliberately serve only a few resources over http, such as certificate revocation or captive-portal checks.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		secure := succeeded(in.Measurements(domain.TypeHTTP))
		if len(secure) == 0 {
			return nil
		}
		var out []engine.Outcome
		for _, p := range succeeded(in.Probes(domain.TypeHTTP, domain.ProbePlainHTTP)) {
			res, ok := engine.ResultOf[mhttp.Result](p)
			if !ok || strings.HasPrefix(res.FinalURL, "https://") || res.StatusCode >= 400 {
				continue
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityInfo,
				Summary:        fmt.Sprintf("%s answers over plain http (%d) without redirecting to https", p.Target.Host, res.StatusCode),
				MeasurementIDs: []string{p.ID, secure[0].ID},
				Hypotheses: []domain.Hypothesis{{
					Summary:    "The site serves content over http on purpose or has not set up the redirect",
					Confidence: domain.ConfidenceMedium,
					Supporting: []domain.Evidence{ev("The final response came over http", p.ID)},
					Missing:    []domain.Evidence{missing("The site's intent is unknown")},
				}},
			})
		}
		return out
	},
}

// HTTPHSTSMissing fires when https responses carry no Strict-Transport-Security header.
var HTTPHSTSMissing = engine.Rule{
	ID:          "HTTP_HSTS_MISSING",
	Version:     1,
	Title:       "No Strict-Transport-Security header",
	Description: "The https response has no Strict-Transport-Security header. Informational.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"The header is a hardening measure. Its absence is common and is not a fault by itself.",
		"Only the final response of the chain is looked at, and only the headers nw keeps.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var out []engine.Outcome
		for _, m := range succeeded(in.Measurements(domain.TypeHTTP)) {
			res, ok := engine.ResultOf[mhttp.Result](m)
			if !ok || !strings.HasPrefix(res.FinalURL, "https://") {
				continue
			}
			if _, has := res.Headers["strict-transport-security"]; has {
				continue
			}
			out = append(out, engine.Outcome{
				Severity:       domain.SeverityInfo,
				Summary:        fmt.Sprintf("The https response of %s has no Strict-Transport-Security header", m.Target.Host),
				MeasurementIDs: []string{m.ID},
				Hypotheses: []domain.Hypothesis{{
					Summary:    "The site has not enabled HSTS",
					Confidence: domain.ConfidenceMedium,
					Supporting: []domain.Evidence{ev("The header is not in the response", m.ID)},
					Missing:    []domain.Evidence{missing("Whether the header appears on other paths was not checked")},
				}},
			})
		}
		return out
	},
}
