package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	mtls "github.com/hesamzakerirad/nwrk/internal/measurement/tls"
)

// TLSCertificateInvalid fires when the certificate fails verification.
var TLSCertificateInvalid = engine.Rule{
	ID:          "TLS_CERTIFICATE_INVALID",
	Version:     1,
	Title:       "TLS certificate is not valid",
	Description: "The server's certificate failed verification: it is expired, not trusted, or issued for another name.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS},
	Caveats: []string{
		"Verification uses this machine's trust store and clock. A wrong clock or a missing root certificate here produces the same error as a bad certificate on the server.",
		"A certificate for a different name can mean the server is misconfigured, or that the connection reached a different server than intended.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeTLS)
		bad := withCode(all, domain.TLSCertExpired, domain.TLSCertUntrusted, domain.TLSHostnameMismatch)
		if len(bad) == 0 {
			return nil
		}
		good := succeeded(all)
		host := in.Target()
		first := bad[0]
		o := engine.Outcome{
			Severity:       severityByCoverage(len(bad), len(good)),
			Summary:        fmt.Sprintf("The certificate presented by %s for %s is not valid (%s)", endpoints(bad), host, codes(bad)),
			MeasurementIDs: engine.IDs(bad),
			Recommendations: []domain.Recommendation{
				{Summary: "Inspect the certificate details in the report: subject, issuer, validity and names"},
				{Summary: "Compare from a different network to see whether another certificate is served there"},
			},
		}
		res, _ := engine.ResultOf[mtls.Result](first)
		for _, code := range []domain.ErrorCode{domain.TLSCertExpired, domain.TLSCertUntrusted, domain.TLSHostnameMismatch} {
			ms := withCode(bad, code)
			if len(ms) == 0 {
				continue
			}
			h := certHypothesis(code, ms, res, host)
			if len(good) > 0 {
				h.Contradicting = append(h.Contradicting, ev("TLS verified for "+endpoints(good), engine.IDs(good)...))
				h.Confidence = domain.ConfidenceLow
			}
			o.Hypotheses = append(o.Hypotheses, h)
		}
		return []engine.Outcome{o}
	},
}

func certHypothesis(code domain.ErrorCode, ms []domain.Measurement, res *mtls.Result, host string) domain.Hypothesis {
	ids := engine.IDs(ms)
	var leaf *mtls.Certificate
	if res != nil && len(res.Certificates) > 0 {
		leaf = &res.Certificates[0]
	}
	switch code {
	case domain.TLSCertExpired:
		h := domain.Hypothesis{
			Summary:    "The server's certificate has expired and was not renewed, or this machine's clock is wrong",
			Confidence: domain.ConfidenceMedium,
			Missing:    []domain.Evidence{missing("This machine's clock was not compared with a trusted time source")},
		}
		if leaf != nil {
			h.Supporting = []domain.Evidence{ev(fmt.Sprintf("The certificate is valid from %s to %s", leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02")), ids...)}
			if time.Since(leaf.NotAfter) > 48*time.Hour {
				h.Confidence = domain.ConfidenceHigh
			}
		}
		return h
	case domain.TLSCertUntrusted:
		h := domain.Hypothesis{
			Summary:    "The chain does not lead to a root this machine trusts: a self-signed certificate, a missing intermediate, or a device on the path presenting its own certificate",
			Confidence: domain.ConfidenceMedium,
			Missing:    []domain.Evidence{missing("The path was not compared with a network known to be direct")},
		}
		if leaf != nil {
			h.Supporting = []domain.Evidence{ev("Issuer: "+leaf.Issuer+"; subject: "+leaf.Subject, ids...)}
			if leaf.Issuer == leaf.Subject {
				h.Summary = "The server presents a self-signed certificate"
				h.Confidence = domain.ConfidenceHigh
			}
		}
		return h
	}
	h := domain.Hypothesis{
		Summary:    "The certificate was issued for other names: the server is misconfigured, or the connection reached a different server than intended",
		Confidence: domain.ConfidenceMedium,
		Missing:    []domain.Evidence{missing("Which server the address belongs to was not established")},
	}
	if leaf != nil {
		h.Supporting = []domain.Evidence{ev(fmt.Sprintf("The certificate names %s; the name asked for was %s", strings.Join(leaf.SANs, ", "), host), ids...)}
	}
	return h
}

// TLSHandshakeFailureAfterTCP fires when TCP worked and the handshake did not.
var TLSHandshakeFailureAfterTCP = engine.Rule{
	ID:          "TLS_HANDSHAKE_FAILURE_AFTER_TCP",
	Version:     1,
	Title:       "TLS handshake failed after the connection was established",
	Description: "The TCP connection to an address succeeded, but the TLS handshake with the same address did not complete.",
	Layer:       engine.LayerTLS,
	Requires:    []domain.Type{domain.TypeTLS, domain.TypeTCP},
	Caveats: []string{
		"A failed handshake can come from the server's configuration, this client's configuration, a proxy or other device on the path, or interference with the connection. The error alone does not distinguish these.",
		"Certificate problems are reported separately by TLS_CERTIFICATE_INVALID, not here.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		tcpOK := map[string]bool{}
		for _, m := range succeeded(in.Measurements(domain.TypeTCP)) {
			tcpOK[endpoint(m)] = true
		}
		all := in.Measurements(domain.TypeTLS)
		bad := filter(withCode(all, domain.TLSHandshakeFailure, domain.TLSReset, domain.TLSTimeout, domain.TLSError),
			func(m domain.Measurement) bool { return tcpOK[endpoint(m)] })
		if len(bad) == 0 {
			return nil
		}
		good := succeeded(all)
		ids := engine.IDs(bad)
		o := engine.Outcome{
			Severity:       severityByCoverage(len(bad), len(good)),
			Summary:        fmt.Sprintf("TCP to %s succeeded, but the TLS handshake failed (%s)", endpoints(bad), codes(bad)),
			MeasurementIDs: ids,
			Recommendations: []domain.Recommendation{
				{Summary: "Repeat the handshake to see whether the failure is consistent", Command: cmd("test", "tls", in.Target())},
				{Summary: "Compare with a known-good TLS client on the same machine, for example curl -v or openssl s_client"},
				{Summary: "Repeat from a different network or machine to see whether the failure depends on the path"},
			},
		}
		contra := []domain.Evidence{}
		if len(good) > 0 {
			contra = []domain.Evidence{ev("The handshake succeeded with "+endpoints(good), engine.IDs(good)...)}
		}
		common := []domain.Evidence{missing("No comparison from a different network was made"), missing("No comparison with a known-good TLS client was made")}
		observed := ev("The handshake ended with "+codes(bad)+" after a successful TCP connection", ids...)

		server := domain.Hypothesis{
			Summary:       "The server rejected or could not complete the handshake: a configuration incompatibility, or a server-side failure",
			Confidence:    domain.ConfidenceMedium,
			Supporting:    []domain.Evidence{observed},
			Contradicting: contra,
			Missing:       common,
		}
		path := domain.Hypothesis{
			Summary:       "A proxy or other device on the path interfered with the connection after it was established",
			Confidence:    domain.ConfidenceLow,
			Supporting:    []domain.Evidence{observed},
			Contradicting: contra,
			Missing:       common,
		}
		if len(withCode(bad, domain.TLSReset, domain.TLSTimeout)) == len(bad) {
			server.Confidence, path.Confidence = domain.ConfidenceLow, domain.ConfidenceMedium
			path.Supporting = append(path.Supporting, ev("A reset or silence during the handshake is what both a failing server and an intervening device produce", ids...))
		}
		o.Hypotheses = []domain.Hypothesis{server, path}
		return []engine.Outcome{o}
	},
}
