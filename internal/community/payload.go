// Package community runs the approved community measurement profiles and
// builds the contribution document. It holds no state and starts no
// background work.
package community

import (
	"math"
	"strings"

	"github.com/radestsam/nwrk/contracts"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
)

// Contribution values. They match the contract schema.
const (
	outcomeSuccess  = "success"
	outcomeResponse = "response_received"
	outcomeFailure  = "failure"

	maxDurationMS  = 60000
	maxAnswerCount = 64
)

// allowedErrors is the set of error codes that the contract accepts.
var allowedErrors = map[string]bool{}

func init() {
	for _, c := range []domain.ErrorCode{
		domain.DNSNXDomain, domain.DNSServFail, domain.DNSRefused, domain.DNSNoAnswer, domain.DNSTimeout, domain.DNSTransport, domain.DNSError,
		domain.TCPRefused, domain.TCPTimeout, domain.TCPUnreachable, domain.TCPReset, domain.TCPError,
		domain.TLSCertExpired, domain.TLSCertUntrusted, domain.TLSHostnameMismatch, domain.TLSHandshakeFailure, domain.TLSReset, domain.TLSTimeout, domain.TLSError,
		domain.HTTPTimeout, domain.HTTPRedirectLoop, domain.HTTPProtocolError, domain.HTTPReset, domain.HTTPError,
	} {
		allowedErrors[string(c)] = true
	}
}

// The functions in this file are the only place where engine results become
// contribution data. Each one builds a contracts.Measurement field by field
// from an allowlist. Nothing here marshals an engine result, so an address, a
// resolver, a certificate, a header, a URL or an error message cannot reach
// the document.

// errorCode maps an engine error to a contract error code. A code that the
// contract does not know, such as a local.* code, becomes the generic error of
// the layer.
func errorCode(layer string, e *domain.Error) string {
	if e != nil && allowedErrors[string(e.Code)] {
		code := string(e.Code)
		// A DNS layer holds only DNS errors.
		if layer != "dns" || strings.HasPrefix(code, "dns.") {
			return code
		}
	}
	return layer + ".error"
}

// millis rounds a duration to whole milliseconds inside the contract bounds.
func millis(ms float64) int {
	if math.IsNaN(ms) || ms < 0 {
		return 0
	}
	return int(math.Min(math.Round(ms), maxDurationMS))
}

// dnsMeasurement builds the DNS measurement of one family from the query that
// was sent for it. The system resolver gives no response code, so none is set.
func dnsMeasurement(family string, q dns.QueryResult) contracts.Measurement {
	m := contracts.Measurement{Layer: "dns", Family: family, DurationMS: millis(q.DurationMS)}
	if q.Error == nil && len(q.Answers) > 0 {
		m.Outcome = outcomeSuccess
		m.AnswerCount = min(len(q.Answers), maxAnswerCount)
		return m
	}
	m.Outcome = outcomeFailure
	m.Error = errorCode("dns", q.Error)
	return m
}

// stepMeasurement builds a TCP or TLS measurement. The duration is the time of
// the measurement itself, not a value from its result.
func stepMeasurement(layer, family string, m *domain.Measurement) contracts.Measurement {
	out := contracts.Measurement{Layer: layer, Family: family, DurationMS: millis(m.DurationMS)}
	if m.Status == domain.StatusSuccess {
		out.Outcome = outcomeSuccess
		return out
	}
	out.Outcome = outcomeFailure
	out.Error = errorCode(layer, m.Error)
	return out
}

// httpMeasurement builds the HTTP measurement. Only the status code of the
// response is kept. Any status is a received response, as in a 403 or a 451.
func httpMeasurement(family string, status int, m *domain.Measurement) contracts.Measurement {
	out := contracts.Measurement{Layer: "http", Family: family, DurationMS: millis(m.DurationMS)}
	if m.Status == domain.StatusSuccess && status >= 100 && status <= 599 {
		out.Outcome = outcomeResponse
		out.StatusCode = status
		return out
	}
	out.Outcome = outcomeFailure
	out.Error = errorCode("http", m.Error)
	return out
}
