package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
)

// HTTPErrorResponse fires when the server answers with an error status.
var HTTPErrorResponse = engine.Rule{
	ID:          "HTTP_ERROR_RESPONSE",
	Version:     1,
	Title:       "The server answered with an error status",
	Description: "An HTTP request completed, and the final response has a status of 400 or above.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"A 4xx status usually reflects the requested path or access rules, not the network. Only 5xx and 429 are reported as warnings.",
		"CDNs and bot protection can answer a bare command-line client differently from a browser: nw sends no cookies and a minimal User-Agent.",
		"A response proves some server answered, not that it is the intended origin.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		var bad []domain.Measurement
		statuses := map[int]bool{}
		for _, m := range succeeded(in.Measurements(domain.TypeHTTP)) {
			if res, ok := engine.ResultOf[mhttp.Result](m); ok && res.StatusCode >= 400 {
				bad = append(bad, m)
				statuses[res.StatusCode] = true
			}
		}
		if len(bad) == 0 {
			return nil
		}
		var list []int
		severity := domain.SeverityInfo
		for s := range statuses {
			list = append(list, s)
			if s >= 500 || s == 429 {
				severity = domain.SeverityWarning
			}
		}
		sort.Ints(list)
		var names []string
		for _, s := range list {
			names = append(names, fmt.Sprint(s))
		}
		ids := engine.IDs(bad)
		o := engine.Outcome{
			Severity:       severity,
			Summary:        fmt.Sprintf("The server answered %s", strings.Join(names, ", ")),
			MeasurementIDs: ids,
			Recommendations: []domain.Recommendation{
				{Summary: "Request a specific path you expect to exist, rather than the root", Command: cmd("test", "http", "<url>")},
			},
		}
		for _, s := range list {
			o.Hypotheses = append(o.Hypotheses, httpStatusHypothesis(s, ids))
		}
		return []engine.Outcome{o}
	},
}

func httpStatusHypothesis(status int, ids []string) domain.Hypothesis {
	seen := ev(fmt.Sprintf("The final response had status %d", status), ids...)
	h := domain.Hypothesis{Confidence: domain.ConfidenceMedium, Supporting: []domain.Evidence{seen}}
	switch {
	case status == 429:
		h.Summary = "The server or a CDN is rate limiting this client"
		h.Missing = []domain.Evidence{missing("The rate limit policy and this client's request history are unknown")}
	case status >= 500:
		h.Summary = "The origin server, or an upstream behind a CDN or proxy, is failing or overloaded"
		h.Missing = []domain.Evidence{missing("Whether the failure is persistent was not established; repeat the request")}
	case status == 401 || status == 403:
		h.Summary = "Access rules, bot protection or geographic policy restrict this request"
		h.Confidence = domain.ConfidenceLow
		h.Missing = []domain.Evidence{missing("A comparison with a browser or another network was not made")}
	case status == 404 || status == 410:
		h.Summary = "The root path does not exist on this server; the service may live at another path"
		h.Missing = []domain.Evidence{missing("The path to use is unknown to nw")}
	default:
		h.Summary = "The server rejected the request as sent"
		h.Confidence = domain.ConfidenceLow
		h.Missing = []domain.Evidence{missing("The server's reason is not visible without its response body, which nw does not keep")}
	}
	return h
}

// HTTPRequestFailure fires when the request itself failed at the HTTP level.
var HTTPRequestFailure = engine.Rule{
	ID:          "HTTP_REQUEST_FAILURE",
	Version:     1,
	Title:       "The HTTP request failed",
	Description: "The request did not complete: no full response arrived, a redirect looped, or the reply was not valid HTTP.",
	Layer:       engine.LayerHTTP,
	Requires:    []domain.Type{domain.TypeHTTP},
	Caveats: []string{
		"A timeout after the connection and TLS succeeded means the server stayed silent; a slow server and a stalled path look the same.",
		"Failures in DNS, TCP or TLS during the request are reported by the rules of those layers.",
	},
	Evaluate: func(in *engine.Input) []engine.Outcome {
		all := in.Measurements(domain.TypeHTTP)
		bad := withCode(all, domain.HTTPTimeout, domain.HTTPRedirectLoop, domain.HTTPProtocolError, domain.HTTPReset, domain.HTTPError)
		if len(bad) == 0 {
			return nil
		}
		ids := engine.IDs(bad)
		o := engine.Outcome{
			Severity:       severityByCoverage(len(bad), len(succeeded(all))),
			Summary:        fmt.Sprintf("The HTTP request failed (%s)", codes(bad)),
			MeasurementIDs: ids,
			Recommendations: []domain.Recommendation{
				{Summary: "Repeat the request to see whether the failure is consistent", Command: cmd("test", "http", "<url>")},
			},
		}
		for _, code := range []domain.ErrorCode{domain.HTTPRedirectLoop, domain.HTTPTimeout, domain.HTTPProtocolError, domain.HTTPReset, domain.HTTPError} {
			ms := withCode(bad, code)
			if len(ms) == 0 {
				continue
			}
			seen := ev("The request ended with "+string(code), engine.IDs(ms)...)
			h := domain.Hypothesis{Confidence: domain.ConfidenceMedium, Supporting: []domain.Evidence{seen}}
			switch code {
			case domain.HTTPRedirectLoop:
				h.Summary = "The server or a CDN is configured with redirects that lead back to themselves, for example between HTTP and HTTPS or between www and the bare name"
				h.Missing = []domain.Evidence{missing("The redirect rules of the server are not visible from outside")}
			case domain.HTTPTimeout:
				h.Summary = "The server accepted the connection but did not answer in time: it is overloaded, or its replies are being delayed or dropped"
				h.Confidence = domain.ConfidenceLow
				h.Missing = []domain.Evidence{missing("A longer deadline was not tried"), missing("No comparison from a different network was made")}
			case domain.HTTPProtocolError:
				h.Summary = "The port is served by something other than an HTTP server, or a device on the path alters the traffic"
				h.Confidence = domain.ConfidenceLow
				h.Missing = []domain.Evidence{missing("What is listening on the port was not identified")}
			default:
				h.Summary = "The server or a device on the path closed the connection during the request"
				h.Confidence = domain.ConfidenceLow
				h.Missing = []domain.Evidence{missing("No comparison from a different network was made")}
			}
			o.Hypotheses = append(o.Hypotheses, h)
		}
		return []engine.Outcome{o}
	},
}
