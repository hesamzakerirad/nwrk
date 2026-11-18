// Package domain defines the objects nw measures, finds and reports.
//
// It has no dependency on the command line, terminal rendering or any
// operating system API. The JSON form of these types is the report contract,
// documented in docs/report-schema.md.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"
)

// SchemaVersion is the version of the report contract.
const SchemaVersion = "1"

// Status is the outcome of one measurement.
type Status string

const (
	// StatusSuccess means the measurement completed and the check passed.
	StatusSuccess Status = "success"
	// StatusFailure means the measurement ran and the check did not pass.
	StatusFailure Status = "failure"
	// StatusSkipped means a prerequisite failed, so the measurement did not run.
	StatusSkipped Status = "skipped"
	// StatusInconclusive means the measurement ran but proves nothing.
	StatusInconclusive Status = "inconclusive"
)

// Type names a kind of measurement.
type Type string

const (
	TypeDNS  Type = "dns"
	TypeTCP  Type = "tcp"
	TypeTLS  Type = "tls"
	TypeHTTP Type = "http"
	// TypeLocal is an inspection of this machine's own network setup.
	TypeLocal Type = "local"
)

// Scope says which part of the path a measurement speaks for.
type Scope string

const (
	ScopeLocal         Scope = "local"
	ScopeDomestic      Scope = "domestic"
	ScopeInternational Scope = "international"
)

// ErrorCode is the stable category of a failed measurement.
type ErrorCode string

const (
	DNSNXDomain  ErrorCode = "dns.nxdomain"
	DNSServFail  ErrorCode = "dns.servfail"
	DNSRefused   ErrorCode = "dns.refused"
	DNSNoAnswer  ErrorCode = "dns.no_answer"
	DNSTimeout   ErrorCode = "dns.timeout"
	DNSTransport ErrorCode = "dns.transport"
	DNSError     ErrorCode = "dns.error"

	TCPRefused     ErrorCode = "tcp.refused"
	TCPTimeout     ErrorCode = "tcp.timeout"
	TCPUnreachable ErrorCode = "tcp.unreachable"
	TCPReset       ErrorCode = "tcp.reset"
	TCPError       ErrorCode = "tcp.error"

	TLSCertExpired      ErrorCode = "tls.cert_expired"
	TLSCertUntrusted    ErrorCode = "tls.cert_untrusted"
	TLSHostnameMismatch ErrorCode = "tls.hostname_mismatch"
	TLSHandshakeFailure ErrorCode = "tls.handshake_failure"
	TLSReset            ErrorCode = "tls.reset"
	TLSTimeout          ErrorCode = "tls.timeout"
	TLSError            ErrorCode = "tls.error"

	HTTPTimeout       ErrorCode = "http.timeout"
	HTTPRedirectLoop  ErrorCode = "http.redirect_loop"
	HTTPProtocolError ErrorCode = "http.protocol_error"
	HTTPReset         ErrorCode = "http.reset"
	HTTPError         ErrorCode = "http.error"

	LocalNoInterface ErrorCode = "local.no_interface"
	LocalNoRoute     ErrorCode = "local.no_route"
	LocalNoResolver  ErrorCode = "local.no_resolver"
)

// AllErrorCodes lists every code, for documentation and schema checks.
var AllErrorCodes = []ErrorCode{
	DNSNXDomain, DNSServFail, DNSRefused, DNSNoAnswer, DNSTimeout, DNSTransport, DNSError,
	TCPRefused, TCPTimeout, TCPUnreachable, TCPReset, TCPError,
	TLSCertExpired, TLSCertUntrusted, TLSHostnameMismatch, TLSHandshakeFailure, TLSReset, TLSTimeout, TLSError,
	HTTPTimeout, HTTPRedirectLoop, HTTPProtocolError, HTTPReset, HTTPError,
	LocalNoInterface, LocalNoRoute, LocalNoResolver,
}

// Error is a structured failure. Message is for people and may change;
// Code is for programs and is stable within a schema version.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Target says what a measurement was aimed at. Empty fields are omitted.
type Target struct {
	Host   string `json:"host,omitempty"`
	URL    string `json:"url,omitempty"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Family string `json:"family,omitempty"` // "ipv4" or "ipv6"
}

// ResolverInfo identifies the DNS resolver that produced a measurement.
type ResolverInfo struct {
	// Kind is "system" for the operating system's resolver, or the
	// transport ("udp", "tcp") of an explicitly chosen one.
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	// Servers lists the name servers the operating system is configured
	// with, for context. It is set only for the system resolver.
	Servers []string `json:"servers,omitempty"`
}

// Detailer is implemented by results that can describe themselves in plain
// lines for the human report. It carries no formatting or color.
type Detailer interface {
	Details() []string
}

// Measurement is one test execution and its structured result.
type Measurement struct {
	ID         string         `json:"id"`
	Type       Type           `json:"type"`
	Version    string         `json:"version"`
	Status     Status         `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	EndedAt    time.Time      `json:"ended_at"`
	DurationMS float64        `json:"duration_ms"`
	Scope      Scope          `json:"scope,omitempty"`
	Target     Target         `json:"target"`
	Resolver   *ResolverInfo  `json:"resolver,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
	Result     any            `json:"result,omitempty"`
	Error      *Error         `json:"error,omitempty"`
	Note       string         `json:"note,omitempty"`
	Redacted   []string       `json:"redacted,omitempty"`
}

// Millis converts d to milliseconds with microsecond precision.
func Millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// Begin starts a measurement of the given type.
func Begin(t Type, version string, target Target) *Measurement {
	return &Measurement{
		Type:      t,
		Version:   version,
		Target:    target,
		StartedAt: time.Now().UTC(),
	}
}

// Probe names, recorded in params.probe.
const (
	ProbeMultipleResponses  = "multiple_responses"  // dns: listen for several replies to one query
	ProbeDNSSEC             = "dnssec"              // dns: signature state and alias chain
	ProbeAnswerReachability = "answer_reachability" // tcp: connect to the addresses a resolver returned
	ProbeSNITarget          = "sni_target"          // tls: repeat the handshake with the target name
	ProbeSNIControl         = "sni_control"         // tls: handshake with a neutral control name
	ProbeLegacyTLS          = "legacy_tls"          // tls: offer only TLS 1.0 and 1.1
	ProbePlainHTTP          = "plain_http"          // http: the same request over http://
	ProbeHTTP3              = "http3"               // http: the same request over HTTP/3 (QUIC)
)

// Probe returns the name of the probe a measurement belongs to, or "".
// A probe is a measurement made as evidence for interference rules, such as
// a handshake with another server name. Probes do not count in the layer
// summary and are not explained by the ordinary rules.
func (m Measurement) Probe() string {
	p, _ := m.Params["probe"].(string)
	return p
}

// Finish stamps the end time and duration. The status stays as set.
func (m *Measurement) Finish() *Measurement {
	m.EndedAt = time.Now().UTC()
	m.DurationMS = Millis(m.EndedAt.Sub(m.StartedAt))
	return m
}

// Succeed marks m successful with result.
func (m *Measurement) Succeed(result any) *Measurement {
	m.Status = StatusSuccess
	m.Result = result
	return m.Finish()
}

// Fail marks m failed. result may carry partial evidence and may be nil.
func (m *Measurement) Fail(code ErrorCode, message string, result any) *Measurement {
	m.Status = StatusFailure
	m.Error = &Error{Code: code, Message: message}
	m.Result = result
	return m.Finish()
}

// Skip marks m as not run, with the reason in Note.
func (m *Measurement) Skip(note string) *Measurement {
	m.Status = StatusSkipped
	m.Note = note
	return m.Finish()
}

// Severity ranks a finding. Warning and error are actionable: they make
// nw diagnose exit with status 1. Info is context and never does.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Actionable reports whether a finding of this severity means the target
// has a problem.
func (s Severity) Actionable() bool { return s == SeverityWarning || s == SeverityError }

// Confidence is a qualitative level, never a probability.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Evidence points at what supports or contradicts a statement. Missing
// evidence has no measurement IDs: it says what was not observed.
type Evidence struct {
	MeasurementIDs []string `json:"measurement_ids,omitempty"`
	Text           string   `json:"text"`
}

// Finding is a condition the measurements support. It is an observation:
// what happened, never why.
type Finding struct {
	ID             string   `json:"id"`
	Code           string   `json:"code"`
	RuleVersion    int      `json:"rule_version,omitempty"`
	Title          string   `json:"title,omitempty"`
	Layer          string   `json:"layer,omitempty"`
	Severity       Severity `json:"severity"`
	Summary        string   `json:"summary"`
	MeasurementIDs []string `json:"measurement_ids"`
	Caveats        []string `json:"caveats,omitempty"`
}

// Hypothesis is a possible explanation for findings, never a verdict.
type Hypothesis struct {
	ID               string     `json:"id"`
	Summary          string     `json:"summary"`
	FindingIDs       []string   `json:"finding_ids"`
	Confidence       Confidence `json:"confidence"`
	Supporting       []Evidence `json:"supporting,omitempty"`
	Contradicting    []Evidence `json:"contradicting,omitempty"`
	Missing          []Evidence `json:"missing,omitempty"`
	NextMeasurements []string   `json:"next_measurements,omitempty"`
}

// Recommendation is a safe next step: a measurement to repeat or a thing
// to inspect. It never changes anything on the user's system.
type Recommendation struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Command    string   `json:"command,omitempty"`
	FindingIDs []string `json:"finding_ids,omitempty"`
}

// Layer statuses used in the summary, besides the measurement statuses.
const (
	LayerPartial = "partial" // some measurements of the layer succeeded and some failed
	LayerNotRun  = "not_run" // the profile does not include the layer
)

// LayerStatus is the outcome of one protocol layer, without a score.
type LayerStatus struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
}

// ScopeStatus is the reachability of one scope: "ok" for local checks;
// "reachable", "partial", "unreachable" or "not_checked" for the others.
type ScopeStatus struct {
	Scope  Scope  `json:"scope"`
	Status string `json:"status"`
}

// Verdicts say which layer of the path the problem is in, for nw doctor.
const (
	VerdictHealthy       = "healthy"
	VerdictLocal         = "local"
	VerdictDomestic      = "domestic"
	VerdictInternational = "international"
	VerdictUpstream      = "upstream"
	VerdictPartial       = "partial"
)

// Summary is the at-a-glance result of a diagnosis.
type Summary struct {
	// Outcome is "ok" when no actionable finding was made, else "problem".
	Outcome string        `json:"outcome"`
	Layers  []LayerStatus `json:"layers"`
	// Scopes and Verdict are set by nw doctor: which part of the path works,
	// and which layer the problem is in.
	Scopes  []ScopeStatus `json:"scopes,omitempty"`
	Verdict string        `json:"verdict,omitempty"`
}

// Platform describes where the run happened.
type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// DiagnosticRun is one complete session: what was asked and by which build.
type DiagnosticRun struct {
	ID          string    `json:"id"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	Command     string    `json:"command"`
	Target      string    `json:"target"`
	Profile     string    `json:"profile,omitempty"`
	Region      string    `json:"region,omitempty"`
	ToolVersion string    `json:"tool_version"`
	Platform    Platform  `json:"platform"`
}

// Report is the document nw prints with --output json.
type Report struct {
	SchemaVersion   string           `json:"schema_version"`
	Run             DiagnosticRun    `json:"run"`
	Measurements    []Measurement    `json:"measurements"`
	Findings        []Finding        `json:"findings"`
	Hypotheses      []Hypothesis     `json:"hypotheses"`
	Recommendations []Recommendation `json:"recommendations"`
	Summary         *Summary         `json:"summary,omitempty"`
}

// NewReport starts a report for one command run. Every list is non-nil so
// the JSON always has arrays, never null.
func NewReport(command, target, toolVersion string) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		Run: DiagnosticRun{
			ID:          newID("run"),
			StartedAt:   time.Now().UTC(),
			Command:     command,
			Target:      target,
			ToolVersion: toolVersion,
			Platform:    Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		},
		Measurements:    []Measurement{},
		Findings:        []Finding{},
		Hypotheses:      []Hypothesis{},
		Recommendations: []Recommendation{},
	}
}

// Add appends m and gives it the next stable ID (m-001, m-002, ...).
func (r *Report) Add(m *Measurement) {
	m.ID = fmt.Sprintf("m-%03d", len(r.Measurements)+1)
	r.Measurements = append(r.Measurements, *m)
}

// Actionable reports whether any finding is a warning or an error.
func (r *Report) Actionable() bool {
	for _, f := range r.Findings {
		if f.Severity.Actionable() {
			return true
		}
	}
	return false
}

// Summarize fills Summary from the measurements and findings.
func (r *Report) Summarize() {
	sum := &Summary{Outcome: "ok"}
	if r.Actionable() {
		sum.Outcome = "problem"
	}
	for _, t := range []Type{TypeDNS, TypeTCP, TypeTLS, TypeHTTP} {
		var ok, fail, skip int
		for _, m := range r.Measurements {
			if m.Type != t || m.Probe() != "" {
				continue
			}
			switch m.Status {
			case StatusSuccess:
				ok++
			case StatusFailure:
				fail++
			case StatusSkipped:
				skip++
			}
		}
		st := string(StatusSuccess)
		switch {
		case ok+fail+skip == 0:
			st = LayerNotRun
		case fail > 0 && ok > 0:
			st = LayerPartial
		case fail > 0:
			st = string(StatusFailure)
		case ok == 0:
			st = string(StatusSkipped)
		}
		sum.Layers = append(sum.Layers, LayerStatus{Layer: string(t), Status: st})
	}
	r.Summary = sum
}

// Finish stamps the end of the run.
func (r *Report) Finish() { r.Run.EndedAt = time.Now().UTC() }

// HasFailure reports whether any measurement failed.
func (r *Report) HasFailure() bool {
	for _, m := range r.Measurements {
		if m.Status == StatusFailure {
			return true
		}
	}
	return false
}

func newID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
