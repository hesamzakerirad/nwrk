// Package engine turns measurements into findings, hypotheses and
// recommendations with explicit, deterministic rules.
//
// It never measures anything and never prints anything. The same measurements
// and the same rule versions always give the same output.
package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/radestsam/nwrk/internal/domain"
)

// Layers a rule can belong to, in the order reports list them.
const (
	LayerDNS          = "dns"
	LayerTCP          = "tcp"
	LayerTLS          = "tls"
	LayerHTTP         = "http"
	LayerIPFamily     = "ip_family"
	LayerLocal        = "local"
	LayerReachability = "reachability"
	LayerOther        = "other"
)

// Rule is one explicit check over the measurements of a run.
type Rule struct {
	// ID is stable. It is a technical name and appears in reports and docs.
	ID string
	// Version changes whenever the rule's conditions or wording change.
	Version     int
	Title       string
	Description string
	Layer       string
	// Requires lists measurement types that must have run, and not been
	// skipped, for the rule to apply at all.
	Requires []domain.Type
	// Caveats are the known false-positive conditions. They are copied into
	// every finding the rule makes.
	Caveats  []string
	Evaluate func(*Input) []Outcome
}

// Outcome is what a rule concludes from one observed condition.
type Outcome struct {
	Severity       domain.Severity
	Summary        string
	MeasurementIDs []string
	// ExtraCaveats are specific to this occurrence.
	ExtraCaveats    []string
	Hypotheses      []domain.Hypothesis
	Recommendations []domain.Recommendation
}

// Input is the read-only view of a run that rules evaluate.
type Input struct {
	Report *domain.Report
}

// Measurements returns the ordinary measurements of type t, in report
// order. Probes are left out; ask for them with Probes.
func (in *Input) Measurements(t domain.Type) []domain.Measurement {
	var out []domain.Measurement
	for _, m := range in.Report.Measurements {
		if m.Type == t && m.Probe() == "" {
			out = append(out, m)
		}
	}
	return out
}

// Probes returns the measurements of type t made as the named probe.
func (in *Input) Probes(t domain.Type, probe string) []domain.Measurement {
	var out []domain.Measurement
	for _, m := range in.Report.Measurements {
		if m.Type == t && m.Probe() == probe {
			out = append(out, m)
		}
	}
	return out
}

// Ran reports whether any measurement of type t was executed, that is not
// merely skipped.
func (in *Input) Ran(t domain.Type) bool {
	for _, m := range in.Report.Measurements {
		if m.Type == t && m.Probe() == "" && m.Status != domain.StatusSkipped {
			return true
		}
	}
	return false
}

// Target returns the host the run was about.
func (in *Input) Target() string {
	for _, m := range in.Report.Measurements {
		if m.Target.Host != "" {
			return m.Target.Host
		}
	}
	return in.Report.Run.Target
}

// ResultOf returns the typed result of m. It works for results held in
// memory and for results read back from JSON.
func ResultOf[T any](m domain.Measurement) (*T, bool) {
	if m.Result == nil {
		return nil, false
	}
	if v, ok := m.Result.(*T); ok {
		return v, true
	}
	b, err := json.Marshal(m.Result)
	if err != nil {
		return nil, false
	}
	v := new(T)
	if json.Unmarshal(b, v) != nil {
		return nil, false
	}
	return v, true
}

// IDs returns the IDs of ms.
func IDs(ms []domain.Measurement) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.ID)
	}
	return out
}

// Evaluate runs rules over rep and writes the findings, hypotheses and
// recommendations into it. Findings are ordered by severity, then by the
// order of rules. Hypotheses are ordered by confidence, then by finding.
//
// Every failed measurement ends up referenced by at least one finding. One
// that no rule explains gets UNCLASSIFIED_FAILURE, so a failure can never be
// silent.
func Evaluate(rules []Rule, rep *domain.Report) {
	in := &Input{Report: rep}
	type produced struct {
		rule Rule
		out  Outcome
	}
	var all []produced
	for _, r := range rules {
		if !applies(in, r) {
			continue
		}
		for _, o := range r.Evaluate(in) {
			all = append(all, produced{r, o})
		}
	}
	covered := map[string]bool{}
	for _, p := range all {
		for _, id := range p.out.MeasurementIDs {
			covered[id] = true
		}
	}
	if un := unclassified(in, covered); un != nil {
		all = append(all, produced{unclassifiedRule, *un})
	}

	sort.SliceStable(all, func(i, j int) bool {
		return severityRank(all[i].out.Severity) > severityRank(all[j].out.Severity)
	})

	rep.Findings = []domain.Finding{}
	rep.Hypotheses = []domain.Hypothesis{}
	rep.Recommendations = []domain.Recommendation{}
	recIndex := map[string]int{}
	for i, p := range all {
		fid := fmt.Sprintf("f-%03d", i+1)
		caveats := append(append([]string{}, p.rule.Caveats...), p.out.ExtraCaveats...)
		rep.Findings = append(rep.Findings, domain.Finding{
			ID:             fid,
			Code:           p.rule.ID,
			RuleVersion:    p.rule.Version,
			Title:          p.rule.Title,
			Layer:          p.rule.Layer,
			Severity:       p.out.Severity,
			Summary:        p.out.Summary,
			MeasurementIDs: nonNil(p.out.MeasurementIDs),
			Caveats:        caveats,
		})
		for _, h := range p.out.Hypotheses {
			h.Confidence = capConfidence(h)
			h.FindingIDs = []string{fid}
			rep.Hypotheses = append(rep.Hypotheses, h)
		}
		for _, rec := range p.out.Recommendations {
			key := rec.Summary + "\x00" + rec.Command
			if idx, ok := recIndex[key]; ok {
				rep.Recommendations[idx].FindingIDs = append(rep.Recommendations[idx].FindingIDs, fid)
				continue
			}
			rec.FindingIDs = []string{fid}
			recIndex[key] = len(rep.Recommendations)
			rep.Recommendations = append(rep.Recommendations, rec)
		}
	}
	sort.SliceStable(rep.Hypotheses, func(i, j int) bool {
		return confidenceRank(rep.Hypotheses[i].Confidence) > confidenceRank(rep.Hypotheses[j].Confidence)
	})
	for i := range rep.Hypotheses {
		rep.Hypotheses[i].ID = fmt.Sprintf("h-%03d", i+1)
	}
	for i := range rep.Recommendations {
		rep.Recommendations[i].ID = fmt.Sprintf("r-%03d", i+1)
	}
}

func applies(in *Input, r Rule) bool {
	for _, t := range r.Requires {
		if !in.Ran(t) {
			return false
		}
	}
	return true
}

var unclassifiedRule = Rule{
	ID:      "UNCLASSIFIED_FAILURE",
	Version: 1,
	Title:   "A measurement failed and no rule explains it",
	Layer:   LayerOther,
	Caveats: []string{"This finding only says that a measurement failed. Read the error code and message of the measurements it lists."},
}

func unclassified(in *Input, covered map[string]bool) *Outcome {
	var ms []domain.Measurement
	for _, m := range in.Report.Measurements {
		// A failed probe is evidence for the rules that use it; it is not
		// by itself a problem with the target.
		if m.Status == domain.StatusFailure && m.Probe() == "" && !covered[m.ID] {
			ms = append(ms, m)
		}
	}
	if len(ms) == 0 {
		return nil
	}
	var codes []string
	seen := map[string]bool{}
	for _, m := range ms {
		if m.Error != nil && !seen[string(m.Error.Code)] {
			seen[string(m.Error.Code)] = true
			codes = append(codes, string(m.Error.Code))
		}
	}
	sort.Strings(codes)
	return &Outcome{
		Severity:       domain.SeverityWarning,
		Summary:        fmt.Sprintf("%d measurement(s) failed without a more specific finding (%s)", len(ms), strings.Join(codes, ", ")),
		MeasurementIDs: IDs(ms),
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityError:
		return 3
	case domain.SeverityWarning:
		return 2
	}
	return 1
}

func confidenceRank(c domain.Confidence) int {
	switch c {
	case domain.ConfidenceHigh:
		return 3
	case domain.ConfidenceMedium:
		return 2
	}
	return 1
}

// capConfidence enforces that no hypothesis reaches high confidence from a
// single measurement: high needs supporting evidence from at least two
// different measurements, otherwise it is lowered to medium.
func capConfidence(h domain.Hypothesis) domain.Confidence {
	if h.Confidence != domain.ConfidenceHigh {
		return h.Confidence
	}
	seen := map[string]bool{}
	for _, e := range h.Supporting {
		for _, id := range e.MeasurementIDs {
			seen[id] = true
		}
	}
	if len(seen) < 2 {
		return domain.ConfidenceMedium
	}
	return h.Confidence
}
