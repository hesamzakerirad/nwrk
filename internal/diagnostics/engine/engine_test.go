package engine

import (
	"encoding/json"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	mhttp "github.com/hesamzakerirad/nwrk/internal/measurement/http"
)

func TestResultOfWorksForMemoryAndJSON(t *testing.T) {
	m := domain.Measurement{Result: &mhttp.Result{StatusCode: 503}}
	if r, ok := ResultOf[mhttp.Result](m); !ok || r.StatusCode != 503 {
		t.Fatalf("in memory: %+v %v", r, ok)
	}
	b, _ := json.Marshal(m)
	var back domain.Measurement
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if r, ok := ResultOf[mhttp.Result](back); !ok || r.StatusCode != 503 {
		t.Fatalf("after JSON: %+v %v", r, ok)
	}
	if _, ok := ResultOf[mhttp.Result](domain.Measurement{}); ok {
		t.Fatal("a measurement without a result has no typed result")
	}
}

func TestUnclassifiedFailureIsTheSafetyNet(t *testing.T) {
	rep := domain.NewReport("diagnose", "x", "t")
	m := domain.Begin(domain.TypeTCP, "1", domain.Target{Host: "x"})
	rep.Add(m.Fail(domain.TCPReset, "reset", nil))
	Evaluate(nil, rep)
	if len(rep.Findings) != 1 || rep.Findings[0].Code != "UNCLASSIFIED_FAILURE" || rep.Findings[0].Severity != domain.SeverityWarning {
		t.Fatalf("%+v", rep.Findings)
	}
}

func TestNoFindingsWhenNothingFailed(t *testing.T) {
	rep := domain.NewReport("diagnose", "x", "t")
	rep.Add(domain.Begin(domain.TypeTCP, "1", domain.Target{}).Succeed(nil))
	Evaluate(nil, rep)
	if len(rep.Findings) != 0 || rep.Findings == nil || rep.Hypotheses == nil || rep.Recommendations == nil {
		t.Fatalf("%+v", rep)
	}
}

func TestRecommendationsAreMergedAcrossFindings(t *testing.T) {
	rule := func(id string) Rule {
		return Rule{ID: id, Version: 1, Layer: LayerOther, Requires: []domain.Type{domain.TypeTCP},
			Evaluate: func(in *Input) []Outcome {
				return []Outcome{{Severity: domain.SeverityWarning, Summary: id, MeasurementIDs: []string{"m-001"},
					Recommendations: []domain.Recommendation{{Summary: "same step"}}}}
			}}
	}
	rep := domain.NewReport("diagnose", "x", "t")
	rep.Add(domain.Begin(domain.TypeTCP, "1", domain.Target{}).Succeed(nil))
	Evaluate([]Rule{rule("A"), rule("B")}, rep)
	if len(rep.Recommendations) != 1 || len(rep.Recommendations[0].FindingIDs) != 2 {
		t.Fatalf("%+v", rep.Recommendations)
	}
}
