package schema

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/domain"
)

func TestSchemaCompiles(t *testing.T) {
	if _, err := compile(); err != nil {
		t.Fatal(err)
	}
}

// The error code list in the schema and in the code must not drift apart.
func TestErrorCodesMatchDomain(t *testing.T) {
	var doc struct {
		Defs struct {
			ErrorCode struct {
				Enum []string `json:"enum"`
			} `json:"errorCode"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(ReportV1, &doc); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, c := range domain.AllErrorCodes {
		want = append(want, string(c))
	}
	got := slices.Clone(doc.Defs.ErrorCode.Enum)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("schema codes %v\ndomain codes %v", got, want)
	}
}

func TestRejectsInvalidDocuments(t *testing.T) {
	bad := map[string]string{
		"wrong version":      `{"schema_version":"2","run":{},"measurements":[],"findings":[],"hypotheses":[],"recommendations":[]}`,
		"missing arrays":     `{"schema_version":"1"}`,
		"failure w/o error":  minimal(`"status":"failure"`),
		"unknown error code": minimal(`"status":"failure","error":{"code":"dns.bogus","message":"x"}`),
		"skipped w/o note":   minimal(`"status":"skipped"`),
		"bad type":           minimal(`"status":"skipped","note":"n","type":"icmp"`),
	}
	for name, doc := range bad {
		if err := ValidateReport([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateReport([]byte(minimal(`"status":"skipped","note":"n"`))); err != nil {
		t.Errorf("minimal valid document rejected: %v", err)
	}
}

func minimal(extra string) string {
	m := `"id":"m-001","type":"dns","version":"1","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:00:01Z","duration_ms":1,"target":{}`
	return `{"schema_version":"1","run":{"id":"r","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:00:01Z","command":"c","target":"t","tool_version":"1","platform":{"os":"x","arch":"y"}},"measurements":[{` +
		replaceType(m, extra) + `}],"findings":[],"hypotheses":[],"recommendations":[]}`
}

// replaceType lets a case override "type" by listing it in extra.
func replaceType(base, extra string) string {
	if contains(extra, `"type"`) {
		base = `"id":"m-001","version":"1","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:00:01Z","duration_ms":1,"target":{}`
	}
	return base + "," + extra
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
