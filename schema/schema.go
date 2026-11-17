// Package schema holds the machine-readable JSON Schema of the nw report
// and a validator for it. Only tests use the validator.
package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ReportV1 is the JSON Schema for report documents, schema version 1.
//
//go:embed report.v1.json
var ReportV1 []byte

var (
	once     sync.Once
	compiled *jsonschema.Schema
	compErr  error
)

func compile() (*jsonschema.Schema, error) {
	once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(ReportV1))
		if err != nil {
			compErr = err
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("report.v1.json", doc); err != nil {
			compErr = err
			return
		}
		compiled, compErr = c.Compile("report.v1.json")
	})
	return compiled, compErr
}

// ValidateReport checks a JSON document against the report schema.
func ValidateReport(doc []byte) error {
	s, err := compile()
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	return s.Validate(v)
}
