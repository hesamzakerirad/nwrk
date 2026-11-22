// Package contracts holds the NWRK community contribution contract: the JSON
// Schemas, the approved measurement profiles and a validator.
//
// The files in this directory are the single source of truth. The nw client
// embeds them. The NWRK Status server copies them from a release tag and must
// pass the same fixtures in fixtures/.
package contracts

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// MaxBodyBytes is the largest request body that the server accepts.
const MaxBodyBytes = 65536

// SchemaVersion is the version string of the contribution document.
const SchemaVersion = "community-contribution.v1"

const (
	contributionID = "https://nwrk.ir/schema/community-contribution.v1.json"
	profileID      = "https://nwrk.ir/schema/community-profile.v1.json"
	apiID          = "https://nwrk.ir/schema/community-api.v1.json"
	publicID       = "https://nwrk.ir/schema/community-public.v1.json"
)

//go:embed schemas/*.json profiles/*.json profiles/CHECKSUMS
var files embed.FS

var (
	compileOnce sync.Once
	compiler    *jsonschema.Compiler
	compileErr  error
)

func schemaCompiler() (*jsonschema.Compiler, error) {
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		for url, name := range map[string]string{
			contributionID: "schemas/community-contribution.v1.schema.json",
			profileID:      "schemas/community-profile.v1.schema.json",
			apiID:          "schemas/community-api.v1.schema.json",
			publicID:       "schemas/community-public.v1.schema.json",
		} {
			raw, err := files.ReadFile(name)
			if err != nil {
				compileErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				compileErr = fmt.Errorf("%s: %w", name, err)
				return
			}
			if err := c.AddResource(url, doc); err != nil {
				compileErr = err
				return
			}
		}
		compiler = c
	})
	return compiler, compileErr
}

// Schema returns the raw bytes of a schema file, such as
// "community-contribution.v1.schema.json".
func Schema(name string) ([]byte, error) { return files.ReadFile("schemas/" + name) }

// validateAgainst checks raw JSON against the schema at ref.
func validateAgainst(ref string, raw []byte) error {
	c, err := schemaCompiler()
	if err != nil {
		return err
	}
	sch, err := c.Compile(ref)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return &ValidationError{Stage: StageSyntax, Code: "invalid_json", Reason: err.Error()}
	}
	if err := sch.Validate(doc); err != nil {
		return &ValidationError{Stage: StageSchema, Code: "schema_violation", Reason: firstLine(err.Error())}
	}
	return nil
}

// ValidateAPI checks raw JSON against a message definition of the API schema,
// for example "submission" or "challengeResponse".
func ValidateAPI(def string, raw []byte) error {
	return validateAgainst(apiID+"#/$defs/"+def, raw)
}

// ValidatePublic checks raw JSON against a message definition of the public
// statistics schema, for example "windowResult" or "summaryResponse".
func ValidatePublic(def string, raw []byte) error {
	return validateAgainst(publicID+"#/$defs/"+def, raw)
}

// ValidateProfileDocument checks raw JSON against the profile schema.
func ValidateProfileDocument(raw []byte) error { return validateAgainst(profileID, raw) }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// Validation stages, in the order that the server applies them.
const (
	StageSize     = "size"
	StageSyntax   = "syntax"
	StageSchema   = "schema"
	StageSemantic = "semantic"
)

// ValidationError says why a document was rejected. Code is the API error
// code that the server returns for the same failure.
type ValidationError struct {
	Stage  string
	Code   string
	Path   string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s (%s): %s: %s", e.Code, e.Stage, e.Path, e.Reason)
	}
	return fmt.Sprintf("%s (%s): %s", e.Code, e.Stage, e.Reason)
}

// Profile is an approved measurement profile.
type Profile struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id"`
	Version       int        `json:"version"`
	Description   string     `json:"description"`
	Limits        Limits     `json:"limits"`
	Services      []Service  `json:"services"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// Limits bounds one contribution run.
type Limits struct {
	Concurrency   int            `json:"concurrency"`
	TimeoutsMS    map[string]int `json:"timeouts_ms"`
	TotalBudgetMS int            `json:"total_budget_ms"`
}

// Service is a public service that has one or more endpoints.
type Service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	OfficialURL string `json:"official_url"`
}

// Endpoint is one approved target.
type Endpoint struct {
	TargetID         string   `json:"target_id"`
	ServiceID        string   `json:"service_id"`
	Hostname         string   `json:"hostname"`
	Port             int      `json:"port"`
	Scheme           string   `json:"scheme"`
	Path             string   `json:"path"`
	Method           string   `json:"method"`
	Families         []string `json:"families"`
	MeasurementTypes []string `json:"measurement_types"`
	RedirectPolicy   string   `json:"redirect_policy"`
	MaxResponseBytes int      `json:"max_response_bytes"`
}

// Endpoint returns the endpoint with the given target ID.
func (p *Profile) Endpoint(targetID string) (*Endpoint, bool) {
	for i := range p.Endpoints {
		if p.Endpoints[i].TargetID == targetID {
			return &p.Endpoints[i], true
		}
	}
	return nil, false
}

// Profiles returns every embedded profile, sorted by ID and version. It
// verifies each file against profiles/CHECKSUMS and against the profile
// schema, and it checks that a service has the same definition everywhere.
func Profiles() ([]*Profile, error) {
	sums, err := checksums()
	if err != nil {
		return nil, err
	}
	entries, err := fs.Glob(files, "profiles/*.json")
	if err != nil {
		return nil, err
	}
	var out []*Profile
	for _, name := range entries {
		raw, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		base := strings.TrimPrefix(name, "profiles/")
		sum := sha256.Sum256(raw)
		if want, ok := sums[base]; !ok {
			return nil, fmt.Errorf("%s has no entry in CHECKSUMS", base)
		} else if got := hex.EncodeToString(sum[:]); got != want {
			return nil, fmt.Errorf("%s changed: checksum %s, expected %s. A published profile is immutable: add a new profile version", base, got, want)
		}
		if err := ValidateProfileDocument(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		var p Profile
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		if err := checkProfile(&p); err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		out = append(out, &p)
	}
	for base := range sums {
		if _, err := files.ReadFile("profiles/" + base); err != nil {
			return nil, fmt.Errorf("CHECKSUMS lists %s, which is missing", base)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})
	for i := 1; i < len(out); i++ {
		if out[i].ID == out[i-1].ID && out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("profile %s version %d is defined twice", out[i].ID, out[i].Version)
		}
	}
	if err := checkServicesAgree(out); err != nil {
		return nil, err
	}
	if err := checkEndpointsAgree(out); err != nil {
		return nil, err
	}
	return out, nil
}

func checksums() (map[string]string, error) {
	raw, err := files.ReadFile("profiles/CHECKSUMS")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("bad CHECKSUMS line %q", line)
		}
		out[f[1]] = f[0]
	}
	return out, nil
}

// checkProfile applies the rules that JSON Schema cannot express.
func checkProfile(p *Profile) error {
	services := map[string]bool{}
	for _, s := range p.Services {
		if services[s.ID] {
			return fmt.Errorf("duplicate service %q", s.ID)
		}
		services[s.ID] = true
	}
	targets := map[string]bool{}
	hosts := map[string]bool{}
	for _, e := range p.Endpoints {
		if targets[e.TargetID] {
			return fmt.Errorf("duplicate target %q", e.TargetID)
		}
		targets[e.TargetID] = true
		if !services[e.ServiceID] {
			return fmt.Errorf("target %q uses unknown service %q", e.TargetID, e.ServiceID)
		}
		key := e.Hostname + e.Path
		if hosts[key] {
			return fmt.Errorf("target %q repeats %s%s", e.TargetID, e.Hostname, e.Path)
		}
		hosts[key] = true
	}
	for _, s := range p.Services {
		used := false
		for _, e := range p.Endpoints {
			if e.ServiceID == s.ID {
				used = true
			}
		}
		if !used {
			return fmt.Errorf("service %q has no endpoint", s.ID)
		}
	}
	if len(p.Endpoints) > 15 {
		return fmt.Errorf("%d endpoints: a profile has at most 15", len(p.Endpoints))
	}
	return nil
}

// checkServicesAgree makes sure that a service ID means the same thing in
// every profile.
func checkServicesAgree(ps []*Profile) error {
	seen := map[string]Service{}
	for _, p := range ps {
		for _, s := range p.Services {
			if prev, ok := seen[s.ID]; ok && prev != s {
				return fmt.Errorf("service %q is defined differently in profile %s", s.ID, p.ID)
			}
			seen[s.ID] = s
		}
	}
	return nil
}

// checkEndpointsAgree makes sure that a target ID means one fixed endpoint in
// every profile. A changed endpoint needs a new target ID, because stored
// results refer to the target ID.
func checkEndpointsAgree(ps []*Profile) error {
	seen := map[string]Endpoint{}
	for _, p := range ps {
		for _, e := range p.Endpoints {
			if prev, ok := seen[e.TargetID]; ok && !sameEndpoint(prev, e) {
				return fmt.Errorf("target %q is defined differently in profile %s version %d: a changed endpoint needs a new target ID", e.TargetID, p.ID, p.Version)
			}
			seen[e.TargetID] = e
		}
	}
	return nil
}

func sameEndpoint(a, b Endpoint) bool {
	return a.ServiceID == b.ServiceID && a.Hostname == b.Hostname && a.Port == b.Port &&
		a.Scheme == b.Scheme && a.Path == b.Path && a.Method == b.Method &&
		slices.Equal(a.Families, b.Families) && slices.Equal(a.MeasurementTypes, b.MeasurementTypes) &&
		a.RedirectPolicy == b.RedirectPolicy && a.MaxResponseBytes == b.MaxResponseBytes
}

// Contribution is the decoded contribution document.
type Contribution struct {
	SchemaVersion string `json:"schema_version"`
	Client        struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"client"`
	Profile struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	} `json:"profile"`
	Results []Result `json:"results"`
}

// Result holds the measurements of one target.
type Result struct {
	TargetID     string        `json:"target_id"`
	Measurements []Measurement `json:"measurements"`
}

// Measurement is one layer result for one address family.
type Measurement struct {
	Layer       string `json:"layer"`
	Family      string `json:"family"`
	Outcome     string `json:"outcome"`
	DurationMS  int    `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	DNSRcode    string `json:"dns_rcode,omitempty"`
	AnswerCount int    `json:"answer_count,omitempty"`
}

// ValidateContribution checks a contribution document in the order that the
// server uses: size, JSON syntax, schema, then the profile rules. It returns
// the decoded document, or a *ValidationError.
func ValidateContribution(raw []byte, profiles []*Profile) (*Contribution, error) {
	if len(raw) > MaxBodyBytes {
		return nil, &ValidationError{Stage: StageSize, Code: "payload_too_large", Reason: fmt.Sprintf("%d bytes, the limit is %d", len(raw), MaxBodyBytes)}
	}
	if err := validateAgainst(contributionID, raw); err != nil {
		return nil, err
	}
	var c Contribution
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, &ValidationError{Stage: StageSyntax, Code: "invalid_json", Reason: err.Error()}
	}
	return &c, checkContribution(&c, profiles)
}

func checkContribution(c *Contribution, profiles []*Profile) error {
	var p *Profile
	for _, cand := range profiles {
		if cand.ID == c.Profile.ID && cand.Version == c.Profile.Version {
			p = cand
		}
	}
	if p == nil {
		return &ValidationError{Stage: StageSemantic, Code: "unknown_profile", Path: "profile", Reason: fmt.Sprintf("%s version %d is not approved", c.Profile.ID, c.Profile.Version)}
	}
	seenTarget := map[string]bool{}
	for i, r := range c.Results {
		path := fmt.Sprintf("results[%d]", i)
		e, ok := p.Endpoint(r.TargetID)
		if !ok {
			return &ValidationError{Stage: StageSemantic, Code: "unknown_target", Path: path + ".target_id", Reason: fmt.Sprintf("%q is not in profile %s", r.TargetID, p.ID)}
		}
		if seenTarget[r.TargetID] {
			return &ValidationError{Stage: StageSemantic, Code: "invalid_result", Path: path + ".target_id", Reason: "target appears twice"}
		}
		seenTarget[r.TargetID] = true
		seen := map[string]bool{}
		for j, m := range r.Measurements {
			mp := fmt.Sprintf("%s.measurements[%d]", path, j)
			key := m.Layer + "/" + m.Family
			if seen[key] {
				return &ValidationError{Stage: StageSemantic, Code: "invalid_result", Path: mp, Reason: "duplicate " + key}
			}
			seen[key] = true
			if !contains(e.Families, m.Family) {
				return &ValidationError{Stage: StageSemantic, Code: "invalid_result", Path: mp + ".family", Reason: fmt.Sprintf("%s does not serve %s", r.TargetID, m.Family)}
			}
			if !contains(e.MeasurementTypes, m.Layer) {
				return &ValidationError{Stage: StageSemantic, Code: "invalid_result", Path: mp + ".layer", Reason: fmt.Sprintf("%s does not use layer %s", r.TargetID, m.Layer)}
			}
			if m.Layer == "http" && m.DurationMS > p.Limits.TimeoutsMS["http"]+1000 {
				return &ValidationError{Stage: StageSemantic, Code: "invalid_result", Path: mp + ".duration_ms", Reason: "longer than the profile timeout"}
			}
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
