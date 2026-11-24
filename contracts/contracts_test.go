package contracts

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/radestsam/nwrk/internal/domain"
)

func mustProfiles(t *testing.T) []*Profile {
	t.Helper()
	ps, err := Profiles()
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func readFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProfilesLoad(t *testing.T) {
	ps := mustProfiles(t)
	var ids []string
	for _, p := range ps {
		ids = append(ids, p.ID)
		if p.Limits.Concurrency < 4 || p.Limits.Concurrency > 6 {
			t.Errorf("%s: concurrency %d, want 4 to 6", p.ID, p.Limits.Concurrency)
		}
		if p.Limits.TotalBudgetMS > 90000 {
			t.Errorf("%s: budget above 90 s", p.ID)
		}
	}
	want := []string{"ir-core-v1", "ir-dev-v1"}
	if !slices.Equal(ids, want) {
		t.Fatalf("profiles %v, want %v", ids, want)
	}
}

func TestProfileRules(t *testing.T) {
	good := Profile{
		Services:  []Service{{ID: "a"}},
		Endpoints: []Endpoint{{TargetID: "a", ServiceID: "a", Hostname: "a.example", Path: "/"}},
	}
	if err := checkProfile(&good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *Profile){
		"duplicate service": func(p *Profile) { p.Services = append(p.Services, Service{ID: "a"}) },
		"duplicate target":  func(p *Profile) { p.Endpoints = append(p.Endpoints, p.Endpoints[0]) },
		"unknown service":   func(p *Profile) { p.Endpoints[0].ServiceID = "zzz" },
		"service no target": func(p *Profile) { p.Services = append(p.Services, Service{ID: "b"}) },
		"repeated host path": func(p *Profile) {
			p.Endpoints = append(p.Endpoints, Endpoint{TargetID: "b", ServiceID: "a", Hostname: "a.example", Path: "/"})
		},
		"too many endpoints": func(p *Profile) {
			for i := 0; i < 15; i++ {
				p.Endpoints = append(p.Endpoints, Endpoint{TargetID: "x" + string(rune('a'+i)), ServiceID: "a", Hostname: "h.example", Path: "/" + string(rune('a'+i))})
			}
		},
	}
	for name, mutate := range cases {
		p := good
		p.Services = slices.Clone(good.Services)
		p.Endpoints = slices.Clone(good.Endpoints)
		mutate(&p)
		if err := checkProfile(&p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestServicesAgree(t *testing.T) {
	a := &Profile{ID: "a", Services: []Service{{ID: "s", Name: "One"}}}
	b := &Profile{ID: "b", Services: []Service{{ID: "s", Name: "Two"}}}
	if err := checkServicesAgree([]*Profile{a, b}); err == nil {
		t.Fatal("different definitions of one service were accepted")
	}
}

func TestEndpointsAgree(t *testing.T) {
	e := Endpoint{TargetID: "a", ServiceID: "s", Hostname: "a.example", Path: "/", Families: []string{"ipv4"}}
	a := &Profile{ID: "p", Version: 1, Endpoints: []Endpoint{e}}
	same := &Profile{ID: "p", Version: 2, Endpoints: []Endpoint{e}}
	if err := checkEndpointsAgree([]*Profile{a, same}); err != nil {
		t.Fatalf("same endpoint refused: %v", err)
	}
	changed := e
	changed.Path = "/other"
	b := &Profile{ID: "p", Version: 2, Endpoints: []Endpoint{changed}}
	if err := checkEndpointsAgree([]*Profile{a, b}); err == nil {
		t.Fatal("a changed endpoint with the same target ID was accepted")
	}
}

// Profile endpoints must be reviewable at a glance: HEAD reads no body, and
// no endpoint may be an address literal.
func TestProfileEndpointsAreSafe(t *testing.T) {
	for _, p := range mustProfiles(t) {
		for _, e := range p.Endpoints {
			if e.Method == "HEAD" && e.MaxResponseBytes != 0 {
				t.Errorf("%s/%s: HEAD with a body limit", p.ID, e.TargetID)
			}
			if strings.ContainsAny(e.Path, "?#") {
				t.Errorf("%s/%s: path has a query or fragment", p.ID, e.TargetID)
			}
			if e.RedirectPolicy != "none" {
				t.Errorf("%s/%s: redirect policy %q", p.ID, e.TargetID, e.RedirectPolicy)
			}
		}
	}
}

func TestHostnameRejectsAddresses(t *testing.T) {
	ps := mustProfiles(t)
	raw, _ := json.Marshal(ps[0])
	for _, host := range []string{"192.0.2.1", "2001-db8.example.123", "localhost", "[::1]", "a_b.example"} {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		doc["endpoints"].([]any)[0].(map[string]any)["hostname"] = host
		b, _ := json.Marshal(doc)
		if err := ValidateProfileDocument(b); err == nil {
			t.Errorf("hostname %q was accepted", host)
		}
	}
}

// The error list in the schema is the engine list without local.* codes.
func TestErrorCodesMatchDomain(t *testing.T) {
	raw, err := Schema("community-contribution.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs struct {
			ErrorCode struct {
				Enum []string `json:"enum"`
			} `json:"errorCode"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, c := range domain.AllErrorCodes {
		if !strings.HasPrefix(string(c), "local.") {
			want = append(want, string(c))
		}
	}
	got := slices.Clone(doc.Defs.ErrorCode.Enum)
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("schema codes %v\nengine codes %v", got, want)
	}
}

// Every object in the contribution schema must reject unknown fields, and no
// property may be named like data that the contract forbids.
func TestSchemaIsClosedAndHasNoForbiddenFields(t *testing.T) {
	forbidden := []string{"ip", "addr", "host", "url", "uri", "header", "cookie", "cert", "serial", "mac", "device", "install", "location", "resolver", "body", "country", "asn"}
	for _, name := range []string{"community-contribution.v1.schema.json", "community-profile.v1.schema.json"} {
		raw, err := Schema(name)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		walk(t, name, "$", doc, func(path string, obj map[string]any) {
			// Only real object definitions are checked. The properties inside
			// if, then and else blocks are conditions, not definitions.
			if props, ok := obj["properties"].(map[string]any); ok && obj["type"] == "object" {
				if obj["additionalProperties"] != false {
					t.Errorf("%s %s: object is not closed", name, path)
				}
				if strings.HasPrefix(name, "community-contribution") {
					for key := range props {
						for _, f := range forbidden {
							if strings.Contains(strings.ToLower(key), f) {
								t.Errorf("%s %s: property %q looks like forbidden data (%s)", name, path, key, f)
							}
						}
					}
				}
			}
		})
	}
}

func walk(t *testing.T, name, path string, node any, visit func(string, map[string]any)) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		visit(path, v)
		for k, c := range v {
			walk(t, name, path+"."+k, c, visit)
		}
	case []any:
		for i, c := range v {
			walk(t, name, path+"["+string(rune('0'+i%10))+"]", c, visit)
		}
	}
}

type contributionManifest struct {
	Valid   map[string]struct{} `json:"valid"`
	Invalid map[string]struct {
		Stage  string `json:"stage"`
		Code   string `json:"code"`
		Reason string `json:"reason"`
	} `json:"invalid"`
}

func loadManifest(t *testing.T) contributionManifest {
	t.Helper()
	var m contributionManifest
	if err := json.Unmarshal(readFile(t, "fixtures/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func jsonFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, "manifest.json") {
			out = append(out, filepath.ToSlash(p))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// A fixture that is not in the manifest would never be checked.
func TestManifestCoversEveryContributionFixture(t *testing.T) {
	m := loadManifest(t)
	var listed []string
	for k := range m.Valid {
		listed = append(listed, "fixtures/"+k)
	}
	for k := range m.Invalid {
		listed = append(listed, "fixtures/"+k)
	}
	sort.Strings(listed)
	var onDisk []string
	for _, f := range jsonFiles(t, "fixtures") {
		if !strings.HasPrefix(f, "fixtures/api/") {
			onDisk = append(onDisk, f)
		}
	}
	if !slices.Equal(listed, onDisk) {
		t.Fatalf("manifest and disk differ\nmanifest: %v\ndisk:     %v", listed, onDisk)
	}
}

func TestValidFixturesPass(t *testing.T) {
	ps := mustProfiles(t)
	for name := range loadManifest(t).Valid {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateContribution(readFile(t, "fixtures/"+name), ps); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidFixturesFailAtTheDeclaredStage(t *testing.T) {
	ps := mustProfiles(t)
	for name, want := range loadManifest(t).Invalid {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateContribution(readFile(t, "fixtures/"+name), ps)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("not rejected (%s): %v", want.Reason, err)
			}
			if ve.Stage != want.Stage || ve.Code != want.Code {
				t.Fatalf("rejected as %s/%s, want %s/%s (%s)\n%v", ve.Stage, ve.Code, want.Stage, want.Code, want.Reason, ve)
			}
		})
	}
}

func TestEveryInvalidSchemaRuleIsExercised(t *testing.T) {
	m := loadManifest(t)
	if n := len(m.Invalid); n < 40 {
		t.Fatalf("only %d invalid fixtures", n)
	}
}

func TestOversizeBodyIsRejectedBeforeParsing(t *testing.T) {
	body := []byte(`{"pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`)
	_, err := ValidateContribution(body, mustProfiles(t))
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Stage != StageSize || ve.Code != "payload_too_large" {
		t.Fatalf("got %v", err)
	}
}

func TestBrokenJSONIsRejected(t *testing.T) {
	for _, in := range []string{"", "{", "[]", "null", `{"schema_version":`} {
		_, err := ValidateContribution([]byte(in), mustProfiles(t))
		var ve *ValidationError
		if !errors.As(err, &ve) || (ve.Stage != StageSyntax && ve.Stage != StageSchema) {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

// The largest valid contribution must fit in the body limit with room to spare.
func TestLargestFixtureFitsTheLimit(t *testing.T) {
	for _, f := range jsonFiles(t, "fixtures/valid") {
		if n := len(readFile(t, f)); n > MaxBodyBytes/2 {
			t.Errorf("%s is %d bytes", f, n)
		}
	}
}

type apiManifest struct {
	Fixtures map[string]struct {
		Def   string `json:"def"`
		Valid bool   `json:"valid"`
	} `json:"fixtures"`
}

func TestAPIFixtures(t *testing.T) {
	var m apiManifest
	if err := json.Unmarshal(readFile(t, "fixtures/api/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for k := range m.Fixtures {
		listed = append(listed, "fixtures/api/"+k)
	}
	sort.Strings(listed)
	var onDisk []string
	for _, f := range jsonFiles(t, "fixtures/api") {
		if !strings.HasSuffix(f, "pow-vectors.json") {
			onDisk = append(onDisk, f)
		}
	}
	if !slices.Equal(listed, onDisk) {
		t.Fatalf("api manifest and disk differ\nmanifest: %v\ndisk:     %v", listed, onDisk)
	}
	for name, f := range m.Fixtures {
		t.Run(name, func(t *testing.T) {
			err := ValidateAPI(f.Def, readFile(t, "fixtures/api/"+name))
			if f.Valid && err != nil {
				t.Fatal(err)
			}
			if !f.Valid && err == nil {
				t.Fatal("invalid message was accepted")
			}
		})
	}
}

func TestPoWVectors(t *testing.T) {
	var doc struct {
		Vectors []struct {
			ChallengeID string `json:"challenge_id"`
			Token       string `json:"token"`
			Difficulty  int    `json:"difficulty_bits"`
			Nonce       string `json:"nonce"`
			Bits        int    `json:"leading_zero_bits"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readFile(t, "fixtures/api/pow-vectors.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		if got := LeadingZeroBits(v.ChallengeID, v.Token, v.Nonce); got != v.Bits {
			t.Errorf("%s: %d leading zero bits, want %d", v.Nonce, got, v.Bits)
		}
		if !CheckPoW(v.ChallengeID, v.Token, v.Nonce, v.Difficulty) {
			t.Errorf("%s: nonce does not solve the challenge", v.Nonce)
		}
		if got := SolvePoW(v.ChallengeID, v.Token, v.Difficulty); got != v.Nonce {
			t.Errorf("solver found %s, vector says %s", got, v.Nonce)
		}
	}
}

func TestCheckPoWRejectsBadNonces(t *testing.T) {
	for _, n := range []string{"", "-1", "1.5", "abc", "99999999999999999999999"} {
		if CheckPoW("01JD5X8Q4M7R2N6T9V3W5Y0ZAB", "x", n, 0) {
			t.Errorf("nonce %q was accepted", n)
		}
	}
}
