package aggregation

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/radestsam/nwrk/contracts"
)

type fixture struct {
	Description string `json:"description"`
	Config      Config `json:"config"`
	Rows        []Row  `json:"rows"`
	Expect      struct {
		Hourly       json.RawMessage `json:"hourly"`
		Samples      json.RawMessage `json:"samples"`
		Daily        json.RawMessage `json:"daily"`
		DailySamples json.RawMessage `json:"daily_samples"`
		Windows      []struct {
			Request struct {
				Target string `json:"target"`
				ASN    ASNKey `json:"asn"`
				Window string `json:"window"`
				AsOf   string `json:"as_of"`
			} `json:"request"`
			Result json.RawMessage `json:"result"`
		} `json:"windows"`
	} `json:"expect"`
}

func (c *Config) UnmarshalJSON(b []byte) error {
	var v struct {
		Threshold int `json:"threshold"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	c.Threshold = v.Threshold
	return nil
}

func load(t *testing.T, name string) fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// same compares two JSON documents by value.
func same(t *testing.T, what string, got any, want json.RawMessage) {
	t.Helper()
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(gb, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("%s differs\n got: %s\nwant: %s", what, clip(gb), clip(want))
	}
}

func clip(b []byte) string {
	if len(b) > 1500 {
		return string(b[:1500]) + "..."
	}
	return string(b)
}

func fixtureNames(t *testing.T) []string {
	raw, err := os.ReadFile("fixtures/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.Files
}

func TestManifestListsEveryFixture(t *testing.T) {
	listed := fixtureNames(t)
	onDisk, _ := filepath.Glob("fixtures/*.json")
	var names []string
	for _, p := range onDisk {
		if b := filepath.Base(p); b != "manifest.json" {
			names = append(names, b)
		}
	}
	a, b := slices.Clone(listed), slices.Clone(names)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		t.Fatalf("manifest %v, files %v", a, b)
	}
}

func TestFixtures(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			f := load(t, name)
			hourly, samples := Hourly(f.Rows), Samples(f.Rows)
			if f.Expect.Hourly != nil {
				same(t, "hourly", hourly, f.Expect.Hourly)
			}
			if f.Expect.Samples != nil {
				same(t, "samples", samples, f.Expect.Samples)
			}
			if f.Expect.Daily != nil || f.Expect.DailySamples != nil {
				d, ds := Daily(hourly, samples)
				if f.Expect.Daily != nil {
					same(t, "daily", d, f.Expect.Daily)
				}
				if f.Expect.DailySamples != nil {
					same(t, "daily samples", ds, f.Expect.DailySamples)
				}
			}
			for _, w := range f.Expect.Windows {
				res, err := Window(hourly, samples, Request{Target: w.Request.Target, ASN: w.Request.ASN, Window: w.Request.Window, AsOf: w.Request.AsOf}, f.Config)
				if err != nil {
					t.Fatal(err)
				}
				same(t, "window "+w.Request.Target+" "+w.Request.Window, res, w.Result)
			}
		})
	}
}

func TestOrderOfRowsDoesNotMatter(t *testing.T) {
	for _, name := range fixtureNames(t) {
		f := load(t, name)
		want := Hourly(f.Rows)
		wantS := Samples(f.Rows)
		for seed := int64(1); seed <= 3; seed++ {
			rows := slices.Clone(f.Rows)
			rand.New(rand.NewSource(seed)).Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
			if !reflect.DeepEqual(want, Hourly(rows)) || !reflect.DeepEqual(wantS, Samples(rows)) {
				t.Fatalf("%s: shuffled rows (seed %d) give another result", name, seed)
			}
		}
	}
}

// Rebuilding an hour from its rows gives the same rollup as the first time,
// even when the rows of other hours change.
func TestRebuildOfOneHourIsStable(t *testing.T) {
	f := load(t, "hourly-basic.json")
	all := Hourly(f.Rows)
	var hour string
	for _, r := range f.Rows {
		hour = r.Hour
		break
	}
	var only []Row
	for _, r := range f.Rows {
		if r.Hour == hour {
			only = append(only, r)
		}
	}
	var fromAll []Rollup
	for _, h := range all {
		if h.Hour == hour {
			fromAll = append(fromAll, h)
		}
	}
	if !reflect.DeepEqual(fromAll, Hourly(only)) {
		t.Fatal("an hour built alone differs from the same hour built with the others")
	}
}

// Computing the days from the hours gives the same rollup as computing a day
// from its rows directly, for every day of every fixture.
func TestDailyEqualsSumOfHours(t *testing.T) {
	for _, name := range fixtureNames(t) {
		f := load(t, name)
		days, _ := Daily(Hourly(f.Rows), Samples(f.Rows))
		for _, d := range days {
			var rows []Row
			for _, r := range f.Rows {
				if r.Hour[:10] == d.Day && r.Target == d.Target && asnOf(r.ASN) == d.ASN && r.Layer == d.Layer && r.Family == d.Family {
					rows = append(rows, r)
				}
			}
			var sumA, sumS int
			for _, r := range rows {
				sumA++
				if r.Success() {
					sumS++
				}
			}
			if d.Attempts != sumA || d.Successes != sumS {
				t.Fatalf("%s %s: daily %d/%d, rows %d/%d", name, d.Day, d.Attempts, d.Successes, sumA, sumS)
			}
		}
	}
}

func TestBucketEdges(t *testing.T) {
	cases := map[int]int{0: 0, 10: 0, 11: 1, 25: 1, 26: 2, 60000: 15, 30001: 15, 30000: 14}
	for ms, want := range cases {
		if got := Bucket(ms); got != want {
			t.Errorf("Bucket(%d) = %d, want %d", ms, got, want)
		}
	}
}

func TestRateRoundsHalfUp(t *testing.T) {
	if v := RateBP(1, 3); *v != 3333 {
		t.Error(*v)
	}
	if v := RateBP(2, 3); *v != 6667 {
		t.Error(*v)
	}
	if v := RateBP(1, 8); *v != 1250 {
		t.Error(*v)
	}
	if RateBP(1, 0) != nil {
		t.Error("zero denominator")
	}
	if v := RateBP(1, 16); *v != 625 { // 625.0 exactly
		t.Error(*v)
	}
	if v := RateBP(1, 32); *v != 313 { // 312.5 rounds up
		t.Error(*v)
	}
}

func TestWindowRefusesBadInput(t *testing.T) {
	if _, err := Window(nil, nil, Request{Target: "a", Window: "2h", AsOf: "2026-11-22T12:00:00Z"}, Config{}); err == nil {
		t.Error("unknown window accepted")
	}
	if _, err := Window(nil, nil, Request{Target: "a", Window: "6h", AsOf: "2026-11-22T12:30:00Z"}, Config{}); err == nil {
		t.Error("as_of that is not an hour boundary was accepted")
	}
}

func TestNoPrivateFieldsInRollups(t *testing.T) {
	f := load(t, "hourly-basic.json")
	raw, _ := json.Marshal(Hourly(f.Rows))
	for _, s := range []string{"submission", "S0001"} {
		if contains(raw, s) {
			t.Errorf("rollups hold %q", s)
		}
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func contains(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }

// Every expected window result must be a valid public message, so the
// specification and the public schema cannot drift apart.
func TestExpectedResultsMatchThePublicSchema(t *testing.T) {
	n := 0
	for _, name := range fixtureNames(t) {
		f := load(t, name)
		for _, w := range f.Expect.Windows {
			n++
			if err := contracts.ValidatePublic("windowResult", w.Result); err != nil {
				t.Errorf("%s %s %s: %v", name, w.Request.Target, w.Request.Window, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no window results were checked")
	}
}

func TestPublicSchemaRefusesBadResults(t *testing.T) {
	bad := map[string]string{
		"published without layers": `{"target":"a","asn":1,"window":"6h","from":"2026-11-22T06:00:00Z","to":"2026-11-22T12:00:00Z","submissions":30,"threshold":20,"published":true,"state":"reachable_response_observed"}`,
		"unpublished with layers":  `{"target":"a","asn":1,"window":"6h","from":"2026-11-22T06:00:00Z","to":"2026-11-22T12:00:00Z","submissions":3,"threshold":20,"published":false,"state":"insufficient_data","layers":{}}`,
		"unpublished with a state": `{"target":"a","asn":1,"window":"6h","from":"2026-11-22T06:00:00Z","to":"2026-11-22T12:00:00Z","submissions":3,"threshold":20,"published":false,"state":"reachable_response_observed"}`,
		"extra field":              `{"target":"a","asn":1,"window":"6h","from":"2026-11-22T06:00:00Z","to":"2026-11-22T12:00:00Z","submissions":3,"threshold":20,"published":false,"state":"insufficient_data","ip":"203.0.113.1"}`,
		"time not on the hour":     `{"target":"a","asn":1,"window":"6h","from":"2026-11-22T06:30:00Z","to":"2026-11-22T12:00:00Z","submissions":3,"threshold":20,"published":false,"state":"insufficient_data"}`,
		"unknown window":           `{"target":"a","asn":1,"window":"2h","from":"2026-11-22T06:00:00Z","to":"2026-11-22T12:00:00Z","submissions":3,"threshold":20,"published":false,"state":"insufficient_data"}`,
	}
	for name, doc := range bad {
		if err := contracts.ValidatePublic("windowResult", []byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
