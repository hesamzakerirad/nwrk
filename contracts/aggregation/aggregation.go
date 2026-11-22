// Package aggregation is the reference implementation of the NWRK aggregation
// specification (spec.md). It turns measurement rows into hourly and daily
// rollups, and rollups into window results with a classification.
//
// The package has no dependency on the rest of nw. The server in NWRK Status
// has its own implementation, and both must give the same output for every
// fixture in fixtures/.
package aggregation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Constants of specification version 1 (section 9).
const (
	DefaultThreshold      = 20
	CompletionReachableBP = 9000
	CompletionFailureBP   = 5000
	RefusalBP             = 5000
	DegradedDropBP        = 2000
	DegradedP95Factor     = 2
	BaselineHours         = 168
)

// Layers and families in the order that results list them.
var (
	Layers   = []string{"dns", "tcp", "tls", "http"}
	Families = []string{"ipv4", "ipv6"}
)

// BucketLimits are the upper limits of the histogram buckets in ms (section 4).
var BucketLimits = [16]int{10, 25, 50, 100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000, 30000, 60000}

// WindowHours maps the window names to their length in hours (section 6).
var WindowHours = map[string]int{"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}

// States of the classification (section 8).
const (
	StateInsufficient = "insufficient_data"
	StateFailure      = "network_failure_observed"
	StateRefusal      = "server_refusal_observed"
	StateDegraded     = "degraded_observations"
	StateReachable    = "reachable_response_observed"
	StateHTTP         = "http_response_received"
)

const timeFormat = "2006-01-02T15:04:05Z"

// Row is one measurement with the data of its submission (section 2).
type Row struct {
	Submission string `json:"submission"`
	Hour       string `json:"hour"`
	Target     string `json:"target"`
	ASN        *int   `json:"asn"`
	Layer      string `json:"layer"`
	Family     string `json:"family"`
	Outcome    string `json:"outcome"`
	DurationMS int    `json:"duration_ms"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Success reports whether the measurement is a success (section 1).
func (r Row) Success() bool { return r.Outcome == "success" || r.Outcome == "response_received" }

// Rollup is an hourly rollup, or a daily one when Day is set (sections 3 and 5).
type Rollup struct {
	Hour          string         `json:"hour,omitempty"`
	Day           string         `json:"day,omitempty"`
	Target        string         `json:"target"`
	ASN           int            `json:"asn"`
	Layer         string         `json:"layer"`
	Family        string         `json:"family"`
	Attempts      int            `json:"attempts"`
	Successes     int            `json:"successes"`
	Failures      int            `json:"failures"`
	StatusCounts  map[string]int `json:"status_counts"`
	ErrorCounts   map[string]int `json:"error_counts"`
	DurationCount int            `json:"duration_count"`
	DurationSumMS int            `json:"duration_sum_ms"`
	DurationMinMS *int           `json:"duration_min_ms"`
	DurationMaxMS *int           `json:"duration_max_ms"`
	Histogram     [16]int        `json:"histogram"`
}

// Sample counts the distinct submissions of an hour, or of a day when Day is set.
type Sample struct {
	Hour        string `json:"hour,omitempty"`
	Day         string `json:"day,omitempty"`
	Target      string `json:"target"`
	ASN         int    `json:"asn"`
	Submissions int    `json:"submissions"`
}

func asnOf(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// Bucket returns the histogram bucket of a duration (section 4).
func Bucket(ms int) int {
	for i, limit := range BucketLimits {
		if ms <= limit {
			return i
		}
	}
	return len(BucketLimits) - 1
}

type rollupKey struct {
	hour, target string
	asn          int
	layer, fam   string
}

// Hourly builds the hourly rollups of the rows, sorted as the specification says.
func Hourly(rows []Row) []Rollup {
	groups := map[rollupKey]*Rollup{}
	for _, r := range rows {
		k := rollupKey{r.Hour, r.Target, asnOf(r.ASN), r.Layer, r.Family}
		g := groups[k]
		if g == nil {
			g = &Rollup{Hour: r.Hour, Target: r.Target, ASN: k.asn, Layer: r.Layer, Family: r.Family,
				StatusCounts: map[string]int{}, ErrorCounts: map[string]int{}}
			groups[k] = g
		}
		g.Attempts++
		if !r.Success() {
			g.Failures++
			g.ErrorCounts[r.Error]++
			continue
		}
		g.Successes++
		g.DurationCount++
		g.DurationSumMS += r.DurationMS
		g.Histogram[Bucket(r.DurationMS)]++
		g.DurationMinMS = minPtr(g.DurationMinMS, r.DurationMS)
		g.DurationMaxMS = maxPtr(g.DurationMaxMS, r.DurationMS)
		if r.Layer == "http" && r.StatusCode != 0 {
			g.StatusCounts[strconv.Itoa(r.StatusCode)]++
		}
	}
	out := make([]Rollup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return lessRollup(out[i], out[j], false) })
	return out
}

func lessRollup(a, b Rollup, daily bool) bool {
	ta, tb := a.Hour, b.Hour
	if daily {
		ta, tb = a.Day, b.Day
	}
	switch {
	case ta != tb:
		return ta < tb
	case a.Target != b.Target:
		return a.Target < b.Target
	case a.ASN != b.ASN:
		return a.ASN < b.ASN
	case a.Layer != b.Layer:
		return a.Layer < b.Layer
	}
	return a.Family < b.Family
}

func minPtr(p *int, v int) *int {
	if p == nil || v < *p {
		return &v
	}
	return p
}

func maxPtr(p *int, v int) *int {
	if p == nil || v > *p {
		return &v
	}
	return p
}

// Samples counts the distinct submissions for each hour, target and ASN (section 3.1).
func Samples(rows []Row) []Sample {
	type key struct {
		hour, target string
		asn          int
	}
	sets := map[key]map[string]bool{}
	for _, r := range rows {
		k := key{r.Hour, r.Target, asnOf(r.ASN)}
		if sets[k] == nil {
			sets[k] = map[string]bool{}
		}
		sets[k][r.Submission] = true
	}
	out := make([]Sample, 0, len(sets))
	for k, s := range sets {
		out = append(out, Sample{Hour: k.hour, Target: k.target, ASN: k.asn, Submissions: len(s)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Hour != b.Hour:
			return a.Hour < b.Hour
		case a.Target != b.Target:
			return a.Target < b.Target
		}
		return a.ASN < b.ASN
	})
	return out
}

// Daily adds the hourly rollups and samples of each UTC day (section 5).
func Daily(hourly []Rollup, samples []Sample) ([]Rollup, []Sample) {
	groups := map[rollupKey]*Rollup{}
	for _, h := range hourly {
		day := h.Hour[:10]
		k := rollupKey{day, h.Target, h.ASN, h.Layer, h.Family}
		g := groups[k]
		if g == nil {
			g = &Rollup{Day: day, Target: h.Target, ASN: h.ASN, Layer: h.Layer, Family: h.Family,
				StatusCounts: map[string]int{}, ErrorCounts: map[string]int{}}
			groups[k] = g
		}
		g.Attempts += h.Attempts
		g.Successes += h.Successes
		g.Failures += h.Failures
		g.DurationCount += h.DurationCount
		g.DurationSumMS += h.DurationSumMS
		for k, v := range h.StatusCounts {
			g.StatusCounts[k] += v
		}
		for k, v := range h.ErrorCounts {
			g.ErrorCounts[k] += v
		}
		for i, v := range h.Histogram {
			g.Histogram[i] += v
		}
		if h.DurationMinMS != nil {
			g.DurationMinMS = minPtr(g.DurationMinMS, *h.DurationMinMS)
		}
		if h.DurationMaxMS != nil {
			g.DurationMaxMS = maxPtr(g.DurationMaxMS, *h.DurationMaxMS)
		}
	}
	days := make([]Rollup, 0, len(groups))
	for _, g := range groups {
		days = append(days, *g)
	}
	sort.Slice(days, func(i, j int) bool { return lessRollup(days[i], days[j], true) })

	type skey struct {
		day, target string
		asn         int
	}
	sums := map[skey]int{}
	for _, s := range samples {
		sums[skey{s.Hour[:10], s.Target, s.ASN}] += s.Submissions
	}
	ds := make([]Sample, 0, len(sums))
	for k, v := range sums {
		ds = append(ds, Sample{Day: k.day, Target: k.target, ASN: k.asn, Submissions: v})
	}
	sort.Slice(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		switch {
		case a.Day != b.Day:
			return a.Day < b.Day
		case a.Target != b.Target:
			return a.Target < b.Target
		}
		return a.ASN < b.ASN
	})
	return days, ds
}

// RateBP is a rate in basis points, rounded half up, or nil if the denominator is 0 (section 6.2).
func RateBP(n, m int) *int {
	if m == 0 {
		return nil
	}
	v := (n*10000 + m/2) / m
	return &v
}

// Percentile returns the p-th percentile of a histogram in ms, or nil if it is empty (section 6.3).
func Percentile(hist [16]int, p int) *float64 {
	n := 0
	for _, c := range hist {
		n += c
	}
	if n == 0 {
		return nil
	}
	rank := (p*n + 99) / 100
	run := 0
	for i, c := range hist {
		if run+c < rank {
			run += c
			continue
		}
		lo := 0
		if i > 0 {
			lo = BucketLimits[i-1]
		}
		hi := BucketLimits[i]
		tenths := lo*10 + ((hi-lo)*10*(rank-run)*2+c)/(2*c)
		v := float64(tenths) / 10
		return &v
	}
	return nil
}

// Series says what a window is computed for: one target and one ASN, or all ASNs.
type Series struct {
	Target string
	ASN    int
	All    bool
}

// Request asks for one window result.
type Request struct {
	Target string
	ASN    ASNKey
	Window string
	AsOf   string
}

// ASNKey is an ASN number or the word "all" in JSON.
type ASNKey struct {
	N   int
	All bool
}

// MarshalJSON writes a number, or "all".
func (a ASNKey) MarshalJSON() ([]byte, error) {
	if a.All {
		return []byte(`"all"`), nil
	}
	return []byte(strconv.Itoa(a.N)), nil
}

// UnmarshalJSON reads a number, or "all".
func (a *ASNKey) UnmarshalJSON(b []byte) error {
	if string(b) == `"all"` {
		*a = ASNKey{All: true}
		return nil
	}
	return json.Unmarshal(b, &a.N)
}

// Config holds the values that a deployment can change.
type Config struct {
	Threshold int
}

func (c Config) threshold() int {
	if c.Threshold > 0 {
		return c.Threshold
	}
	return DefaultThreshold
}

// FamilyResult is the count of one family in one layer.
type FamilyResult struct {
	Attempts  int  `json:"attempts"`
	Successes int  `json:"successes"`
	SuccessBP *int `json:"success_bp"`
}

// LayerResult is the sum of one layer over a window.
type LayerResult struct {
	Attempts    int                     `json:"attempts"`
	Successes   int                     `json:"successes"`
	Failures    int                     `json:"failures"`
	SuccessBP   *int                    `json:"success_bp"`
	P50MS       *float64                `json:"p50_ms"`
	P95MS       *float64                `json:"p95_ms"`
	ErrorCounts map[string]int          `json:"error_counts"`
	Families    map[string]FamilyResult `json:"families"`
	// StatusCounts is set only for http. A pointer keeps an empty map in the output.
	StatusCounts *map[string]int `json:"status_counts,omitempty"`
}

// Baseline is the comparison period of a window (section 8).
type Baseline struct {
	Submissions  int      `json:"submissions"`
	CompletionBP int      `json:"completion_bp"`
	P95MS        *float64 `json:"p95_ms"`
}

// Result is the result for one series and window (section 6.1).
type Result struct {
	Target            string
	ASN               ASNKey
	Window            string
	From, To          string
	Submissions       int
	Threshold         int
	Published         bool
	State             string
	Layers            map[string]*LayerResult
	CompletionBP      *int
	Baseline          *Baseline
	NetworksObserved  *int
	NetworksPublished *int
}

// MarshalJSON writes the fields that the specification lists. An unpublished
// result has no layers, completion rate or baseline.
func (r Result) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"target": r.Target, "asn": r.ASN, "window": r.Window, "from": r.From, "to": r.To,
		"submissions": r.Submissions, "threshold": r.Threshold, "published": r.Published, "state": r.State,
	}
	if r.NetworksObserved != nil {
		m["networks_observed"] = *r.NetworksObserved
		m["networks_published"] = *r.NetworksPublished
	}
	if r.Published {
		m["layers"] = r.Layers
		m["completion_bp"] = r.CompletionBP
		m["baseline"] = r.Baseline
	}
	return json.Marshal(m)
}

type sums struct {
	rollups []Rollup
	subs    int
}

func collect(hourly []Rollup, samples []Sample, target string, asn ASNKey, from, to time.Time) sums {
	var s sums
	in := func(hour string) bool {
		t, err := time.Parse(timeFormat, hour)
		return err == nil && !t.Before(from) && t.Before(to)
	}
	for _, h := range hourly {
		if h.Target == target && (asn.All || h.ASN == asn.N) && in(h.Hour) {
			s.rollups = append(s.rollups, h)
		}
	}
	for _, sm := range samples {
		if sm.Target == target && (asn.All || sm.ASN == asn.N) && in(sm.Hour) {
			s.subs += sm.Submissions
		}
	}
	return s
}

func layersOf(rs []Rollup) map[string]*LayerResult {
	out := map[string]*LayerResult{}
	for _, layer := range Layers {
		l := &LayerResult{ErrorCounts: map[string]int{}, Families: map[string]FamilyResult{}}
		var hist [16]int
		fam := map[string]*FamilyResult{"ipv4": {}, "ipv6": {}}
		var status map[string]int
		if layer == "http" {
			status = map[string]int{}
			l.StatusCounts = &status
		}
		for _, r := range rs {
			if r.Layer != layer {
				continue
			}
			l.Attempts += r.Attempts
			l.Successes += r.Successes
			for i, v := range r.Histogram {
				hist[i] += v
			}
			for k, v := range r.ErrorCounts {
				l.ErrorCounts[k] += v
			}
			for k, v := range r.StatusCounts {
				if status != nil {
					status[k] += v
				}
			}
			if f := fam[r.Family]; f != nil {
				f.Attempts += r.Attempts
				f.Successes += r.Successes
			}
		}
		l.Failures = l.Attempts - l.Successes
		l.SuccessBP = RateBP(l.Successes, l.Attempts)
		l.P50MS, l.P95MS = Percentile(hist, 50), Percentile(hist, 95)
		for _, name := range Families {
			f := fam[name]
			l.Families[name] = FamilyResult{Attempts: f.Attempts, Successes: f.Successes, SuccessBP: RateBP(f.Successes, f.Attempts)}
		}
		out[layer] = l
	}
	return out
}

func completion(layers map[string]*LayerResult) *int {
	return RateBP(layers["http"].Successes, layers["dns"].Attempts)
}

// Window computes the result of a request from the hourly rollups and samples.
func Window(hourly []Rollup, samples []Sample, req Request, cfg Config) (Result, error) {
	hours, ok := WindowHours[req.Window]
	if !ok {
		return Result{}, fmt.Errorf("unknown window %q", req.Window)
	}
	to, err := time.Parse(timeFormat, req.AsOf)
	if err != nil || to.Minute() != 0 || to.Second() != 0 {
		return Result{}, fmt.Errorf("as_of %q is not an hour boundary", req.AsOf)
	}
	from := to.Add(-time.Duration(hours) * time.Hour)
	th := cfg.threshold()
	cur := collect(hourly, samples, req.Target, req.ASN, from, to)
	res := Result{Target: req.Target, ASN: req.ASN, Window: req.Window, From: from.Format(timeFormat), To: to.Format(timeFormat),
		Submissions: cur.subs, Threshold: th, Published: cur.subs >= th}

	if req.ASN.All {
		seen := map[int]int{}
		for _, s := range samples {
			if s.Target != req.Target || s.ASN == 0 {
				continue
			}
			if t, err := time.Parse(timeFormat, s.Hour); err == nil && !t.Before(from) && t.Before(to) {
				seen[s.ASN] += s.Submissions
			}
		}
		observed, published := len(seen), 0
		for _, n := range seen {
			if n >= th {
				published++
			}
		}
		res.NetworksObserved, res.NetworksPublished = &observed, &published
	}
	if !res.Published {
		res.State = StateInsufficient
		return res, nil
	}

	res.Layers = layersOf(cur.rollups)
	res.CompletionBP = completion(res.Layers)

	bFrom := from.Add(-BaselineHours * time.Hour)
	b := collect(hourly, samples, req.Target, req.ASN, bFrom, from)
	if b.subs >= th {
		bl := layersOf(b.rollups)
		if bc := completion(bl); bc != nil {
			res.Baseline = &Baseline{Submissions: b.subs, CompletionBP: *bc, P95MS: bl["http"].P95MS}
		}
	}
	res.State = classify(res)
	return res, nil
}

func classify(r Result) string {
	httpL := r.Layers["http"]
	comp := r.CompletionBP
	if comp != nil && *comp < CompletionFailureBP {
		return StateFailure
	}
	if httpL.Successes > 0 {
		status := *httpL.StatusCounts
		refused := status["403"] + status["451"]
		if bp := RateBP(refused, httpL.Successes); bp != nil && *bp >= RefusalBP {
			return StateRefusal
		}
	}
	if b := r.Baseline; b != nil {
		if comp != nil && b.CompletionBP-*comp >= DegradedDropBP {
			return StateDegraded
		}
		if httpL.P95MS != nil && b.P95MS != nil && *httpL.P95MS >= DegradedP95Factor**b.P95MS {
			return StateDegraded
		}
	}
	if comp != nil && *comp >= CompletionReachableBP {
		return StateReachable
	}
	return StateHTTP
}
