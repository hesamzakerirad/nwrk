package regions

import (
	"strings"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/domain"
)

func TestShippedPresetsAreValid(t *testing.T) {
	if got := strings.Join(Names(), ","); got != "cn,global,ir,ru,tr" {
		t.Fatalf("presets: %s", got)
	}
	for _, n := range Names() {
		p, err := Load(n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if p.Description == "" || len(p.Targets) == 0 {
			t.Errorf("%s: incomplete: %+v", n, p)
		}
	}
}

func TestGlobalPreset(t *testing.T) {
	p, err := Load("global")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Resolvers) != 3 || p.Resolvers[0].Address != "1.1.1.1" {
		t.Fatalf("%+v", p.Resolvers)
	}
	if len(p.TargetsIn(domain.ScopeDomestic)) != 0 || len(p.TargetsIn(domain.ScopeInternational)) != 3 {
		t.Fatalf("%+v", p.Targets)
	}
}

func TestIRIncludesGlobalAndAddsDomesticAnchors(t *testing.T) {
	g, _ := Load("global")
	p, err := Load("ir")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.TargetsIn(domain.ScopeInternational)) != len(g.TargetsIn(domain.ScopeInternational)) {
		t.Fatal("ir must contain the whole global set")
	}
	if len(p.TargetsIn(domain.ScopeDomestic)) < 3 {
		t.Fatalf("ir needs several domestic anchors so one outage does not decide: %+v", p.Targets)
	}
	if len(p.Resolvers) != len(g.Resolvers) {
		t.Fatal("ir ships no domestic resolver; users add their own")
	}
}

func TestEveryEntryRecordsItsReason(t *testing.T) {
	for _, n := range Names() {
		p, _ := Load(n)
		for _, r := range p.Resolvers {
			if len(r.Reason) < 20 {
				t.Errorf("%s: resolver %s has no real reason", n, r.Address)
			}
		}
		for _, tg := range p.Targets {
			if len(tg.Reason) < 20 || tg.Host() == "" {
				t.Errorf("%s: target %s has no real reason", n, tg.URL)
			}
		}
	}
}

// Wording policy (SPEC 8.5): presets use technical vocabulary and no
// target may relate to circumvention.
func TestPresetsKeepToTheWordingPolicy(t *testing.T) {
	banned := []string{"censor", "circumvent", "bypass", "vpn", "proxy", "sanction", "unblock", "filter-breaking"}
	for _, n := range Names() {
		b, err := files.ReadFile("presets/" + n + ".toml")
		if err != nil {
			t.Fatal(err)
		}
		// The policy covers the data; comments may name it.
		var data []string
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				data = append(data, line)
			}
		}
		text := strings.ToLower(strings.Join(data, "\n"))
		for _, w := range banned {
			if strings.Contains(text, w) {
				t.Errorf("%s.toml uses %q", n, w)
			}
		}
	}
}

func TestUnknownRegion(t *testing.T) {
	if _, err := Load("zz"); err == nil || !strings.Contains(err.Error(), "cn, global, ir, ru, tr") {
		t.Fatalf("the error must list the choices: %v", err)
	}
	if !Valid("ir") || Valid("zz") {
		t.Fatal("Valid is wrong")
	}
}

func TestValidationCatchesBadPresets(t *testing.T) {
	good := Preset{Name: "x", Resolvers: []Resolver{{Address: "1.1.1.1", Name: "n", Reason: "r"}},
		Targets: []Target{{URL: "https://example.test/", Name: "n", Scope: domain.ScopeInternational, Reason: "r"}}}
	if err := good.validate("x"); err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(*Preset){
		"wrong name":         func(p *Preset) { p.Name = "y" },
		"resolver not an IP": func(p *Preset) { p.Resolvers[0].Address = "dns.example" },
		"no reason":          func(p *Preset) { p.Targets[0].Reason = "" },
		"bad scope":          func(p *Preset) { p.Targets[0].Scope = "far" },
		"bad url":            func(p *Preset) { p.Targets[0].URL = "ftp://example.test" },
		"duplicate":          func(p *Preset) { p.Targets = append(p.Targets, p.Targets[0]) },
	}
	for name, f := range mutate {
		p := good
		p.Resolvers = append([]Resolver{}, good.Resolvers...)
		p.Targets = append([]Target{}, good.Targets...)
		f(&p)
		if err := p.validate("x"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
