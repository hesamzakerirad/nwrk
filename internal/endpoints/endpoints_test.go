package endpoints

import (
	"strings"
	"testing"
)

func TestBuiltinPresetsAreValid(t *testing.T) {
	names := Builtin()
	if len(names) == 0 || names[0] != "dev" {
		t.Fatalf("Builtin() = %v; want dev", names)
	}
	for _, n := range names {
		p, err := Load(n, nil)
		if err != nil {
			t.Fatalf("Load(%q): %v", n, err)
		}
		for _, e := range p.Endpoints {
			if !strings.HasPrefix(e.URL, "https://") {
				t.Errorf("%s: %s is not https", n, e.URL)
			}
		}
	}
}

func TestDevCoversTheDeveloperServices(t *testing.T) {
	p, err := Load("dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, e := range p.Endpoints {
		hosts[e.Host()] = true
	}
	for _, h := range []string{"github.com", "proxy.golang.org", "registry.npmjs.org", "pypi.org", "registry-1.docker.io", "crates.io", "formulae.brew.sh"} {
		if !hosts[h] {
			t.Errorf("dev preset lacks %s", h)
		}
	}
}

func TestUserPresets(t *testing.T) {
	user := []Preset{{Name: "work", Endpoints: []Endpoint{{URL: "https://intranet.example.com/"}}}}
	if err := ValidateUser(user); err != nil {
		t.Fatal(err)
	}
	p, err := Load("work", user)
	if err != nil || p.Endpoints[0].Host() != "intranet.example.com" {
		t.Fatalf("Load(work) = %+v, %v", p, err)
	}
	if got := strings.Join(Names(user), ","); got != "dev,work" {
		t.Errorf("Names = %s", got)
	}
	if _, err := Load("nope", user); err == nil || !strings.Contains(err.Error(), "dev, work") {
		t.Errorf("unknown preset error = %v", err)
	}
}

func TestUserPresetErrors(t *testing.T) {
	ep := []Endpoint{{URL: "https://example.com/"}}
	bad := map[string][]Preset{
		"built-in name": {{Name: "dev", Endpoints: ep}},
		"bad name":      {{Name: "My Work", Endpoints: ep}},
		"no endpoints":  {{Name: "work"}},
		"not http":      {{Name: "work", Endpoints: []Endpoint{{URL: "ftp://example.com/"}}}},
		"credentials":   {{Name: "work", Endpoints: []Endpoint{{URL: "https://user:pw@example.com/"}}}},
		"duplicate url": {{Name: "work", Endpoints: append(ep, ep...)}},
		"duplicate":     {{Name: "work", Endpoints: ep}, {Name: "work", Endpoints: ep}},
	}
	for name, u := range bad {
		if err := ValidateUser(u); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
