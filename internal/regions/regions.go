// Package regions holds the region presets: reviewed lists of reference
// resolvers and targets that nw doctor probes. They are embedded in the
// binary. nw never detects the user's country; a preset is used only when
// the user selects it.
package regions

import (
	"embed"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/radestsam/nwrk/internal/domain"
)

//go:embed presets/*.toml
var files embed.FS

// Default is the preset doctor uses when none is selected.
const Default = "global"

// Resolver is a reference DNS resolver.
type Resolver struct {
	Address string `toml:"address"`
	Name    string `toml:"name"`
	Reason  string `toml:"reason"`
}

// Target is a reference URL to reach.
type Target struct {
	URL    string       `toml:"url"`
	Name   string       `toml:"name"`
	Scope  domain.Scope `toml:"scope"`
	Reason string       `toml:"reason"`
}

// Host returns the host name of the target's URL.
func (t Target) Host() string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Preset is a region preset with its included presets already merged in.
type Preset struct {
	Name        string
	Description string
	Resolvers   []Resolver
	Targets     []Target
}

type file struct {
	Name        string     `toml:"name"`
	Description string     `toml:"description"`
	Includes    []string   `toml:"includes"`
	Resolvers   []Resolver `toml:"resolvers"`
	Targets     []Target   `toml:"targets"`
}

// Names lists the available presets, sorted.
func Names() []string {
	entries, err := files.ReadDir("presets")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(out)
	return out
}

// Valid reports whether name is a preset.
func Valid(name string) bool {
	for _, n := range Names() {
		if n == name {
			return true
		}
	}
	return false
}

// Load returns the preset called name, with the presets it includes merged
// in first. The result is validated.
func Load(name string) (Preset, error) {
	return load(name, map[string]bool{})
}

func load(name string, seen map[string]bool) (Preset, error) {
	if seen[name] {
		return Preset{}, fmt.Errorf("preset %q includes itself", name)
	}
	seen[name] = true
	b, err := files.ReadFile("presets/" + name + ".toml")
	if err != nil {
		return Preset{}, fmt.Errorf("unknown region %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	var f file
	md, err := toml.Decode(string(b), &f)
	if err != nil {
		return Preset{}, fmt.Errorf("preset %q: %w", name, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		return Preset{}, fmt.Errorf("preset %q: unknown keys %v", name, u)
	}
	p := Preset{Name: f.Name, Description: f.Description}
	for _, inc := range f.Includes {
		base, err := load(inc, seen)
		if err != nil {
			return Preset{}, err
		}
		p.Resolvers = append(p.Resolvers, base.Resolvers...)
		p.Targets = append(p.Targets, base.Targets...)
	}
	p.Resolvers = append(p.Resolvers, f.Resolvers...)
	p.Targets = append(p.Targets, f.Targets...)
	if err := p.validate(name); err != nil {
		return Preset{}, err
	}
	return p, nil
}

func (p Preset) validate(file string) error {
	if p.Name != file {
		return fmt.Errorf("preset file %q declares the name %q", file, p.Name)
	}
	seen := map[string]bool{}
	for _, r := range p.Resolvers {
		if _, err := netip.ParseAddr(r.Address); err != nil {
			return fmt.Errorf("preset %q: resolver %q is not an IP address", p.Name, r.Address)
		}
		if r.Reason == "" || r.Name == "" {
			return fmt.Errorf("preset %q: resolver %s needs a name and a reason", p.Name, r.Address)
		}
		if seen[r.Address] {
			return fmt.Errorf("preset %q: resolver %s is listed twice", p.Name, r.Address)
		}
		seen[r.Address] = true
	}
	for _, t := range p.Targets {
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
			return fmt.Errorf("preset %q: target %q is not an http(s) URL", p.Name, t.URL)
		}
		if t.Reason == "" || t.Name == "" {
			return fmt.Errorf("preset %q: target %s needs a name and a reason", p.Name, t.URL)
		}
		if t.Scope != domain.ScopeInternational && t.Scope != domain.ScopeDomestic {
			return fmt.Errorf("preset %q: target %s has scope %q (want international or domestic)", p.Name, t.URL, t.Scope)
		}
		if seen[t.URL] {
			return fmt.Errorf("preset %q: target %s is listed twice", p.Name, t.URL)
		}
		seen[t.URL] = true
	}
	return nil
}

// TargetsIn returns the targets of one scope, in preset order.
func (p Preset) TargetsIn(s domain.Scope) []Target {
	var out []Target
	for _, t := range p.Targets {
		if t.Scope == s {
			out = append(out, t)
		}
	}
	return out
}
