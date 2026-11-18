// Package endpoints holds endpoint presets: named lists of URLs that
// nw reach requests. The built-in presets are embedded in the binary. Users
// add their own in the config file, in the same format.
package endpoints

import (
	"embed"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed presets/*.toml
var files embed.FS

// Default is the preset nw reach uses when none is chosen.
const Default = "dev"

// Endpoint is one URL to request.
type Endpoint struct {
	URL    string `toml:"url"`
	Name   string `toml:"name"`
	Reason string `toml:"reason"`
}

// Host returns the host name of the endpoint's URL.
func (e Endpoint) Host() string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Preset is a named list of endpoints. The same format is used in the
// built-in files and in the config file.
type Preset struct {
	Name        string     `toml:"name"`
	Description string     `toml:"description"`
	Endpoints   []Endpoint `toml:"endpoints"`
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Builtin returns the names of the built-in presets, sorted.
func Builtin() []string {
	entries, _ := files.ReadDir("presets")
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(out)
	return out
}

// Names returns the built-in preset names and the names of user, sorted.
func Names(user []Preset) []string {
	out := Builtin()
	for _, p := range user {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// Load returns the preset called name. It looks in the built-in presets
// first and then in user. User presets may not reuse a built-in name.
func Load(name string, user []Preset) (Preset, error) {
	if b, err := files.ReadFile("presets/" + name + ".toml"); err == nil {
		var p Preset
		md, err := toml.Decode(string(b), &p)
		if err != nil {
			return Preset{}, fmt.Errorf("preset %q: %w", name, err)
		}
		if u := md.Undecoded(); len(u) > 0 {
			return Preset{}, fmt.Errorf("preset %q: unknown keys %v", name, u)
		}
		if p.Name != name {
			return Preset{}, fmt.Errorf("preset file %q declares the name %q", name, p.Name)
		}
		return p, p.Validate(true)
	}
	for _, p := range user {
		if p.Name == name {
			return p, p.Validate(false)
		}
	}
	return Preset{}, fmt.Errorf("unknown endpoint preset %q (available: %s)", name, strings.Join(Names(user), ", "))
}

// ValidateUser checks every preset from the config file.
func ValidateUser(user []Preset) error {
	seen := map[string]bool{}
	for _, p := range user {
		if seen[p.Name] {
			return fmt.Errorf("endpoint preset %q is defined twice", p.Name)
		}
		seen[p.Name] = true
		for _, b := range Builtin() {
			if b == p.Name {
				return fmt.Errorf("endpoint preset %q is built in; choose another name", p.Name)
			}
		}
		if err := p.Validate(false); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks a preset. A built-in preset must also say why each
// endpoint was chosen.
func (p Preset) Validate(builtin bool) error {
	if !nameRE.MatchString(p.Name) {
		return fmt.Errorf("endpoint preset name %q must be 1 to 32 lowercase letters, digits or hyphens, starting with a letter", p.Name)
	}
	if len(p.Endpoints) == 0 {
		return fmt.Errorf("endpoint preset %q has no endpoints", p.Name)
	}
	seen := map[string]bool{}
	for _, e := range p.Endpoints {
		u, err := url.Parse(e.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return fmt.Errorf("endpoint preset %q: %q is not an http(s) URL", p.Name, e.URL)
		}
		if builtin && (e.Name == "" || e.Reason == "") {
			return fmt.Errorf("endpoint preset %q: %s needs a name and a reason", p.Name, e.URL)
		}
		if seen[e.URL] {
			return fmt.Errorf("endpoint preset %q: %s is listed twice", p.Name, e.URL)
		}
		seen[e.URL] = true
	}
	return nil
}
